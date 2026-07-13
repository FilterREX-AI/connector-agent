// Package evidencebundle is the shared FilterREX Evidence Bundle v1.0 writer.
//
// Phase 3B-1: this package packages *already-captured* command outputs into a
// bundle ZIP that is indistinguishable — to the FilterREX importer — from a
// bundle produced by the Python collector, except for `collection_method`.
//
// It knows NOTHING about SSH or the REST API. It only:
//   - groups captures by switch,
//   - resolves each command's canonical filename + support level from the
//     embedded Brocade command profile (the single source of truth shared with
//     collectors/brocade/brocade_command_profile.json and the TS catalog),
//   - writes one file per successful command,
//   - computes sha256 of each file,
//   - emits manifest.json (Evidence Bundle v1.0 schema — no support_level, no
//     generated_at drift),
//   - and packages everything into a ZIP.
//
// The SSH capture path (Phase 3B-2) and the export operation wiring
// (Phase 3B-3) are intentionally NOT in this package.
package evidencebundle

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Bundle format constants — must stay aligned with the Python collector
// (collectors/brocade/filterrex_collect_brocade.py) and the TS contract.
const (
	BundleVersion      = "1.0"
	Vendor             = "brocade-fos"
	BundleRoot         = "filterrex-evidence-bundle"
	AgentBundleZipName = "filterrex-agent-evidence-bundle.zip"

	// CollectionMethodAgent is the only value this writer emits by default.
	CollectionMethodAgent = "agent"
)

//go:embed brocade_command_profile.json
var embeddedProfileJSON []byte

// EmbeddedProfileJSON returns the raw bytes of the embedded command profile so
// tests can assert parity against the canonical collectors/brocade copy.
func EmbeddedProfileJSON() []byte {
	out := make([]byte, len(embeddedProfileJSON))
	copy(out, embeddedProfileJSON)
	return out
}

// CommandCapture is a single already-executed read-only command result handed
// to the writer. The writer never runs anything; it only packages these.
type CommandCapture struct {
	SwitchName string // human-facing switch name (identity for grouping)
	FabricRole string // "source" | "target" | "" (unknown)
	Command    string // canonical command id, e.g. "switchshow", "sfpshow -all"
	// Filename is optional. When empty the writer resolves it from the profile.
	// When set it MUST match the profile filename for the command.
	Filename    string
	Stdout      []byte
	Stderr      []byte
	ExitCode    int
	TimedOut    bool
	CollectedAt time.Time
}

// SwitchMeta carries optional per-switch identity written into the manifest.
type SwitchMeta struct {
	SwitchName string
	FID        *int
	WWN        string
	DomainID   *int
	Model      string
	Notes      string
}

// BuildOptions controls bundle-level manifest fields.
type BuildOptions struct {
	// CollectionMethod defaults to "agent" when empty.
	CollectionMethod string
	// FabricRole is the bundle-level role. "" or "auto" derives it from the
	// captures (single role → that role, otherwise "unknown").
	FabricRole string
	// CustomerSupplied maps to manifest.customer_supplied.
	CustomerSupplied bool
	// CollectedAt is the bundle-level timestamp. Zero → time.Now().UTC().
	CollectedAt time.Time
	// SwitchMeta supplies optional per-switch identity, keyed by SwitchName.
	SwitchMeta []SwitchMeta
	// Collector labels the collection-summary.json producer.
	Collector string
}

// ── Evidence Bundle v1.0 manifest schema (must mirror evidenceBundleTypes.ts) ──

type manifestFile struct {
	Command     string `json:"command"`
	Path        string `json:"path"`
	SHA256      string `json:"sha256,omitempty"`
	CollectedAt string `json:"collected_at,omitempty"`
}

type manifestSwitch struct {
	SwitchName string         `json:"switch_name"`
	Files      []manifestFile `json:"files"`
	WWN        string         `json:"wwn,omitempty"`
	DomainID   *int           `json:"domain_id,omitempty"`
	FID        *int           `json:"fid,omitempty"`
	Model      string         `json:"model,omitempty"`
	Notes      string         `json:"notes,omitempty"`
}

// Manifest is the v1.0 manifest.json shape. Note: NO support_level and NO
// generated_at — support level is derived by the importer from the catalog.
type Manifest struct {
	BundleVersion    string           `json:"bundle_version"`
	CollectionMethod string           `json:"collection_method"`
	CustomerSupplied bool             `json:"customer_supplied"`
	CollectedAt      string           `json:"collected_at"`
	FabricRole       string           `json:"fabric_role"`
	Vendor           string           `json:"vendor"`
	Switches         []manifestSwitch `json:"switches"`
}

// Summary mirrors the Python collection-summary.json (provenance only; not part
// of the parsed contract).
type Summary struct {
	Collector         string `json:"collector"`
	ProfileVersion    string `json:"profile_version"`
	SwitchesAttempted int    `json:"switches_attempted"`
	CommandsAttempted int    `json:"commands_attempted"`
	CommandsSucceeded int    `json:"commands_succeeded"`
	CommandsFailed    int    `json:"commands_failed"`
	StartedAt         string `json:"started_at"`
	FinishedAt        string `json:"finished_at"`
	FabricRole        string `json:"fabric_role"`
}

// BuildResult is the output of BuildEvidenceBundle.
type BuildResult struct {
	Zip      []byte
	Manifest Manifest
	Summary  Summary
	Log      string
}

// ── profile ──

type profileCommand struct {
	ID           string `json:"id"`
	Exec         string `json:"exec"`
	Filename     string `json:"filename"`
	SupportLevel string `json:"supportLevel"`
	Importance   string `json:"importance"`
}

type commandProfile struct {
	ProfileVersion string            `json:"profile_version"`
	Vendor         string            `json:"vendor"`
	Defaults       map[string]string `json:"defaults"`
	Commands       []profileCommand  `json:"commands"`
}

func loadEmbeddedProfile() (*commandProfile, map[string]profileCommand, error) {
	var p commandProfile
	if err := json.Unmarshal(embeddedProfileJSON, &p); err != nil {
		return nil, nil, fmt.Errorf("parse embedded profile: %w", err)
	}
	if p.Vendor != Vendor {
		return nil, nil, fmt.Errorf("embedded profile vendor %q != %q", p.Vendor, Vendor)
	}
	byID := make(map[string]profileCommand, len(p.Commands))
	for _, c := range p.Commands {
		byID[c.ID] = c
	}
	return &p, byID, nil
}

// ── path sanitization (must mirror Python sanitize_path_segment) ──

var (
	reSpaces = regexp.MustCompile(`\s+`)
	reUnsafe = regexp.MustCompile(`[^A-Za-z0-9._-]`)
)

func sanitizeSegment(value, fallback string) string {
	v := strings.TrimSpace(value)
	v = strings.ReplaceAll(v, "/", "-")
	v = strings.ReplaceAll(v, "\\", "-")
	v = reSpaces.ReplaceAllString(v, "-")
	v = reUnsafe.ReplaceAllString(v, "")
	v = strings.Trim(v, "-._")
	if v == "" {
		return fallback
	}
	return v
}

// isUnsafeBundlePath mirrors the TS isUnsafeBundlePath guard: absolute paths or
// any ".." segment are unsafe.
func isUnsafeBundlePath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "\\") {
		return true
	}
	for _, seg := range strings.Split(strings.ReplaceAll(p, "\\", "/"), "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

func iso(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
}

func captureOK(c CommandCapture) bool {
	return c.ExitCode == 0 && !c.TimedOut && strings.TrimSpace(string(c.Stdout)) != ""
}

func normalizeRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "source":
		return "source"
	case "target":
		return "target"
	default:
		return "unknown"
	}
}

// BuildEvidenceBundle packages the supplied captures into an Evidence Bundle
// v1.0 ZIP with collection_method "agent" (unless overridden). It fails clearly
// on unknown commands, filename mismatches, and path collisions rather than
// silently overwriting evidence.
func BuildEvidenceBundle(captures []CommandCapture, opts BuildOptions) (*BuildResult, error) {
	profile, _, err := loadEmbeddedProfile()
	if err != nil {
		return nil, err
	}
	known := make(map[string]bool, len(profile.Commands))
	for _, pc := range profile.Commands {
		known[pc.ID] = true
	}

	method := opts.CollectionMethod
	if method == "" {
		method = CollectionMethodAgent
	}
	collectedAt := opts.CollectedAt
	if collectedAt.IsZero() {
		collectedAt = time.Now().UTC()
	}
	collector := opts.Collector
	if collector == "" {
		collector = "filterrex_agent_brocade"
	}

	metaByName := make(map[string]SwitchMeta, len(opts.SwitchMeta))
	for _, m := range opts.SwitchMeta {
		metaByName[m.SwitchName] = m
	}

	// Group captures by switch, preserving first-seen order.
	type switchGroup struct {
		name     string
		role     string
		safeRole string
		safeName string
		captures []CommandCapture
	}
	var order []string
	groups := make(map[string]*switchGroup)
	for _, c := range captures {
		g, ok := groups[c.SwitchName]
		if !ok {
			role := normalizeRole(c.FabricRole)
			g = &switchGroup{
				name:     c.SwitchName,
				role:     role,
				safeRole: role,
				safeName: sanitizeSegment(c.SwitchName, "switch"),
			}
			groups[c.SwitchName] = g
			order = append(order, c.SwitchName)
		}
		g.captures = append(g.captures, c)
	}

	// Fail clearly on folder collisions: two distinct switch names (or
	// role/switch pairs) that sanitize to the same bundle folder.
	folderOwner := make(map[string]string)
	for _, name := range order {
		g := groups[name]
		folder := g.safeRole + "/" + g.safeName
		if owner, exists := folderOwner[folder]; exists && owner != g.name {
			return nil, fmt.Errorf(
				"path collision: switches %q and %q both map to folder %q; rename one before bundling",
				owner, g.name, folder)
		}
		folderOwner[folder] = g.name
	}

	log := []string{fmt.Sprintf("FilterREX Brocade agent bundle %s", iso(collectedAt))}
	filesByRel := make(map[string][]byte)
	relOwner := make(map[string]string)

	var manifestSwitches []manifestSwitch
	roleSet := make(map[string]struct{})
	attempted, succeeded, failed := 0, 0, 0

	for _, name := range order {
		g := groups[name]
		roleSet[g.role] = struct{}{}

		// Command order = profile order, so agent output is stable and matches
		// the producer contract independent of capture arrival order.
		byCmd := make(map[string]CommandCapture)
		for _, c := range g.captures {
			if !known[c.Command] {
				return nil, fmt.Errorf("unknown command %q on switch %q is not in the Brocade profile", c.Command, g.name)
			}
			if _, dup := byCmd[c.Command]; dup {
				return nil, fmt.Errorf("duplicate capture for command %q on switch %q", c.Command, g.name)
			}
			byCmd[c.Command] = c
		}

		var files []manifestFile
		seenCmd := make(map[string]bool)
		for _, pc := range profile.Commands {
			c, present := byCmd[pc.ID]
			if !present {
				continue
			}
			attempted++
			if seenCmd[pc.ID] {
				return nil, fmt.Errorf("duplicate capture for command %q on switch %q", pc.ID, g.name)
			}
			seenCmd[pc.ID] = true

			if c.Filename != "" && c.Filename != pc.Filename {
				return nil, fmt.Errorf(
					"filename mismatch for command %q on switch %q: got %q, profile expects %q",
					pc.ID, g.name, c.Filename, pc.Filename)
			}

			if !captureOK(c) {
				failed++
				status := fmt.Sprintf("exit=%d", c.ExitCode)
				if c.TimedOut {
					status = "timeout"
				}
				log = append(log, fmt.Sprintf("[%s] %s: `%s` — not included in manifest", status, g.name, pc.ID))
				continue
			}

			rel := fmt.Sprintf("%s/%s/%s", g.safeRole, g.safeName, pc.Filename)
			if isUnsafeBundlePath(rel) {
				return nil, fmt.Errorf("refusing unsafe bundle path %q for switch %q", rel, g.name)
			}
			if owner, exists := relOwner[rel]; exists {
				return nil, fmt.Errorf(
					"path collision: %q already written for switch %q, cannot reuse for %q",
					rel, owner, g.name)
			}
			relOwner[rel] = g.name

			sum := sha256.Sum256(c.Stdout)
			filesByRel[rel] = c.Stdout
			files = append(files, manifestFile{
				Command:     pc.ID,
				Path:        rel,
				SHA256:      hex.EncodeToString(sum[:]),
				CollectedAt: isoOrEmpty(c.CollectedAt),
			})
			succeeded++
			log = append(log, fmt.Sprintf("[ok] %s: `%s`", g.name, pc.ID))
		}

		ms := manifestSwitch{SwitchName: g.name, Files: files}
		if meta, ok := metaByName[g.name]; ok {
			ms.WWN = meta.WWN
			ms.DomainID = meta.DomainID
			ms.FID = meta.FID
			ms.Model = meta.Model
			ms.Notes = meta.Notes
		}
		manifestSwitches = append(manifestSwitches, ms)
	}

	// Derive bundle fabric_role.
	bundleRole := normalizeRole(opts.FabricRole)
	if opts.FabricRole == "" || strings.EqualFold(opts.FabricRole, "auto") {
		if len(roleSet) == 1 {
			for r := range roleSet {
				bundleRole = r
			}
		} else {
			bundleRole = "unknown"
		}
	}

	manifest := Manifest{
		BundleVersion:    BundleVersion,
		CollectionMethod: method,
		CustomerSupplied: opts.CustomerSupplied,
		CollectedAt:      iso(collectedAt),
		FabricRole:       bundleRole,
		Vendor:           Vendor,
		Switches:         manifestSwitches,
	}

	summary := Summary{
		Collector:         collector,
		ProfileVersion:    profile.ProfileVersion,
		SwitchesAttempted: len(order),
		CommandsAttempted: attempted,
		CommandsSucceeded: succeeded,
		CommandsFailed:    failed,
		StartedAt:         iso(collectedAt),
		FinishedAt:        iso(collectedAt),
		FabricRole:        bundleRole,
	}
	log = append(log, fmt.Sprintf("Summary: %d/%d commands captured across %d switch(es); %d failed.",
		succeeded, attempted, len(order), failed))
	logText := strings.Join(log, "\n") + "\n"

	zipBytes, err := writeZip(manifest, summary, logText, filesByRel, collectedAt)
	if err != nil {
		return nil, err
	}

	return &BuildResult{Zip: zipBytes, Manifest: manifest, Summary: summary, Log: logText}, nil
}

func isoOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return iso(t)
}

func writeZip(manifest Manifest, summary Summary, logText string, filesByRel map[string][]byte, modTime time.Time) ([]byte, error) {
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	manifestJSON = append(manifestJSON, '\n')

	summaryJSON, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal summary: %w", err)
	}
	summaryJSON = append(summaryJSON, '\n')

	// Deterministic entry order: metadata first, then command files sorted.
	var rels []string
	for rel := range filesByRel {
		rels = append(rels, rel)
	}
	sort.Strings(rels)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name string, content []byte) error {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.Modified = modTime.UTC().Truncate(time.Second)
		w, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		_, err = w.Write(content)
		return err
	}

	if err := add(BundleRoot+"/manifest.json", manifestJSON); err != nil {
		return nil, err
	}
	if err := add(BundleRoot+"/collection-log.txt", []byte(logText)); err != nil {
		return nil, err
	}
	if err := add(BundleRoot+"/collection-summary.json", summaryJSON); err != nil {
		return nil, err
	}
	for _, rel := range rels {
		if err := add(BundleRoot+"/"+rel, filesByRel[rel]); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
