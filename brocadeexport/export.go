package brocadeexport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/forgeai/connector-agent/brocadecli"
	"github.com/forgeai/connector-agent/evidencebundle"
)

// artifactTimeLayout produces immutable, sortable, filesystem-safe names, e.g.
// filterrex-agent-evidence-bundle-20260713T143022Z.zip
const artifactTimeLayout = "20060102T150405Z"

// ensureArtifactDir creates the artifact directory (0700 if missing) and rejects
// world-writable locations. Existing directories are left as-is except for this
// safety check.
func ensureArtifactDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create artifact_dir %q: %w", dir, err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("stat artifact_dir %q: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("artifact_dir %q is not a directory", dir)
	}
	if info.Mode().Perm()&0002 != 0 {
		return fmt.Errorf("artifact_dir %q is world-writable (mode %o); refuse to write evidence there", dir, info.Mode().Perm())
	}
	return nil
}

// RunExport performs the local Brocade evidence-bundle export using the supplied
// runner (injectable for tests). It enforces the capability gate, captures via
// brocadecli, packages via evidencebundle, writes an immutable timestamped ZIP
// (0600) into the artifact directory, and appends a local audit record.
//
// It never uploads, never reaches the cloud, and never records secrets.
func RunExport(ctx context.Context, cfg *ExportConfig, runner brocadecli.CommandRunner, req RequestMeta) (*ExportResult, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	dir := cfg.EffectiveArtifactDir()
	if err := ensureArtifactDir(dir); err != nil {
		return nil, err
	}

	started := time.Now().UTC()

	captures, collLog, err := brocadecli.Collect(ctx, runner, cfg.BrocadeTargets(), brocadecli.CollectOptions{
		CollectedAt: started,
	})
	if err != nil {
		return nil, fmt.Errorf("capture failed: %w", err)
	}

	meta := make([]evidencebundle.SwitchMeta, 0, len(cfg.Targets))
	for _, t := range cfg.Targets {
		meta = append(meta, evidencebundle.SwitchMeta{
			SwitchName: t.SwitchName,
			FID:        t.FID,
			Notes:      t.Notes,
		})
	}

	res, err := evidencebundle.BuildEvidenceBundle(captures, evidencebundle.BuildOptions{
		CollectionMethod: evidencebundle.CollectionMethodAgent,
		CollectedAt:      started,
		SwitchMeta:       meta,
		Collector:        "filterrex_agent_brocade_export",
	})
	if err != nil {
		return nil, fmt.Errorf("bundle build failed: %w", err)
	}

	finished := time.Now().UTC()

	// Write immutable, timestamped artifact (0600). Never silently overwrite.
	name := fmt.Sprintf("filterrex-agent-evidence-bundle-%s.zip", started.Format(artifactTimeLayout))
	outPath := filepath.Join(dir, name)
	if _, statErr := os.Stat(outPath); statErr == nil {
		return nil, fmt.Errorf("artifact %q already exists; refusing to overwrite", outPath)
	}
	if err := os.WriteFile(outPath, res.Zip, 0600); err != nil {
		return nil, fmt.Errorf("write artifact %q: %w", outPath, err)
	}

	sum := sha256.Sum256(res.Zip)
	shaHex := hex.EncodeToString(sum[:])

	parsed, supporting := countSupportLevels(res.Manifest)
	targetsSucceeded := countTargetsWithFiles(res.Manifest)

	result := &ExportResult{
		OK:               true,
		ArtifactType:     "evidence_bundle",
		Vendor:           evidencebundle.Vendor,
		CollectionMethod: evidencebundle.CollectionMethodAgent,
		Path:             outPath,
		Switches:         res.Summary.SwitchesAttempted,
		ParsedFiles:      parsed,
		SupportingFiles:  supporting,
		Warnings:         res.Summary.CommandsFailed,
		SHA256:           shaHex,
		StartedAt:        started.Format(time.RFC3339),
		FinishedAt:       finished.Format(time.RFC3339),
	}

	rec := AuditRecord{
		Event:             "brocade.export",
		RequesterType:     req.RequesterType,
		Requester:         req.Requester,
		ConfigPath:        req.ConfigPath,
		Vendor:            evidencebundle.Vendor,
		CollectionMethod:  evidencebundle.CollectionMethodAgent,
		Targets:           auditTargets(cfg),
		CommandsAttempted: res.Summary.CommandsAttempted,
		CommandsSucceeded: res.Summary.CommandsSucceeded,
		CommandsFailed:    res.Summary.CommandsFailed,
		TargetsAttempted:  res.Summary.SwitchesAttempted,
		TargetsSucceeded:  targetsSucceeded,
		TargetsFailed:     res.Summary.SwitchesAttempted - targetsSucceeded,
		Warnings:          warningLines(collLog),
		OutputPath:        outPath,
		SHA256:            shaHex,
		StartedAt:         result.StartedAt,
		FinishedAt:        result.FinishedAt,
		OK:                true,
	}
	if err := writeAuditRecord(dir, rec); err != nil {
		// The artifact is already written; surface the audit failure but keep
		// the (successful) result available to the caller.
		return result, fmt.Errorf("export succeeded but audit write failed: %w", err)
	}
	result.Audit = rec

	return result, nil
}

// RunExportWithSSH is the production entrypoint: it constructs real, read-only
// key-based SSH runners (host-key verification required) grouped by known_hosts
// file, then delegates to RunExport. Runners are closed before returning.
func RunExportWithSSH(ctx context.Context, cfg *ExportConfig, req RequestMeta) (*ExportResult, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	byKnownHosts := map[string]brocadecli.CommandRunner{}
	byHost := map[string]brocadecli.CommandRunner{}
	var closers []func() error
	closeAll := func() {
		for _, c := range closers {
			_ = c()
		}
	}

	for _, t := range cfg.Targets {
		kh := cfg.effectiveKnownHosts(t)
		r, ok := byKnownHosts[kh]
		if !ok {
			nr, closeFn, err := brocadecli.NewSSHRunner(brocadecli.SSHRunnerConfig{
				KnownHostsPath: kh,
				ConnectTimeout: cfg.connectTimeout(),
				CommandTimeout: cfg.commandTimeout(),
				Port:           cfg.SSHPort,
			})
			if err != nil {
				closeAll()
				return nil, fmt.Errorf("init ssh runner for known_hosts %q: %w", kh, err)
			}
			byKnownHosts[kh] = nr
			closers = append(closers, closeFn)
			r = nr
		}
		byHost[t.Host] = r
	}
	defer closeAll()

	return RunExport(ctx, cfg, &dispatchRunner{byHost: byHost}, req)
}

// dispatchRunner routes each target's commands to the SSH runner built for that
// target's host (which carries the correct known_hosts verification).
type dispatchRunner struct {
	byHost map[string]brocadecli.CommandRunner
}

func (d *dispatchRunner) Run(ctx context.Context, target brocadecli.BrocadeTarget, exec string) brocadecli.CommandResult {
	r, ok := d.byHost[target.Host]
	if !ok {
		return brocadecli.CommandResult{
			ExitCode: -1,
			Started:  time.Now().UTC(),
			Err:      fmt.Errorf("no ssh runner configured for host %s", target.Host),
		}
	}
	return r.Run(ctx, target, exec)
}

// countSupportLevels splits included manifest files into parsed vs supporting_only
// using the embedded command profile's support levels.
func countSupportLevels(m evidencebundle.Manifest) (parsed, supporting int) {
	levels := map[string]string{}
	if cmds, err := evidencebundle.ProfileCommands(); err == nil {
		for _, c := range cmds {
			levels[c.ID] = c.SupportLevel
		}
	}
	for _, sw := range m.Switches {
		for _, f := range sw.Files {
			if levels[f.Command] == "parsed" {
				parsed++
			} else {
				supporting++
			}
		}
	}
	return parsed, supporting
}

// countTargetsWithFiles counts switches that produced at least one included file.
func countTargetsWithFiles(m evidencebundle.Manifest) int {
	n := 0
	for _, sw := range m.Switches {
		if len(sw.Files) > 0 {
			n++
		}
	}
	return n
}

func auditTargets(cfg *ExportConfig) []AuditTarget {
	out := make([]AuditTarget, 0, len(cfg.Targets))
	for _, t := range cfg.Targets {
		out = append(out, AuditTarget{
			SwitchName: t.SwitchName,
			Host:       t.Host,
			FabricRole: t.FabricRole,
		})
	}
	return out
}

func warningLines(l brocadecli.CollectionLog) []string {
	var out []string
	for _, e := range l.Entries {
		if e.Included {
			continue
		}
		status := fmt.Sprintf("exit=%d", e.ExitCode)
		if e.TimedOut {
			status = "timeout"
		}
		line := fmt.Sprintf("%s (%s): %s [%s]", e.SwitchName, e.Host, e.CommandID, status)
		if e.Note != "" {
			line += " " + e.Note
		}
		out = append(out, line)
	}
	return out
}
