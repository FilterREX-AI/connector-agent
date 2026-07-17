// Package targetconfigure is the interactive, one-shot local wizard that
// prepares a Brocade FC switch for the two-path FilterREX runtime (Workbench
// HTTPS REST + Evidence Bundle SSH). See:
//   - connector-agent/RELEASE-v0.1.0-preview.3.md
//   - docs/brocade-target-two-path-auth.md
//
// Boundaries this wizard preserves:
//   - Never accepts switch credentials on the command line.
//   - Never echoes password, private-key bytes, connector token, or signed
//     URLs to stdout/stderr or to any audit line.
//   - Never writes secrets outside the operator-supplied --config-dir.
//   - Refuses to trust an SSH host key returned by the network fetch until the
//     operator confirms an out-of-band comparison AND passes a fingerprint
//     challenge.
//   - Copies imported keys into managed storage; targets.json only ever
//     references files under --config-dir.
//   - Atomic writes: temp file → fsync → rename → fsync parent dir.
//   - Partial success is allowed: REST-only ready or SSH-only ready are valid
//     terminal states, saved with precise reason codes.
//
// This package exposes a single entry point, Run, so the wizard is reachable
// both from the standalone binary (cmd/targetconfigure) and as a
// `target configure` subcommand of the top-level connector-agent binary.
// Run never calls os.Exit — the caller owns process termination — so the
// package is testable and safe to embed.
package targetconfigure

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/filterrex-ai/connector-agent/brocaderest"
)


// ─── config-file layout ──────────────────────────────────────────────────────

const (
	targetsFile   = "targets.json"
	restSecretDir = "secrets/rest"
	sshKeyDir     = "keys"
	tlsDir        = "tls"
	knownHostsFn  = "known_hosts"
)

type targetsDoc struct {
	Version int                      `json:"version"`
	Targets map[string]*targetRecord `json:"targets"`
}

type targetRecord struct {
	// TargetID is the authoritative application target-profile UUID this
	// record maps to. The outer targets.json map key is a LOCAL profile
	// label (operator's choice); TargetID is the cloud/app identity. When
	// unset, EffectiveTargetID falls back to the map key only if that key
	// is itself a valid UUID (backward-compat for existing configs).
	TargetID   string     `json:"target_id,omitempty"`
	Address    string     `json:"address"`
	RESTPort   int        `json:"rest_port,omitempty"`
	SSHPort    int        `json:"ssh_port,omitempty"`
	REST       *restEntry `json:"rest,omitempty"`
	SSH        *sshEntry  `json:"ssh,omitempty"`
	LastWizard string     `json:"last_wizard_at,omitempty"`
	Readiness  readiness  `json:"readiness"`
}

type restEntry struct {
	TransportMode string `json:"transport_mode"` // https-verified | http-lab-only
	Username      string `json:"username"`
	PasswordFile  string `json:"password_file"`
	CAFile        string `json:"ca_file,omitempty"`
}

type sshEntry struct {
	Username       string `json:"username"`
	KeyPath        string `json:"key_path"`
	PublicKeyPath  string `json:"public_key_path,omitempty"`
	KnownHostsPath string `json:"known_hosts_path"`

	// Key metadata — DERIVED from the actual key material at configure time.
	// Published verbatim on heartbeat as `ssh_key_algorithm` / `ssh_key_bits`
	// / `ssh_key_origin` / `ssh_key_fingerprint_sha256`. Never asserted by
	// the operator; imported keys always report what they actually are.
	KeyAlgorithm         string `json:"key_algorithm,omitempty"` // "rsa" | "ed25519"
	KeyBits              int    `json:"key_bits,omitempty"`      // e.g. 3072 for RSA
	KeyOrigin            string `json:"key_origin,omitempty"`    // "generated" | "imported"
	KeyFingerprintSHA256 string `json:"key_fingerprint_sha256,omitempty"`
}

type readiness struct {
	RESTReady         bool   `json:"rest_ready"`
	RESTReason        string `json:"rest_reason,omitempty"`
	RESTSecurityState string `json:"rest_security_state,omitempty"`
	SSHReady          bool   `json:"ssh_ready"`
	SSHReason         string `json:"ssh_reason,omitempty"`
	// SSHProbeStage is the highest stage that has been proven for this target.
	// After `target configure` completes without probing, this is "not_run".
	SSHProbeStage string `json:"ssh_probe_stage,omitempty"`

	// LastSSHProbeAt is set every time an SSH probe RAN, regardless of
	// outcome. It is NEVER set from wizard save time — that lives in
	// `LastWizard`. The heartbeat consumes this to compute freshness.
	LastSSHProbeAt string `json:"last_ssh_probe_at,omitempty"` // RFC3339
	// LastSuccessfulSSHProbeAt is the most recent `command_succeeded`
	// probe. It is preserved across later failures so the app can show
	// "last verified" independently of the current state.
	LastSuccessfulSSHProbeAt string `json:"last_successful_ssh_probe_at,omitempty"` // RFC3339
}


// ─── entry point ─────────────────────────────────────────────────────────────

// Run parses args and executes the wizard. It never calls os.Exit; the caller
// receives the intended process exit code:
//
//	0 — success (including partial REST-only / SSH-only readiness saved)
//	1 — wizard flow error (details already printed to stderr)
//	2 — invalid CLI usage (flag parse failure, missing/rejected flags)
func Run(args []string) int {
	fs := flag.NewFlagSet("target configure", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	configDir := fs.String("config-dir", "/config", "Writable target-config directory.")
	profile := fs.String("profile", "", "Local profile identifier (targets.json map key). May be a target UUID or a safe label; must be paired with --target-id when not a UUID.")
	targetID := fs.String("target-id", "", "Authoritative application target-profile UUID. When --profile is a UUID and this is omitted, the profile is used.")
	stateDir := fs.String("state-dir", "/var/lib/filterrex", "Read-only mount of the connector state volume (identity).")
	nonInteractive := fs.Bool("y", false, "Reserved: refuse to run unattended. Always false in this preview.")

	// Key-selection flags. These are MUTUALLY EXCLUSIVE:
	//   --key-algo rsa-3072        generate a fresh RSA-3072 key   (default)
	//   --key-algo ed25519         generate a fresh Ed25519 key
	//   --import-existing <path>   import an existing private key; algorithm
	//                              and size are DERIVED from the key itself
	//                              and MUST NOT be asserted by the operator.
	keyAlgo := fs.String("key-algo", "", "Generate key of this algorithm: rsa-3072 (default) or ed25519. Mutually exclusive with --import-existing.")
	importExisting := fs.String("import-existing", "", "Import an existing SSH private key from this path (read-only). Mutually exclusive with --key-algo.")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *nonInteractive {
		fmt.Fprintln(os.Stderr, "target configure: -y is not supported: the wizard requires interactive out-of-band fingerprint verification.")
		return 2
	}
	if strings.TrimSpace(*profile) == "" {
		fmt.Fprintln(os.Stderr, "target configure: --profile is required.")
		return 2
	}
	if strings.TrimSpace(*configDir) == "" {
		fmt.Fprintln(os.Stderr, "target configure: --config-dir is required.")
		return 2
	}

	// Validate the profile is a safe identifier before any path is derived
	// from it. Profile labels flow into per-target filenames via
	// profileSlug, so anything containing path separators or control
	// characters is rejected outright.
	if !isSafeProfileName(*profile) {
		fmt.Fprintln(os.Stderr, "target configure: --profile must be a safe identifier (letters, digits, dot, dash, underscore).")
		return 2
	}

	// Resolve the effective target UUID up front. --target-id wins when set;
	// otherwise a UUID-shaped --profile is accepted as its own target ID
	// (backward compat). A non-UUID profile without --target-id is rejected:
	// we will NEVER publish per_target["faba"] on the wire.
	resolvedTargetID, terr := resolveTargetIDArgs(*profile, *targetID)
	if terr != nil {
		fmt.Fprintln(os.Stderr, "target configure:", terr.Error())
		return 2
	}

	// Mutual exclusion: never let an operator assert an algorithm for an
	// imported key. Imported keys always self-describe.
	if strings.TrimSpace(*keyAlgo) != "" && strings.TrimSpace(*importExisting) != "" {
		fmt.Fprintln(os.Stderr, "target configure: --key-algo and --import-existing are mutually exclusive.")
		return 2
	}

	kc, err := parseKeyChoice(*keyAlgo, *importExisting)
	if err != nil {
		fmt.Fprintln(os.Stderr, "target configure:", err.Error())
		return 2
	}

	if err := run(*configDir, *stateDir, *profile, resolvedTargetID, kc); err != nil {
		fmt.Fprintln(os.Stderr, "target configure:", err.Error())
		return 1
	}
	return 0
}

// resolveTargetIDArgs mirrors EffectiveTargetID but for raw CLI inputs (no
// record yet on disk). It returns the canonical lowercase target UUID or a
// diagnostic error string for stderr. Non-interactive `target configure` MUST
// reject a non-UUID profile without --target-id so a typo never silently
// publishes readiness under a stray label.
func resolveTargetIDArgs(profile, targetIDFlag string) (string, error) {
	tid := strings.TrimSpace(targetIDFlag)
	if tid != "" {
		id := canonicalUUID(tid)
		if id == "" {
			return "", errors.New("--target-id must be a valid target-profile UUID (v4)")
		}
		return id, nil
	}
	if id := canonicalUUID(profile); id != "" {
		return id, nil
	}
	return "", errors.New("--target-id is required when --profile is not a UUID (target_id_required)")
}

// isSafeProfileName restricts profile labels to characters that are safe as
// filename stems (profileSlug already re-sanitizes, but we reject at the
// boundary rather than silently rewriting the operator's identifier).
var safeProfileRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func isSafeProfileName(s string) bool {
	return safeProfileRe.MatchString(strings.TrimSpace(s))
}

// keyChoice captures the resolved key-selection intent for the wizard.
// Exactly one of GenerateAlgorithm / ImportPath is populated. Interactive
// mode may still override it when the operator opts to reuse an existing
// on-disk key.
type keyChoice struct {
	// GenerateAlgorithm is one of "rsa-3072" or "ed25519". Empty means
	// the operator did not force generation via a flag.
	GenerateAlgorithm string
	// ImportPath is a non-empty read-only path when --import-existing was
	// supplied on the command line.
	ImportPath string
	// FromFlag records whether the choice came from a CLI flag (vs the
	// interactive default). Used to decide whether to reprompt.
	FromFlag bool
}

func parseKeyChoice(keyAlgo, importPath string) (keyChoice, error) {
	keyAlgo = strings.TrimSpace(strings.ToLower(keyAlgo))
	importPath = strings.TrimSpace(importPath)
	switch {
	case importPath != "":
		return keyChoice{ImportPath: importPath, FromFlag: true}, nil
	case keyAlgo == "":
		// Default: RSA-3072 (FOS 7.x/8.x compatibility default), only when
		// interactive path runs generation without further prompting.
		return keyChoice{GenerateAlgorithm: "rsa-3072", FromFlag: false}, nil
	case keyAlgo == "rsa-3072", keyAlgo == "rsa":
		return keyChoice{GenerateAlgorithm: "rsa-3072", FromFlag: true}, nil
	case keyAlgo == "ed25519":
		return keyChoice{GenerateAlgorithm: "ed25519", FromFlag: true}, nil
	default:
		return keyChoice{}, fmt.Errorf("--key-algo %q not supported (use rsa-3072 or ed25519)", keyAlgo)
	}
}

// isProfileUUID accepts any RFC 4122 v1–v5 UUID in canonical hyphenated
// form. It refuses enrollment tokens, arbitrary strings, or anything
// containing path separators — the profile string is the filename stem for
// per-target keys and secrets.
var profileUUIDRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

func isProfileUUID(s string) bool {
	return profileUUIDRe.MatchString(strings.TrimSpace(s))
}


// WizardVersion is the human-facing version string printed in the wizard
// banner. It is intentionally a package-level var so `main` can propagate
// the ldflag-injected host version (`main.HostVersion`) without creating
// an import cycle. Defaults to "dev" for local `go run` builds.
var WizardVersion = "dev"

// ─── main flow ───────────────────────────────────────────────────────────────

func run(configDir, stateDir, profile, resolvedTargetID string, kc keyChoice) error {
	uid, gid := os.Geteuid(), os.Getegid()
	version := strings.TrimSpace(WizardVersion)
	if version == "" {
		version = "dev"
	}
	fmt.Printf("target configure (%s)\n  config-dir: %s\n  state-dir:  %s\n  profile:    %s\n  target-id:  %s\n  euid/egid:  %d/%d\n\n",
		version, configDir, stateDir, profile, resolvedTargetID, uid, gid)



	if err := ensureDirs(configDir); err != nil {
		return err
	}

	// Sanitized cloud-side lookup would go here — authenticated using the
	// connector identity from stateDir. In this build we perform local
	// enrollment validation only (identity file existence) so the wizard can
	// operate on air-gapped hosts too. When the connector-identity-aware
	// lookup lands, it slots in here without changing the operator UX.
	if err := verifyConnectorIdentity(stateDir); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v (proceeding with local-only configuration)\n\n", err)
	}

	doc, err := loadTargets(configDir)
	if err != nil {
		return err
	}
	existing := doc.Targets[profile]
	if existing != nil {
		fmt.Println("Existing configuration detected for this profile — you will be prompted to reuse or replace each artifact.")
	}

	// Detect an application-target remap: the operator supplied a
	// --target-id (or a UUID-shaped --profile) that resolves to a DIFFERENT
	// canonical UUID than the record previously mapped to. When that
	// happens we require explicit confirmation and reset SSH readiness so
	// a previously-verified switch profile cannot silently authorize a new
	// application target.
	mappingChanged := false
	if existing != nil {
		prevResolved, perr := EffectiveTargetID(profile, existing)
		if perr == nil && prevResolved != "" && prevResolved != resolvedTargetID {
			mappingChanged = true
			fmt.Println("")
			fmt.Println("Local profile:         " + profile)
			fmt.Println("Previous target ID:    " + prevResolved)
			fmt.Println("Requested target ID:   " + resolvedTargetID)
			fmt.Println("")
			fmt.Println("This changes the application target associated with this local profile")
			fmt.Println("and will reset SSH readiness. An explicit `target probe` will be required")
			fmt.Println("before the connector can publish ssh_ready=true under the new UUID.")
			if !confirmYesNo("Continue with remap", false) {
				return errors.New("aborted by operator (target-id remap not confirmed)")
			}
		}
	}

	// Snapshot the pre-mutation state so the regression-probe guard can
	// compare the new record against what was previously verified. `rec`
	// is aliased to `existing` below so we cannot read prior values off it
	// after prompts overwrite them.
	var prev struct {
		hasSSH             bool
		wasSSHReady        bool
		address            string
		sshPort            int
		sshUsername        string
		sshKeyPath         string
		sshFingerprint     string
	}
	if existing != nil {
		prev.address = existing.Address
		prev.sshPort = existing.SSHPort
		prev.wasSSHReady = existing.Readiness.SSHReady
		if existing.SSH != nil {
			prev.hasSSH = true
			prev.sshUsername = existing.SSH.Username
			prev.sshKeyPath = existing.SSH.KeyPath
			prev.sshFingerprint = existing.SSH.KeyFingerprintSHA256
		}
	}

	rec := &targetRecord{Address: "", Readiness: readiness{}}
	if existing != nil {
		rec = existing
	}
	// Stamp authoritative target ID. When the operator remaps the profile
	// to a different application UUID, wipe readiness so nothing carries
	// over from the previous target.
	rec.TargetID = resolvedTargetID
	if mappingChanged {
		rec.Readiness = readiness{
			SSHReady:      false,
			SSHReason:     "setup_pending",
			SSHProbeStage: "not_run",
		}
		// A timestamp from a probe against the previous target UUID must
		// not appear beneath the new UUID, even as history.
		prev.hasSSH = false
		prev.wasSSHReady = false
	}

	// 1) address + ports
	addr, restPort, sshPort, err := promptAddressAndPorts(rec)
	if err != nil {
		return err
	}
	rec.Address = addr
	rec.RESTPort = restPort
	rec.SSHPort = sshPort

	// 2) account username
	restUser := prompt("REST username", firstNonEmpty(existingUser(rec, "rest"), "filterrex_ro"))
	sshUser := prompt("SSH username", firstNonEmpty(existingUser(rec, "ssh"), restUser))

	// 3) REST password
	restPasswordFile, restSecState, err := configureRESTPassword(configDir, profile, rec)
	if err != nil {
		return err
	}

	// 4) SSH key
	keyMeta, err := configureSSHKey(configDir, profile, rec, kc)
	if err != nil {
		return err
	}
	sshKeyPath := keyMeta.KeyPath
	sshPubPath := keyMeta.PublicKeyPath

	// 5) host-key enrollment with out-of-band challenge. `hostKeyRefreshed`
	// is true whenever the operator accepted a new host key this run — in
	// that case the regression-probe guard MUST NOT auto-probe, because the
	// switch-side trust anchor just changed.
	knownHostsPath, hostKeyRefreshed, hkErr := enrollHostKey(configDir, addr, sshPort, rec)
	if hkErr != nil {
		fmt.Fprintf(os.Stderr, "\nhost-key enrollment failed: %v\n", hkErr)
	}

	// Assemble the working record before probes.
	rec.REST = &restEntry{
		TransportMode: string(brocaderest.TransportHTTPSVerified),
		Username:      restUser,
		PasswordFile:  restPasswordFile,
	}
	if existing != nil && existing.REST != nil && existing.REST.CAFile != "" {
		rec.REST.CAFile = existing.REST.CAFile
	}
	rec.SSH = &sshEntry{
		Username:             sshUser,
		KeyPath:              sshKeyPath,
		PublicKeyPath:        sshPubPath,
		KnownHostsPath:       knownHostsPath,
		KeyAlgorithm:         keyMeta.Algorithm,
		KeyBits:              keyMeta.Bits,
		KeyOrigin:            keyMeta.Origin,
		KeyFingerprintSHA256: keyMeta.FingerprintSHA256,
	}

	// 6) REST probe
	restReady, restReason := probeREST(rec, restSecState)
	rec.Readiness.RESTReady = restReady
	rec.Readiness.RESTReason = restReason
	rec.Readiness.RESTSecurityState = restSecState

	// 7) SSH readiness.
	//
	// `target configure` NEVER runs an SSH auth probe on first setup — the
	// switch-side `sshutil importpubkey` step happens between configure and
	// the first probe, so an inline probe would deterministically publish a
	// misleading auth failure. Instead we publish `setup_pending` +
	// `not_run` so the wire contract clearly says "operator has not yet run
	// `target probe`".
	//
	// Automatic regression probing on the reconfigure/repair path is tightly
	// constrained: it runs only when EVERY dimension that could have caused
	// a legitimate first-run failure is unchanged. If any of the following
	// were altered this run, we return to setup_pending / not_run and let
	// `target probe` prove the new configuration explicitly:
	//   - previous SSH state was not verified
	//   - a new key was generated or imported (fingerprint drift)
	//   - the managed key path changed
	//   - the SSH username changed
	//   - the management address or SSH port changed
	//   - the host key was refreshed this run
	//   - a missing identity was repaired (no prior SSH entry)
	sshReady, sshReason, sshStage := false, "setup_pending", "not_run"
	keyReused := prev.hasSSH &&
		rec.SSH.KeyFingerprintSHA256 != "" &&
		rec.SSH.KeyFingerprintSHA256 == prev.sshFingerprint &&
		rec.SSH.KeyPath == prev.sshKeyPath
	identityUnchanged := prev.hasSSH &&
		rec.SSH.Username == prev.sshUsername &&
		rec.Address == prev.address &&
		rec.SSHPort == prev.sshPort
	canRegressionProbe := hkErr == nil &&
		!hostKeyRefreshed &&
		prev.hasSSH &&
		prev.wasSSHReady &&
		keyReused &&
		identityUnchanged
	if canRegressionProbe {
		r, reason := probeSSH(rec)
		sshReady = r
		nowStr := time.Now().UTC().Format(time.RFC3339)
		rec.Readiness.LastSSHProbeAt = nowStr
		if r {
			sshReason = ""
			sshStage = "command_succeeded"
			rec.Readiness.LastSuccessfulSSHProbeAt = nowStr
		} else {
			sshReason = reason
			sshStage = "auth_succeeded" // best-effort: we know the earlier config had reached command_succeeded
			// Do NOT clear LastSuccessfulSSHProbeAt — a later failure must
			// preserve the last known good so the app can display it.
		}
	}
	rec.Readiness.SSHReady = sshReady
	rec.Readiness.SSHReason = sshReason
	rec.Readiness.SSHProbeStage = sshStage

	rec.LastWizard = time.Now().UTC().Format(time.RFC3339)



	// 8) atomic write, preserving other profiles' entries.
	if doc.Targets == nil {
		doc.Targets = map[string]*targetRecord{}
	}
	if doc.Version == 0 {
		doc.Version = 1
	}
	doc.Targets[profile] = rec
	if err := writeTargets(configDir, doc); err != nil {
		return err
	}

	printStatusBlock(rec)
	if !restReady || !sshReady {
		fmt.Println("\nNext step: after installing the public key on the switch (`sshutil importpubkey`),")
		fmt.Println("run `connector-agent target probe --profile <uuid>` to prove end-to-end SSH readiness.")
	}
	if sshPubPath != "" {
		fmt.Printf("\nSSH public key to install on the switch (read-only account):\n  %s\n", sshPubPath)
	}

	// Post-configure interactive menu — NEVER auto-probes. The default action
	// is "finish and test later" so a first-run setup that has not yet had
	// `sshutil importpubkey` performed on the switch cannot deterministically
	// publish a misleading auth failure. This is also the ONLY entry point
	// that will move a `setup_pending` record forward inside the wizard: we
	// deliberately never auto-forward-probe based on unchanged inputs alone.
	if !sshReady {
		postConfigureMenu(configDir, doc, profile, rec, sshPubPath)
	}
	return nil
}

// printStatusBlock renders the same four-line status block from both the
// wizard save path and `target probe`. Kept in one place so operators see an
// identical shape regardless of which command last touched the record.
func printStatusBlock(rec *targetRecord) {
	fmt.Println("\nSaved.")
	fmt.Printf("  Live Workbench queries        %s\n", stateLine(rec.Readiness.RESTReady, rec.Readiness.RESTReason))
	fmt.Printf("  SSH evidence collection       %s\n", stateLine(rec.Readiness.SSHReady, rec.Readiness.SSHReason))
	if rec.SSH != nil {
		fmt.Printf("  Key                           %s · %s\n", describeKey(rec.SSH), rec.SSH.KeyOrigin)
		fmt.Printf("  Key fingerprint               %s\n", rec.SSH.KeyFingerprintSHA256)
	}
}

// postConfigureMenu offers an explicit, operator-driven verification step
// after configure. It NEVER runs a probe without an unambiguous "yes, the key
// is on the switch, test SSH now" choice. Default is "finish and test later".
func postConfigureMenu(configDir string, doc *targetsDoc, profile string, rec *targetRecord, sshPubPath string) {
	for {
		fmt.Println("\nHas the displayed public key been imported on the switch?")
		fmt.Println("  1) Yes — test SSH now")
		fmt.Println("  2) Show import instructions")
		fmt.Println("  3) Finish setup and test later")
		choice := prompt("Choice", "3")
		switch strings.TrimSpace(choice) {
		case "1":
			ready, reason := probeSSH(rec)
			nowStr := time.Now().UTC().Format(time.RFC3339)
			rec.Readiness.SSHReady = ready
			rec.Readiness.LastSSHProbeAt = nowStr
			if ready {
				rec.Readiness.SSHReason = ""
				rec.Readiness.SSHProbeStage = "command_succeeded"
				rec.Readiness.LastSuccessfulSSHProbeAt = nowStr
			} else {
				rec.Readiness.SSHReason = reason
				// We reached at least the transport layer if the failure was
				// not a pure connection error; probeSSH already returns a
				// specific code, so map conservatively.
				rec.Readiness.SSHProbeStage = mapProbeStage(reason)
				// Preserve prior LastSuccessfulSSHProbeAt on failure.
			}
			// Note: LastWizard is NOT updated here — this is a probe, not a
			// wizard save. LastWizard remains the last configure-time write.
			doc.Targets[profile] = rec
			if werr := writeTargets(configDir, doc); werr != nil {
				fmt.Fprintf(os.Stderr, "warning: could not persist probe result: %v\n", werr)
			}
			printStatusBlock(rec)
			if !ready {
				fmt.Println("\nSSH probe did not authenticate. Verify `sshutil importpubkey`")
				fmt.Println("on the switch loaded the correct public key for this account, then")
				fmt.Println("re-run `connector-agent target probe --profile <uuid>`.")
			}
			return
		case "2":
			fmt.Println("\nOn Brocade Fabric OS, install the collector public key with:")
			fmt.Println("  sshutil importpubkey")
			if sshPubPath != "" {
				fmt.Printf("Public key file (stage it on an SCP/SFTP server the switch can reach):\n  %s\n", sshPubPath)
			}
			fmt.Println("Use the read-only switch account (e.g. filterrex_ro). `sshutil allowuser` is for")
			fmt.Println("switch-initiated outgoing SSH and is NOT required for connector login.")
			continue
		case "", "3":
			return
		default:
			fmt.Println("Please enter 1, 2, or 3.")
			continue
		}
	}
}

// mapProbeStage narrows a probeSSH failure reason to the closest SSHProbeStage
// value. We stay conservative: unknown failures fall back to `dial_ok` (we
// connected but could not authenticate) rather than claiming a stage we did
// not actually reach.
func mapProbeStage(reason string) string {
	switch reason {
	case "ssh_connection_failed":
		return "dial_failed"
	case "host_key_verification_failed", "known_hosts_missing":
		return "host_key_verification_failed"
	case "ssh_auth_failed":
		return "auth_failed"
	case "read_only_probe_failed":
		return "auth_ok"
	case "missing_ssh_key":
		return "not_run"
	default:
		return "auth_failed"
	}
}

// RunProbe is the entry point for `connector-agent target probe`. It NEVER
// mutates address/port/username/key/host-key state — it only re-runs the SSH
// probe against the existing on-disk configuration and refreshes the readiness
// record. Exit codes mirror Run:
//
//	0 — probe succeeded (or record updated with a specific failure reason)
//	1 — flow error (missing config, unreadable targets.json)
//	2 — invalid CLI usage
func RunProbe(args []string) int {
	fs := flag.NewFlagSet("target probe", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configDir := fs.String("config-dir", "/config", "Writable target-config directory.")
	profile := fs.String("profile", "", "Local profile identifier (targets.json map key).")
	targetID := fs.String("target-id", "", "Optional assertion: expected application target UUID for this profile. Never populates or changes the record; a mismatch fails the probe.")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*profile) == "" {
		fmt.Fprintln(os.Stderr, "target probe: --profile is required.")
		return 2
	}
	if !isSafeProfileName(*profile) {
		fmt.Fprintln(os.Stderr, "target probe: --profile must be a safe identifier (letters, digits, dot, dash, underscore).")
		return 2
	}
	if strings.TrimSpace(*configDir) == "" {
		fmt.Fprintln(os.Stderr, "target probe: --config-dir is required.")
		return 2
	}
	if strings.TrimSpace(*targetID) != "" && canonicalUUID(*targetID) == "" {
		fmt.Fprintln(os.Stderr, "target probe: --target-id must be a valid target-profile UUID (v4).")
		return 2
	}

	doc, err := loadTargets(*configDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "target probe:", err.Error())
		return 1
	}
	rec := doc.Targets[*profile]
	if rec == nil || rec.SSH == nil {
		fmt.Fprintln(os.Stderr, "target probe: no SSH configuration exists for this profile — run `target configure` first.")
		return 1
	}

	// Assertion-only: `target probe` never populates or rewrites TargetID.
	// If the operator supplied --target-id, it must match the record's
	// currently resolved identity, otherwise we refuse the probe rather
	// than silently probing under an unexpected mapping.
	recResolved, rerr := EffectiveTargetID(*profile, rec)
	if rerr != nil {
		fmt.Fprintln(os.Stderr, "target probe:", rerr.Error()+" — run `target configure --profile "+*profile+" --target-id <uuid>` to set the application target UUID.")
		return 1
	}
	if asserted := canonicalUUID(*targetID); asserted != "" && asserted != recResolved {
		fmt.Fprintln(os.Stderr, "target probe: target_id_mismatch (record resolves to "+recResolved+", asserted "+asserted+"). Refusing to probe without reconfiguration.")
		return 1
	}

	ready, reason := probeSSH(rec)
	nowStr := time.Now().UTC().Format(time.RFC3339)
	rec.Readiness.SSHReady = ready
	rec.Readiness.LastSSHProbeAt = nowStr
	if ready {
		rec.Readiness.SSHReason = ""
		rec.Readiness.SSHProbeStage = "command_succeeded"
		rec.Readiness.LastSuccessfulSSHProbeAt = nowStr
	} else {
		rec.Readiness.SSHReason = reason
		rec.Readiness.SSHProbeStage = mapProbeStage(reason)
		// Preserve prior LastSuccessfulSSHProbeAt on failure.
	}
	// LastWizard intentionally NOT updated by target probe: probe time and
	// wizard save time are distinct facts.
	doc.Targets[*profile] = rec
	if err := writeTargets(*configDir, doc); err != nil {
		fmt.Fprintln(os.Stderr, "target probe: write failed:", err.Error())
		return 1
	}
	printStatusBlock(rec)
	if !ready {
		return 0 // probe result persisted; readiness reason speaks for itself
	}
	return 0
}

func describeKey(s *sshEntry) string {
	if s == nil || s.KeyAlgorithm == "" {
		return "unknown"
	}
	if s.KeyBits > 0 {
		return fmt.Sprintf("%s %d", strings.ToUpper(s.KeyAlgorithm), s.KeyBits)
	}
	return strings.ToUpper(s.KeyAlgorithm)
}


func stateLine(ready bool, reason string) string {
	if ready {
		return "Ready"
	}
	if reason == "" {
		reason = "setup_required"
	}
	return "Setup required: " + reason
}

// ─── steps ───────────────────────────────────────────────────────────────────

func ensureDirs(configDir string) error {
	for _, d := range []struct {
		p    string
		mode os.FileMode
	}{
		{configDir, 0o700},
		{filepath.Join(configDir, restSecretDir), 0o700},
		{filepath.Join(configDir, sshKeyDir), 0o700},
		{filepath.Join(configDir, tlsDir), 0o700},
	} {
		if err := os.MkdirAll(d.p, d.mode); err != nil {
			return fmt.Errorf("mkdir %s: %w", d.p, err)
		}
		if err := os.Chmod(d.p, d.mode); err != nil {
			return fmt.Errorf("chmod %s: %w", d.p, err)
		}
	}
	return nil
}

func verifyConnectorIdentity(stateDir string) error {
	candidates := []string{
		filepath.Join(stateDir, "identity.json"),
		filepath.Join(stateDir, "connector.json"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return nil
		}
	}
	return errors.New("no connector identity found in state-dir")
}

var (
	hostRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,253}$`)
)

func promptAddressAndPorts(existing *targetRecord) (string, int, int, error) {
	defAddr := existing.Address
	for {
		addr := prompt("Management hostname or address", defAddr)
		if err := validateHost(addr); err != nil {
			fmt.Fprintln(os.Stderr, "invalid:", err)
			continue
		}
		restPort := promptPort("REST port", firstNonZero(existing.RESTPort, 443))
		sshPort := promptPort("SSH port", firstNonZero(existing.SSHPort, 22))
		return addr, restPort, sshPort, nil
	}
}

func validateHost(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return errors.New("required")
	}
	if strings.Contains(s, "://") || strings.Contains(s, "/") || strings.Contains(s, "?") || strings.Contains(s, "@") {
		return errors.New("enter a bare hostname or address; no scheme, path, query, or user@")
	}
	if strings.HasPrefix(s, "[") {
		if !strings.HasSuffix(s, "]") {
			return errors.New("malformed IPv6 literal")
		}
		if ip := net.ParseIP(s[1 : len(s)-1]); ip == nil {
			return errors.New("malformed IPv6 literal")
		}
		return nil
	}
	if ip := net.ParseIP(s); ip != nil {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			if os.Getenv("FILTERREX_LAB_MODE") != "1" {
				return errors.New("loopback/link-local requires FILTERREX_LAB_MODE=1")
			}
		}
		return nil
	}
	if !hostRe.MatchString(s) {
		return errors.New("hostname contains disallowed characters")
	}
	if _, err := url.Parse("//" + s); err != nil {
		return errors.New("hostname is not parseable")
	}
	return nil
}

func promptPort(label string, def int) int {
	for {
		v := prompt(label, strconv.Itoa(def))
		n, err := strconv.Atoi(v)
		if err == nil && n > 0 && n < 65536 {
			return n
		}
		fmt.Fprintln(os.Stderr, "port must be 1..65535")
	}
}

func configureRESTPassword(configDir, profile string, rec *targetRecord) (string, string, error) {
	slug := profileSlug(profile)
	path := filepath.Join(configDir, restSecretDir, slug)

	if existsRegularSecret(path) {
		switch confirmChoice("REST password file exists. Reuse / Replace / Abort", "reuse") {
		case "reuse":
			return path, "production_verified", nil
		case "abort":
			return "", "", errors.New("aborted by operator")
		}
	}
	pw, err := readSecretNoEcho("REST password for " + rec.Address + " (input hidden): ")
	if err != nil {
		return "", "", err
	}
	if len(pw) == 0 {
		return "", "", errors.New("password is empty")
	}
	defer zeroBytes(pw)
	if err := atomicWriteFile(path, pw, 0o600); err != nil {
		return "", "", err
	}
	return path, "production_verified", nil
}

// keyMetadata carries the DERIVED description of an on-disk private key.
// It is always populated from the actual key material, never asserted.
type keyMetadata struct {
	KeyPath           string
	PublicKeyPath     string
	Algorithm         string // "rsa" | "ed25519"
	Bits              int    // e.g. 3072 for RSA; 0 for Ed25519
	Origin            string // "generated" | "imported"
	FingerprintSHA256 string // "SHA256:…"
}

func configureSSHKey(configDir, profile string, rec *targetRecord, kc keyChoice) (keyMetadata, error) {
	slug := profileSlug(profile)
	keyPath := filepath.Join(configDir, sshKeyDir, slug)
	pubPath := keyPath + ".pub"

	// If a key already exists on disk, offer to reuse it — but re-derive
	// metadata from the key bytes so the heartbeat stays accurate even
	// after operator-facing state (KeyAlgorithm etc.) has been cleared.
	if existsRegularSecret(keyPath) {
		switch confirmChoice("SSH key exists. Reuse / Regenerate / Import", "reuse") {
		case "reuse":
			meta, err := deriveKeyMetadata(keyPath, pubPath, "generated")
			if err != nil {
				return keyMetadata{}, err
			}
			// Preserve the previously-recorded origin when reusing.
			if rec != nil && rec.SSH != nil && rec.SSH.KeyOrigin != "" {
				meta.Origin = rec.SSH.KeyOrigin
			}
			return meta, nil
		case "import":
			return importSSHKey(keyPath, pubPath)
		case "regenerate":
			// fall through to generation
		}
	}

	// Choose the generator: flag first, then interactive default.
	algo := kc.GenerateAlgorithm
	if kc.ImportPath != "" {
		return importSSHKeyFrom(kc.ImportPath, keyPath, pubPath)
	}
	if !kc.FromFlag {
		// Interactive default: RSA-3072 for FOS 7.x/8.x compatibility.
		// Operators who need Ed25519 can rerun with --key-algo ed25519.
		choice := confirmChoice(
			"Generate RSA-3072 (recommended for FOS 7.x/8.x), Ed25519, or Import an existing key",
			"rsa-3072",
		)
		switch choice {
		case "import":
			return importSSHKey(keyPath, pubPath)
		case "ed25519":
			algo = "ed25519"
		default:
			algo = "rsa-3072"
		}
	}

	switch algo {
	case "ed25519":
		return generateEd25519(keyPath, pubPath)
	case "rsa-3072", "rsa":
		return generateRSA3072(keyPath, pubPath)
	default:
		return keyMetadata{}, fmt.Errorf("unsupported generator algorithm %q", algo)
	}
}

func generateEd25519(keyPath, pubPath string) (keyMetadata, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return keyMetadata{}, fmt.Errorf("ed25519 generate: %w", err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "filterrex-ro")
	if err != nil {
		return keyMetadata{}, fmt.Errorf("marshal private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(pemBlock)
	if err := atomicWriteFile(keyPath, privPEM, 0o600); err != nil {
		return keyMetadata{}, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return keyMetadata{}, err
	}
	if err := atomicWriteFile(pubPath, ssh.MarshalAuthorizedKey(sshPub), 0o644); err != nil {
		return keyMetadata{}, err
	}
	return keyMetadata{
		KeyPath:           keyPath,
		PublicKeyPath:     pubPath,
		Algorithm:         "ed25519",
		Bits:              0,
		Origin:            "generated",
		FingerprintSHA256: sshFingerprintSHA256(sshPub),
	}, nil
}

func generateRSA3072(keyPath, pubPath string) (keyMetadata, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return keyMetadata{}, fmt.Errorf("rsa generate: %w", err)
	}
	// PKCS#8 PEM so ssh.ParsePrivateKey (and OpenSSH) accept it uniformly.
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return keyMetadata{}, fmt.Errorf("marshal rsa private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	if err := atomicWriteFile(keyPath, privPEM, 0o600); err != nil {
		return keyMetadata{}, err
	}
	sshPub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		return keyMetadata{}, err
	}
	if err := atomicWriteFile(pubPath, ssh.MarshalAuthorizedKey(sshPub), 0o644); err != nil {
		return keyMetadata{}, err
	}
	return keyMetadata{
		KeyPath:           keyPath,
		PublicKeyPath:     pubPath,
		Algorithm:         "rsa",
		Bits:              3072,
		Origin:            "generated",
		FingerprintSHA256: sshFingerprintSHA256(sshPub),
	}, nil
}

// importSSHKey is the interactive entry point (prompts for the source path).
func importSSHKey(keyPath, pubPath string) (keyMetadata, error) {
	src := prompt("Path to existing private key on the setup host", "")
	if src == "" {
		return keyMetadata{}, errors.New("import path is required")
	}
	return importSSHKeyFrom(src, keyPath, pubPath)
}

// importSSHKeyFrom copies an existing private key into managed storage,
// DERIVES its algorithm and size from the key itself (never trusting an
// external assertion), and always rewrites the .pub file from the private
// key so an adjacent stale .pub can never mislead heartbeat metadata.
func importSSHKeyFrom(src, keyPath, pubPath string) (keyMetadata, error) {
	fi, err := os.Lstat(src)
	if err != nil {
		return keyMetadata{}, fmt.Errorf("import source unreadable")
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return keyMetadata{}, errors.New("import source is a symlink; refusing")
	}
	if !fi.Mode().IsRegular() {
		return keyMetadata{}, errors.New("import source is not a regular file")
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return keyMetadata{}, fmt.Errorf("import source permissions %#o are too permissive; use 0600 or 0400", fi.Mode().Perm())
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return keyMetadata{}, errors.New("import source read failed")
	}
	signer, err := ssh.ParsePrivateKey(b)
	if err != nil {
		zeroBytes(b)
		// Distinguish encrypted keys — this release does not persist a
		// passphrase, so we reject them with a stable reason code that
		// the wire contract already understands.
		if strings.Contains(strings.ToLower(err.Error()), "passphrase") {
			return keyMetadata{}, errors.New("encrypted_private_key_unsupported")
		}
		return keyMetadata{}, errors.New("import source is not a valid SSH private key")
	}
	if err := atomicWriteFile(keyPath, b, 0o600); err != nil {
		zeroBytes(b)
		return keyMetadata{}, err
	}
	zeroBytes(b)
	pub := signer.PublicKey()
	if err := atomicWriteFile(pubPath, ssh.MarshalAuthorizedKey(pub), 0o644); err != nil {
		return keyMetadata{}, err
	}
	algo, bits := deriveAlgoBits(pub)
	return keyMetadata{
		KeyPath:           keyPath,
		PublicKeyPath:     pubPath,
		Algorithm:         algo,
		Bits:              bits,
		Origin:            "imported",
		FingerprintSHA256: sshFingerprintSHA256(pub),
	}, nil
}

// deriveKeyMetadata reads an already-stored private key and re-derives its
// algorithm, size, and fingerprint. Used by the "reuse" branch so heartbeat
// metadata stays accurate across wizard runs.
func deriveKeyMetadata(keyPath, pubPath, defaultOrigin string) (keyMetadata, error) {
	b, err := os.ReadFile(keyPath)
	if err != nil {
		return keyMetadata{}, fmt.Errorf("read stored key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(b)
	zeroBytes(b)
	if err != nil {
		return keyMetadata{}, errors.New("stored key is not a valid SSH private key")
	}
	pub := signer.PublicKey()
	algo, bits := deriveAlgoBits(pub)
	return keyMetadata{
		KeyPath:           keyPath,
		PublicKeyPath:     pubPath,
		Algorithm:         algo,
		Bits:              bits,
		Origin:            defaultOrigin,
		FingerprintSHA256: sshFingerprintSHA256(pub),
	}, nil
}

// deriveAlgoBits maps a parsed ssh.PublicKey to the wire vocabulary.
func deriveAlgoBits(pub ssh.PublicKey) (string, int) {
	switch pub.Type() {
	case ssh.KeyAlgoED25519:
		return "ed25519", 0
	case ssh.KeyAlgoRSA, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512:
		if ck, ok := pub.(ssh.CryptoPublicKey); ok {
			if rp, ok := ck.CryptoPublicKey().(*rsa.PublicKey); ok {
				return "rsa", rp.N.BitLen()
			}
		}
		return "rsa", 0
	default:
		return "unknown", 0
	}
}

// sshFingerprintSHA256 returns "SHA256:<base64-nopad>" matching OpenSSH's
// `ssh-keygen -lf` output.
func sshFingerprintSHA256(pub ssh.PublicKey) string {
	sum := sha256.Sum256(pub.Marshal())
	return "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "=")
}


func enrollHostKey(configDir, host string, sshPort int, existing *targetRecord) (string, bool, error) {
	khPath := filepath.Join(configDir, knownHostsFn)

	if hasKnownHostEntry(khPath, host) {
		if confirmChoice("known_hosts already has an entry for "+host+". Reuse or Refresh", "reuse") == "reuse" {
			return khPath, false, nil
		}
	}

	pub, hostKey, err := fetchHostKey(host, sshPort)
	if err != nil {
		return khPath, false, err
	}
	sum := sha256.Sum256(pub.Marshal())
	fpRaw := base64.StdEncoding.EncodeToString(sum[:])
	fpNoPad := strings.TrimRight(fpRaw, "=")
	fmt.Printf("\nSwitch presented SSH host key:\n  type:        %s\n  SHA256 fp:   SHA256:%s\n\n", pub.Type(), fpNoPad)
	fmt.Println("This key was received over the network and is NOT yet trusted.")
	fmt.Println("Compare the fingerprint above with the switch console, an existing")
	fmt.Println("trusted SSH session, or an approved inventory record.")

	if !confirmYesNo("I have compared the fingerprint against a trusted source", false) {
		return khPath, false, errors.New("host key not confirmed out-of-band")
	}
	want := ""
	if len(fpNoPad) >= 12 {
		want = fpNoPad[len(fpNoPad)-12:]
	} else {
		want = fpNoPad
	}
	got := strings.TrimSpace(prompt("Type the final 12 characters of the fingerprint (excluding trailing '=')", ""))
	if got != want {
		return khPath, false, errors.New("fingerprint challenge failed")
	}

	line := knownHostsLine(host, sshPort, hostKey)
	if err := appendLineAtomic(khPath, line, 0o640); err != nil {
		return khPath, false, err
	}
	return khPath, true, nil
}

func fetchHostKey(host string, port int) (ssh.PublicKey, []byte, error) {
	var captured ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: "filterrex-hostkey-probe",
		Auth: []ssh.AuthMethod{ssh.Password("")},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			captured = key
			return errors.New("host-key-only")
		},
		Timeout: 8 * time.Second,
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	_, _ = ssh.Dial("tcp", addr, cfg)
	if captured == nil {
		return nil, nil, errors.New("no host key returned (connection failed)")
	}
	return captured, captured.Marshal(), nil
}

func knownHostsLine(host string, port int, wire []byte) string {
	hostPart := host
	if port != 22 {
		hostPart = "[" + host + "]:" + strconv.Itoa(port)
	}
	key, err := ssh.ParsePublicKey(wire)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s %s %s\n", hostPart, key.Type(), base64.StdEncoding.EncodeToString(wire))
}

func hasKnownHostEntry(path, host string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, host+" ") || strings.HasPrefix(line, "["+host+"]:") {
			return true
		}
	}
	return false
}

func probeREST(rec *targetRecord, _ string) (bool, string) {
	cfg := brocaderest.Config{
		TargetProfileID: "wizard-probe",
		Host:            rec.Address,
		Port:            rec.RESTPort,
		TransportMode:   brocaderest.TransportMode(rec.REST.TransportMode),
		Username:        rec.REST.Username,
		PasswordFile:    rec.REST.PasswordFile,
		CAFile:          rec.REST.CAFile,
	}
	client, err := brocaderest.New(cfg)
	if err != nil {
		var e *brocaderest.Error
		if errors.As(err, &e) {
			return false, e.Code
		}
		return false, brocaderest.ErrCodeRESTConnectionFailed
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if e := client.ProbeSwitchStatus(ctx); e != nil {
		return false, e.Code
	}
	return true, ""
}

func probeSSH(rec *targetRecord) (bool, string) {
	keyBytes, err := os.ReadFile(rec.SSH.KeyPath)
	if err != nil {
		return false, "missing_ssh_key"
	}
	signer, perr := ssh.ParsePrivateKey(keyBytes)
	zeroBytes(keyBytes)
	if perr != nil {
		return false, "missing_ssh_key"
	}
	cb, err := hostKeyCallbackFromFile(rec.SSH.KnownHostsPath)
	if err != nil {
		return false, "known_hosts_missing"
	}
	cfg := &ssh.ClientConfig{
		User:            rec.SSH.Username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: cb,
		Timeout:         8 * time.Second,
	}
	addr := net.JoinHostPort(rec.Address, strconv.Itoa(rec.SSHPort))
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		msg := err.Error()
		switch {
		case strings.Contains(msg, "unable to authenticate"):
			return false, "ssh_auth_failed"
		case strings.Contains(msg, "host key"):
			return false, "host_key_verification_failed"
		default:
			return false, "ssh_connection_failed"
		}
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return false, "read_only_probe_failed"
	}
	defer sess.Close()
	return true, ""
}

// ─── low-level helpers ──────────────────────────────────────────────────────

func hostKeyCallbackFromFile(path string) (ssh.HostKeyCallback, error) {
	return func(hostname string, remote net.Addr, presented ssh.PublicKey) error {
		b, err := os.ReadFile(path)
		if err != nil {
			return errors.New("known_hosts unreadable")
		}
		presentedMarshal := presented.Marshal()
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) < 3 {
				continue
			}
			if !strings.HasPrefix(parts[0], strings.SplitN(hostname, ":", 2)[0]) &&
				!strings.Contains(parts[0], hostname) {
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(parts[2])
			if err != nil {
				continue
			}
			if bytesEqual(raw, presentedMarshal) {
				return nil
			}
		}
		return errors.New("host key not enrolled")
	}, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func loadTargets(configDir string) (*targetsDoc, error) {
	p := filepath.Join(configDir, targetsFile)
	b, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return &targetsDoc{Version: 1, Targets: map[string]*targetRecord{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", p, err)
	}
	var d targetsDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	if d.Targets == nil {
		d.Targets = map[string]*targetRecord{}
	}
	return &d, nil
}

func writeTargets(configDir string, doc *targetsDoc) error {
	buf, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if len(buf) == 0 || buf[len(buf)-1] != '\n' {
		buf = append(buf, '\n')
	}
	_ = sort.StringsAreSorted
	return atomicWriteFile(filepath.Join(configDir, targetsFile), buf, 0o600)
}

func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".wizard-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	if fi, err := os.Stat(path); err == nil {
		if fi.Mode().Perm()&0o077 != 0 && mode&0o077 == 0 {
			return fmt.Errorf("post-write permissions %#o are too permissive on %s", fi.Mode().Perm(), path)
		}
	}
	return nil
}

func appendLineAtomic(path, line string, mode os.FileMode) error {
	existing, _ := os.ReadFile(path)
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		existing = append(existing, '\n')
	}
	existing = append(existing, []byte(line)...)
	return atomicWriteFile(path, existing, mode)
}

func existsRegularSecret(p string) bool {
	fi, err := os.Lstat(p)
	if err != nil {
		return false
	}
	return fi.Mode().IsRegular()
}

func profileSlug(id string) string {
	safe := regexp.MustCompile(`[^A-Za-z0-9._-]+`).ReplaceAllString(id, "-")
	if safe == "" {
		safe = "target"
	}
	return safe
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
func firstNonZero(a, b int) int {
	if a != 0 {
		return a
	}
	return b
}

func existingUser(rec *targetRecord, kind string) string {
	if rec == nil {
		return ""
	}
	switch kind {
	case "rest":
		if rec.REST != nil {
			return rec.REST.Username
		}
	case "ssh":
		if rec.SSH != nil {
			return rec.SSH.Username
		}
	}
	return ""
}

// ─── prompt helpers ─────────────────────────────────────────────────────────

func prompt(label, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	var line string
	if _, err := fmt.Fscanln(os.Stdin, &line); err != nil {
		line = ""
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func confirmYesNo(label string, def bool) bool {
	suffix := "[y/N]"
	if def {
		suffix = "[Y/n]"
	}
	fmt.Printf("%s %s: ", label, suffix)
	var line string
	_, _ = fmt.Fscanln(os.Stdin, &line)
	line = strings.ToLower(strings.TrimSpace(line))
	if line == "" {
		return def
	}
	return line == "y" || line == "yes"
}

func confirmChoice(label, def string) string {
	fmt.Printf("%s [%s]: ", label, def)
	var line string
	_, _ = fmt.Fscanln(os.Stdin, &line)
	line = strings.ToLower(strings.TrimSpace(line))
	if line == "" {
		return def
	}
	return line
}

// readSecretNoEcho reads a line from stdin with terminal echo disabled via
// golang.org/x/term, which uses termios ioctls directly and restores state
// even on SIGINT/SIGTERM. We refuse when stdin is not a terminal — a piped
// password on a wizard prompt is almost always a bug (script leaking secrets
// into process listings, shell history, or ~/.*_history).
func readSecretNoEcho(label string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("stdin is not a terminal; refusing to read secret from a pipe or redirect")
	}
	fmt.Fprint(os.Stderr, label)
	buf, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}
	return buf, nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
