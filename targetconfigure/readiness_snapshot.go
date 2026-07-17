// SSH-readiness snapshot loader consumed by the supervisor when building
// the heartbeat capability manifest.
//
// This is intentionally READ-ONLY and best-effort:
//   - It reads `targets.json` once per heartbeat and returns immutable
//     value copies. It never reopens key files, never derives fingerprints,
//     and never runs SSH — the explicit `target probe` path owns those.
//   - It returns the persisted key metadata (algorithm/bits/origin/
//     fingerprint) and per-target SSH readiness as recorded by the wizard
//     or by `target probe`. Fingerprint verification against on-disk key
//     bytes is not repeated here; the probe path checks that.
//   - If `targets.json` is missing or malformed, the loader returns an
//     empty snapshot and a non-nil error. The supervisor treats the error
//     as a bounded local warning and still publishes REST readiness.
//
// Option-B identity model (preview.13): the outer targets.json map key is a
// LOCAL profile label. The heartbeat is keyed by canonical application
// target-profile UUID (`target_id`). This loader:
//   - resolves each record via EffectiveTargetID (canonical lowercase UUID),
//   - drops records that cannot be resolved and does NOT publish anything
//     under an arbitrary profile label,
//   - drops all records that share a resolved UUID (duplicate mapping — we
//     cannot tell which one is authoritative, so we publish neither).
package targetconfigure

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SSHReadinessSnapshot is the SSH-owned subset of readiness the supervisor
// merges into the heartbeat's PerTarget map. Fields are named after the
// wire contract locked by the Go/TS golden test.
type SSHReadinessSnapshot struct {
	SSHReady                 bool
	SSHReason                string
	SSHProbeStage            string
	SSHKeyAlgorithm          string
	SSHKeyBits               int
	SSHKeyOrigin             string
	SSHKeyFingerprintSHA256  string
	SSHUsername              string
	SwitchHostKeyFingerprint string
	LastProbeAt              string // "" when never probed
	LastSuccessfulProbeAt    string // "" when never observed success
}

// SnapshotLoadWarning names a bounded, secret-free diagnostic the loader
// emits when a record cannot be resolved. The supervisor logs these
// verbatim; nothing here carries operator secrets or key material.
type SnapshotLoadWarning struct {
	ProfileName string
	Reason      string // "target_id_missing" | "invalid_target_id" | "duplicate_target_id"
	TargetID    string // populated only for duplicate_target_id
	Count       int    // populated only for duplicate_target_id
}

func (w SnapshotLoadWarning) String() string {
	if w.Reason == "duplicate_target_id" {
		return fmt.Sprintf("target.readiness.skipped reason=duplicate_target_id target_id=%s record_count=%d", w.TargetID, w.Count)
	}
	return fmt.Sprintf("target.readiness.skipped reason=%s profile=%s", w.Reason, w.ProfileName)
}

// LoadSSHReadinessSnapshot reads targets.json and returns SSH-only readiness
// keyed by CANONICAL application target UUID. Records that have no SSH
// configuration, no resolvable target_id, or a target_id shared with another
// record are omitted.
//
// An empty configDir returns (nil, nil, nil): the connector was not started
// with a target-config directory and there is nothing to publish.
func LoadSSHReadinessSnapshot(configDir string) (map[string]SSHReadinessSnapshot, []SnapshotLoadWarning, error) {
	if configDir == "" {
		return nil, nil, nil
	}
	// Fast path: file absent → no SSH snapshots yet, not an error.
	if _, err := os.Stat(filepath.Join(configDir, targetsFile)); os.IsNotExist(err) {
		return nil, nil, nil
	}
	doc, err := loadTargets(configDir)
	if err != nil {
		return nil, nil, err
	}
	if doc == nil || len(doc.Targets) == 0 {
		return nil, nil, nil
	}

	var warnings []SnapshotLoadWarning

	// Pass 1: bucket resolvable records by canonical target_id. Records
	// without an SSH block are skipped silently (no readiness to publish).
	type resolved struct {
		profileName string
		rec         *targetRecord
	}
	buckets := make(map[string][]resolved, len(doc.Targets))
	for profileName, rec := range doc.Targets {
		if rec == nil || rec.SSH == nil {
			continue
		}
		targetID, rerr := EffectiveTargetID(profileName, rec)
		if rerr != nil {
			warnings = append(warnings, SnapshotLoadWarning{
				ProfileName: profileName,
				Reason:      rerr.Error(),
			})
			continue
		}
		buckets[targetID] = append(buckets[targetID], resolved{profileName: profileName, rec: rec})
	}

	// Pass 2: publish only single-record buckets. Duplicates are ambiguous;
	// we refuse to guess which local profile authorizes the shared target.
	out := make(map[string]SSHReadinessSnapshot, len(buckets))
	for targetID, matches := range buckets {
		if len(matches) != 1 {
			warnings = append(warnings, SnapshotLoadWarning{
				Reason:   "duplicate_target_id",
				TargetID: targetID,
				Count:    len(matches),
			})
			continue
		}
		rec := matches[0].rec
		s := SSHReadinessSnapshot{
			SSHReady:                rec.Readiness.SSHReady,
			SSHReason:               rec.Readiness.SSHReason,
			SSHProbeStage:           rec.Readiness.SSHProbeStage,
			SSHKeyAlgorithm:         rec.SSH.KeyAlgorithm,
			SSHKeyBits:              rec.SSH.KeyBits,
			SSHKeyOrigin:            rec.SSH.KeyOrigin,
			SSHKeyFingerprintSHA256: rec.SSH.KeyFingerprintSHA256,
			SSHUsername:             rec.SSH.Username,
			LastProbeAt:             rec.Readiness.LastSSHProbeAt,
			LastSuccessfulProbeAt:   rec.Readiness.LastSuccessfulSSHProbeAt,
		}
		if fp, err := readKnownHostFingerprint(rec.SSH.KnownHostsPath, rec.Address); err == nil {
			s.SwitchHostKeyFingerprint = fp
		}
		out[targetID] = s
	}
	if len(out) == 0 {
		return nil, warnings, nil
	}
	return out, warnings, nil
}

// readKnownHostFingerprint parses the enrolled known_hosts file and returns
// the SHA-256 fingerprint of the host key entry matching `host`. It is
// deliberately best-effort: any error (file missing, unparseable, no match)
// returns an empty string with the error. The heartbeat still publishes
// SSH readiness when this cannot be computed.
func readKnownHostFingerprint(khPath, host string) (string, error) {
	if khPath == "" || host == "" {
		return "", os.ErrNotExist
	}
	b, err := os.ReadFile(khPath)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Match either bare host or [host]:port form (OpenSSH known_hosts).
		if !(strings.HasPrefix(line, host+" ") || strings.HasPrefix(line, "["+host+"]:")) {
			continue
		}
		// Format: "<hostpattern> <keytype> <base64key> [comment]"
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		authorized := fields[1] + " " + fields[2]
		pub, _, _, _, perr := ssh.ParseAuthorizedKey([]byte(authorized))
		if perr != nil {
			continue
		}
		return sshFingerprintSHA256(pub), nil
	}
	return "", os.ErrNotExist
}
