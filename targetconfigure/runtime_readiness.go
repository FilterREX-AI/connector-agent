// Runtime SSH-readiness sidecar (preview.18).
//
// Preview.17 fixed the daemon's targets-dir path but left probe writes going
// into targets.json under a lock in that same directory. When the operator
// bind-mounts /etc/filterrex/targets read-only (the documented safe default),
// the probe cannot even create the .targets.lock file — every remote probe
// dies with permission denied and readiness never becomes fresh.
//
// This module separates the two facts:
//
//   • targets.json (owned by `target configure`, may be RO for the daemon)
//     — immutable per-target identity, address, keys, host key.
//
//   • brocade-ssh-readiness.json (this file) — mutable, daemon-writable,
//     lives under a *writable* runtime-state directory (default
//     <configDir>/state, typically /etc/filterrex/state on the docker volume).
//     Records last probe outcome, timestamps, and a configuration fingerprint
//     so we never publish stale readiness against a rotated key.
//
// The loader keeps the legacy in-targets readiness as a fall-back so hosts
// that upgrade without reconfiguring keep publishing what they published
// before.
package targetconfigure

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	runtimeReadinessFile = "brocade-ssh-readiness.json"
	runtimeReadinessLock = ".brocade-ssh-readiness.lock"
)

// ErrRuntimeStateUnwritable is returned when the daemon cannot create/write
// the runtime-state directory. It is safe to surface over the relay: it
// names a bounded operator condition, not a secret.
var (
	ErrRuntimeStateUnwritable = errors.New("runtime_state_unwritable")
	ErrRuntimeStateLockFailed = errors.New("runtime_state_lock_failed")
)

// RuntimeReadinessRecord is the on-disk shape of one target's mutable probe
// state. Fingerprint fields are copied from the target record at probe time
// so a later key/address change invalidates the entry automatically.
type RuntimeReadinessRecord struct {
	TargetID                 string `json:"target_id"`
	ConfigFingerprint        string `json:"config_fingerprint"`
	SSHReady                 bool   `json:"ssh_ready"`
	SSHReason                string `json:"ssh_reason,omitempty"`
	SSHProbeStage            string `json:"ssh_probe_stage,omitempty"`
	LastProbeAt              string `json:"last_probe_at,omitempty"`
	LastSuccessfulProbeAt    string `json:"last_successful_probe_at,omitempty"`
}

type runtimeReadinessDoc struct {
	Version int                                `json:"version"`
	Targets map[string]RuntimeReadinessRecord  `json:"targets"`
	// UpdatedAt is informational only — the merge never trusts a clock
	// alone, always a fingerprint.
	UpdatedAt string `json:"updated_at,omitempty"`
}

// ConfigFingerprintFromRecord builds the fingerprint used to invalidate a
// runtime entry when the underlying target configuration changes. It hashes
// the small set of fields that authorize an SSH login — anything else
// (labels, readiness itself) is deliberately excluded so probe overwrites
// don't roll the fingerprint.
func ConfigFingerprintFromRecord(rec *targetRecord) string {
	if rec == nil {
		return ""
	}
	var username, keyFp, keyAlg, khPath string
	var keyBits int
	if rec.SSH != nil {
		username = rec.SSH.Username
		keyFp = rec.SSH.KeyFingerprintSHA256
		keyAlg = rec.SSH.KeyAlgorithm
		keyBits = rec.SSH.KeyBits
		khPath = rec.SSH.KnownHostsPath
	}
	hostKey := ""
	if fp, err := readKnownHostFingerprint(khPath, rec.Address); err == nil {
		hostKey = fp
	}
	raw := strings.Join([]string{
		strings.TrimSpace(rec.Address),
		fmt.Sprintf("%d", rec.SSHPort),
		username,
		keyAlg,
		fmt.Sprintf("%d", keyBits),
		keyFp,
		hostKey,
	}, "|")
	sum := sha256.Sum256([]byte(raw))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func acquireRuntimeReadinessLock(runtimeStateDir string) (func(), error) {
	if strings.TrimSpace(runtimeStateDir) == "" {
		return nil, ErrConfigDirRequired
	}
	if err := os.MkdirAll(runtimeStateDir, 0o700); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRuntimeStateUnwritable, err)
	}
	path := filepath.Join(runtimeStateDir, runtimeReadinessLock)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRuntimeStateUnwritable, err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, ErrRuntimeStateLockFailed
		}
		time.Sleep(100 * time.Millisecond)
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}

// LoadRuntimeReadiness reads the runtime-state sidecar. A missing file is
// not an error — it just returns an empty map.
func LoadRuntimeReadiness(runtimeStateDir string) (map[string]RuntimeReadinessRecord, error) {
	if strings.TrimSpace(runtimeStateDir) == "" {
		return nil, nil
	}
	p := filepath.Join(runtimeStateDir, runtimeReadinessFile)
	b, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var doc runtimeReadinessDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	if doc.Targets == nil {
		return nil, nil
	}
	return doc.Targets, nil
}

// UpsertRuntimeReadiness atomically inserts or replaces a single target's
// runtime record. Other entries are preserved.
func UpsertRuntimeReadiness(runtimeStateDir string, rec RuntimeReadinessRecord) error {
	if strings.TrimSpace(runtimeStateDir) == "" {
		return ErrConfigDirRequired
	}
	if strings.TrimSpace(rec.TargetID) == "" {
		return ErrInvalidTargetID
	}
	release, err := acquireRuntimeReadinessLock(runtimeStateDir)
	if err != nil {
		return err
	}
	defer release()

	existing, err := LoadRuntimeReadiness(runtimeStateDir)
	if err != nil {
		// Sidecar corrupt — start clean rather than block probes forever.
		existing = nil
	}
	if existing == nil {
		existing = map[string]RuntimeReadinessRecord{}
	}
	existing[rec.TargetID] = rec

	doc := runtimeReadinessDoc{
		Version:   1,
		Targets:   existing,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	buf, err := json.MarshalIndent(&doc, "", "  ")
	if err != nil {
		return err
	}
	if len(buf) == 0 || buf[len(buf)-1] != '\n' {
		buf = append(buf, '\n')
	}
	if err := atomicWriteFile(filepath.Join(runtimeStateDir, runtimeReadinessFile), buf, 0o600); err != nil {
		return fmt.Errorf("%w: %v", ErrRuntimeStateUnwritable, err)
	}
	return nil
}
