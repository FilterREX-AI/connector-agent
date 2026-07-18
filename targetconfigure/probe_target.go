// Remote/UUID-scoped probe entry point (preview.16).
//
// RunProbeForTarget is the single canonical implementation of "run the SSH
// readiness probe against an existing on-disk record" callable by BOTH the
// interactive CLI (`target probe`) and the connector's remote relay handler
// (`brocade-probe` platform). It NEVER mutates address/port/username/key/
// host-key state — it only re-runs `probeSSH` and persists the readiness
// timestamps under a cross-process advisory lock.
//
// Identity resolution is authoritative-UUID first: the caller passes the
// application target-profile UUID and we look up the local record that
// resolves to that UUID via EffectiveTargetID. A local map-key match is
// never sufficient.
package targetconfigure

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// ProbeOutcome is a bounded, secret-free representation of a probe result
// suitable for shipping over the relay. All string fields belong to fixed
// vocabularies — never raw errors or filesystem paths.
type ProbeOutcome struct {
	Ready                    bool   `json:"ready"`
	Stage                    string `json:"stage"`  // ssh_probe_stage enum
	Reason                   string `json:"reason"` // "" when Ready
	LastProbeAt              string `json:"lastProbeAt"`
	LastSuccessfulProbeAt    string `json:"lastSuccessfulProbeAt"`
	SSHKeyAlgorithm          string `json:"sshKeyAlgorithm,omitempty"`
	SSHKeyBits               int    `json:"sshKeyBits,omitempty"`
	SSHKeyOrigin             string `json:"sshKeyOrigin,omitempty"`
	SSHKeyFingerprintSHA256  string `json:"sshKeyFingerprintSha256,omitempty"`
	SwitchHostKeyFingerprint string `json:"switchHostKeyFingerprintSha256,omitempty"`
	SSHUsername              string `json:"sshUsername,omitempty"`
}

// Bounded, secret-free error codes returned by RunProbeForTarget. Anything
// outside this set indicates a genuine infrastructure failure and should
// surface as `probe_execution_failed`.
var (
	ErrTargetNotConfigured = errors.New("target_not_configured")
	ErrDuplicateTargetID   = errors.New("duplicate_target_id")
	ErrProbeLockFailed     = errors.New("probe_lock_failed")
	ErrConfigDirRequired   = errors.New("config_dir_required")
)

const lockFileName = ".targets.lock"

// acquireTargetsLock takes an exclusive advisory lock on <configDir>/.targets.lock
// scoped to the process. Callers MUST invoke the returned release func.
func acquireTargetsLock(configDir string) (func(), error) {
	if configDir == "" {
		return nil, ErrConfigDirRequired
	}
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(configDir, lockFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	// LOCK_EX blocks. Bound with a coarse timeout using LOCK_NB in a loop
	// so a stuck peer cannot pin the caller indefinitely.
	deadline := time.Now().Add(30 * time.Second)
	for {
		if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
			break
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, ErrProbeLockFailed
		}
		time.Sleep(100 * time.Millisecond)
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}

// RunProbeForTarget resolves the record whose authoritative target UUID equals
// targetID, runs probeSSH, and atomically persists the new readiness. It is
// safe for concurrent callers (CLI + relay handler): the on-disk lock file
// serializes read-modify-write.
//
// Returned ProbeOutcome is populated even when Ready=false — a failed probe
// is still new readiness information. err is non-nil ONLY for genuine
// infrastructure failures; a legitimate authentication failure returns
// (outcome, nil) with Ready=false and a bounded Reason.
func RunProbeForTarget(ctx context.Context, configDir, targetID string) (ProbeOutcome, error) {
	if configDir == "" {
		return ProbeOutcome{}, ErrConfigDirRequired
	}
	canon := canonicalUUID(targetID)
	if canon == "" {
		return ProbeOutcome{}, ErrInvalidTargetID
	}
	release, err := acquireTargetsLock(configDir)
	if err != nil {
		return ProbeOutcome{}, err
	}
	defer release()

	doc, err := loadTargets(configDir)
	if err != nil {
		return ProbeOutcome{}, err
	}
	if doc == nil || len(doc.Targets) == 0 {
		return ProbeOutcome{}, ErrTargetNotConfigured
	}

	// Resolve by authoritative target_id. Duplicates fail closed.
	var (
		matchProfile string
		matchRec     *targetRecord
		matchCount   int
	)
	for profileName, rec := range doc.Targets {
		if rec == nil || rec.SSH == nil {
			continue
		}
		id, rerr := EffectiveTargetID(profileName, rec)
		if rerr != nil || id != canon {
			continue
		}
		matchCount++
		matchProfile = profileName
		matchRec = rec
	}
	if matchCount == 0 {
		return ProbeOutcome{}, ErrTargetNotConfigured
	}
	if matchCount > 1 {
		return ProbeOutcome{}, ErrDuplicateTargetID
	}

	// Cooperate with ctx cancellation without cancelling an in-flight ssh
	// dial (probeSSH has its own 8s timeout).
	if err := ctx.Err(); err != nil {
		return ProbeOutcome{}, err
	}

	ready, reason := probeSSH(matchRec)
	nowStr := time.Now().UTC().Format(time.RFC3339)
	matchRec.Readiness.SSHReady = ready
	matchRec.Readiness.LastSSHProbeAt = nowStr
	if ready {
		matchRec.Readiness.SSHReason = ""
		matchRec.Readiness.SSHProbeStage = "command_succeeded"
		matchRec.Readiness.LastSuccessfulSSHProbeAt = nowStr
	} else {
		matchRec.Readiness.SSHReason = reason
		matchRec.Readiness.SSHProbeStage = mapProbeStage(reason)
		// Preserve prior LastSuccessfulSSHProbeAt on failure.
	}
	doc.Targets[matchProfile] = matchRec
	if err := writeTargets(configDir, doc); err != nil {
		return ProbeOutcome{}, err
	}

	// Build the bounded outcome. Fingerprint fields come from the persisted
	// wizard state; nothing is derived from live key material here.
	out := ProbeOutcome{
		Ready:                   ready,
		Stage:                   matchRec.Readiness.SSHProbeStage,
		Reason:                  matchRec.Readiness.SSHReason,
		LastProbeAt:             matchRec.Readiness.LastSSHProbeAt,
		LastSuccessfulProbeAt:   matchRec.Readiness.LastSuccessfulSSHProbeAt,
		SSHKeyAlgorithm:         matchRec.SSH.KeyAlgorithm,
		SSHKeyBits:              matchRec.SSH.KeyBits,
		SSHKeyOrigin:            matchRec.SSH.KeyOrigin,
		SSHKeyFingerprintSHA256: matchRec.SSH.KeyFingerprintSHA256,
		SSHUsername:             matchRec.SSH.Username,
	}
	if fp, ferr := readKnownHostFingerprint(matchRec.SSH.KnownHostsPath, matchRec.Address); ferr == nil {
		out.SwitchHostKeyFingerprint = fp
	}
	return out, nil
}
