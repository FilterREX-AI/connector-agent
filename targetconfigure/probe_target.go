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
	"strings"
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

// RunProbeForTarget is the legacy writable-targets probe path used by the
// interactive `target probe` CLI. It read-modify-writes targets.json under
// the on-disk lock in targetsDir. Requires targetsDir to be writable.
func RunProbeForTarget(ctx context.Context, targetsDir, targetID string) (ProbeOutcome, error) {
	return runProbeForTargetImpl(ctx, targetsDir, "", targetID)
}

// RunProbeForTargetSidecar is the remote/daemon probe path. It reads
// targets.json from a possibly read-only targetsDir (no lock) and persists
// the outcome into the runtime-state sidecar under runtimeStateDir. This is
// what the connector's brocade-probe relay handler invokes so a read-only
// mount of /etc/filterrex/targets never blocks a probe.
func RunProbeForTargetSidecar(ctx context.Context, targetsDir, runtimeStateDir, targetID string) (ProbeOutcome, error) {
	if strings.TrimSpace(runtimeStateDir) == "" {
		return ProbeOutcome{}, ErrConfigDirRequired
	}
	return runProbeForTargetImpl(ctx, targetsDir, runtimeStateDir, targetID)
}

func runProbeForTargetImpl(ctx context.Context, targetsDir, runtimeStateDir, targetID string) (ProbeOutcome, error) {
	if targetsDir == "" {
		return ProbeOutcome{}, ErrConfigDirRequired
	}
	canon := canonicalUUID(targetID)
	if canon == "" {
		return ProbeOutcome{}, ErrInvalidTargetID
	}

	useSidecar := strings.TrimSpace(runtimeStateDir) != ""

	// Legacy path locks the targets dir. Sidecar path reads targets.json
	// without a lock (writes there are atomic renames).
	var releaseTargets func()
	if !useSidecar {
		r, err := acquireTargetsLock(targetsDir)
		if err != nil {
			return ProbeOutcome{}, err
		}
		releaseTargets = r
		defer releaseTargets()
	}

	doc, err := loadTargets(targetsDir)
	if err != nil {
		return ProbeOutcome{}, err
	}
	if doc == nil || len(doc.Targets) == 0 {
		return ProbeOutcome{}, ErrTargetNotConfigured
	}

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

	if err := ctx.Err(); err != nil {
		return ProbeOutcome{}, err
	}

	ready, reason := probeSSH(matchRec)
	nowStr := time.Now().UTC().Format(time.RFC3339)
	stage := "command_succeeded"
	if !ready {
		stage = mapProbeStage(reason)
	}
	lastSuccess := matchRec.Readiness.LastSuccessfulSSHProbeAt
	if ready {
		lastSuccess = nowStr
	}

	if useSidecar {
		rec := RuntimeReadinessRecord{
			TargetID:              canon,
			ConfigFingerprint:     ConfigFingerprintFromRecord(matchRec),
			SSHReady:              ready,
			SSHReason:             "",
			SSHProbeStage:         stage,
			LastProbeAt:           nowStr,
			LastSuccessfulProbeAt: lastSuccess,
		}
		if !ready {
			rec.SSHReason = reason
		}
		if err := UpsertRuntimeReadiness(runtimeStateDir, rec); err != nil {
			return ProbeOutcome{}, err
		}
	} else {
		matchRec.Readiness.SSHReady = ready
		matchRec.Readiness.LastSSHProbeAt = nowStr
		matchRec.Readiness.SSHProbeStage = stage
		if ready {
			matchRec.Readiness.SSHReason = ""
			matchRec.Readiness.LastSuccessfulSSHProbeAt = nowStr
		} else {
			matchRec.Readiness.SSHReason = reason
		}
		doc.Targets[matchProfile] = matchRec
		if err := writeTargets(targetsDir, doc); err != nil {
			return ProbeOutcome{}, err
		}
	}

	out := ProbeOutcome{
		Ready:                   ready,
		Stage:                   stage,
		Reason:                  "",
		LastProbeAt:             nowStr,
		LastSuccessfulProbeAt:   lastSuccess,
		SSHKeyAlgorithm:         matchRec.SSH.KeyAlgorithm,
		SSHKeyBits:              matchRec.SSH.KeyBits,
		SSHKeyOrigin:            matchRec.SSH.KeyOrigin,
		SSHKeyFingerprintSHA256: matchRec.SSH.KeyFingerprintSHA256,
		SSHUsername:             matchRec.SSH.Username,
	}
	if !ready {
		out.Reason = reason
	}
	if fp, ferr := readKnownHostFingerprint(matchRec.SSH.KnownHostsPath, matchRec.Address); ferr == nil {
		out.SwitchHostKeyFingerprint = fp
	}
	return out, nil
}
