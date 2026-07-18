// preview.22 — collection-safe target projection.
//
// Historically the connector had two Brocade sources of truth:
//
//   * targets.json (wizard + `target probe`)      — used by the readiness
//     heartbeat and remote SSH probes.
//   * /etc/filterrex/brocade-export.json (legacy) — used by the agent
//     evidence collection path.
//
// Nothing wrote the legacy file after preview.13, so every server-dispatched
// collection failed with `credential_profile_missing` even when the operator
// had proven SSH via the wizard.
//
// This file exposes the ONE public entry point the collection path uses to
// resolve a target and its effective SSH readiness state — identical to the
// data the heartbeat/probe path consumes. No `targetRecord` leaks out; only
// a bounded, secret-free projection.
package targetconfigure

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// ReadinessFreshWindow is the maximum age of a successful SSH probe that
// the agent will accept as authorization for a server-initiated collection.
// Kept comfortably shorter than the app-side capability freshness window
// so an operator refresh always beats an about-to-expire heartbeat.
const ReadinessFreshWindow = 15 * time.Minute

// SSH readiness gate codes returned by LoadResolvedBrocadeTarget. These are
// stable, secret-free, and mirror the fixed vocabulary shipped to the
// control plane (`agent_evidence_wiring.go` maps them 1:1 to the public
// error code allowlist in `agentevidence/handler.go`).
var (
	ErrSSHSetupPending = errors.New("ssh_setup_pending")
	ErrSSHProbeStale   = errors.New("ssh_probe_stale")
	ErrSSHNotReady     = errors.New("ssh_not_ready")
)

// ResolvedBrocadeTarget is the exact, artifact-resolved projection of one
// targets.json record that the collection path needs — no more, no less.
// Every path is already translated to a daemon-absolute location via
// ResolveManagedTargetArtifact; the caller may open them directly.
type ResolvedBrocadeTarget struct {
	// Identity
	TargetID    string // canonical lowercase application UUID
	ProfileName string // outer targets.json map key (operator label)

	// Network
	Host    string
	SSHPort int

	// SSH identity + artifacts (absolute paths, ready to open).
	SSHUsername    string
	PrivateKeyPath string
	KnownHostsPath string

	// Key metadata (for audit; never used to authorize).
	KeyAlgorithm         string
	KeyBits              int
	KeyOrigin            string
	KeyFingerprintSHA256 string
}

// EffectiveSSHReadiness carries just enough state for the collection path to
// decide "safe to launch SSH now?". It merges the immutable record with the
// runtime-state sidecar, exactly as the heartbeat loader does, then applies
// the freshness window.
type EffectiveSSHReadiness struct {
	Ready                 bool
	Stage                 string // ssh_probe_stage vocabulary
	Reason                string // bounded vocabulary; "" when Ready
	LastProbeAt           string // RFC3339, may be ""
	LastSuccessfulProbeAt string // RFC3339, may be ""
	Fresh                 bool   // last successful probe is within ReadinessFreshWindow
	ConfigFingerprint     string // fingerprint of the record used for the decision
}

// LoadResolvedBrocadeTarget is the ONE loader the collection path consumes.
// It never opens key material and never runs SSH; it resolves identity,
// artifact paths, and effective readiness state and returns them.
//
// Errors are returned as sentinels from the fixed vocabulary so the caller
// can map them directly to public error codes. Any unexpected filesystem or
// parse condition surfaces as ErrTargetConfigUnreadable.
func LoadResolvedBrocadeTarget(targetsDir, runtimeStateDir, targetID string) (ResolvedBrocadeTarget, EffectiveSSHReadiness, error) {
	inv := InspectTargetConfigForTarget(targetsDir, targetID)
	if inv.TargetID == "" {
		return ResolvedBrocadeTarget{}, EffectiveSSHReadiness{}, ErrInvalidTargetID
	}
	switch inv.Status {
	case TargetConfigMissing:
		return ResolvedBrocadeTarget{}, EffectiveSSHReadiness{}, ErrTargetConfigMissing
	case TargetConfigUnreadable:
		return ResolvedBrocadeTarget{}, EffectiveSSHReadiness{}, ErrTargetConfigUnreadable
	}
	switch inv.ResolvedStatus {
	case TargetConfigNoTarget:
		return ResolvedBrocadeTarget{}, EffectiveSSHReadiness{}, ErrTargetNotConfigured
	case TargetConfigDuplicate:
		return ResolvedBrocadeTarget{}, EffectiveSSHReadiness{}, ErrDuplicateTargetID
	case TargetConfigKeyMissing:
		return ResolvedBrocadeTarget{}, EffectiveSSHReadiness{}, errors.New("ssh_key_missing")
	case TargetConfigKeyUnreadable:
		return ResolvedBrocadeTarget{}, EffectiveSSHReadiness{}, errors.New("ssh_key_unreadable")
	case TargetConfigKnownHostsMissing:
		return ResolvedBrocadeTarget{}, EffectiveSSHReadiness{}, errors.New("known_hosts_missing")
	case TargetConfigHostKeyMissing:
		return ResolvedBrocadeTarget{}, EffectiveSSHReadiness{}, errors.New("known_hosts_missing")
	case TargetConfigUnmanagedArtifact:
		return ResolvedBrocadeTarget{}, EffectiveSSHReadiness{}, errors.New("target_configuration_invalid")
	}
	if inv.ResolvedStatus != TargetConfigOK {
		return ResolvedBrocadeTarget{}, EffectiveSSHReadiness{}, fmt.Errorf("%s", inv.ResolvedStatus)
	}

	// Re-load the record to pull identity fields + readiness overlay.
	doc, err := loadTargets(targetsDir)
	if err != nil || doc == nil {
		return ResolvedBrocadeTarget{}, EffectiveSSHReadiness{}, ErrTargetConfigUnreadable
	}

	var (
		matchProfile string
		matchRec     *targetRecord
		matchCount   int
	)
	for profileName, rec := range doc.Targets {
		id, rerr := EffectiveTargetID(profileName, rec)
		if rerr != nil || id != inv.TargetID {
			continue
		}
		matchCount++
		matchProfile = profileName
		matchRec = rec
	}
	if matchCount == 0 {
		return ResolvedBrocadeTarget{}, EffectiveSSHReadiness{}, ErrTargetNotConfigured
	}
	if matchCount > 1 {
		return ResolvedBrocadeTarget{}, EffectiveSSHReadiness{}, ErrDuplicateTargetID
	}
	if matchRec == nil || matchRec.SSH == nil {
		return ResolvedBrocadeTarget{}, EffectiveSSHReadiness{}, errors.New("ssh_key_missing")
	}

	privateKeyPath, kerr := ResolveManagedTargetArtifact(targetsDir, matchRec.SSH.KeyPath, ArtifactSSHPrivateKey)
	if kerr != nil {
		return ResolvedBrocadeTarget{}, EffectiveSSHReadiness{}, errors.New("ssh_key_missing")
	}
	knownHostsPath, khErr := ResolveManagedTargetArtifact(targetsDir, matchRec.SSH.KnownHostsPath, ArtifactKnownHosts)
	if khErr != nil {
		return ResolvedBrocadeTarget{}, EffectiveSSHReadiness{}, errors.New("known_hosts_missing")
	}

	resolved := ResolvedBrocadeTarget{
		TargetID:             inv.TargetID,
		ProfileName:          matchProfile,
		Host:                 strings.TrimSpace(matchRec.Address),
		SSHPort:              matchRec.SSHPort,
		SSHUsername:          matchRec.SSH.Username,
		PrivateKeyPath:       privateKeyPath,
		KnownHostsPath:       knownHostsPath,
		KeyAlgorithm:         matchRec.SSH.KeyAlgorithm,
		KeyBits:              matchRec.SSH.KeyBits,
		KeyOrigin:            matchRec.SSH.KeyOrigin,
		KeyFingerprintSHA256: matchRec.SSH.KeyFingerprintSHA256,
	}

	readiness := effectiveReadinessFromRecord(targetsDir, runtimeStateDir, inv.TargetID, matchRec)
	return resolved, readiness, nil
}

// effectiveReadinessFromRecord mirrors LoadSSHReadinessSnapshotWithRuntime
// but without the map/warning overhead — we already have the single record.
func effectiveReadinessFromRecord(targetsDir, runtimeStateDir, targetID string, rec *targetRecord) EffectiveSSHReadiness {
	out := EffectiveSSHReadiness{
		Ready:                 rec.Readiness.SSHReady,
		Stage:                 rec.Readiness.SSHProbeStage,
		Reason:                rec.Readiness.SSHReason,
		LastProbeAt:           rec.Readiness.LastSSHProbeAt,
		LastSuccessfulProbeAt: rec.Readiness.LastSuccessfulSSHProbeAt,
		ConfigFingerprint:     ConfigFingerprintFromRecord(targetsDir, rec),
	}
	if runtimeStateDir != "" {
		if sidecar, err := LoadRuntimeReadiness(runtimeStateDir); err == nil {
			if entry, ok := sidecar[targetID]; ok {
				if entry.ConfigFingerprint == out.ConfigFingerprint {
					out.Ready = entry.SSHReady
					out.Reason = entry.SSHReason
					out.Stage = entry.SSHProbeStage
					if entry.LastProbeAt != "" {
						out.LastProbeAt = entry.LastProbeAt
					}
					if entry.LastSuccessfulProbeAt != "" {
						out.LastSuccessfulProbeAt = entry.LastSuccessfulProbeAt
					}
				}
			}
		}
	}
	out.Fresh = readinessFresh(out.LastSuccessfulProbeAt, time.Now().UTC(), ReadinessFreshWindow)
	return out
}

func readinessFresh(lastSuccessAt string, now time.Time, window time.Duration) bool {
	if strings.TrimSpace(lastSuccessAt) == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, lastSuccessAt)
	if err != nil {
		return false
	}
	return now.Sub(t.UTC()) <= window
}

// ReadinessGateError returns the sentinel that best describes an
// EffectiveSSHReadiness that is not authorized to launch SSH. Returns nil
// when the readiness is fresh, ready, and successful.
func ReadinessGateError(r EffectiveSSHReadiness) error {
	if r.Ready && r.Fresh {
		return nil
	}
	if strings.TrimSpace(r.LastSuccessfulProbeAt) == "" {
		return ErrSSHSetupPending
	}
	if !r.Fresh {
		return ErrSSHProbeStale
	}
	if !r.Ready {
		return ErrSSHNotReady
	}
	return nil
}
