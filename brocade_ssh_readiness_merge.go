// Brocade SSH readiness merge for the heartbeat capability manifest.
//
// The wizard/`target probe` path persists per-target SSH readiness into
// targets.json under the operator's --config-dir. The heartbeat needs to
// publish that alongside REST readiness (owned by BrocadeRESTReadinessSnapshot)
// under `capability_status.collect_brocade_evidence_bundle_v1.per_target`.
//
// This file is a pure function so it can be unit-tested without spinning up
// a supervisor. Ownership rules — enforced here:
//
//   - REST-owned fields (RESTReady, RESTReason, RESTSecurityState,
//     TLSPolicy, LastRESTErrorCode, LastRESTErrorAt) come ONLY from
//     restSnapshot and are never overwritten by SSH data.
//   - SSH-owned fields (SSHReady, SSHReason, SSHProbeStage, key metadata,
//     username, host-key fingerprint, LastProbeAt, LastSuccessfulProbeAt)
//     come ONLY from sshSnapshot.
//   - A target present in only one snapshot publishes only that side —
//     the other side stays zero-valued (never fabricated).
//   - Freshness is recomputed at publish time: a persisted SSHReady=true
//     whose LastSuccessfulProbeAt is older than sshFreshnessTTL flips to
//     SSHReady=false with reason `probe_stale`. LastSuccessfulProbeAt is
//     preserved so the app can still show the last verified time.
//   - LastProbeAt is passed through as-is (it is a fact about when the
//     probe last ran, independent of freshness).

package main

import (
	"time"

	"github.com/filterrex-ai/connector-agent/targetconfigure"
)

// sshFreshnessTTL mirrors src/components/toolchains/runchecks/lib/
// getRunChecksReadinessState.ts's RUN_CHECKS_STALE_MS (10 minutes). Kept
// slightly below the app's stale window so the connector reports stale
// before the RPC would otherwise trust an old success.
const sshFreshnessTTL = 10 * time.Minute

// mergeBrocadePerTargetReadiness combines REST and SSH readiness into a
// single per-target map. It is pure — time is injected — so tests never
// depend on wall-clock behavior.
func mergeBrocadePerTargetReadiness(
	restSnapshot map[string]PerTargetReadiness,
	sshSnapshot map[string]targetconfigure.SSHReadinessSnapshot,
	now time.Time,
) map[string]PerTargetReadiness {
	if len(restSnapshot) == 0 && len(sshSnapshot) == 0 {
		return nil
	}
	out := make(map[string]PerTargetReadiness, len(restSnapshot)+len(sshSnapshot))

	// REST-only fields flow in first.
	for id, r := range restSnapshot {
		out[id] = r
	}

	// SSH-only fields overlay onto whatever REST left for the same target.
	for id, s := range sshSnapshot {
		p := out[id] // zero value when REST had no entry — SSH-only publish
		p.SSHReady = s.SSHReady
		p.SSHReason = s.SSHReason
		p.SSHProbeStage = s.SSHProbeStage
		p.SSHKeyAlgorithm = s.SSHKeyAlgorithm
		p.SSHKeyBits = s.SSHKeyBits
		p.SSHKeyOrigin = s.SSHKeyOrigin
		p.SSHKeyFingerprintSHA256 = s.SSHKeyFingerprintSHA256
		p.SSHUsername = s.SSHUsername
		p.SwitchHostKeyFingerprintSHA256 = s.SwitchHostKeyFingerprint
		p.LastProbeAt = s.LastProbeAt
		p.LastSuccessfulProbeAt = s.LastSuccessfulProbeAt

		// Freshness recomputation: a persisted success older than the TTL
		// must flip to not-ready with `probe_stale`, without erasing the
		// last-successful timestamp (the app still surfaces it).
		if p.SSHReady && p.SSHProbeStage == "command_succeeded" {
			lastOK, ok := parseRFC3339(p.LastSuccessfulProbeAt)
			if !ok || now.Sub(lastOK) > sshFreshnessTTL {
				p.SSHReady = false
				if p.SSHReason == "" {
					p.SSHReason = "probe_stale"
				}
			}
		}

		out[id] = p
	}
	return out
}

func parseRFC3339(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
