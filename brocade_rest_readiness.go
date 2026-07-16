// FilterREX Connector Host — Brocade REST readiness registry.
//
// Records per-target REST verification results from the Brocade adapter and
// exposes them for inclusion in the heartbeat capability manifest under
// `capability_status.collect_brocade_evidence_bundle_v1.per_target`.
//
// The control-plane RPC `authorize_brocade_live_query` requires
// `per_target.<uuid>.rest_ready = true` and freshness stamped by the DB
// trigger `stamp_capability_status_reported_at`. This registry supplies the
// former; the trigger supplies the latter.
//
// Invariants:
//   - Never stores raw response bodies, credentials, IP addresses, or
//     certificate contents. Only stable machine codes and short reasons.
//   - Never sets `reported_at`. That field is server-owned.
//   - A prior success is republished as ready ONLY while it is within the
//     local TTL. Beyond that, `RESTReady` flips to false with reason
//     `rest_readiness_stale`, so an idle connector cannot renew stale
//     freshness merely by sending heartbeats.
//   - Callers may `Delete` a target so removed / disabled / non-Brocade /
//     LAN-only targets do not leak prior readiness.

package main

import (
	"sync"
	"time"
)

// brocadeRESTReadinessTTL is the local expiry for a successful REST probe.
// Kept comfortably below the RPC freshness window (10 minutes) so a target
// that stops probing is reported not-ready well before the server would
// otherwise consider its heartbeat-stamped `reported_at` still valid.
const brocadeRESTReadinessTTL = 5 * time.Minute

type brocadeRESTObservation struct {
	// Readiness is the last observation, ready or not. Copied into the
	// heartbeat snapshot verbatim (subject to TTL expiry below).
	Readiness PerTargetReadiness
	// LastOKAt is the time of the most recent successful REST probe. Zero
	// means no success has ever been observed for this target.
	LastOKAt time.Time
}

// BrocadeRESTReadinessRegistry is a thread-safe map of per-target REST
// observations. It is intentionally an addressable value type (not a
// package-level global) so tests, reconciliation, and future per-supervisor
// ownership all work without hidden shared state.
type BrocadeRESTReadinessRegistry struct {
	mu           sync.RWMutex
	observations map[string]brocadeRESTObservation
	now          func() time.Time
}

// NewBrocadeRESTReadinessRegistry returns an empty registry using the real
// clock. Tests may replace `now` after construction.
func NewBrocadeRESTReadinessRegistry() *BrocadeRESTReadinessRegistry {
	return &BrocadeRESTReadinessRegistry{
		observations: make(map[string]brocadeRESTObservation),
		now:          time.Now,
	}
}

// RecordSuccess marks the target as REST-ready. Clears any prior error.
// `securityState` and `tlsPolicy` are diagnostic — the authorization RPC
// only reads `rest_ready` and the server-stamped `reported_at`.
func (r *BrocadeRESTReadinessRegistry) RecordSuccess(
	targetProfileID, securityState, tlsPolicy string,
) {
	if targetProfileID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observations[targetProfileID] = brocadeRESTObservation{
		Readiness: PerTargetReadiness{
			RESTReady:         true,
			RESTSecurityState: securityState,
			TLSPolicy:         tlsPolicy,
		},
		LastOKAt: r.now(),
	}
}

// RecordFailure marks the target as not REST-ready. `code` must be a stable
// sanitized identifier (e.g. rest_auth_failed, rest_tls_handshake_failed).
// `reason` is a short non-secret hint safe to log — never a raw error body.
func (r *BrocadeRESTReadinessRegistry) RecordFailure(
	targetProfileID, code, reason string,
) {
	if targetProfileID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	prev := r.observations[targetProfileID]
	r.observations[targetProfileID] = brocadeRESTObservation{
		Readiness: PerTargetReadiness{
			RESTReady:         false,
			RESTReason:        reason,
			RESTSecurityState: prev.Readiness.RESTSecurityState,
			TLSPolicy:         prev.Readiness.TLSPolicy,
			LastRESTErrorCode: code,
			LastRESTErrorAt:   r.now().UTC().Format(time.RFC3339),
		},
		LastOKAt: prev.LastOKAt, // preserve for diagnostics only; TTL still applies
	}
}

// Delete removes a target — called by reconciliation when a target is
// removed, disabled, changes target type, or moves connector.
func (r *BrocadeRESTReadinessRegistry) Delete(targetProfileID string) {
	if targetProfileID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.observations, targetProfileID)
}

// Snapshot returns a copy of the current per-target readiness suitable for
// inclusion in a heartbeat. Applies the local TTL: a prior `RESTReady=true`
// that has not been refreshed within `brocadeRESTReadinessTTL` flips to
// false with reason `rest_readiness_stale`. This prevents an old success
// from being renewed indefinitely by unrelated heartbeats.
func (r *BrocadeRESTReadinessRegistry) Snapshot() map[string]PerTargetReadiness {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.observations) == 0 {
		return nil
	}
	now := r.now()
	out := make(map[string]PerTargetReadiness, len(r.observations))
	for id, obs := range r.observations {
		readiness := obs.Readiness
		if readiness.RESTReady {
			if obs.LastOKAt.IsZero() || now.Sub(obs.LastOKAt) > brocadeRESTReadinessTTL {
				readiness.RESTReady = false
				if readiness.RESTReason == "" {
					readiness.RESTReason = "rest_readiness_stale"
				}
				if readiness.LastRESTErrorCode == "" {
					readiness.LastRESTErrorCode = "rest_readiness_stale"
				}
			}
		}
		out[id] = readiness
	}
	return out
}

// resetForTest wipes all observations. Kept unexported; only tests use it.
func (r *BrocadeRESTReadinessRegistry) resetForTest() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observations = make(map[string]brocadeRESTObservation)
}

// ── Package-level singleton bridge ─────────────────────────────────────────
//
// The Brocade adapter is instantiated per worker without a supervisor handle,
// so the simplest safe wiring is a package-level registry the adapter records
// into and the supervisor reads from. Kept minimal: instance ownership +
// explicit Delete keep test isolation and reconciliation cleanup correct.

var brocadeRESTReadiness = NewBrocadeRESTReadinessRegistry()

// BrocadeRESTReadinessSnapshot returns the current registry snapshot for
// inclusion in the heartbeat capability manifest.
func BrocadeRESTReadinessSnapshot() map[string]PerTargetReadiness {
	return brocadeRESTReadiness.Snapshot()
}

// DeleteBrocadeRESTReadiness clears a target from the registry.
func DeleteBrocadeRESTReadiness(targetProfileID string) {
	brocadeRESTReadiness.Delete(targetProfileID)
}

// brocadeRESTSecurityState derives the per-target `rest_security_state`
// value from the actual transport chosen for a Brocade REST target.
//
// The compatibility TLS policy (`fos82-legacy`) does NOT weaken the security
// posture on its own — certificate and hostname verification remain on
// unless `InsecureSkipVerify` is explicitly set. This function reflects that.
func brocadeRESTSecurityState(baseURL string, insecureSkipVerify bool) string {
	if len(baseURL) >= 7 && baseURL[:7] == "http://" {
		return "lab_http_cleartext"
	}
	if insecureSkipVerify {
		return "lab_tls_unverified"
	}
	return "production_verified"
}
