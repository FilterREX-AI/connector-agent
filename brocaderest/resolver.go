// Package brocaderest is the connector-side HTTPS REST client for Brocade FC
// switches used by the Workbench live-query path.
//
// Preview.3 scaffold: this package defines the public surface (types + fixed
// operation resolver) that the rest of the connector will call. The wire
// implementation (`http.Client` with per-target `transport_mode`, on-demand
// password read from `password_file`, sanitized error mapping, structured
// audit) lands in a follow-up commit within the same preview.3 milestone.
//
// Non-negotiable invariants this package is designed around:
//
//   - The REST password is read from its `0600` file at request time and never
//     serialized, logged, sent to FilterREX, or retained in configuration
//     objects longer than required for authentication.
//   - Only Brocade operations registered in the resolver below can execute.
//     The browser sends {target_profile_id, operation_id, parameters{}} only;
//     it cannot supply a raw URL, raw REST path, Authorization header,
//     arbitrary CLI command, transport override, or credential selector.
//   - Transport policy is chosen by the connector, not the caller:
//     https-verified (default) or http-lab-only (requires FILTERREX_LAB_MODE=1
//     on the host). Preview.3 defers https-pinned until SPKI pinning + planned
//     rotation are implemented.
//
// See docs/brocade-target-two-path-auth.md and
// connector-agent/RELEASE-v0.1.0-preview.3.md.
package brocaderest

import (
	"errors"
	"fmt"
)

// TransportMode is the connector-chosen transport policy for a REST target.
type TransportMode string

const (
	TransportHTTPSVerified TransportMode = "https-verified"
	TransportHTTPLabOnly   TransportMode = "http-lab-only"
)

// SecurityState is reported in the heartbeat alongside rest_ready and is kept
// deliberately separate from readiness. A target can be operationally ready
// while advertising a weak security posture.
type SecurityState string

const (
	SecurityProductionVerified SecurityState = "production_verified"
	SecurityCertificatePinned  SecurityState = "certificate_pinned"
	SecurityLabTLSUnverified   SecurityState = "lab_tls_unverified"
	SecurityLabHTTPCleartext   SecurityState = "lab_http_cleartext"
)

// Operation is one allowlisted, parameter-schema-bound REST call. The resolver
// is the only bridge between a browser-supplied operation_id and an actual
// URL/method/body — there is no fallback path.
type Operation struct {
	ID            string
	Method        string // GET | POST (read-only path only)
	PathTemplate  string // e.g. "/rest/running/brocade-fibrechannel-switch/fibrechannel-switch"
	AllowedParams map[string]ParamSchema
	Description   string
}

// ParamSchema describes a single allowlisted parameter for an Operation.
type ParamSchema struct {
	Type     string // "string" | "int" | "bool"
	Required bool
	Pattern  string // optional regex; empty means any value of Type
	Max      int    // optional length/value cap
}

// operations is the fixed allowlist. Additions require a code change and
// review; nothing here can be extended at runtime by a request.
var operations = map[string]Operation{
	"brocade.switch.status": {
		ID:           "brocade.switch.status",
		Method:       "GET",
		PathTemplate: "/rest/running/brocade-fibrechannel-switch/fibrechannel-switch",
		Description:  "Read-only switch identity + state.",
	},
	"brocade.fabric.show": {
		ID:           "brocade.fabric.show",
		Method:       "GET",
		PathTemplate: "/rest/running/brocade-fabric/fabric-switch",
		Description:  "Read-only fabric membership snapshot.",
	},
	// Additional read-only operations land here alongside the corresponding
	// SSH command-profile entries; the two paths never carry different
	// authority for the same logical query.
}

// ErrUnknownOperation is returned when a caller (ultimately the browser)
// references an operation_id that is not in the resolver.
var ErrUnknownOperation = errors.New("brocaderest: unknown operation")

// Resolve returns the fixed Operation entry for id, or ErrUnknownOperation.
// It never accepts a raw path.
func Resolve(id string) (Operation, error) {
	op, ok := operations[id]
	if !ok {
		return Operation{}, fmt.Errorf("%w: %q", ErrUnknownOperation, id)
	}
	return op, nil
}

// KnownOperationIDs returns the sorted set of registered operation IDs. Used
// by the no-secret-scan harness and by capability advertisement.
func KnownOperationIDs() []string {
	out := make([]string, 0, len(operations))
	for id := range operations {
		out = append(out, id)
	}
	return out
}
