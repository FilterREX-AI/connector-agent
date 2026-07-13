// Package brocadecli is the FilterREX agent's read-only Brocade SSH capture
// module (Phase 3B-2).
//
// It answers exactly one question: how does the agent obtain raw Brocade CLI
// text safely? It SSHes to one or more Brocade switches, runs ONLY the commands
// declared in the embedded read-only command profile
// (evidencebundle.ProfileCommands), captures raw stdout/stderr/exit/timing, and
// converts successful captures into []evidencebundle.CommandCapture that the
// existing evidencebundle.BuildEvidenceBundle writer packages into an Evidence
// Bundle v1.0 ZIP (collection_method: "agent").
//
// Deliberate boundaries (Phase 3B-2):
//   - No public API accepts a free-form command string. The command set is
//     derived internally from the embedded profile only.
//   - No relay call, local-API endpoint, /v1/execute wiring, or cloud-triggered
//     export. This module is internal and exercised only by Go tests here.
//   - No virtual-fabric context switching. FID is recorded as manifest metadata
//     only; FID-aware command execution is deferred.
//   - Non-interactive key-based SSH only — no password or keyboard-interactive
//     auth path exists. Host-key verification is required (KnownHostsPath).
package brocadecli

// FID is recorded as metadata only in 3B-2. FID-aware command execution
// (setcontext / fosexec / VF selection) is deferred to a later phase.

// BrocadeTarget describes a single read-only Brocade switch to capture from.
type BrocadeTarget struct {
	SwitchName string // human-facing switch name (manifest identity + grouping)
	Host       string // hostname or IP
	Username   string // SSH username
	FabricRole string // "source" | "target" | "" (unknown)
	FID        *int   // recorded as manifest metadata ONLY; no VF context switch
	SSHKeyPath string // path to a private key file (key-based auth only)
	PortRange  string // optional; overrides the profile default port range
	Notes      string // free-form note recorded in manifest metadata
}
