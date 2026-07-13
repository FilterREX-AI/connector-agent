// FilterREX Connector Host — SAN-only supported target types
//
// SOURCE for the public SAN-only distribution. The export pipeline copies
// this to the public repo as `supported_types_gen.go` (build-constraint lines
// stripped) so the public connector advertises only the SAN targets it can
// actually collect.
//
// Keep this limited to target types with a compiled public adapter. Today
// that is Brocade only; do not add cisco-mds/emulex here until a live adapter
// ships publicly, to avoid a capability/schema mismatch.

package main

// SupportedTargetTypes lists the target types the SAN-only host schema supports.
var SupportedTargetTypes = []string{
	"brocade",
}
