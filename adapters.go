// FilterREX Connector Host — SAN-only adapter registration
//
// This is the SOURCE for the public SAN-only distribution. The export
// pipeline (scripts/export-connector-public.sh) copies this file to the
// public repo as `adapters.go`, stripping the build-constraint lines so it
// compiles with a plain `go build .` (no tags).
//
// In the private repo it is compiled only under `-tags sanonly`, which lets
// CI verify the SAN-only wiring builds without shipping the full adapter set.
//
// Keep this file limited to Brocade — it is the only live collector the
// public FilterREX SAN connector is meant to advertise or contain.

package main

// registerAdapters wires only the read-only Brocade SAN adapter.
func registerAdapters(supervisor *Supervisor) {
	supervisor.RegisterAdapter("brocade", NewBrocadeAdapter)
}
