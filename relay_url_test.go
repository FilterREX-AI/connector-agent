// FilterREX Connector Host — Relay URL Unit Tests (SAN-safe)
//
// Vendor-free regression tests that ship in every build, including the
// SAN-only public distribution. Vendor-specific relay tests live in
// relay_test.go (build tag !sanonly).

package main

import "testing"

func TestJoinURLPublic_Basic(t *testing.T) {
	cases := []struct {
		base, path, want string
	}{
		{"https://switch.local", "/rest/running/brocade-chassis/chassis", "https://switch.local/rest/running/brocade-chassis/chassis"},
		{"https://switch.local/", "/rest/running/brocade-chassis/chassis", "https://switch.local/rest/running/brocade-chassis/chassis"},
		{"https://switch.local", "rest/running/brocade-fabric/fabric", "https://switch.local/rest/running/brocade-fabric/fabric"},
		{"https://switch.local/", "", "https://switch.local"},
	}
	for _, c := range cases {
		if got := joinURL(c.base, c.path); got != c.want {
			t.Errorf("joinURL(%q, %q) = %q, want %q", c.base, c.path, got, c.want)
		}
	}
}
