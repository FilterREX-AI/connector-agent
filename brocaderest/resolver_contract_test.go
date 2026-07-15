package brocaderest

import "testing"

// TestSwitchStatusOperationContract asserts the exact fixed catalog entry for
// brocade.switch.status. The FOS REST module name MUST include the
// "-switch" segment ("brocade-fibrechannel-switch"); preview.3 shipped the
// non-existent "brocade-fibrechannel" module and FOS answered every request
// with HTTP 400 Invalid REST URI. Keep this assertion as an exact string
// equality so the regression cannot recur silently.
func TestSwitchStatusOperationContract(t *testing.T) {
	op, err := Resolve("brocade.switch.status")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	const wantPath = "/rest/running/brocade-fibrechannel-switch/fibrechannel-switch"
	if op.PathTemplate != wantPath {
		t.Fatalf("unexpected PathTemplate: got %q, want %q", op.PathTemplate, wantPath)
	}
	if op.Method != "GET" {
		t.Fatalf("unexpected Method: got %q, want GET", op.Method)
	}
	if op.ID != "brocade.switch.status" {
		t.Fatalf("unexpected ID: got %q", op.ID)
	}
}
