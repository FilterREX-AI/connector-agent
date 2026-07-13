package brocadecli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/filterrex-ai/connector-agent/evidencebundle"
)

// dirBackedRunner is a fake runner that returns the exact captured command
// output committed under evidencebundle/testdata/input — the same fixtures the
// deterministic directory producer (and thus the TS conformance fixture) uses.
// It proves the SSH-capture code path yields the identical evidence artifact,
// without needing a real switch.
type dirBackedRunner struct {
	inputDir     string
	execFilename map[string]string // resolved exec -> canonical filename
	roleByName   map[string]string
}

func newDirBackedRunner(t *testing.T, inputDir string, roleByName map[string]string) *dirBackedRunner {
	t.Helper()
	profile, err := evidencebundle.ProfileCommands()
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	pr := evidencebundle.DefaultPortRange()
	m := map[string]string{}
	for _, pc := range profile {
		exec := pc.Exec
		if pr != "" {
			exec = replaceAll(exec, "{port_range}", pr)
		}
		m[exec] = pc.Filename
	}
	return &dirBackedRunner{inputDir: inputDir, execFilename: m, roleByName: roleByName}
}

func replaceAll(s, old, new string) string {
	out := ""
	for {
		i := indexOf(s, old)
		if i < 0 {
			return out + s
		}
		out += s[:i] + new
		s = s[i+len(old):]
	}
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func (d *dirBackedRunner) Run(_ context.Context, target BrocadeTarget, exec string) CommandResult {
	res := CommandResult{Started: time.Unix(0, 0).UTC()}
	filename, ok := d.execFilename[exec]
	if !ok {
		res.ExitCode = 127
		return res
	}
	role := d.roleByName[target.SwitchName]
	path := filepath.Join(d.inputDir, role, target.SwitchName, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		// Not captured for this switch — mirror the directory producer, which
		// simply omits absent files.
		res.ExitCode = 127
		return res
	}
	res.ExitCode = 0
	res.Stdout = data
	return res
}

// TestCollector_MatchesDirectoryProducer proves the capture path produces the
// same evidence manifest (switches, files, commands, sha256) as the directory
// producer that generates the committed TS conformance fixture. Same manifest +
// same file bytes ⇒ the capture-produced bundle passes the identical TS consumer
// chain the fixture already satisfies.
func TestCollector_MatchesDirectoryProducer(t *testing.T) {
	inputDir := filepath.Join("..", "evidencebundle", "testdata", "input")
	invPath := filepath.Join("..", "evidencebundle", "testdata", "inventory.json")

	inv, err := evidencebundle.LoadInventory(invPath)
	if err != nil {
		t.Fatalf("load inventory: %v", err)
	}
	dirRes, err := evidencebundle.BuildFromDirectory(inputDir, inv, evidencebundle.CollectionMethodAgent)
	if err != nil {
		t.Fatalf("BuildFromDirectory: %v", err)
	}

	collectedAt, _ := time.Parse(time.RFC3339, inv.CollectedAt)
	roleByName := map[string]string{}
	targets := make([]BrocadeTarget, 0, len(inv.Switches))
	for _, s := range inv.Switches {
		role := s.FabricRole
		if role == "" {
			role = inv.FabricRole
		}
		roleByName[s.SwitchName] = role
		targets = append(targets, BrocadeTarget{
			SwitchName: s.SwitchName,
			Host:       "10.0.0.1",
			Username:   "readonly",
			FabricRole: role,
			FID:        s.FID,
			Notes:      s.Notes,
		})
	}

	runner := newDirBackedRunner(t, inputDir, roleByName)
	capRes, _, err := CollectBundle(context.Background(), runner, targets, CollectOptions{
		CollectedAt: collectedAt.UTC(),
	})
	if err != nil {
		t.Fatalf("CollectBundle: %v", err)
	}

	// customer_supplied is a provenance flag, not evidence: the directory
	// producer marks the fixture customer-supplied, the agent capture path does
	// not. Normalize it so the comparison is purely about captured evidence
	// (switches, files, commands, sha256).
	dirM := dirRes.Manifest
	capM := capRes.Manifest
	dirM.CustomerSupplied = false
	capM.CustomerSupplied = false

	dirJSON, _ := json.Marshal(dirM)
	capJSON, _ := json.Marshal(capM)
	if string(dirJSON) != string(capJSON) {
		t.Fatalf("capture manifest differs from directory producer:\n dir: %s\n cap: %s", dirJSON, capJSON)
	}
}
