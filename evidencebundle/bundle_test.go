package evidencebundle

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fixedTime(t *testing.T) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, "2026-07-12T23:30:24Z")
	if err != nil {
		t.Fatalf("parse fixed time: %v", err)
	}
	return ts
}

func unzip(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	out := make(map[string][]byte)
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open entry %s: %v", f.Name, err)
		}
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(rc); err != nil {
			t.Fatalf("read entry %s: %v", f.Name, err)
		}
		rc.Close()
		out[f.Name] = buf.Bytes()
	}
	return out
}

func readManifest(t *testing.T, entries map[string][]byte) Manifest {
	t.Helper()
	raw, ok := entries[BundleRoot+"/manifest.json"]
	if !ok {
		t.Fatal("manifest.json missing from bundle")
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	return m
}

// TestBuildEvidenceBundle_HappyPath covers the core contract: agent method,
// safe relative paths, sha256 correctness, per-file/bundle timestamps, and that
// supporting-only commands are packaged (not dropped, not marked in manifest).
func TestBuildEvidenceBundle_HappyPath(t *testing.T) {
	ct := fixedTime(t)
	captures := []CommandCapture{
		{SwitchName: "SW-A", FabricRole: "source", Command: "switchshow", Stdout: []byte("switchshow output\n"), ExitCode: 0, CollectedAt: ct},
		{SwitchName: "SW-A", FabricRole: "source", Command: "cfgshow", Stdout: []byte("cfgshow output\n"), ExitCode: 0, CollectedAt: ct},
		{SwitchName: "SW-A", FabricRole: "source", Command: "sfpshow -all", Stdout: []byte("sfp data\n"), ExitCode: 0, CollectedAt: ct},
	}
	res, err := BuildEvidenceBundle(captures, BuildOptions{CollectedAt: ct, CustomerSupplied: true})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	entries := unzip(t, res.Zip)
	m := readManifest(t, entries)

	if m.BundleVersion != "1.0" {
		t.Errorf("bundle_version = %q, want 1.0", m.BundleVersion)
	}
	if m.Vendor != Vendor {
		t.Errorf("vendor = %q, want %q", m.Vendor, Vendor)
	}
	if m.CollectionMethod != CollectionMethodAgent {
		t.Errorf("collection_method = %q, want agent", m.CollectionMethod)
	}
	if m.FabricRole != "source" {
		t.Errorf("fabric_role = %q, want source (derived)", m.FabricRole)
	}
	if m.CollectedAt != "2026-07-12T23:30:24Z" {
		t.Errorf("collected_at = %q", m.CollectedAt)
	}
	if len(m.Switches) != 1 || len(m.Switches[0].Files) != 3 {
		t.Fatalf("unexpected switch/file count: %+v", m.Switches)
	}

	for _, f := range m.Switches[0].Files {
		if isUnsafeBundlePath(f.Path) {
			t.Errorf("unsafe path emitted: %q", f.Path)
		}
		body, ok := entries[BundleRoot+"/"+f.Path]
		if !ok {
			t.Errorf("referenced file missing from zip: %q", f.Path)
			continue
		}
		sum := sha256.Sum256(body)
		if want := hex.EncodeToString(sum[:]); want != f.SHA256 {
			t.Errorf("sha256 mismatch for %q: manifest=%s actual=%s", f.Path, f.SHA256, want)
		}
		if f.CollectedAt != "2026-07-12T23:30:24Z" {
			t.Errorf("file collected_at = %q", f.CollectedAt)
		}
	}

	// Manifest must NOT carry support_level or generated_at (schema purity).
	if bytes.Contains(entries[BundleRoot+"/manifest.json"], []byte("support_level")) {
		t.Error("manifest must not contain support_level")
	}
	if bytes.Contains(entries[BundleRoot+"/manifest.json"], []byte("generated_at")) {
		t.Error("manifest must not contain generated_at")
	}
}

// TestBuildEvidenceBundle_ExcludesFailures ensures failed/empty/timed-out
// captures are logged but not written into the manifest or the ZIP.
func TestBuildEvidenceBundle_ExcludesFailures(t *testing.T) {
	ct := fixedTime(t)
	captures := []CommandCapture{
		{SwitchName: "SW-A", FabricRole: "target", Command: "switchshow", Stdout: []byte("ok\n"), ExitCode: 0, CollectedAt: ct},
		{SwitchName: "SW-A", FabricRole: "target", Command: "fabricshow", Stdout: []byte("nope\n"), ExitCode: 1, CollectedAt: ct},
		{SwitchName: "SW-A", FabricRole: "target", Command: "nsshow", Stdout: []byte(""), ExitCode: 0, CollectedAt: ct},
		{SwitchName: "SW-A", FabricRole: "target", Command: "cfgshow", Stdout: []byte("late\n"), TimedOut: true, ExitCode: 0, CollectedAt: ct},
	}
	res, err := BuildEvidenceBundle(captures, BuildOptions{CollectedAt: ct})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	m := readManifest(t, unzip(t, res.Zip))
	if len(m.Switches) != 1 || len(m.Switches[0].Files) != 1 {
		t.Fatalf("expected only 1 successful file, got %+v", m.Switches)
	}
	if m.Switches[0].Files[0].Command != "switchshow" {
		t.Errorf("unexpected surviving command %q", m.Switches[0].Files[0].Command)
	}
	if res.Summary.CommandsFailed != 3 {
		t.Errorf("commands_failed = %d, want 3", res.Summary.CommandsFailed)
	}
}

func TestBuildEvidenceBundle_UnknownCommandFails(t *testing.T) {
	_, err := BuildEvidenceBundle([]CommandCapture{
		{SwitchName: "SW-A", Command: "rm -rf", Stdout: []byte("x"), ExitCode: 0},
	}, BuildOptions{})
	if err == nil {
		t.Fatal("expected error for unknown command")
	}
}

func TestBuildEvidenceBundle_FilenameMismatchFails(t *testing.T) {
	_, err := BuildEvidenceBundle([]CommandCapture{
		{SwitchName: "SW-A", Command: "switchshow", Filename: "wrong.txt", Stdout: []byte("x"), ExitCode: 0},
	}, BuildOptions{})
	if err == nil {
		t.Fatal("expected filename mismatch error")
	}
}

func TestBuildEvidenceBundle_PathCollisionFailsClearly(t *testing.T) {
	// Two distinct switch names that sanitize to the same folder must fail,
	// never silently overwrite each other's evidence.
	_, err := BuildEvidenceBundle([]CommandCapture{
		{SwitchName: "DCX6/PROD-A", FabricRole: "source", Command: "switchshow", Stdout: []byte("a\n"), ExitCode: 0},
		{SwitchName: "DCX6 PROD-A", FabricRole: "source", Command: "switchshow", Stdout: []byte("b\n"), ExitCode: 0},
	}, BuildOptions{})
	if err == nil {
		t.Fatal("expected path collision error")
	}
}

func TestBuildEvidenceBundle_DuplicateCommandFails(t *testing.T) {
	_, err := BuildEvidenceBundle([]CommandCapture{
		{SwitchName: "SW-A", Command: "switchshow", Stdout: []byte("a\n"), ExitCode: 0},
		{SwitchName: "SW-A", Command: "switchshow", Stdout: []byte("b\n"), ExitCode: 0},
	}, BuildOptions{})
	if err == nil {
		t.Fatal("expected duplicate command error")
	}
}

// TestProfileParity guards against drift between the Go-embedded command profile
// and the canonical collectors/brocade copy. Skips in split-repo checkouts.
func TestProfileParity(t *testing.T) {
	canonical := filepath.Join("..", "..", "collectors", "brocade", "brocade_command_profile.json")
	data, err := os.ReadFile(canonical)
	if err != nil {
		t.Skipf("canonical profile not available (%v); embedded-only check", err)
	}
	if !bytes.Equal(data, EmbeddedProfileJSON()) {
		t.Errorf("embedded profile != %s — copy the canonical file to keep producers aligned", canonical)
	}
}

// TestDirectoryFixtureReproducible builds the committed agent fixture from
// testdata and asserts it is a valid v1.0 agent bundle. When UPDATE_AGENT_FIXTURE
// is set it (re)writes the committed TS fixture so the Go producer is the source
// of truth for the TS conformance harness.
func TestDirectoryFixtureReproducible(t *testing.T) {
	inv, err := LoadInventory(filepath.Join("testdata", "inventory.json"))
	if err != nil {
		t.Fatalf("load inventory: %v", err)
	}
	res, err := BuildFromDirectory(filepath.Join("testdata", "input"), inv, CollectionMethodAgent)
	if err != nil {
		t.Fatalf("build from dir: %v", err)
	}
	m := readManifest(t, unzip(t, res.Zip))
	if m.CollectionMethod != CollectionMethodAgent {
		t.Errorf("collection_method = %q", m.CollectionMethod)
	}
	if len(m.Switches) != 2 {
		t.Fatalf("expected 2 switches, got %d", len(m.Switches))
	}
	if os.Getenv("UPDATE_AGENT_FIXTURE") != "" {
		out := filepath.Join("..", "..", "src", "lib", "evidenceBundle", "__tests__", "fixtures", "brocade-valid-agent-output.zip")
		if err := os.WriteFile(out, res.Zip, 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		t.Logf("updated %s", out)
	}
}
