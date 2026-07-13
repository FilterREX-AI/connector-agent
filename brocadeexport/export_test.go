package brocadeexport

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/filterrex-ai/connector-agent/brocadecli"
)

// fakeRunner returns canned successful output for every profile command, except
// for a set of (host, exec-substring) pairs configured to fail.
type fakeRunner struct {
	failOnExecSubstr map[string]bool // exec substring → fail
}

func (f *fakeRunner) Run(_ context.Context, target brocadecli.BrocadeTarget, exec string) brocadecli.CommandResult {
	for sub := range f.failOnExecSubstr {
		if strings.Contains(exec, sub) {
			return brocadecli.CommandResult{
				Stdout:   nil,
				Stderr:   []byte("command failed"),
				ExitCode: 1,
			}
		}
	}
	return brocadecli.CommandResult{
		Stdout:   []byte("raw output for " + target.SwitchName + ": " + exec + "\n"),
		ExitCode: 0,
	}
}

func fid(v int) *int { return &v }

func baseConfig(t *testing.T) *ExportConfig {
	t.Helper()
	dir := t.TempDir()
	artifacts := filepath.Join(dir, "artifacts")
	return &ExportConfig{
		Enabled:                  true,
		ArtifactDir:              artifacts,
		KnownHostsPath:           filepath.Join(dir, "known_hosts"),
		AllowInsecureArtifactDir: true, // TempDir lives under a temp root
		Targets: []TargetConfig{
			{SwitchName: "DCX6-PROD-A", Host: "10.10.10.21", Username: "readonly", SSHKeyPath: "/opt/keys/ro", FabricRole: "source", FID: fid(128)},
			{SwitchName: "DCX6-PROD-B", Host: "10.10.10.22", Username: "readonly", SSHKeyPath: "/opt/keys/ro", FabricRole: "target", FID: fid(128)},
		},
	}
}

func TestRunExport_HappyPath(t *testing.T) {
	cfg := baseConfig(t)
	res, err := RunExport(context.Background(), cfg, &fakeRunner{}, RequestMeta{
		RequesterType: "local_cli", Requester: "test", ConfigPath: "/etc/filterrex/x.json",
	})
	if err != nil {
		t.Fatalf("RunExport: %v", err)
	}
	if !res.OK || res.ArtifactType != "evidence_bundle" || res.Vendor != "brocade-fos" || res.CollectionMethod != "agent" {
		t.Fatalf("unexpected metadata: %+v", res)
	}
	if res.Switches != 2 {
		t.Fatalf("switches = %d, want 2", res.Switches)
	}
	if res.ParsedFiles == 0 {
		t.Fatalf("parsed_files should be > 0, got %d", res.ParsedFiles)
	}
	if res.Warnings != 0 {
		t.Fatalf("warnings = %d, want 0", res.Warnings)
	}
	if len(res.SHA256) != 64 {
		t.Fatalf("sha256 length = %d, want 64", len(res.SHA256))
	}
	// The ZIP exists, is timestamped, and is 0600.
	if !strings.HasPrefix(filepath.Base(res.Path), "filterrex-agent-evidence-bundle-") {
		t.Fatalf("artifact name not timestamped: %s", res.Path)
	}
	info, err := os.Stat(res.Path)
	if err != nil {
		t.Fatalf("stat artifact: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("artifact perm = %o, want 0600", info.Mode().Perm())
	}
	// Audit log exists and is 0600.
	auditPath := filepath.Join(cfg.EffectiveArtifactDir(), AuditLogName)
	ainfo, err := os.Stat(auditPath)
	if err != nil {
		t.Fatalf("stat audit log: %v", err)
	}
	if ainfo.Mode().Perm() != 0600 {
		t.Fatalf("audit perm = %o, want 0600", ainfo.Mode().Perm())
	}
	// Artifact dir is 0700.
	dinfo, _ := os.Stat(cfg.EffectiveArtifactDir())
	if dinfo.Mode().Perm() != 0700 {
		t.Fatalf("artifact dir perm = %o, want 0700", dinfo.Mode().Perm())
	}
}

func TestRunExport_CapabilityGateOff(t *testing.T) {
	cfg := baseConfig(t)
	cfg.Enabled = false
	_, err := RunExport(context.Background(), cfg, &fakeRunner{}, RequestMeta{})
	if !errors.Is(err, ErrCapabilityDisabled) {
		t.Fatalf("expected ErrCapabilityDisabled, got %v", err)
	}
	// Nothing should have been written.
	if entries, _ := os.ReadDir(cfg.EffectiveArtifactDir()); len(entries) != 0 {
		t.Fatalf("artifact dir should be empty, got %d entries", len(entries))
	}
}

func TestRunExport_PartialFailureIncrementsWarnings(t *testing.T) {
	cfg := baseConfig(t)
	// Fail one command across all switches.
	res, err := RunExport(context.Background(), cfg, &fakeRunner{failOnExecSubstr: map[string]bool{"switchshow": true}}, RequestMeta{})
	if err != nil {
		t.Fatalf("RunExport: %v", err)
	}
	if res.Warnings == 0 {
		t.Fatalf("expected warnings > 0 after a command failure")
	}
	if !res.OK {
		t.Fatalf("bundle should still be OK despite a failed command")
	}
	if len(res.Audit.Warnings) == 0 {
		t.Fatalf("audit record should carry warning lines")
	}
}

func TestValidate_Failures(t *testing.T) {
	t.Run("no targets", func(t *testing.T) {
		cfg := baseConfig(t)
		cfg.Targets = nil
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for no targets")
		}
	})
	t.Run("missing ssh key", func(t *testing.T) {
		cfg := baseConfig(t)
		cfg.Targets[0].SSHKeyPath = ""
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for missing ssh_key_path")
		}
	})
	t.Run("missing known_hosts", func(t *testing.T) {
		cfg := baseConfig(t)
		cfg.KnownHostsPath = ""
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for missing known_hosts_path")
		}
	})
	t.Run("relative artifact dir rejected", func(t *testing.T) {
		cfg := baseConfig(t)
		cfg.AllowInsecureArtifactDir = false
		cfg.ArtifactDir = "relative/path"
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for relative artifact_dir")
		}
	})
	t.Run("tmp artifact dir rejected", func(t *testing.T) {
		cfg := baseConfig(t)
		cfg.AllowInsecureArtifactDir = false
		cfg.ArtifactDir = "/tmp/filterrex"
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for /tmp artifact_dir")
		}
	})
}

func TestAuditRecord_NoSecrets(t *testing.T) {
	cfg := baseConfig(t)
	res, err := RunExport(context.Background(), cfg, &fakeRunner{}, RequestMeta{
		RequesterType: "local_cli", Requester: "connector-agent export-brocade-bundle", ConfigPath: "/etc/filterrex/brocade-export.json",
	})
	if err != nil {
		t.Fatalf("RunExport: %v", err)
	}
	auditPath := filepath.Join(cfg.EffectiveArtifactDir(), AuditLogName)
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	// No key material or key paths should appear in the audit trail.
	for _, forbidden := range []string{"/opt/keys/ro", "ssh_key", "PRIVATE KEY", "password", "readonly"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("audit log leaked sensitive token %q", forbidden)
		}
	}
	// It must still be valid JSON with the expected identity fields.
	var rec AuditRecord
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &rec); err != nil {
		t.Fatalf("audit line not valid JSON: %v", err)
	}
	if rec.RequesterType != "local_cli" || rec.SHA256 != res.SHA256 || len(rec.Targets) != 2 {
		t.Fatalf("unexpected audit record: %+v", rec)
	}
}
