package brocadeexport

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveAgentEvidenceArtifactDir_Default(t *testing.T) {
	t.Setenv(AgentEvidenceArtifactDirEnv, "")
	path, source, err := ResolveAgentEvidenceArtifactDir()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if source != "default" {
		t.Fatalf("source = %q, want default", source)
	}
	if path != AgentEvidenceArtifactDir {
		t.Fatalf("path = %q, want %q", path, AgentEvidenceArtifactDir)
	}
	// The default path must NOT reach into the container's read-only root.
	if strings.HasPrefix(path, "/var/lib/filterrex") {
		t.Fatalf("default path %q must not point at /var/lib/filterrex (read-only in container)", path)
	}
}

func TestResolveAgentEvidenceArtifactDir_EnvOverride(t *testing.T) {
	// Resolve does not touch the filesystem; use a synthetic non-/tmp path.
	const override = "/var/opt/filterrex-test/artifacts"
	t.Setenv(AgentEvidenceArtifactDirEnv, override)
	path, source, err := ResolveAgentEvidenceArtifactDir()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if source != "env" {
		t.Fatalf("source = %q, want env", source)
	}
	if path != filepath.Clean(override) {
		t.Fatalf("path = %q, want %q", path, override)
	}
}

func TestResolveAgentEvidenceArtifactDir_EnvRelativeRejected(t *testing.T) {
	t.Setenv(AgentEvidenceArtifactDirEnv, "relative/path")
	_, _, err := ResolveAgentEvidenceArtifactDir()
	if err == nil {
		t.Fatal("expected error for relative env override")
	}
}

func TestResolveAgentEvidenceArtifactDir_EnvTmpRejected(t *testing.T) {
	t.Setenv(AgentEvidenceArtifactDirEnv, "/tmp/filterrex-agent")
	_, _, err := ResolveAgentEvidenceArtifactDir()
	if err == nil {
		t.Fatal("expected error for /tmp env override")
	}
}

func TestResolveAgentEvidenceArtifactDir_EnvRootRejected(t *testing.T) {
	t.Setenv(AgentEvidenceArtifactDirEnv, "/")
	_, _, err := ResolveAgentEvidenceArtifactDir()
	if err == nil {
		t.Fatal("expected error for filesystem root")
	}
}

func TestVerifyWritableDirectory_CreatesAndProbes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "artifacts")
	if err := VerifyWritableDirectory(dir); err != nil {
		t.Fatalf("verify: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("perm = %o, want 0700", info.Mode().Perm())
	}
	// No probe file should linger.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("directory should be empty after probe, got %d entries", len(entries))
	}
}

func TestVerifyWritableDirectory_ExistingUnwritable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses directory perms")
	}
	dir := filepath.Join(t.TempDir(), "locked")
	if err := os.MkdirAll(dir, 0o500); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	err := VerifyWritableDirectory(dir)
	if err == nil {
		t.Fatal("expected error for unwritable existing directory")
	}
	if !errors.Is(err, ErrArtifactDirNotWritable) {
		t.Fatalf("expected ErrArtifactDirNotWritable, got %v", err)
	}
}

func TestVerifyWritableDirectory_ReadOnlyParent(t *testing.T) {
	// Simulate the container failure: /var/lib/filterrex does not exist and
	// its parent is not writable to the calling user.
	if os.Getuid() == 0 {
		t.Skip("root bypasses directory perms")
	}
	base := t.TempDir()
	if err := os.Chmod(base, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(base, 0o700) })
	target := filepath.Join(base, "filterrex", "artifacts")
	err := VerifyWritableDirectory(target)
	if err == nil {
		t.Fatal("expected error for read-only parent")
	}
	if !errors.Is(err, ErrArtifactDirNotWritable) {
		t.Fatalf("expected ErrArtifactDirNotWritable, got %v", err)
	}
}
