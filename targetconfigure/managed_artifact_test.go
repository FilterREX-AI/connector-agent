package targetconfigure

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestResolveManagedTargetArtifactTranslatesConfigMount(t *testing.T) {
	targetsDir := t.TempDir()
	got, err := ResolveManagedTargetArtifact(targetsDir, "/config/keys/426cd1e7", ArtifactSSHPrivateKey)
	if err != nil {
		t.Fatalf("ResolveManagedTargetArtifact returned error: %v", err)
	}
	want := filepath.Join(targetsDir, "keys", "426cd1e7")
	if got != want {
		t.Fatalf("resolved path = %q; want %q", got, want)
	}
}

func TestManagedArtifactPathForRecordPersistsRelativePaths(t *testing.T) {
	targetsDir := t.TempDir()
	got := managedArtifactPathForRecord(targetsDir, filepath.Join(targetsDir, "known_hosts"), ArtifactKnownHosts)
	if got != "known_hosts" {
		t.Fatalf("record path = %q; want known_hosts", got)
	}
}

func TestResolveManagedTargetArtifactRejectsUnmanagedAbsolutePath(t *testing.T) {
	_, err := ResolveManagedTargetArtifact(t.TempDir(), "/etc/ssh/ssh_host_rsa_key", ArtifactSSHPrivateKey)
	if !errors.Is(err, ErrManagedArtifactUnmanaged) {
		t.Fatalf("error = %v; want ErrManagedArtifactUnmanaged", err)
	}
}

func TestResolveManagedTargetArtifactRejectsTraversal(t *testing.T) {
	_, err := ResolveManagedTargetArtifact(t.TempDir(), "keys/../known_hosts", ArtifactSSHPrivateKey)
	if !errors.Is(err, ErrManagedArtifactUnmanaged) {
		t.Fatalf("error = %v; want ErrManagedArtifactUnmanaged", err)
	}
}
