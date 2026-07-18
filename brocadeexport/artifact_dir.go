// Agent-evidence artifact directory resolution (preview.23).
//
// The server-dispatched agent-evidence path writes its Evidence Bundle ZIP to
// a durable local directory. Preview.22 accidentally defaulted this to
// /var/lib/filterrex/artifacts — a location under the connector container's
// read-only root filesystem — which caused every dispatched Brocade collection
// to fail with `bundle_generation_failed / mkdir /var/lib/filterrex:
// read-only file system` even though SSH readiness and switch capture were
// green.
//
// This file centralizes the resolver, the safety rules, and a real
// writability probe. The local `export-brocade-bundle` CLI keeps its own
// DefaultArtifactDir + --out behavior — it is a deliberate operator
// invocation and does not run inside the read-only container root.

package brocadeexport

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AgentEvidenceArtifactDir is the daemon default for server-dispatched
// agent-evidence bundles. It lives inside the writable `filterrex-config`
// volume that the compose file already mounts at /etc/filterrex, so no
// operator action is required for the standard install.
const AgentEvidenceArtifactDir = "/etc/filterrex/artifacts"

// AgentEvidenceArtifactDirEnv is the runtime override. When set to a valid,
// absolute, non-/tmp path it wins over the daemon default. It exists mainly
// for operators running a customized bind-mount layout.
const AgentEvidenceArtifactDirEnv = "FILTERREX_AGENT_EVIDENCE_ARTIFACT_DIR"

// ArtifactDirNotWritableCode is the public error code surfaced to the app
// when the daemon cannot write its evidence artifact directory. It is a
// distinct code — not a hint on `bundle_generation_failed` — so the UI can
// map it to a targeted operator sentence without inspecting a nested field.
const ArtifactDirNotWritableCode = "artifact_dir_not_writable"

// ErrArtifactDirNotWritable is returned by VerifyWritableDirectory /
// ResolveAgentEvidenceArtifactDir when the resolved location cannot be
// written to as the connector's runtime user. Callers should map this to
// ArtifactDirNotWritableCode when reporting to the control plane; the
// underlying OS error stays in the local audit log.
var ErrArtifactDirNotWritable = errors.New("agent evidence artifact directory is not writable")

// ResolveAgentEvidenceArtifactDir returns the effective artifact directory
// for the server-dispatched agent-evidence path, the source that produced it
// ("env" or "default"), and any validation error.
//
// The path is validated (absolute, not /tmp, not root, no control chars)
// BEFORE any filesystem operation. Writability is intentionally not tested
// here — callers should invoke VerifyWritableDirectory when they actually
// intend to use the path, so a probe failure attributes cleanly.
func ResolveAgentEvidenceArtifactDir() (path string, source string, err error) {
	if v := strings.TrimSpace(os.Getenv(AgentEvidenceArtifactDirEnv)); v != "" {
		if err := validateAgentArtifactDir(v); err != nil {
			return "", "env", fmt.Errorf("%s=%q: %w", AgentEvidenceArtifactDirEnv, v, err)
		}
		return filepath.Clean(v), "env", nil
	}
	return AgentEvidenceArtifactDir, "default", nil
}

// validateAgentArtifactDir enforces the safety rules for the daemon path.
// Mirrors the exporter Validate() rules but is stricter about root paths
// and control characters so operators cannot silently point evidence at "/"
// or a path with embedded newlines via an env var.
func validateAgentArtifactDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("path must be absolute")
	}
	for _, r := range dir {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("path contains control characters")
		}
	}
	clean := filepath.Clean(dir)
	if clean == "/" {
		return fmt.Errorf("path %q refuses filesystem root", dir)
	}
	if clean == "/tmp" || strings.HasPrefix(clean, "/tmp/") {
		return fmt.Errorf("path %q is under /tmp; choose a durable location like %s",
			dir, AgentEvidenceArtifactDir)
	}
	return nil
}

// VerifyWritableDirectory is a real write probe: it creates the directory
// if missing (0700), inspects it, then writes and removes a temporary 0600
// file inside it as the calling process. This catches the case where the
// directory already exists but is not writable by the connector user —
// os.MkdirAll returns nil for that scenario.
//
// The temporary filename is never logged publicly.
func VerifyWritableDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("%w: mkdir %s: %v", ErrArtifactDirNotWritable, path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%w: stat %s: %v", ErrArtifactDirNotWritable, path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrArtifactDirNotWritable, path)
	}
	if info.Mode().Perm()&0o002 != 0 {
		return fmt.Errorf("%w: %s is world-writable (mode %o); refuse to write evidence there",
			ErrArtifactDirNotWritable, path, info.Mode().Perm())
	}
	f, err := os.CreateTemp(path, ".filterrex-write-check-*")
	if err != nil {
		return fmt.Errorf("%w: create probe in %s: %v", ErrArtifactDirNotWritable, path, err)
	}
	name := f.Name()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(name)
		return fmt.Errorf("%w: chmod probe in %s: %v", ErrArtifactDirNotWritable, path, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("%w: close probe in %s: %v", ErrArtifactDirNotWritable, path, err)
	}
	if err := os.Remove(name); err != nil {
		return fmt.Errorf("%w: cleanup probe in %s: %v", ErrArtifactDirNotWritable, path, err)
	}
	return nil
}
