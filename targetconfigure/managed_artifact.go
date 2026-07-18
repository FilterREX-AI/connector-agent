package targetconfigure

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

type ArtifactKind string

const (
	ArtifactSSHPrivateKey ArtifactKind = "ssh_private_key"
	ArtifactSSHPublicKey  ArtifactKind = "ssh_public_key"
	ArtifactKnownHosts    ArtifactKind = "known_hosts"
	ArtifactRESTSecret    ArtifactKind = "rest_secret"
	ArtifactTLSMaterial   ArtifactKind = "tls_material"
)

var (
	ErrManagedArtifactEmpty      = errors.New("managed_artifact_path_empty")
	ErrManagedArtifactControl    = errors.New("managed_artifact_path_control_char")
	ErrManagedArtifactUnmanaged  = errors.New("unmanaged_artifact_path")
	ErrManagedArtifactTraversal  = errors.New("managed_artifact_path_traversal")
	ErrManagedArtifactOutsideDir = errors.New("managed_artifact_path_outside_targets_dir")
)

// ResolveManagedTargetArtifact resolves target artifact paths written by the
// wizard under one mount point (historically /config) for a daemon that reads
// the same host directory under another mount point (/etc/filterrex/targets).
// It only accepts known managed artifact subpaths and fails closed for any
// other absolute path. No caller should perform generic string prefix rewrites.
func ResolveManagedTargetArtifact(targetsDir, storedPath string, kind ArtifactKind) (string, error) {
	rel, err := managedArtifactRelativePath(targetsDir, storedPath, kind)
	if err != nil {
		return "", err
	}
	base := filepath.Clean(strings.TrimSpace(targetsDir))
	if base == "." || base == "" {
		return "", ErrManagedArtifactOutsideDir
	}
	candidate := filepath.Clean(filepath.Join(base, filepath.FromSlash(rel)))
	if !pathWithinDir(base, candidate) {
		return "", ErrManagedArtifactOutsideDir
	}

	// If the artifact already exists, resolve symlinks and re-check containment.
	// Missing files are allowed to resolve to their intended managed location so
	// callers can return precise not-found diagnostics.
	if resolved, rerr := filepath.EvalSymlinks(candidate); rerr == nil {
		resolvedBase := base
		if b, berr := filepath.EvalSymlinks(base); berr == nil {
			resolvedBase = b
		}
		if !pathWithinDir(resolvedBase, resolved) {
			return "", ErrManagedArtifactOutsideDir
		}
		return resolved, nil
	} else if !os.IsNotExist(rerr) {
		return "", rerr
	}
	return candidate, nil
}

func managedArtifactRelativePath(targetsDir, storedPath string, kind ArtifactKind) (string, error) {
	path := strings.TrimSpace(storedPath)
	if path == "" {
		return "", ErrManagedArtifactEmpty
	}
	for _, r := range path {
		if r == 0 || unicode.IsControl(r) {
			return "", ErrManagedArtifactControl
		}
	}

	slashPath := filepath.ToSlash(filepath.Clean(path))
	var rel string
	switch {
	case filepath.IsAbs(path):
		if strings.HasPrefix(slashPath, "/config/") {
			rel = strings.TrimPrefix(slashPath, "/config/")
			break
		}
		base := filepath.ToSlash(filepath.Clean(strings.TrimSpace(targetsDir)))
		if base != "" && base != "." && (slashPath == base || strings.HasPrefix(slashPath, base+"/")) {
			rel = strings.TrimPrefix(strings.TrimPrefix(slashPath, base), "/")
			break
		}
		return "", ErrManagedArtifactUnmanaged
	default:
		rel = slashPath
	}

	rel = strings.TrimPrefix(filepath.ToSlash(filepath.Clean(filepath.FromSlash(rel))), "./")
	if rel == "." || rel == "" {
		return "", ErrManagedArtifactTraversal
	}
	if strings.HasPrefix(rel, "../") || rel == ".." || strings.Contains(rel, "/../") {
		return "", ErrManagedArtifactTraversal
	}
	if !artifactKindAllowsRelativePath(kind, rel) {
		return "", ErrManagedArtifactUnmanaged
	}
	return rel, nil
}

func artifactKindAllowsRelativePath(kind ArtifactKind, rel string) bool {
	switch kind {
	case ArtifactSSHPrivateKey, ArtifactSSHPublicKey:
		return strings.HasPrefix(rel, sshKeyDir+"/") && rel != sshKeyDir+"/"
	case ArtifactKnownHosts:
		return rel == knownHostsFn
	case ArtifactRESTSecret:
		return strings.HasPrefix(rel, restSecretDir+"/") && rel != restSecretDir+"/"
	case ArtifactTLSMaterial:
		return strings.HasPrefix(rel, tlsDir+"/") && rel != tlsDir+"/"
	default:
		return false
	}
}

func pathWithinDir(base, candidate string) bool {
	base = filepath.Clean(base)
	candidate = filepath.Clean(candidate)
	if candidate == base {
		return true
	}
	return strings.HasPrefix(candidate, base+string(os.PathSeparator))
}

func managedArtifactPathForRecord(targetsDir, absolutePath string, kind ArtifactKind) string {
	resolved, err := ResolveManagedTargetArtifact(targetsDir, absolutePath, kind)
	if err != nil {
		return absolutePath
	}
	rel, err := filepath.Rel(filepath.Clean(targetsDir), resolved)
	if err != nil || strings.HasPrefix(rel, "..") {
		return absolutePath
	}
	return filepath.ToSlash(rel)
}
