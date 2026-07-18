package targetconfigure

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const (
	TargetConfigOK                = "ok"
	TargetConfigMissing           = "target_configuration_missing"
	TargetConfigUnreadable        = "target_configuration_unreadable"
	TargetConfigNoTarget          = "target_not_configured"
	TargetConfigDuplicate         = "duplicate_target_id"
	TargetConfigKeyMissing        = "ssh_key_not_found"
	TargetConfigKeyUnreadable     = "ssh_key_unreadable"
	TargetConfigKnownHostsMissing = "known_hosts_not_found"
	TargetConfigHostKeyMissing    = "host_key_not_configured"
	TargetConfigUnmanagedArtifact = "unmanaged_artifact_path"

	DefaultBrocadeTargetsDir = "/etc/filterrex/targets"
)

// TargetConfigInventory is a bounded, secret-free summary of the target
// configuration store. It is safe for local connector logs and lets operators
// distinguish a missing mount from a UUID lookup miss.
type TargetConfigInventory struct {
	Dir               string
	File              string
	DirectoryPresent  bool
	DirectoryReadable bool
	FilePresent       bool
	FileReadable      bool
	ParseSuccessful   bool
	RecordsLoaded     int
	Status            string
}

// TargetConfigResolution is the daemon/doctor shared path-resolution result.
// Present/Readable are compatibility aliases for FilePresent/FileReadable.
type TargetConfigResolution struct {
	Dir               string
	File              string
	Source            string
	Warning           string
	Present           bool
	Readable          bool
	DirectoryPresent  bool
	DirectoryReadable bool
	FilePresent       bool
	FileReadable      bool
	ParseSuccessful   bool
	RecordsLoaded     int
	Status            string
}

// TargetConfigTargetInventory extends TargetConfigInventory with a bounded,
// secret-free answer to: "does this exact application target UUID have a usable
// SSH profile in targets.json?" It never returns raw target records or key data.
type TargetConfigTargetInventory struct {
	TargetConfigInventory
	TargetID             string
	TargetMatchCount     int
	TargetProfileFound   bool
	SSHUsernamePresent   bool
	PrivateKeyPresent    bool
	PrivateKeyReadable   bool
	PublicKeyPresent     bool
	PublicKeyReadable    bool
	KnownHostsPresent    bool
	KnownHostsReadable   bool
	KnownHostsEntryFound bool
	ResolvedStatus       string
}

func ResolveTargetConfigStore(envOverride, configDir string) TargetConfigResolution {
	return ResolveTargetConfigStoreWithCanonical(envOverride, configDir, DefaultBrocadeTargetsDir)
}

func ResolveTargetConfigStoreWithCanonical(envOverride, configDir, canonicalDir string) TargetConfigResolution {
	env := strings.TrimSpace(envOverride)
	if env != "" {
		return inspectTargetConfigCandidate(env, "env", "")
	}
	canonical := inspectTargetConfigCandidate(canonicalDir, "canonical", "")
	legacyDir := filepath.Join(configDir, "targets")
	legacy := inspectTargetConfigCandidate(legacyDir, "legacy", "legacy_targets_dir")
	if canonical.FileReadable {
		if legacy.FileReadable && legacy.Dir != canonical.Dir {
			canonical.Warning = "multiple_target_config_sources"
		}
		return canonical
	}
	if legacy.FileReadable {
		return legacy
	}
	return canonical
}

func inspectTargetConfigCandidate(dir, source, warning string) TargetConfigResolution {
	inv := InspectTargetConfigDir(dir)
	return TargetConfigResolution{
		Dir:               inv.Dir,
		File:              inv.File,
		Source:            source,
		Warning:           warning,
		Present:           inv.FilePresent,
		Readable:          inv.FileReadable,
		DirectoryPresent:  inv.DirectoryPresent,
		DirectoryReadable: inv.DirectoryReadable,
		FilePresent:       inv.FilePresent,
		FileReadable:      inv.FileReadable,
		ParseSuccessful:   inv.ParseSuccessful,
		RecordsLoaded:     inv.RecordsLoaded,
		Status:            inv.Status,
	}
}

// InspectTargetConfigDir checks <targetsDir>/targets.json at file granularity.
// It never returns raw filesystem or parse errors; callers should log only the
// bounded Status plus booleans/counts.
func InspectTargetConfigDir(targetsDir string) TargetConfigInventory {
	dir := strings.TrimSpace(targetsDir)
	inv := TargetConfigInventory{
		Dir:    dir,
		File:   filepath.Join(dir, targetsFile),
		Status: TargetConfigMissing,
	}
	if dir == "" {
		return inv
	}
	if st, err := os.Stat(dir); err == nil && st.IsDir() {
		inv.DirectoryPresent = true
		if f, ferr := os.Open(dir); ferr == nil {
			inv.DirectoryReadable = true
			_ = f.Close()
		}
	}
	b, err := os.ReadFile(inv.File)
	if os.IsNotExist(err) {
		return inv
	}
	if err != nil {
		inv.FilePresent = true
		inv.Status = TargetConfigUnreadable
		return inv
	}
	inv.FilePresent = true
	inv.FileReadable = true

	var doc targetsDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		inv.Status = TargetConfigUnreadable
		return inv
	}
	if doc.Targets != nil {
		inv.RecordsLoaded = len(doc.Targets)
	}
	inv.ParseSuccessful = true
	inv.Status = TargetConfigOK
	return inv
}

func InspectTargetConfigForTarget(targetsDir, targetID string) TargetConfigTargetInventory {
	base := InspectTargetConfigDir(targetsDir)
	out := TargetConfigTargetInventory{
		TargetConfigInventory: base,
		TargetID:              canonicalUUID(targetID),
		ResolvedStatus:        base.Status,
	}
	if out.TargetID == "" {
		out.ResolvedStatus = ErrInvalidTargetID.Error()
		return out
	}
	if base.Status != TargetConfigOK {
		return out
	}
	doc, err := loadTargets(targetsDir)
	if err != nil || doc == nil {
		out.ResolvedStatus = TargetConfigUnreadable
		return out
	}

	var match *targetRecord
	for profileName, rec := range doc.Targets {
		id, rerr := EffectiveTargetID(profileName, rec)
		if rerr != nil || id != out.TargetID {
			continue
		}
		out.TargetMatchCount++
		out.TargetProfileFound = true
		match = rec
	}

	switch {
	case out.TargetMatchCount == 0:
		out.ResolvedStatus = TargetConfigNoTarget
		return out
	case out.TargetMatchCount > 1:
		out.ResolvedStatus = TargetConfigDuplicate
		return out
	}
	if match == nil || match.SSH == nil {
		out.ResolvedStatus = TargetConfigKeyMissing
		return out
	}

	out.SSHUsernamePresent = strings.TrimSpace(match.SSH.Username) != ""
	privateKeyPath, privateKeyErr := ResolveManagedTargetArtifact(targetsDir, match.SSH.KeyPath, ArtifactSSHPrivateKey)
	publicKeyPath, publicKeyErr := ResolveManagedTargetArtifact(targetsDir, match.SSH.PublicKeyPath, ArtifactSSHPublicKey)
	knownHostsPath, knownHostsErr := ResolveManagedTargetArtifact(targetsDir, match.SSH.KnownHostsPath, ArtifactKnownHosts)
	if privateKeyErr != nil || knownHostsErr != nil || isUnmanagedArtifactError(publicKeyErr) {
		out.ResolvedStatus = TargetConfigUnmanagedArtifact
		return out
	}
	out.PrivateKeyPresent, out.PrivateKeyReadable = filePresence(privateKeyPath)
	if publicKeyErr == nil {
		out.PublicKeyPresent, out.PublicKeyReadable = filePresence(publicKeyPath)
	}
	out.KnownHostsPresent, out.KnownHostsReadable = filePresence(knownHostsPath)
	if knownHostsPath != "" && match.Address != "" {
		if _, err := readKnownHostFingerprint(targetsDir, match.SSH.KnownHostsPath, match.Address); err == nil {
			out.KnownHostsEntryFound = true
		}
	}

	switch {
	case !out.SSHUsernamePresent || !out.PrivateKeyPresent:
		out.ResolvedStatus = TargetConfigKeyMissing
		return out
	case !out.PrivateKeyReadable:
		out.ResolvedStatus = TargetConfigKeyUnreadable
		return out
	case !out.KnownHostsPresent:
		out.ResolvedStatus = TargetConfigKnownHostsMissing
		return out
	case !out.KnownHostsReadable:
		out.ResolvedStatus = TargetConfigUnreadable
		return out
	case !out.KnownHostsEntryFound:
		out.ResolvedStatus = TargetConfigHostKeyMissing
		return out
	}
	out.ResolvedStatus = TargetConfigOK
	return out
}

func isUnmanagedArtifactError(err error) bool {
	return errors.Is(err, ErrManagedArtifactUnmanaged) ||
		errors.Is(err, ErrManagedArtifactTraversal) ||
		errors.Is(err, ErrManagedArtifactOutsideDir) ||
		errors.Is(err, ErrManagedArtifactControl)
}

func filePresence(path string) (present bool, readable bool) {
	path = strings.TrimSpace(path)
	if path == "" {
		return false, false
	}
	if st, err := os.Stat(path); err == nil && !st.IsDir() {
		present = true
	}
	if _, err := os.ReadFile(path); err == nil {
		readable = true
	}
	return present, readable
}
