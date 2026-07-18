package targetconfigure

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

const (
	TargetConfigOK         = "ok"
	TargetConfigMissing    = "target_configuration_missing"
	TargetConfigUnreadable = "target_configuration_unreadable"
)

// TargetConfigInventory is a bounded, secret-free summary of the target
// configuration store. It is safe for local connector logs and lets operators
// distinguish a missing mount from a UUID lookup miss.
type TargetConfigInventory struct {
	Dir              string
	File             string
	DirectoryPresent bool
	FilePresent      bool
	FileReadable     bool
	RecordsLoaded    int
	Status           string
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
	inv.Status = TargetConfigOK
	return inv
}
