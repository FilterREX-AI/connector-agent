package evidencebundle

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Inventory describes the switches whose captured output lives in a directory
// tree laid out as <role>/<switch>/<command>.txt (the same layout the Python
// collector's --fixture-root mode reads). It lets a producer assemble a bundle
// from an already-captured directory of raw command output.
type Inventory struct {
	CollectedAt      string            `json:"collected_at"`
	FabricRole       string            `json:"fabric_role"`
	CustomerSupplied bool              `json:"customer_supplied"`
	Switches         []InventorySwitch `json:"switches"`
}

// InventorySwitch is one switch entry in an Inventory.
type InventorySwitch struct {
	SwitchName string `json:"switch_name"`
	FabricRole string `json:"fabric_role"`
	FID        *int   `json:"fid,omitempty"`
	WWN        string `json:"wwn,omitempty"`
	DomainID   *int   `json:"domain_id,omitempty"`
	Model      string `json:"model,omitempty"`
	Notes      string `json:"notes,omitempty"`
}

// LoadInventory reads and parses an inventory JSON file.
func LoadInventory(path string) (*Inventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var inv Inventory
	if err := json.Unmarshal(data, &inv); err != nil {
		return nil, fmt.Errorf("parse inventory %s: %w", path, err)
	}
	return &inv, nil
}

// BuildFromDirectory assembles an Evidence Bundle from a directory of captured
// raw command output. It is deterministic given the same inputs and inventory:
// files are read verbatim, timestamps come from the inventory, and command
// order follows the embedded profile. This is used both by the fixture
// generator and by the conformance test to prove reproducibility.
func BuildFromDirectory(inputDir string, inv *Inventory, collectionMethod string) (*BuildResult, error) {
	if inv == nil {
		return nil, fmt.Errorf("inventory is required")
	}
	collectedAt, err := parseInventoryTime(inv.CollectedAt)
	if err != nil {
		return nil, err
	}

	metaByName := make(map[string]InventorySwitch, len(inv.Switches))
	for _, s := range inv.Switches {
		metaByName[s.SwitchName] = s
	}

	var captures []CommandCapture
	var switchMeta []SwitchMeta

	// Stable switch order: inventory order.
	for _, s := range inv.Switches {
		role := s.FabricRole
		if role == "" {
			role = inv.FabricRole
		}
		safeRole := normalizeRole(role)
		safeName := sanitizeSegment(s.SwitchName, "switch")
		switchDir := filepath.Join(inputDir, safeRole, safeName)

		entries, err := os.ReadDir(switchDir)
		if err != nil {
			return nil, fmt.Errorf("read switch dir %s: %w", switchDir, err)
		}
		var files []string
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".txt") {
				files = append(files, e.Name())
			}
		}
		sort.Strings(files)

		for _, fname := range files {
			command, ok := CommandForFilename(fname)
			if !ok {
				return nil, fmt.Errorf("no profile command maps to file %q in %s", fname, switchDir)
			}
			data, err := os.ReadFile(filepath.Join(switchDir, fname))
			if err != nil {
				return nil, err
			}
			captures = append(captures, CommandCapture{
				SwitchName:  s.SwitchName,
				FabricRole:  role,
				Command:     command,
				Filename:    fname,
				Stdout:      data,
				ExitCode:    0,
				CollectedAt: collectedAt,
			})
		}

		switchMeta = append(switchMeta, SwitchMeta{
			SwitchName: s.SwitchName,
			FID:        s.FID,
			WWN:        s.WWN,
			DomainID:   s.DomainID,
			Model:      s.Model,
			Notes:      s.Notes,
		})
	}

	return BuildEvidenceBundle(captures, BuildOptions{
		CollectionMethod: collectionMethod,
		FabricRole:       inv.FabricRole,
		CustomerSupplied: inv.CustomerSupplied,
		CollectedAt:      collectedAt,
		SwitchMeta:       switchMeta,
	})
}

func parseInventoryTime(s string) (time.Time, error) {
	if strings.TrimSpace(s) == "" {
		return time.Time{}, fmt.Errorf("inventory collected_at is required for deterministic bundles")
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse collected_at %q: %w", s, err)
	}
	return t.UTC(), nil
}
