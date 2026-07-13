package brocadeexport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// LoadConfig reads and parses the local export config JSON file. It sets
// ConfigPath for the audit record. It does NOT read any key material; the SSH
// key is only opened later by the runner at capture time. Unknown fields are
// rejected so typos in the local config fail loudly rather than silently
// disabling a setting.
func LoadConfig(path string) (*ExportConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	var cfg ExportConfig
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	cfg.ConfigPath = path
	return &cfg, nil
}
