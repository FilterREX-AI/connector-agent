package brocadeexport

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// AuditRecord is one local, credential-free audit entry for an export attempt.
// It records who/what requested the export, the targets used, command and
// target outcome counts, the output path, the bundle sha256, and timings.
// It NEVER contains secrets: no key material, no key-path contents, no passwords.
type AuditRecord struct {
	Event         string `json:"event"`
	RequesterType string `json:"requester_type"`
	Requester     string `json:"requester"`
	ConfigPath    string `json:"config_path,omitempty"`

	Vendor           string `json:"vendor"`
	CollectionMethod string `json:"collection_method"`

	// Targets used — identity only (switch_name + host). No credentials.
	Targets []AuditTarget `json:"targets"`

	CommandsAttempted int `json:"commands_attempted"`
	CommandsSucceeded int `json:"commands_succeeded"`
	CommandsFailed    int `json:"commands_failed"`
	TargetsAttempted  int `json:"targets_attempted"`
	TargetsSucceeded  int `json:"targets_succeeded"`
	TargetsFailed     int `json:"targets_failed"`

	// Warnings is a human-readable list of per-command/per-target problems.
	Warnings []string `json:"warnings,omitempty"`

	OutputPath string `json:"output_path,omitempty"`
	SHA256     string `json:"sha256,omitempty"`

	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`

	// OK is false when the export failed before producing an artifact.
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// AuditTarget is the non-sensitive identity of a target in the audit record.
type AuditTarget struct {
	SwitchName string `json:"switch_name"`
	Host       string `json:"host"`
	FabricRole string `json:"fabric_role,omitempty"`
}

// RequestMeta describes who/what initiated the export, for the audit trail.
type RequestMeta struct {
	RequesterType string // e.g. "local_cli"
	Requester     string // e.g. "connector-agent export-brocade-bundle"
	ConfigPath    string // non-secret path; key material is never recorded
}

// writeAuditRecord appends the record as a single JSON line to the audit log in
// artifactDir. The file is created 0600 and the directory is assumed to already
// exist with restrictive permissions (ensured by ensureArtifactDir).
func writeAuditRecord(artifactDir string, rec AuditRecord) error {
	path := filepath.Join(artifactDir, AuditLogName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()
	// Enforce 0600 even if the file pre-existed with looser bits.
	_ = f.Chmod(0600)

	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal audit record: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("write audit record: %w", err)
	}
	return nil
}
