package brocadeexport

import (
	"encoding/json"
	"errors"
)

// ErrCapabilityDisabled is returned when the export is attempted while the
// brocade_bundle_export capability gate is off (the default).
var ErrCapabilityDisabled = errors.New("brocade_bundle_export capability is disabled (default off); enable it in the local export config to run")

// ExportResult is the machine-readable outcome returned by a successful export.
// It intentionally reports only non-sensitive metadata. In this local CLI phase
// the full local artifact path is returned; when this operation later becomes a
// network/relay-mediated capability, an artifact ID/handle should be returned
// instead so host filesystem paths are not exposed to cloud-visible contexts.
type ExportResult struct {
	OK               bool   `json:"ok"`
	ArtifactType     string `json:"artifact_type"`
	Vendor           string `json:"vendor"`
	CollectionMethod string `json:"collection_method"`
	Path             string `json:"path"`
	Switches         int    `json:"switches"`
	ParsedFiles      int    `json:"parsed_files"`
	SupportingFiles  int    `json:"supporting_files"`
	// Warnings is the simple count surfaced in the metadata shape
	// (== commands_failed). The richer breakdown lives in the audit record.
	Warnings  int    `json:"warnings"`
	SHA256    string `json:"sha256"`
	StartedAt string `json:"started_at"`
	FinishedAt string `json:"finished_at"`

	// Audit is the full local audit record for this run. It is written to the
	// audit JSONL by RunExport and is exposed here so the caller (CLI) can also
	// emit it to the structured agent logger. Not part of the returned JSON.
	Audit AuditRecord `json:"-"`
}

// JSON renders the result as indented JSON for CLI stdout.
func (r *ExportResult) JSON() string {
	b, _ := json.MarshalIndent(r, "", "  ")
	return string(b)
}

// ErrorResult is the machine-readable shape printed to stdout on failure so the
// CLI stays scriptable even when an export cannot complete.
type ErrorResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

// ErrorJSON renders a failure as indented JSON for CLI stdout.
func ErrorJSON(err error) string {
	b, _ := json.MarshalIndent(ErrorResult{OK: false, Error: err.Error()}, "", "  ")
	return string(b)
}
