// Package brocadeexport is the FilterREX agent's explicit, local-only "Export
// Brocade Evidence Bundle" operation (Phase 3B-3).
//
// It is a thin orchestration layer that composes two already-proven pieces:
//
//	brocadecli      → read-only SSH capture of raw Brocade CLI output
//	evidencebundle  → Evidence Bundle v1.0 ZIP writer (collection_method: "agent")
//
// and adds exactly what an operator-initiated local export needs: a capability
// gate (default OFF), local target configuration, an immutable timestamped
// artifact on local disk, and a local audit trail.
//
// Deliberate boundaries (Phase 3B-3):
//   - No network surface of its own. This package is exercised only by the local
//     `export-brocade-bundle` CLI subcommand and by Go tests.
//   - No cloud trigger, no relay, no /v1/execute wiring, no customer one-click.
//   - No auto-upload to service_request_evidence — the operator uploads the ZIP
//     manually later (Phase 2B).
//   - No Cisco, no REST-to-CLI rendering, no SAN-evidence parsing.
package brocadeexport

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/filterrex-ai/connector-agent/brocadecli"
)

// DefaultArtifactDir is the recommended, restrictive location for exported
// bundles and the local audit log.
const DefaultArtifactDir = "/var/lib/filterrex/artifacts"

// AuditLogName is the local, append-only audit trail file (JSON lines).
const AuditLogName = "brocade-export-audit.jsonl"

// TargetConfig is one Brocade switch in the local export config. It maps to a
// brocadecli.BrocadeTarget; no cloud credential storage is involved.
//
// TargetProfileID links this local switch entry to the FilterREX
// connector_target_profiles row it corresponds to. It is REQUIRED for
// server-initiated (agent-evidence) collection so the agent can resolve a
// dispatched job's target_profile_id to a local SSH config; it is OPTIONAL
// for the local `export-brocade-bundle` CLI.
type TargetConfig struct {
	SwitchName      string `json:"switch_name"`
	Host            string `json:"host"`
	Username        string `json:"username"`
	SSHKeyPath      string `json:"ssh_key_path"`
	TargetProfileID string `json:"target_profile_id,omitempty"`
	// KnownHostsPath overrides the top-level ExportConfig.KnownHostsPath for
	// this target. Host-key verification is always required.
	KnownHostsPath string `json:"known_hosts_path,omitempty"`
	FabricRole     string `json:"fabric_role,omitempty"`
	FID            *int   `json:"fid,omitempty"`
	PortRange      string `json:"port_range,omitempty"`
	Notes          string `json:"notes,omitempty"`

	// REST is the optional HTTPS live-query binding for this switch. When
	// present it enables the Workbench live-query path via the connector
	// (see docs/brocade-target-two-path-auth.md). The password is never
	// inlined here — it must live in a 0600 file referenced by PasswordFile.
	// This block is parsed and reported in heartbeat readiness but is not yet
	// consumed by the live-query executor in this build (ships in preview.3).
	REST *RESTConfig `json:"rest,omitempty"`
}

// RESTConfig describes the HTTPS REST binding for a Brocade switch.
//
// TransportMode is the single source of truth for the transport policy:
//
//	"https-verified"      — production; HTTPS with TLS certificate verification.
//	"https-lab-insecure"  — lab only; requires InsecureTLSLabOnly=true.
//	"http-lab-insecure"   — lab only; requires InsecureHTTPLabOnly=true.
//
// Only "https-verified" reports production-ready in the heartbeat.
type RESTConfig struct {
	TransportMode       string `json:"transport_mode,omitempty"`
	Port                int    `json:"port,omitempty"`
	Username            string `json:"username,omitempty"`
	PasswordFile        string `json:"password_file,omitempty"`
	CAFile              string `json:"ca_file,omitempty"`
	InsecureTLSLabOnly  bool   `json:"insecure_tls_lab_only,omitempty"`
	InsecureHTTPLabOnly bool   `json:"insecure_http_lab_only,omitempty"`
}


// ExportConfig is the local-only configuration for the export operation. It is
// loaded from a JSON file on the agent host (no YAML dependency is added). The
// capability gate defaults OFF: nothing runs unless an operator sets it true.
type ExportConfig struct {
	// Enabled is the capability gate (documented as brocade_bundle_export).
	// Default false — the operation refuses to run when this is not true.
	Enabled bool `json:"brocade_bundle_export"`

	// ArtifactDir is where the bundle ZIP and audit log are written. Created
	// with 0700 if missing. Defaults to DefaultArtifactDir when empty.
	ArtifactDir string `json:"artifact_dir,omitempty"`

	// KnownHostsPath is the default known_hosts file for all targets. A target
	// may override it via TargetConfig.KnownHostsPath. Host-key verification is
	// mandatory — there is no insecure fallback.
	KnownHostsPath string `json:"known_hosts_path,omitempty"`

	// SSH tuning (optional).
	ConnectTimeoutSeconds int `json:"connect_timeout_seconds,omitempty"`
	CommandTimeoutSeconds int `json:"command_timeout_seconds,omitempty"`
	SSHPort               int `json:"ssh_port,omitempty"`

	// Targets is the local Brocade switch list.
	Targets []TargetConfig `json:"brocade_targets"`

	// AllowInsecureArtifactDir opts out of the safe-location checks (relative
	// paths, /tmp). Off by default to push operators toward DefaultArtifactDir.
	AllowInsecureArtifactDir bool `json:"allow_insecure_artifact_dir,omitempty"`

	// ConfigPath is populated at load time for the audit record. Not serialized.
	ConfigPath string `json:"-"`
}

// EffectiveArtifactDir returns ArtifactDir or the default.
func (c *ExportConfig) EffectiveArtifactDir() string {
	if strings.TrimSpace(c.ArtifactDir) == "" {
		return DefaultArtifactDir
	}
	return c.ArtifactDir
}

// effectiveKnownHosts resolves the known_hosts path for a target: the per-target
// override wins, otherwise the top-level default.
func (c *ExportConfig) effectiveKnownHosts(t TargetConfig) string {
	if strings.TrimSpace(t.KnownHostsPath) != "" {
		return t.KnownHostsPath
	}
	return c.KnownHostsPath
}

func (c *ExportConfig) connectTimeout() time.Duration {
	if c.ConnectTimeoutSeconds <= 0 {
		return 10 * time.Second
	}
	return time.Duration(c.ConnectTimeoutSeconds) * time.Second
}

func (c *ExportConfig) commandTimeout() time.Duration {
	if c.CommandTimeoutSeconds <= 0 {
		return 30 * time.Second
	}
	return time.Duration(c.CommandTimeoutSeconds) * time.Second
}

// BrocadeTargets converts the config targets into brocadecli.BrocadeTarget
// values. The SSH key path is carried through; no key material is read here.
func (c *ExportConfig) BrocadeTargets() []brocadecli.BrocadeTarget {
	out := make([]brocadecli.BrocadeTarget, 0, len(c.Targets))
	for _, t := range c.Targets {
		out = append(out, brocadecli.BrocadeTarget{
			SwitchName: t.SwitchName,
			Host:       t.Host,
			Username:   t.Username,
			FabricRole: t.FabricRole,
			FID:        t.FID,
			SSHKeyPath: t.SSHKeyPath,
			PortRange:  t.PortRange,
			Notes:      t.Notes,
		})
	}
	return out
}

// Validate enforces the capability gate, target completeness, and safe artifact
// locations. Filesystem-permission checks happen at export time (ensureArtifactDir);
// Validate is pure and path-based so it is cheap and testable.
func (c *ExportConfig) Validate() error {
	if !c.Enabled {
		return ErrCapabilityDisabled
	}
	if len(c.Targets) == 0 {
		return fmt.Errorf("no brocade_targets configured")
	}

	dir := c.EffectiveArtifactDir()
	if !c.AllowInsecureArtifactDir {
		if !filepath.IsAbs(dir) {
			return fmt.Errorf("artifact_dir %q must be an absolute path (set allow_insecure_artifact_dir to override)", dir)
		}
		clean := filepath.Clean(dir)
		if clean == "/tmp" || strings.HasPrefix(clean, "/tmp/") {
			return fmt.Errorf("artifact_dir %q is under /tmp; choose a durable location like %s (set allow_insecure_artifact_dir to override)", dir, DefaultArtifactDir)
		}
	}

	for i, t := range c.Targets {
		who := t.SwitchName
		if who == "" {
			who = fmt.Sprintf("target[%d]", i)
		}
		if strings.TrimSpace(t.SwitchName) == "" {
			return fmt.Errorf("%s: switch_name is required", who)
		}
		if strings.TrimSpace(t.Host) == "" {
			return fmt.Errorf("%s: host is required", who)
		}
		if strings.TrimSpace(t.Username) == "" {
			return fmt.Errorf("%s: username is required", who)
		}
		if strings.TrimSpace(t.SSHKeyPath) == "" {
			return fmt.Errorf("%s: ssh_key_path is required (key-based auth only)", who)
		}
		if strings.TrimSpace(c.effectiveKnownHosts(t)) == "" {
			return fmt.Errorf("%s: known_hosts_path is required (host-key verification is mandatory)", who)
		}
	}
	return nil
}
