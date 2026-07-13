// ForgeAI Connector Host — Core Types
//
// Defines the host identity, target profile schema, worker state,
// target-specific config extension points, and generic-http guardrails.

package main

import (
	"time"
)

// ── Agent metadata ──

// HostVersion is overridden at build time via -ldflags "-X main.HostVersion=..."
var HostVersion = "0.7.0-dev"

// ── Host Identity ──

// HostIdentity represents the enrolled connector host.
type HostIdentity struct {
	HostID         string    `json:"host_id"`          // UUID assigned at enrollment
	Label          string    `json:"label"`             // Human-friendly name
	EnrolledAt     time.Time `json:"enrolled_at"`
	ConnectorToken string    `json:"connector_token"`   // fgc_... token for backend auth
	BackendURL     string    `json:"backend_url"`
	PublicKey      string    `json:"public_key,omitempty"` // base64 NaCl public key
}

// ── Host-level configuration ──

// HostConfig holds host-wide settings separate from per-target profiles.
type HostConfig struct {
	LogLevel             string `json:"log_level"`              // debug, info, warn, error
	MaxConcurrentWorkers int    `json:"max_concurrent_workers"` // 0 = unlimited
	WatchdogTimeoutSecs  int    `json:"watchdog_timeout_secs"`  // kill worker if no progress
	AutoUpdatePolicy     string `json:"auto_update_policy"`     // disabled, notify, staged, auto
	PinnedPublicKey      string `json:"pinned_public_key"`      // ed25519 public key for update verification
	InsecureSkipVerify   bool   `json:"insecure_skip_verify"`   // global TLS override
	SyncIntervalSecs     int    `json:"sync_interval_secs"`     // desired-state polling interval
	LocalRetentionDays   int    `json:"local_retention_days"`   // hybrid mode: days to keep local snapshots

	// LanOnly suppresses all cloud snapshot uploads. Snapshots are stored
	// in the local DB only. Set via display_mode = "lan-only" on the control plane.
	LanOnly bool `json:"lan_only"`

	// Remote action controls (both default to false — admin must opt in)
	RemoteLiveQueryEnabled bool `json:"remote_live_query_enabled"` // allow Live Query relay commands
	RemoteRestartEnabled   bool `json:"remote_restart_enabled"`    // allow remote agent restart
}

// DefaultHostConfig returns sensible defaults.
func DefaultHostConfig() HostConfig {
	return HostConfig{
		LogLevel:             "info",
		MaxConcurrentWorkers: 0,
		WatchdogTimeoutSecs:  300,
		AutoUpdatePolicy:     "disabled",
		SyncIntervalSecs:     60,
	}
}

// ── Target Profile ──

// TargetStatus represents the lifecycle state of a target profile.
type TargetStatus string

const (
	TargetStatusPending  TargetStatus = "pending"
	TargetStatusActive   TargetStatus = "active"
	TargetStatusPaused   TargetStatus = "paused"
	TargetStatusDegraded TargetStatus = "degraded"
	TargetStatusRevoked  TargetStatus = "revoked"
	TargetStatusError    TargetStatus = "error"
)

// TargetProfile is the universal schema for a managed target.
type TargetProfile struct {
	// Identity
	TargetID string `json:"target_id"`
	Name     string `json:"name"`

	// Type & mode
	TargetType string `json:"target_type"`
	Mode       string `json:"mode"` // "readonly" (default) or "ops-enabled"

	// State
	Enabled bool         `json:"enabled"`
	Status  TargetStatus `json:"status"`

	// Endpoint
	Endpoint string      `json:"endpoint"`
	TLS      TLSConfig   `json:"tls"`
	Proxy    ProxyConfig `json:"proxy,omitempty"`

	// Auth
	AuthType string `json:"auth_type,omitempty"` // api_token, username_password, etc.

	// Metadata
	Labels       map[string]string `json:"labels,omitempty"`
	Capabilities []string          `json:"capabilities,omitempty"`

	// Polling
	PollIntervalSecs int `json:"poll_interval_secs"`

	// Resource limits
	ResourceLimits ResourceLimits `json:"resource_limits,omitempty"`

	// Maintenance
	Paused            bool   `json:"paused"`
	MaintenanceReason string `json:"maintenance_reason,omitempty"`

	// Credentials
	CredentialRef          string `json:"credential_ref"`
	CredentialRotationDays int    `json:"credential_rotation_days"`

	// Versioning
	ConfigVersion int       `json:"config_version"`
	UpdatedAt     time.Time `json:"updated_at"`

	// Target-specific configuration (opaque to the host, interpreted by the adapter)
	TargetConfig map[string]interface{} `json:"target_config,omitempty"`

	// Worker runtime state (not persisted in profile, used in memory)
	workerState *WorkerState `json:"-"`
}

// TLSConfig holds per-target TLS settings.
type TLSConfig struct {
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	CACertPath         string `json:"ca_cert_path,omitempty"`
	ClientCertPath     string `json:"client_cert_path,omitempty"`
	ClientKeyPath      string `json:"client_key_path,omitempty"`
}

// ProxyConfig holds optional HTTP proxy settings for a target.
type ProxyConfig struct {
	HTTPProxy  string `json:"http_proxy,omitempty"`
	HTTPSProxy string `json:"https_proxy,omitempty"`
	NoProxy    string `json:"no_proxy,omitempty"`
}

// ResourceLimits constrains worker resource usage.
type ResourceLimits struct {
	MaxMemoryMB   int `json:"max_memory_mb,omitempty"`
	MaxResponseMB int `json:"max_response_mb,omitempty"`
	TimeoutSecs   int `json:"timeout_secs,omitempty"`
}

// ── Worker State ──

// WorkerStatus tracks the runtime state of a per-target worker.
type WorkerStatus string

const (
	WorkerStatusIdle     WorkerStatus = "idle"
	WorkerStatusStarting WorkerStatus = "starting"
	WorkerStatusRunning  WorkerStatus = "running"
	WorkerStatusStopped  WorkerStatus = "stopped"
	WorkerStatusDegraded WorkerStatus = "degraded"
	WorkerStatusPaused   WorkerStatus = "paused"
	WorkerStatusFailed   WorkerStatus = "failed"
	WorkerStatusStuck    WorkerStatus = "stuck"
)

// WorkerState holds runtime information about a worker.
type WorkerState struct {
	TargetID          string       `json:"target_id"`
	Status            WorkerStatus `json:"status"`
	LastCollectionAt  time.Time    `json:"last_collection_at"`
	LastErrorAt       time.Time    `json:"last_error_at"`
	LastError         string       `json:"last_error,omitempty"`
	ConsecutiveErrors int          `json:"consecutive_errors"`
	TotalCollections  int64        `json:"total_collections"`
	StartedAt         time.Time    `json:"started_at"`

	// Stage tracking — set at key points in collect()
	// Values: "idle" "scheduled" "connect"
	//         "fetch" "parse" "upload" "complete" "sleep"
	CurrentStage string `json:"current_stage,omitempty"`

	// LastProgressAt is updated at every stage transition.
	// The supervisor watchdog uses this to detect frozen workers.
	LastProgressAt time.Time `json:"last_progress_at"`

	// NextScheduledAt is set when the worker enters sleep.
	// The watchdog skips workers whose NextScheduledAt is
	// still in the future — they are intentionally idle.
	NextScheduledAt time.Time `json:"next_scheduled_at"`

	// RestartCount tracks how many watchdog-triggered restarts
	// have occurred. Used for escalation thresholds.
	RestartCount int `json:"restart_count"`

	// LastRestartAt is when the most recent watchdog restart fired.
	LastRestartAt time.Time `json:"last_restart_at,omitempty"`

	// CycleStartedAt is the time the current collect cycle began.
	CycleStartedAt time.Time `json:"cycle_started_at,omitempty"`
}

// RetryPolicy defines backoff behavior for workers.
type RetryPolicy struct {
	MaxConsecutiveErrors int           `json:"max_consecutive_errors"`
	InitialBackoff       time.Duration `json:"initial_backoff"`
	MaxBackoff           time.Duration `json:"max_backoff"`
	BackoffMultiplier    float64       `json:"backoff_multiplier"`
	FailedAfterErrors    int           `json:"failed_after_errors"`    // escalate degraded→failed after this many errors (0 = never)
	WatchdogTimeoutSecs  int           `json:"watchdog_timeout_secs"`  // kill collect() if it hangs longer than this (0 = 300s default)
}

// DefaultRetryPolicy returns production-safe defaults.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxConsecutiveErrors: 5,
		InitialBackoff:       10 * time.Second,
		MaxBackoff:           60 * time.Second, // Cap at 60s for faster recovery after outages
		BackoffMultiplier:    2.0,
		FailedAfterErrors:    20,
		WatchdogTimeoutSecs:  300,
	}
}

// ── Target-Specific Config Schemas ──

type ProxmoxTargetConfig struct {
	Username string `json:"username,omitempty"`
	TokenID  string `json:"token_id,omitempty"`
	Node     string `json:"node,omitempty"`
}

type TrueNASTargetConfig struct{}

type NutanixTargetConfig struct {
	Username  string `json:"username,omitempty"`
	ClusterID string `json:"cluster_id,omitempty"`
}

type OllamaTargetConfig struct{}

type PrometheusTargetConfig struct {
	ScrapeJobFilter string `json:"scrape_job_filter,omitempty"`
}

type GrafanaTargetConfig struct {
	DashboardTag string `json:"dashboard_tag,omitempty"`
	DashboardUID string `json:"dashboard_uid,omitempty"`
}

type GenericHTTPTargetConfig struct {
	Guardrails GenericHTTPGuardrails `json:"guardrails"`
	Headers    map[string]string     `json:"headers,omitempty"`
}

type PureStorageTargetConfig struct{}

type NetAppONTAPTargetConfig struct {
	Username string `json:"username,omitempty"`
}

type PowerStoreTargetConfig struct{}

type PowerMaxTargetConfig struct {
	SymmetrixID string `json:"symmetrix_id,omitempty"`
}

type PowerFlexTargetConfig struct{}

type GenericHTTPGuardrails struct {
	AllowedMethods   []string `json:"allowed_methods"`
	AllowedPaths     []string `json:"allowed_paths"`
	MaxResponseBytes int64    `json:"max_response_bytes"`
	TimeoutSecs      int      `json:"timeout_secs"`
	DenyPaths        []string `json:"deny_paths"`
}

func DefaultGenericHTTPGuardrails() GenericHTTPGuardrails {
	return GenericHTTPGuardrails{
		AllowedMethods:   []string{"GET", "HEAD", "OPTIONS"},
		AllowedPaths:     []string{},
		MaxResponseBytes: 1 * 1024 * 1024, // 1 MiB hard cap (Phase 2)
		TimeoutSecs:      10,              // 10s hard cap (Phase 2)
		DenyPaths:        []string{},
	}
}

// ── Signed Update Types ──
// Full implementation in updater.go. UpdateState kept here for HostState.

type UpdateState struct {
	CurrentVersion   string `json:"current_version"`
	AvailableVersion string `json:"available_version,omitempty"`
	LastCheckedAt    string `json:"last_checked_at,omitempty"`
	LastUpdateAt     string `json:"last_update_at,omitempty"`
	RollbackVersion  string `json:"rollback_version,omitempty"`
	UpdatePolicy     string `json:"update_policy"` // none, security, stable, beta
}

// ── Adapter Interface ──

type TargetAdapter interface {
	Init(profile *TargetProfile, creds map[string]string) error
	Collect() (map[string]interface{}, error)
	Capabilities() []string
	HealthCheck() error
	Close() error
}

type AdapterFactory func(profile *TargetProfile) (TargetAdapter, error)

// ── Host Capability Manifest ──
// Reports what this host binary actually supports at runtime.

// AdapterCapabilityInfo describes one registered adapter's capabilities.
type AdapterCapabilityInfo struct {
	TargetType   string   `json:"target_type"`
	Capabilities []string `json:"capabilities"`
	OpsSupported bool     `json:"ops_supported"` // always false in Phase 7
}

// HostCapabilityManifest is the runtime support report sent to the control plane.
type HostCapabilityManifest struct {
	AgentVersion       string                  `json:"agent_version"`
	SupportedAdapters  []AdapterCapabilityInfo  `json:"supported_adapters"`
	UpdatePolicy       string                  `json:"update_policy"`
	UpdateChannel      string                  `json:"update_channel,omitempty"`
	OpsEnabledRuntime  bool                    `json:"ops_enabled_runtime"` // false until ops is implemented
}

// ── Host State (persisted) ──

type HostState struct {
	Identity HostIdentity    `json:"identity"`
	Config   HostConfig      `json:"config"`
	Targets  []TargetProfile `json:"targets"`
	Update   UpdateState     `json:"update"`
	Version  int             `json:"version"`

	// Desired-state tracking
	LastSyncRevision int64     `json:"last_sync_revision,omitempty"`
	LastSyncAt       time.Time `json:"last_sync_at,omitempty"`
	LastAckStatus    string    `json:"last_ack_status,omitempty"`
}

// SupportedTargetTypes is now generated in supported_types_gen.go
// Source of truth: src/data/targetTypeRegistry.ts
// Regenerate:      npx tsx scripts/sync-target-types.ts

// IsValidTargetType checks if a target type is supported.
func IsValidTargetType(t string) bool {
	for _, valid := range SupportedTargetTypes {
		if t == valid {
			return true
		}
	}
	return false
}
