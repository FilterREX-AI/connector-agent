// ForgeAI Connector Host — Proxmox Adapter (bridge)
//
// Wraps the existing ProxmoxClient to conform to the TargetAdapter interface.
// The actual Proxmox API logic remains in proxmox.go.

package main

import (
	"fmt"
	"log"
	"time"
)

// ProxmoxAdapter implements TargetAdapter for Proxmox VE targets.
type ProxmoxAdapter struct {
	client  *ProxmoxClient
	profile *TargetProfile
	cfg     *Config // legacy config bridge (temporary)
}

// NewProxmoxAdapter creates a ProxmoxAdapter from a target profile.
func NewProxmoxAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &ProxmoxAdapter{profile: profile}, nil
}

func (a *ProxmoxAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	// Build legacy Config from profile + creds for the existing ProxmoxClient
	cfg := &Config{
		ProxmoxBaseURL:     profile.Endpoint,
		InsecureSkipVerify: profile.TLS.InsecureSkipVerify,
		PollIntervalSecs:   profile.PollIntervalSecs,
	}

	// Extract target-specific config
	if tc := profile.TargetConfig; tc != nil {
		if v, ok := tc["username"].(string); ok {
			cfg.ProxmoxUsername = v
		}
		if v, ok := tc["token_id"].(string); ok {
			cfg.ProxmoxTokenID = v
		}
		if v, ok := tc["node"].(string); ok {
			cfg.ProxmoxNode = v
		}
	}

	// Extract credentials
	if v, ok := creds["password"]; ok {
		cfg.ProxmoxPassword = v
	}
	if v, ok := creds["token_secret"]; ok {
		cfg.ProxmoxTokenSecret = v
	}

	cfg.TimeoutSecs = profile.ResourceLimits.TimeoutSecs
	a.cfg = cfg
	a.client = NewProxmoxClient(cfg)

	// Authenticate if using username/password
	if cfg.ProxmoxTokenID == "" {
		log.Printf("[proxmox:%s] Authenticating as %s...", profile.Name, cfg.ProxmoxUsername)
		if err := a.client.Authenticate(); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
		log.Printf("[proxmox:%s] Authentication successful", profile.Name)
	} else {
		log.Printf("[proxmox:%s] Using API token: %s", profile.Name, cfg.ProxmoxTokenID)
		// Verify connectivity immediately so the worker fails fast
		// instead of waiting for 5 consecutive collection errors.
		if err := a.HealthCheck(); err != nil {
			return fmt.Errorf("initial connectivity check failed: %w", err)
		}
		log.Printf("[proxmox:%s] Connectivity verified", profile.Name)
	}

	return nil
}

func (a *ProxmoxAdapter) Collect() (map[string]interface{}, error) {
	// Re-authenticate if ticket expired
	if a.cfg.ProxmoxTokenID == "" && a.client.IsTicketExpired() {
		log.Printf("[proxmox:%s] Ticket expired, re-authenticating...", a.profile.Name)
		if err := a.client.Authenticate(); err != nil {
			return nil, fmt.Errorf("re-authentication failed: %w", err)
		}
	}

	snapshot, err := a.client.CollectSnapshot()
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": map[string]interface{}{
			"nodes":     snapshot.Nodes,
			"workloads": snapshot.Workloads,
			"storage":   snapshot.Storage,
			"cluster":   snapshot.Cluster,
		},
		"alerts":      snapshot.Alerts,
		"collectedAt": snapshot.CollectedAt,
		"_signals":    extractProxmoxSignals(snapshot.Nodes, snapshot.Cluster),
	}, nil
}

// extractProxmoxSignals mirrors frontend signal rules for Hybrid Mode rollup.
func extractProxmoxSignals(nodes []NodeSnapshot, cluster *ClusterSnapshot) []SnapshotSignal {
	var sigs []SnapshotSignal

	if cluster != nil && !cluster.Quorate {
		sigs = append(sigs, SnapshotSignal{
			Key: "cluster.no-quorum", Label: "Cluster has lost quorum",
			Severity: "critical",
		})
	}

	if cluster != nil {
		for _, cn := range cluster.Nodes {
			if !cn.Online {
				sigs = append(sigs, SnapshotSignal{
					Key: "cluster.node-offline",
					Label: fmt.Sprintf("Cluster node %s offline", cn.Name),
					Entity: cn.Name, Severity: "error",
				})
			}
		}
	}

	for _, n := range nodes {
		if n.Status != "online" {
			sigs = append(sigs, SnapshotSignal{
				Key: "node.offline",
				Label: fmt.Sprintf("Node %s is offline", n.Name),
				Entity: n.Name, Severity: "error",
			})
			continue
		}
		if n.CPU != nil && *n.CPU > 0.9 {
			sigs = append(sigs, SnapshotSignal{
				Key: "node.high-cpu",
				Label: fmt.Sprintf("Node %s CPU > 90%%", n.Name),
				Entity: n.Name, Value: fmt.Sprintf("%.0f%%", *n.CPU*100),
				Severity: "warning",
			})
		}
		if n.MemoryUsed != nil && n.MemoryTotal != nil && *n.MemoryTotal > 0 {
			pct := float64(*n.MemoryUsed) / float64(*n.MemoryTotal)
			if pct > 0.9 {
				sigs = append(sigs, SnapshotSignal{
					Key: "node.high-memory",
					Label: fmt.Sprintf("Node %s memory > 90%%", n.Name),
					Entity: n.Name, Value: fmt.Sprintf("%.0f%%", pct*100),
					Severity: "warning",
				})
			}
		}
	}

	return sigs
}

func (a *ProxmoxAdapter) Capabilities() []string {
	return []string{
		"proxmox.read.health",
		"proxmox.read.workloads",
		"proxmox.read.storage",
		"proxmox.read.cluster",
	}
}

func (a *ProxmoxAdapter) HealthCheck() error {
	if a.cfg.ProxmoxTokenID == "" && a.client.IsTicketExpired() {
		return a.client.Authenticate()
	}
	_, err := a.client.apiGet("/api2/json/version")
	return err
}

func (a *ProxmoxAdapter) Close() error {
	// ProxmoxClient has no persistent connections to close
	a.client = nil
	return nil
}

// ── Legacy bridge: keep old Config for proxmox.go compatibility ──

// The Config type is now only used as a bridge for the legacy
// ProxmoxClient and TrueNASClient. New adapters should not use it.
type Config struct {
	ConnectorToken     string
	BackendURL         string
	TargetType         string

	// Proxmox
	ProxmoxBaseURL     string
	ProxmoxUsername     string
	ProxmoxPassword    string
	ProxmoxTokenID     string
	ProxmoxTokenSecret string
	ProxmoxNode        string

	// TrueNAS
	TrueNASURL    string
	TrueNASAPIKey string

	// Common
	PollIntervalSecs   int
	InsecureSkipVerify bool
	LogLevel           string
	TimeoutSecs        int // 0 = use adapter default
}

// legacyConfigFromEnv builds a Config from environment variables for backward compatibility.
func legacyConfigFromEnv() *Config {
	return loadLegacyConfig()
}

// loadLegacyConfig reads the old single-target env config.
// Returns nil if no CONNECTOR_TOKEN is set (fresh host-mode install).
func loadLegacyConfig() *Config {
	c := &Config{}
	// This is populated by main.go only when running in legacy mode
	return c
}

// ProxmoxAdapterLastCollected is a helper for logging snapshot stats.
func ProxmoxAdapterLastCollected(snapshot *SnapshotData) string {
	return fmt.Sprintf("%d nodes, %d workloads, %d storage",
		len(snapshot.Nodes), len(snapshot.Workloads), len(snapshot.Storage))
}

// ── Re-export time for use in proxmox.go (already imported there) ──
var _ = time.Now // ensure time is used
