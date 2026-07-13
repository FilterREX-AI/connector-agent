// ForgeAI Connector Host — TrueNAS Adapter (bridge)
//
// Wraps the existing TrueNASClient to conform to the TargetAdapter interface.
// The actual TrueNAS API logic remains in truenas.go.

package main

import (
	"fmt"
	"log"
)

// TrueNASAdapter implements TargetAdapter for TrueNAS SCALE/CORE targets.
type TrueNASAdapter struct {
	client  *TrueNASClient
	profile *TargetProfile
	cfg     *Config
}

// NewTrueNASAdapter creates a TrueNASAdapter from a target profile.
func NewTrueNASAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &TrueNASAdapter{profile: profile}, nil
}

func (a *TrueNASAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	cfg := &Config{
		TrueNASURL:         profile.Endpoint,
		InsecureSkipVerify: profile.TLS.InsecureSkipVerify,
		PollIntervalSecs:   profile.PollIntervalSecs,
		TimeoutSecs:        profile.ResourceLimits.TimeoutSecs,
	}

	// Extract credentials — UI stores as "api_token", legacy uses "api_key"
	if v, ok := creds["api_token"]; ok && v != "" {
		cfg.TrueNASAPIKey = v
	} else if v, ok := creds["api_key"]; ok && v != "" {
		cfg.TrueNASAPIKey = v
	} else {
		return fmt.Errorf("missing TrueNAS API token — expected credential key 'api_token' (or legacy 'api_key')")
	}

	a.cfg = cfg
	a.client = NewTrueNASClient(cfg)

	// Verify connectivity
	log.Printf("[truenas:%s] Verifying API access...", profile.Name)
	sysInfo, err := a.client.collectSystemInfo()
	if err != nil {
		return fmt.Errorf("API access verification failed: %w", err)
	}
	log.Printf("[truenas:%s] Connected to %s (%s) — %s",
		profile.Name, sysInfo.Hostname, sysInfo.Platform, sysInfo.Version)

	return nil
}

func (a *TrueNASAdapter) Collect() (map[string]interface{}, error) {
	snapshot, err := a.client.CollectSnapshot()
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": map[string]interface{}{
			"system":            snapshot.System,
			"pools":             snapshot.Pools,
			"datasets":          snapshot.Datasets,
			"snapshot_tasks":    snapshot.SnapshotTasks,
			"replication_tasks": snapshot.ReplicationTasks,
			"shares":            snapshot.Shares,
		},
		"alerts":      snapshot.Alerts,
		"collectedAt": snapshot.CollectedAt,
		"_signals":    extractTruenasSignals(snapshot.Pools, snapshot.ReplicationTasks),
	}, nil
}

// extractTruenasSignals mirrors frontend signal rules for Hybrid Mode rollup.
func extractTruenasSignals(pools []TrueNASPoolSnapshot, replTasks []TrueNASReplicationTask) []SnapshotSignal {
	var sigs []SnapshotSignal

	for _, p := range pools {
		switch p.Status {
		case "DEGRADED":
			sigs = append(sigs, SnapshotSignal{
				Key: "pool.degraded", Label: fmt.Sprintf("Pool %s is degraded", p.Name),
				Entity: p.Name, Severity: "error",
			})
		case "FAULTED", "OFFLINE", "REMOVED", "UNAVAIL":
			sigs = append(sigs, SnapshotSignal{
				Key: "pool.faulted", Label: fmt.Sprintf("Pool %s is faulted", p.Name),
				Entity: p.Name, Severity: "critical",
			})
		}
		if p.ResilverInProgress {
			sigs = append(sigs, SnapshotSignal{
				Key: "pool.resilvering", Label: fmt.Sprintf("Pool %s resilver in progress", p.Name),
				Entity: p.Name, Severity: "warning",
			})
		}
		if p.CapacityBytes != nil && p.UsedBytes != nil && *p.CapacityBytes > 0 {
			pct := int(float64(*p.UsedBytes) / float64(*p.CapacityBytes) * 100)
			if pct >= 80 {
				sigs = append(sigs, SnapshotSignal{
					Key: "pool.high-usage",
					Label: fmt.Sprintf("Pool %s at %d%% capacity", p.Name, pct),
					Entity: p.Name, Value: fmt.Sprintf("%d", pct), Severity: "warning",
				})
			}
		}
	}

	for _, r := range replTasks {
		if !r.Enabled {
			continue
		}
		if r.LastRunOK != nil && !*r.LastRunOK {
			sigs = append(sigs, SnapshotSignal{
				Key: "replication.failed",
				Label: fmt.Sprintf("Replication task %q failed", r.Name),
				Entity: r.Name, Severity: "error",
			})
		}
	}

	return sigs
}

func (a *TrueNASAdapter) Capabilities() []string {
	return []string{
		"truenas.read.health",
		"truenas.read.pools",
		"truenas.read.datasets",
		"truenas.read.snapshots",
		"truenas.read.replication",
		"truenas.read.shares",
		"truenas.read.alerts",
	}
}

func (a *TrueNASAdapter) HealthCheck() error {
	_, err := a.client.collectSystemInfo()
	return err
}

func (a *TrueNASAdapter) Close() error {
	a.client = nil
	return nil
}
