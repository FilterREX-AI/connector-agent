// ForgeAI Local Connector — TrueNAS Adapter
//
// Read-only TrueNAS SCALE / CORE API client that collects ZFS pool health,
// datasets, snapshots, replication tasks, shares, and system alerts into
// a normalized snapshot matching the connector platform schema.
//
// Auth: Bearer token via API key (Settings → API Keys → Add in TrueNAS).

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// ── TrueNAS snapshot data models ──
// JSON tags MUST match the TypeScript TrueNAS*Snapshot interfaces in src/types/connector.ts

type TrueNASPoolSnapshot struct {
	Name               string  `json:"name"`
	GUID               string  `json:"guid"`
	Status             string  `json:"status"`             // online, degraded, faulted, offline
	Healthy            bool    `json:"healthy"`
	CapacityBytes      *int64  `json:"capacity_bytes"`
	UsedBytes          *int64  `json:"used_bytes"`
	FragmentationPct   *int64  `json:"fragmentation_pct"`
	LastScrubAt        string  `json:"last_scrub_at"`
	LastScrubErrors    *int64  `json:"last_scrub_errors"`
	ResilverInProgress bool    `json:"resilver_in_progress"`
	TopologySummary    string  `json:"topology_summary"`
}

type TrueNASVdev struct {
	Name   string `json:"name"`
	Type   string `json:"type"` // mirror, raidz1, raidz2, raidz3, stripe
	Status string `json:"status"`
	Disks  int    `json:"disks"`
}

type TrueNASDatasetSnapshot struct {
	Name          string `json:"name"`
	Pool          string `json:"pool"`
	Type          string `json:"type"` // filesystem, volume, snapshot
	UsedBytes     *int64 `json:"used_bytes"`
	AvailableBytes *int64 `json:"available_bytes"`
	QuotaBytes    *int64 `json:"quota_bytes"`
	Compression   string `json:"compression"`
	Dedup         bool   `json:"dedup"`
	MountPoint    string `json:"mountpoint"`
	RecordSize    *int64 `json:"record_size"`
	ATime         bool   `json:"atime"`
	SnapshotCount *int   `json:"snapshot_count"`
}

type TrueNASZFSSnapshotSummary struct {
	Dataset       string `json:"dataset"`
	SnapshotCount int    `json:"snapshot_count"`
	OldestName    string `json:"oldest_name,omitempty"`
	NewestName    string `json:"newest_name,omitempty"`
	TotalBytes    *int64 `json:"total_bytes"`
}

type TrueNASReplicationTask struct {
	ID             int      `json:"id"`
	Name           string   `json:"name"`
	Direction      string   `json:"direction"` // push, pull
	Transport      string   `json:"transport"` // SSH, LOCAL, LEGACY
	SourceDatasets []string `json:"source_datasets"`
	TargetDataset  string   `json:"target_dataset"`
	Enabled        bool     `json:"enabled"`
	State          string   `json:"state"`        // running, waiting, error, finished
	LastRunAt      string   `json:"last_run_at,omitempty"`
	LastRunOK      *bool    `json:"last_run_ok"`
	AutoSnap       bool     `json:"auto_snapshot"`
}

type TrueNASShareSnapshot struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Path    string `json:"path"`
	Type    string `json:"type"` // smb, nfs
	Enabled bool   `json:"enabled"`
	Comment string `json:"comment,omitempty"`
}

type TrueNASSystemInfo struct {
	Version    string `json:"version"`
	Hostname   string `json:"hostname"`
	Uptime     *int64 `json:"uptime_seconds"`
	Platform   string `json:"platform"` // SCALE or CORE
	Serial     string `json:"serial,omitempty"`
}

type TrueNASSnapshotData struct {
	System           *TrueNASSystemInfo            `json:"system"`
	Pools            []TrueNASPoolSnapshot         `json:"pools"`
	Datasets         []TrueNASDatasetSnapshot      `json:"datasets"`
	SnapshotTasks    []TrueNASZFSSnapshotSummary   `json:"snapshot_tasks"`
	ReplicationTasks []TrueNASReplicationTask       `json:"replication_tasks"`
	Shares           []TrueNASShareSnapshot         `json:"shares"`
	Alerts           []AlertEntry                   `json:"alerts"`
	CollectedAt      string                         `json:"collected_at"`
}

// ── TrueNAS client ──

type TrueNASClient struct {
	cfg        *Config
	httpClient *http.Client
}

func NewTrueNASClient(cfg *Config) *TrueNASClient {
	timeout := 30 * time.Second
	if cfg.TimeoutSecs > 0 {
		timeout = time.Duration(cfg.TimeoutSecs) * time.Second
	}
	if timeout > 30*time.Second {
		timeout = 30 * time.Second
	}
	tlsCfg := &TLSConfig{InsecureSkipVerify: cfg.InsecureSkipVerify}
	return &TrueNASClient{
		cfg:        cfg,
		httpClient: NewHTTPClient(tlsCfg, nil, timeout),
	}
}

// apiGet makes an authenticated GET to the TrueNAS REST API
func (t *TrueNASClient) apiGet(path string) (json.RawMessage, error) {
	base := strings.TrimRight(t.cfg.TrueNASURL, "/")
	// Avoid double-prefixing if endpoint already includes /api/v2.0
	if !strings.Contains(base, "/api/v2.0") {
		base += "/api/v2.0"
	}
	url := base + path
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+t.cfg.TrueNASAPIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	// Detect HTML responses (wrong endpoint or missing API prefix)
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "text/html") || (len(body) > 0 && body[0] == '<') {
		return nil, fmt.Errorf("GET %s: received HTML instead of JSON — verify the endpoint URL points to the TrueNAS host (e.g. https://truenas-ip), not the API path", path)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GET %s HTTP %d: %s", path, resp.StatusCode, string(body))
	}
	return json.RawMessage(body), nil
}

// CollectSnapshot gathers all TrueNAS data into a normalized snapshot
func (t *TrueNASClient) CollectSnapshot() (*TrueNASSnapshotData, error) {
	snap := &TrueNASSnapshotData{
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
		Alerts:      []AlertEntry{},
	}

	// System info
	sysInfo, err := t.collectSystemInfo()
	if err != nil {
		snap.Alerts = append(snap.Alerts, AlertEntry{
			Severity: "warning", Source: "agent",
			Message: "Failed to collect system info: " + err.Error(),
		})
		log.Printf("[truenas] System info failed: %v", err)
	} else {
		snap.System = sysInfo
	}

	// Pools
	pools, err := t.collectPools()
	if err != nil {
		snap.Alerts = append(snap.Alerts, AlertEntry{
			Severity: "error", Source: "agent",
			Message: "Failed to collect pools: " + err.Error(),
		})
		log.Printf("[truenas] Pool collection failed: %v", err)
	} else {
		snap.Pools = pools
	}

	// Datasets
	datasets, err := t.collectDatasets()
	if err != nil {
		snap.Alerts = append(snap.Alerts, AlertEntry{
			Severity: "warning", Source: "agent",
			Message: "Failed to collect datasets: " + err.Error(),
		})
		log.Printf("[truenas] Dataset collection failed: %v", err)
	} else {
		snap.Datasets = datasets
	}

	// ZFS Snapshots (summary)
	snapshots, err := t.collectSnapshotSummary()
	if err != nil {
		log.Printf("[truenas] Snapshot summary failed: %v", err)
	} else {
		snap.SnapshotTasks = snapshots
	}

	// Replication tasks
	repl, err := t.collectReplication()
	if err != nil {
		log.Printf("[truenas] Replication collection failed: %v", err)
	} else {
		snap.ReplicationTasks = repl
	}

	// Shares (SMB + NFS)
	shares, err := t.collectShares()
	if err != nil {
		log.Printf("[truenas] Share collection failed: %v", err)
	} else {
		snap.Shares = shares
	}

	// System alerts from TrueNAS
	sysAlerts, err := t.collectAlerts()
	if err != nil {
		log.Printf("[truenas] Alert collection failed: %v", err)
	} else {
		snap.Alerts = append(snap.Alerts, sysAlerts...)
	}

	// Generate health alerts from collected data
	snap.Alerts = append(snap.Alerts, t.generateAlerts(snap)...)

	return snap, nil
}

// ── Collectors ──

func (t *TrueNASClient) collectSystemInfo() (*TrueNASSystemInfo, error) {
	raw, err := t.apiGet("/system/info")
	if err != nil {
		return nil, err
	}

	var info map[string]interface{}
	if err := json.Unmarshal(raw, &info); err != nil {
		return nil, err
	}

	sys := &TrueNASSystemInfo{
		Version:  getString(info, "version"),
		Hostname: getString(info, "hostname"),
		Serial:   getString(info, "system_serial"),
	}

	if v, ok := getInt(info, "uptime_seconds"); ok {
		sys.Uptime = &v
	}
	// Detect SCALE vs CORE — lowercase to match TS contract
	if strings.Contains(strings.ToUpper(sys.Version), "SCALE") {
		sys.Platform = "SCALE"
	} else {
		sys.Platform = "CORE"
	}

	return sys, nil
}

func (t *TrueNASClient) collectPools() ([]TrueNASPoolSnapshot, error) {
	raw, err := t.apiGet("/pool")
	if err != nil {
		return nil, err
	}

	var poolsRaw []map[string]interface{}
	if err := json.Unmarshal(raw, &poolsRaw); err != nil {
		return nil, err
	}

	var pools []TrueNASPoolSnapshot
	for _, p := range poolsRaw {
		pool := TrueNASPoolSnapshot{
			Name:    getString(p, "name"),
			Status:  strings.ToLower(getString(p, "status")), // lowercase for TS
			Healthy: getBool(p, "healthy"),
			GUID:    getString(p, "guid"),
		}

		// Topology info — build summary string and track vdevs
		var vdevs []TrueNASVdev
		if topo, ok := p["topology"].(map[string]interface{}); ok {
			if dataVdevs, ok := topo["data"].([]interface{}); ok {
				for _, dv := range dataVdevs {
					if vd, ok := dv.(map[string]interface{}); ok {
						vdev := TrueNASVdev{
							Name:   getString(vd, "name"),
							Type:   getString(vd, "type"),
							Status: getString(vd, "status"),
						}
						if children, ok := vd["children"].([]interface{}); ok {
							vdev.Disks = len(children)
						}
						vdevs = append(vdevs, vdev)
					}
				}
			}
		}
		// Build topology_summary e.g. "2x MIRROR (4 disks)"
		pool.TopologySummary = buildTopologySummary(vdevs)

		// Scan info → last_scrub_at, last_scrub_errors, resilver_in_progress
		if scan, ok := p["scan"].(map[string]interface{}); ok {
			scanFunc := getString(scan, "function")
			scanState := getString(scan, "state")
			if errs, ok := getInt(scan, "errors"); ok {
				pool.LastScrubErrors = &errs
			}
			if scanFunc == "SCRUB" && scanState == "FINISHED" {
				if endTime := getString(scan, "end_time"); endTime != "" {
					pool.LastScrubAt = endTime
				}
			}
			if scanFunc == "RESILVER" && scanState == "SCANNING" {
				pool.ResilverInProgress = true
			}
		}

		// Size info
		if sizeVal, ok := p["size"]; ok {
			if size, ok := toInt64(sizeVal); ok {
				pool.CapacityBytes = &size
			}
		}
		if allocVal, ok := p["allocated"]; ok {
			if alloc, ok := toInt64(allocVal); ok {
				pool.UsedBytes = &alloc
			}
		}
		if fragVal, ok := p["fragmentation"]; ok {
			if frag, ok := toInt64(fragVal); ok {
				pool.FragmentationPct = &frag
			}
		}

		pools = append(pools, pool)
	}

	return pools, nil
}

// buildTopologySummary creates a human-readable summary like "2x MIRROR (4 disks)"
func buildTopologySummary(vdevs []TrueNASVdev) string {
	if len(vdevs) == 0 {
		return ""
	}
	// Group by type
	typeCounts := map[string]int{}
	totalDisks := 0
	for _, v := range vdevs {
		typeCounts[strings.ToUpper(v.Type)]++
		totalDisks += v.Disks
	}
	var parts []string
	for vtype, count := range typeCounts {
		if count > 1 {
			parts = append(parts, fmt.Sprintf("%dx %s", count, vtype))
		} else {
			parts = append(parts, vtype)
		}
	}
	summary := strings.Join(parts, " + ")
	if totalDisks > 0 {
		summary += fmt.Sprintf(" (%d disks)", totalDisks)
	}
	return summary
}

func (t *TrueNASClient) collectDatasets() ([]TrueNASDatasetSnapshot, error) {
	raw, err := t.apiGet("/pool/dataset")
	if err != nil {
		return nil, err
	}

	var dsRaw []map[string]interface{}
	if err := json.Unmarshal(raw, &dsRaw); err != nil {
		return nil, err
	}

	var datasets []TrueNASDatasetSnapshot
	for _, d := range dsRaw {
		ds := TrueNASDatasetSnapshot{
			Name:       getString(d, "name"),
			Pool:       getString(d, "pool"),
			Type:       strings.ToLower(getString(d, "type")), // lowercase for TS
			MountPoint: getString(d, "mountpoint"),
		}

		// TrueNAS returns nested property objects like {"value": "...", "rawvalue": "..."}
		ds.UsedBytes = getNestedInt(d, "used")
		ds.AvailableBytes = getNestedInt(d, "available")
		ds.QuotaBytes = getNestedInt(d, "quota")
		ds.RecordSize = getNestedInt(d, "recordsize")

		ds.Compression = getNestedString(d, "compression")

		// Convert dedup and atime strings to booleans
		dedupVal := getNestedString(d, "dedup")
		ds.Dedup = strings.EqualFold(dedupVal, "ON")

		atimeVal := getNestedString(d, "atime")
		ds.ATime = strings.EqualFold(atimeVal, "ON")

		datasets = append(datasets, ds)
	}

	return datasets, nil
}

func (t *TrueNASClient) collectSnapshotSummary() ([]TrueNASZFSSnapshotSummary, error) {
	raw, err := t.apiGet("/zfs/snapshot?limit=1000")
	if err != nil {
		return nil, err
	}

	var snapsRaw []map[string]interface{}
	if err := json.Unmarshal(raw, &snapsRaw); err != nil {
		return nil, err
	}

	// Group by dataset
	type snapInfo struct {
		names []string
		total int64
	}
	groups := map[string]*snapInfo{}

	for _, s := range snapsRaw {
		name := getString(s, "name") // dataset@snapname
		parts := strings.SplitN(name, "@", 2)
		if len(parts) != 2 {
			continue
		}
		dsName := parts[0]
		snapName := parts[1]

		if _, ok := groups[dsName]; !ok {
			groups[dsName] = &snapInfo{}
		}
		groups[dsName].names = append(groups[dsName].names, snapName)

		// Accumulate referenced bytes
		if props, ok := s["properties"].(map[string]interface{}); ok {
			if ref, ok := props["referenced"].(map[string]interface{}); ok {
				if rv, ok := ref["rawvalue"]; ok {
					if bytes, ok := toInt64(rv); ok {
						groups[dsName].total += bytes
					}
				}
			}
		}
	}

	var summaries []TrueNASZFSSnapshotSummary
	for ds, info := range groups {
		summary := TrueNASZFSSnapshotSummary{
			Dataset:       ds,
			SnapshotCount: len(info.names),
			TotalBytes:    &info.total,
		}
		if len(info.names) > 0 {
			summary.OldestName = info.names[0]
			summary.NewestName = info.names[len(info.names)-1]
		}
		summaries = append(summaries, summary)
	}

	return summaries, nil
}

func (t *TrueNASClient) collectReplication() ([]TrueNASReplicationTask, error) {
	raw, err := t.apiGet("/replication")
	if err != nil {
		return nil, err
	}

	var replRaw []map[string]interface{}
	if err := json.Unmarshal(raw, &replRaw); err != nil {
		return nil, err
	}

	var tasks []TrueNASReplicationTask
	for _, r := range replRaw {
		task := TrueNASReplicationTask{
			Name:      getString(r, "name"),
			Direction: strings.ToLower(getString(r, "direction")), // lowercase for TS
			Transport: getString(r, "transport"),
			Enabled:   getBool(r, "enabled"),
			AutoSnap:  getBool(r, "auto"),
		}

		if id, ok := getInt(r, "id"); ok {
			task.ID = int(id)
		}

		if srcDS, ok := r["source_datasets"].([]interface{}); ok {
			for _, ds := range srcDS {
				if s, ok := ds.(string); ok {
					task.SourceDatasets = append(task.SourceDatasets, s)
				}
			}
		}
		task.TargetDataset = getString(r, "target_dataset")

		// Job state
		if job, ok := r["job"].(map[string]interface{}); ok {
			task.State = strings.ToLower(getString(job, "state")) // lowercase for TS
			if ts := getString(job, "time_finished"); ts != "" {
				task.LastRunAt = ts
			}
			// Derive last_run_ok from job state
			jobState := getString(job, "state")
			if jobState != "" {
				ok := strings.EqualFold(jobState, "SUCCESS") || strings.EqualFold(jobState, "FINISHED")
				task.LastRunOK = &ok
			}
		} else {
			task.State = "idle"
		}

		tasks = append(tasks, task)
	}

	return tasks, nil
}

func (t *TrueNASClient) collectShares() ([]TrueNASShareSnapshot, error) {
	var shares []TrueNASShareSnapshot

	// SMB shares
	smbRaw, err := t.apiGet("/sharing/smb")
	if err != nil {
		log.Printf("[truenas] SMB share collection failed: %v", err)
	} else {
		var smbShares []map[string]interface{}
		if err := json.Unmarshal(smbRaw, &smbShares); err == nil {
			for _, s := range smbShares {
				share := TrueNASShareSnapshot{
					Name:    getString(s, "name"),
					Path:    getString(s, "path"),
					Type:    "smb",
					Enabled: getBool(s, "enabled"),
					Comment: getString(s, "comment"),
				}
				if id, ok := getInt(s, "id"); ok {
					share.ID = int(id)
				}
				shares = append(shares, share)
			}
		}
	}

	// NFS shares
	nfsRaw, err := t.apiGet("/sharing/nfs")
	if err != nil {
		log.Printf("[truenas] NFS share collection failed: %v", err)
	} else {
		var nfsShares []map[string]interface{}
		if err := json.Unmarshal(nfsRaw, &nfsShares); err == nil {
			for _, s := range nfsShares {
				// NFS shares can have multiple paths
				paths := []string{}
				if pathList, ok := s["paths"].([]interface{}); ok {
					for _, p := range pathList {
						if ps, ok := p.(string); ok {
							paths = append(paths, ps)
						}
					}
				}
				path := getString(s, "path")
				if path == "" && len(paths) > 0 {
					path = paths[0]
				}

				share := TrueNASShareSnapshot{
					Path:    path,
					Type:    "nfs",
					Enabled: getBool(s, "enabled"),
					Comment: getString(s, "comment"),
				}
				if id, ok := getInt(s, "id"); ok {
					share.ID = int(id)
					share.Name = fmt.Sprintf("nfs-%d", id)
				}
				shares = append(shares, share)
			}
		}
	}

	return shares, nil
}

func (t *TrueNASClient) collectAlerts() ([]AlertEntry, error) {
	raw, err := t.apiGet("/alert/list")
	if err != nil {
		return nil, err
	}

	var alertsRaw []map[string]interface{}
	if err := json.Unmarshal(raw, &alertsRaw); err != nil {
		return nil, err
	}

	var alerts []AlertEntry
	for _, a := range alertsRaw {
		level := strings.ToLower(getString(a, "level"))
		severity := "info"
		switch level {
		case "critical", "error":
			severity = "error"
		case "warning":
			severity = "warning"
		case "notice", "info":
			severity = "info"
		}

		// Skip dismissed alerts
		if getBool(a, "dismissed") {
			continue
		}

		alerts = append(alerts, AlertEntry{
			Severity: severity,
			Source:   "truenas",
			Message:  getString(a, "formatted"),
			Field:    getString(a, "klass"),
		})
	}

	return alerts, nil
}

// generateAlerts produces operator-friendly alerts from collected data
func (t *TrueNASClient) generateAlerts(snap *TrueNASSnapshotData) []AlertEntry {
	var alerts []AlertEntry

	for _, pool := range snap.Pools {
		// Pool health — compare lowercase values
		if pool.Status != "online" {
			alerts = append(alerts, AlertEntry{
				Severity: "error", Source: "health",
				Message: fmt.Sprintf("Pool %s is %s", pool.Name, pool.Status),
				Field:   "pool.status",
			})
		}
		if !pool.Healthy {
			alerts = append(alerts, AlertEntry{
				Severity: "error", Source: "health",
				Message: fmt.Sprintf("Pool %s reported unhealthy", pool.Name),
				Field:   "pool.healthy",
			})
		}

		// Capacity thresholds
		if pool.CapacityBytes != nil && pool.UsedBytes != nil && *pool.CapacityBytes > 0 {
			pct := float64(*pool.UsedBytes) / float64(*pool.CapacityBytes)
			if pct > 0.90 {
				alerts = append(alerts, AlertEntry{
					Severity: "error", Source: "storage",
					Message: fmt.Sprintf("Pool %s capacity critical: %.1f%%", pool.Name, pct*100),
					Field:   "pool.capacity",
				})
			} else if pct > 0.80 {
				alerts = append(alerts, AlertEntry{
					Severity: "warning", Source: "storage",
					Message: fmt.Sprintf("Pool %s capacity high: %.1f%%", pool.Name, pct*100),
					Field:   "pool.capacity",
				})
			}
		}

		// Fragmentation
		if pool.FragmentationPct != nil && *pool.FragmentationPct > 50 {
			sev := "warning"
			if *pool.FragmentationPct > 75 {
				sev = "error"
			}
			alerts = append(alerts, AlertEntry{
				Severity: sev, Source: "storage",
				Message: fmt.Sprintf("Pool %s fragmentation: %d%%", pool.Name, *pool.FragmentationPct),
				Field:   "pool.fragmentation",
			})
		}

		// Scan errors
		if pool.LastScrubErrors != nil && *pool.LastScrubErrors > 0 {
			alerts = append(alerts, AlertEntry{
				Severity: "error", Source: "storage",
				Message: fmt.Sprintf("Pool %s has %d scan errors", pool.Name, *pool.LastScrubErrors),
				Field:   "pool.scan_errors",
			})
		}
	}

	// Replication errors — compare lowercase
	for _, task := range snap.ReplicationTasks {
		if task.State == "error" && task.Enabled {
			alerts = append(alerts, AlertEntry{
				Severity: "error", Source: "replication",
				Message: fmt.Sprintf("Replication task '%s' in error state", task.Name),
				Field:   "replication.state",
			})
		}
	}

	return alerts
}

// ── Helpers ──

// getNestedString extracts the "value" from TrueNAS nested property objects
// e.g. {"compression": {"value": "lz4", "rawvalue": "lz4", ...}}
func getNestedString(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	// Try nested object first
	if obj, ok := v.(map[string]interface{}); ok {
		return getString(obj, "value")
	}
	// Fall back to plain string
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// getNestedInt extracts the "parsed" or "rawvalue" from TrueNAS nested property objects
func getNestedInt(m map[string]interface{}, key string) *int64 {
	v, ok := m[key]
	if !ok {
		return nil
	}
	// Try nested object
	if obj, ok := v.(map[string]interface{}); ok {
		if parsed, ok := obj["parsed"]; ok {
			if i, ok := toInt64(parsed); ok {
				return &i
			}
		}
		if raw, ok := obj["rawvalue"]; ok {
			if i, ok := toInt64(raw); ok {
				return &i
			}
		}
		if val, ok := obj["value"]; ok {
			if i, ok := toInt64(val); ok {
				return &i
			}
		}
	}
	// Try direct value
	if i, ok := toInt64(v); ok {
		return &i
	}
	return nil
}

// toInt64 converts various numeric types to int64
func toInt64(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int:
		return int64(n), true
	case int64:
		return n, true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	case string:
		// Try parsing numeric strings
		var i int64
		_, err := fmt.Sscanf(n, "%d", &i)
		return i, err == nil
	}
	return 0, false
}
