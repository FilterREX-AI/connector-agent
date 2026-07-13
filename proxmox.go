// ForgeAI Local Connector — Proxmox Adapter
//
// Read-only Proxmox VE API client that collects node health, workloads,
// storage, and cluster status into a normalized snapshot.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ── Snapshot data models (matches backend schema) ──

type NodeSnapshot struct {
	Name         string   `json:"name"`
	Status       string   `json:"status"`
	CPU          *float64 `json:"cpu"`
	MemoryUsed   *int64   `json:"memory_used"`
	MemoryTotal  *int64   `json:"memory_total"`
	DiskUsed     *int64   `json:"disk_used"`
	DiskTotal    *int64   `json:"disk_total"`
	UptimeSecs   *int64   `json:"uptime_seconds"`
	PVEVersion   *string  `json:"pve_version"`
}

type WorkloadSnapshot struct {
	VMID        int      `json:"vmid"`
	Name        string   `json:"name"`
	Type        string   `json:"type"` // "qemu" or "lxc"
	Status      string   `json:"status"`
	Node        string   `json:"node"`
	CPU         *float64 `json:"cpu"`
	MemoryUsed  *int64   `json:"memory_used"`
	MemoryTotal *int64   `json:"memory_total"`
}

type StorageSnapshot struct {
	Storage string   `json:"storage"`
	Type    string   `json:"type"`
	Content []string `json:"content"`
	Shared  bool     `json:"shared"`
	Enabled bool     `json:"enabled"`
	Used    *int64   `json:"used"`
	Total   *int64   `json:"total"`
	Nodes   *string  `json:"nodes"`
}

type ClusterNodeInfo struct {
	Name   string `json:"name"`
	NodeID int    `json:"nodeid"`
	Online bool   `json:"online"`
}

type ClusterSnapshot struct {
	Name    *string           `json:"name"`
	Quorate bool             `json:"quorate"`
	Nodes   []ClusterNodeInfo `json:"nodes"`
	Votes   *int             `json:"votes"`
}

type AlertEntry struct {
	Severity string `json:"severity"`
	Source   string `json:"source"`
	Message  string `json:"message"`
	Field    string `json:"field,omitempty"`
}

type SnapshotData struct {
	Nodes       []NodeSnapshot     `json:"nodes"`
	Workloads   []WorkloadSnapshot `json:"workloads"`
	Storage     []StorageSnapshot  `json:"storage"`
	Cluster     *ClusterSnapshot   `json:"cluster,omitempty"`
	Alerts      []AlertEntry       `json:"alerts"`
	CollectedAt string             `json:"collected_at"`
}

// ── Proxmox client ──

type ProxmoxClient struct {
	cfg        *Config
	httpClient *http.Client
	ticket     string
	csrfToken  string
	ticketExp  time.Time
}

func NewProxmoxClient(cfg *Config) *ProxmoxClient {
	timeout := 90 * time.Second
	if cfg.TimeoutSecs > 0 {
		timeout = time.Duration(cfg.TimeoutSecs) * time.Second
	}
	tlsCfg := &TLSConfig{InsecureSkipVerify: cfg.InsecureSkipVerify}
	return &ProxmoxClient{
		cfg:        cfg,
		httpClient: NewHTTPClient(tlsCfg, nil, timeout),
	}
}

func (p *ProxmoxClient) IsTicketExpired() bool {
	return time.Now().After(p.ticketExp)
}

// Authenticate gets a PVE ticket using username/password
func (p *ProxmoxClient) Authenticate() error {
	form := url.Values{}
	form.Set("username", p.cfg.ProxmoxUsername)
	form.Set("password", p.cfg.ProxmoxPassword)

	resp, err := p.httpClient.PostForm(p.cfg.ProxmoxBaseURL+"/api2/json/access/ticket", form)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("auth HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Data struct {
			Ticket            string `json:"ticket"`
			CSRFPreventionToken string `json:"CSRFPreventionToken"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if result.Data.Ticket == "" {
		return fmt.Errorf("empty ticket in response")
	}

	p.ticket = result.Data.Ticket
	p.csrfToken = result.Data.CSRFPreventionToken
	p.ticketExp = time.Now().Add(90 * time.Minute) // PVE tickets last ~2h
	return nil
}

// apiGet makes an authenticated GET request to the Proxmox API
func (p *ProxmoxClient) apiGet(path string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", p.cfg.ProxmoxBaseURL+path, nil)
	if err != nil {
		return nil, err
	}

	if p.cfg.ProxmoxTokenID != "" {
		req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s",
			p.cfg.ProxmoxTokenID, p.cfg.ProxmoxTokenSecret))
	} else {
		req.Header.Set("Cookie", "PVEAuthCookie="+p.ticket)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GET %s HTTP %d: %s", path, resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return result, nil
}

// CollectSnapshot gathers all Proxmox data into a normalized snapshot
func (p *ProxmoxClient) CollectSnapshot() (*SnapshotData, error) {
	snap := &SnapshotData{
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
		Alerts:      []AlertEntry{},
	}

	// Nodes
	nodes, err := p.collectNodes()
	if err != nil {
		snap.Alerts = append(snap.Alerts, AlertEntry{
			Severity: "error", Source: "agent", Message: "Failed to collect nodes: " + err.Error(),
		})
		log.Printf("[collect] Node collection failed: %v", err)
	} else {
		snap.Nodes = nodes
	}

	// Workloads (VMs + CTs)
	workloads, err := p.collectWorkloads(snap.Nodes)
	if err != nil {
		snap.Alerts = append(snap.Alerts, AlertEntry{
			Severity: "warning", Source: "agent", Message: "Workload collection partial: " + err.Error(),
		})
		log.Printf("[collect] Workload collection issue: %v", err)
	}
	snap.Workloads = workloads

	// Storage
	storage, err := p.collectStorage()
	if err != nil {
		snap.Alerts = append(snap.Alerts, AlertEntry{
			Severity: "warning", Source: "agent", Message: "Storage collection failed: " + err.Error(),
		})
		log.Printf("[collect] Storage collection failed: %v", err)
	} else {
		snap.Storage = storage
	}

	// Cluster
	cluster, err := p.collectCluster()
	if err != nil {
		// Not an error — standalone nodes don't have cluster info
		log.Printf("[collect] Cluster info not available (standalone node likely): %v", err)
	} else {
		snap.Cluster = cluster
	}

	// Generate health alerts
	snap.Alerts = append(snap.Alerts, p.generateAlerts(snap)...)

	return snap, nil
}

func (p *ProxmoxClient) collectNodes() ([]NodeSnapshot, error) {
	result, err := p.apiGet("/api2/json/nodes")
	if err != nil {
		return nil, err
	}

	data, ok := result["data"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected nodes response format")
	}

	var nodes []NodeSnapshot
	for _, item := range data {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		name := getString(m, "node")
		if p.cfg.ProxmoxNode != "" && name != p.cfg.ProxmoxNode {
			continue
		}

		status := "unknown"
		if s := getString(m, "status"); s != "" {
			status = s
		}

		node := NodeSnapshot{
			Name:   name,
			Status: status,
		}

		if v, ok := getFloat(m, "cpu"); ok {
			node.CPU = &v
		}
		if v, ok := getInt(m, "mem"); ok {
			node.MemoryUsed = &v
		}
		if v, ok := getInt(m, "maxmem"); ok {
			node.MemoryTotal = &v
		}
		if v, ok := getInt(m, "disk"); ok {
			node.DiskUsed = &v
		}
		if v, ok := getInt(m, "maxdisk"); ok {
			node.DiskTotal = &v
		}
		if v, ok := getInt(m, "uptime"); ok {
			node.UptimeSecs = &v
		}

		// Get PVE version from node status
		if status == "online" {
			ver, err := p.getNodeVersion(name)
			if err == nil && ver != "" {
				node.PVEVersion = &ver
			}
		}

		nodes = append(nodes, node)
	}

	return nodes, nil
}

func (p *ProxmoxClient) getNodeVersion(nodeName string) (string, error) {
	result, err := p.apiGet(fmt.Sprintf("/api2/json/nodes/%s/version", nodeName))
	if err != nil {
		return "", err
	}
	data, ok := result["data"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("unexpected version format")
	}
	return getString(data, "version"), nil
}

func (p *ProxmoxClient) collectWorkloads(nodes []NodeSnapshot) ([]WorkloadSnapshot, error) {
	var allWorkloads []WorkloadSnapshot
	var lastErr error

	nodeNames := []string{}
	for _, n := range nodes {
		if n.Status == "online" {
			nodeNames = append(nodeNames, n.Name)
		}
	}

	for _, nodeName := range nodeNames {
		// VMs (QEMU)
		vms, err := p.collectNodeVMs(nodeName)
		if err != nil {
			lastErr = err
			log.Printf("[collect] VMs on %s: %v", nodeName, err)
		} else {
			allWorkloads = append(allWorkloads, vms...)
		}

		// Containers (LXC)
		cts, err := p.collectNodeCTs(nodeName)
		if err != nil {
			lastErr = err
			log.Printf("[collect] CTs on %s: %v", nodeName, err)
		} else {
			allWorkloads = append(allWorkloads, cts...)
		}
	}

	return allWorkloads, lastErr
}

func (p *ProxmoxClient) collectNodeVMs(nodeName string) ([]WorkloadSnapshot, error) {
	result, err := p.apiGet(fmt.Sprintf("/api2/json/nodes/%s/qemu", nodeName))
	if err != nil {
		return nil, err
	}

	data, ok := result["data"].([]interface{})
	if !ok {
		return nil, nil
	}

	var vms []WorkloadSnapshot
	for _, item := range data {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		vm := WorkloadSnapshot{
			Type: "qemu",
			Node: nodeName,
			Name: getString(m, "name"),
			Status: getString(m, "status"),
		}
		if v, ok := getInt(m, "vmid"); ok {
			vm.VMID = int(v)
		}
		if v, ok := getFloat(m, "cpu"); ok {
			vm.CPU = &v
		}
		if v, ok := getInt(m, "mem"); ok {
			vm.MemoryUsed = &v
		}
		if v, ok := getInt(m, "maxmem"); ok {
			vm.MemoryTotal = &v
		}
		vms = append(vms, vm)
	}
	return vms, nil
}

func (p *ProxmoxClient) collectNodeCTs(nodeName string) ([]WorkloadSnapshot, error) {
	result, err := p.apiGet(fmt.Sprintf("/api2/json/nodes/%s/lxc", nodeName))
	if err != nil {
		return nil, err
	}

	data, ok := result["data"].([]interface{})
	if !ok {
		return nil, nil
	}

	var cts []WorkloadSnapshot
	for _, item := range data {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		ct := WorkloadSnapshot{
			Type: "lxc",
			Node: nodeName,
			Name: getString(m, "name"),
			Status: getString(m, "status"),
		}
		if v, ok := getInt(m, "vmid"); ok {
			ct.VMID = int(v)
		}
		if v, ok := getFloat(m, "cpu"); ok {
			ct.CPU = &v
		}
		if v, ok := getInt(m, "mem"); ok {
			ct.MemoryUsed = &v
		}
		if v, ok := getInt(m, "maxmem"); ok {
			ct.MemoryTotal = &v
		}
		cts = append(cts, ct)
	}
	return cts, nil
}

func (p *ProxmoxClient) collectStorage() ([]StorageSnapshot, error) {
	result, err := p.apiGet("/api2/json/storage")
	if err != nil {
		return nil, err
	}

	data, ok := result["data"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected storage response format")
	}

	var storageList []StorageSnapshot
	for _, item := range data {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		contentStr := getString(m, "content")
		var content []string
		if contentStr != "" {
			content = strings.Split(contentStr, ",")
		}

		s := StorageSnapshot{
			Storage: getString(m, "storage"),
			Type:    getString(m, "type"),
			Content: content,
			Shared:  getBool(m, "shared"),
			Enabled: !getBool(m, "disable"), // PVE uses "disable" flag
		}

		if nodes := getString(m, "nodes"); nodes != "" {
			s.Nodes = &nodes
		}

		// Get usage from first available node's storage status
		storageList = append(storageList, s)
	}

	// Enrich with usage data from a node
	p.enrichStorageUsage(storageList)

	return storageList, nil
}

func (p *ProxmoxClient) enrichStorageUsage(storageList []StorageSnapshot) {
	// Get nodes to query storage status
	nodesResult, err := p.apiGet("/api2/json/nodes")
	if err != nil {
		return
	}
	data, ok := nodesResult["data"].([]interface{})
	if !ok || len(data) == 0 {
		return
	}
	// Use first online node
	for _, item := range data {
		m, ok := item.(map[string]interface{})
		if !ok || getString(m, "status") != "online" {
			continue
		}
		nodeName := getString(m, "node")

		nodeStorage, err := p.apiGet(fmt.Sprintf("/api2/json/nodes/%s/storage", nodeName))
		if err != nil {
			continue
		}
		nsData, ok := nodeStorage["data"].([]interface{})
		if !ok {
			continue
		}

		usageMap := map[string][2]int64{} // storage -> [used, total]
		for _, ns := range nsData {
			nsm, ok := ns.(map[string]interface{})
			if !ok {
				continue
			}
			name := getString(nsm, "storage")
			used, _ := getInt(nsm, "used")
			total, _ := getInt(nsm, "total")
			usageMap[name] = [2]int64{used, total}
		}

		for i := range storageList {
			if usage, ok := usageMap[storageList[i].Storage]; ok {
				u, t := usage[0], usage[1]
				storageList[i].Used = &u
				storageList[i].Total = &t
			}
		}
		break // one node is enough for cluster-wide storage
	}
}

func (p *ProxmoxClient) collectCluster() (*ClusterSnapshot, error) {
	result, err := p.apiGet("/api2/json/cluster/status")
	if err != nil {
		return nil, err
	}

	data, ok := result["data"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected cluster response")
	}

	cluster := &ClusterSnapshot{
		Nodes: []ClusterNodeInfo{},
	}

	for _, item := range data {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		itemType := getString(m, "type")

		if itemType == "cluster" {
			name := getString(m, "name")
			cluster.Name = &name
			if v, ok := getInt(m, "quorate"); ok {
				cluster.Quorate = v == 1
			}
			if v, ok := getInt(m, "nodes"); ok {
				vi := int(v)
				cluster.Votes = &vi
			}
		} else if itemType == "node" {
			nodeID := 0
			if v, ok := getInt(m, "nodeid"); ok {
				nodeID = int(v)
			}
			online := false
			if v, ok := getInt(m, "online"); ok {
				online = v == 1
			}
			cluster.Nodes = append(cluster.Nodes, ClusterNodeInfo{
				Name:   getString(m, "name"),
				NodeID: nodeID,
				Online: online,
			})
		}
	}

	if cluster.Name == nil && len(cluster.Nodes) == 0 {
		return nil, fmt.Errorf("no cluster data found (standalone node)")
	}

	return cluster, nil
}

// generateAlerts creates operator-friendly alerts from collected data
func (p *ProxmoxClient) generateAlerts(snap *SnapshotData) []AlertEntry {
	var alerts []AlertEntry

	for _, n := range snap.Nodes {
		if n.Status != "online" {
			alerts = append(alerts, AlertEntry{
				Severity: "error", Source: "health",
				Message: fmt.Sprintf("Node %s is %s", n.Name, n.Status),
				Field:   "node.status",
			})
		}
		if n.MemoryUsed != nil && n.MemoryTotal != nil && *n.MemoryTotal > 0 {
			pct := float64(*n.MemoryUsed) / float64(*n.MemoryTotal)
			if pct > 0.95 {
				alerts = append(alerts, AlertEntry{
					Severity: "error", Source: "health",
					Message: fmt.Sprintf("Node %s memory critical: %.1f%%", n.Name, pct*100),
					Field:   "node.memory",
				})
			} else if pct > 0.85 {
				alerts = append(alerts, AlertEntry{
					Severity: "warning", Source: "health",
					Message: fmt.Sprintf("Node %s memory high: %.1f%%", n.Name, pct*100),
					Field:   "node.memory",
				})
			}
		}
		if n.DiskUsed != nil && n.DiskTotal != nil && *n.DiskTotal > 0 {
			pct := float64(*n.DiskUsed) / float64(*n.DiskTotal)
			if pct > 0.9 {
				alerts = append(alerts, AlertEntry{
					Severity: "warning", Source: "health",
					Message: fmt.Sprintf("Node %s root disk high: %.1f%%", n.Name, pct*100),
					Field:   "node.disk",
				})
			}
		}
	}

	if snap.Cluster != nil && !snap.Cluster.Quorate {
		alerts = append(alerts, AlertEntry{
			Severity: "error", Source: "cluster",
			Message: "Cluster has lost quorum",
			Field:   "cluster.quorum",
		})
	}

	for _, s := range snap.Storage {
		if !s.Enabled {
			continue
		}
		if s.Used != nil && s.Total != nil && *s.Total > 0 {
			pct := float64(*s.Used) / float64(*s.Total)
			if pct > 0.95 {
				alerts = append(alerts, AlertEntry{
					Severity: "error", Source: "storage",
					Message: fmt.Sprintf("Storage %s nearly full: %.1f%%", s.Storage, pct*100),
					Field:   "storage.usage",
				})
			} else if pct > 0.85 {
				alerts = append(alerts, AlertEntry{
					Severity: "warning", Source: "storage",
					Message: fmt.Sprintf("Storage %s usage high: %.1f%%", s.Storage, pct*100),
					Field:   "storage.usage",
				})
			}
		}
	}

	return alerts
}

// ── Helpers ──

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func getFloat(m map[string]interface{}, key string) (float64, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

func getInt(m map[string]interface{}, key string) (int64, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}

func getBool(m map[string]interface{}, key string) bool {
	v, ok := m[key]
	if !ok {
		return false
	}
	switch b := v.(type) {
	case bool:
		return b
	case float64:
		return b != 0
	case int:
		return b != 0
	}
	return false
}
