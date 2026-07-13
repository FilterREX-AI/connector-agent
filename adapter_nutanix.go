// ForgeAI Connector Host — Nutanix Adapter (read-only)
//
// Collects cluster health, host posture, storage containers, VM summary,
// and alerts from Nutanix Prism Central / Element via REST v2.

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type NutanixAdapter struct {
	profile  *TargetProfile
	client   *http.Client
	baseURL  string
	authHeader string
}

func NewNutanixAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &NutanixAdapter{profile: profile}, nil
}

func (a *NutanixAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	a.profile = profile
	a.baseURL = profile.Endpoint

	timeout := 15 * time.Second
	if profile.ResourceLimits.TimeoutSecs > 0 {
		timeout = time.Duration(profile.ResourceLimits.TimeoutSecs) * time.Second
	}
	a.client = NewHTTPClientFromProfile(profile, timeout)

	username := creds["username"]
	password := creds["password"]
	if username == "" {
		if tc := profile.TargetConfig; tc != nil {
			if v, ok := tc["username"].(string); ok {
				username = v
			}
		}
	}
	if username != "" && password != "" {
		a.authHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	} else if token := creds["service_token"]; token != "" {
		a.authHeader = "Bearer " + token
	}

	log.Printf("[nutanix:%s] Verifying API access at %s...", profile.Name, a.baseURL)
	_, err := a.apiGet("/api/nutanix/v2/cluster/")
	if err != nil {
		return fmt.Errorf("Nutanix API verification failed: %w", err)
	}
	log.Printf("[nutanix:%s] Connected", profile.Name)
	return nil
}

func (a *NutanixAdapter) Collect() (map[string]interface{}, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	// Define independent sub-collection tasks
	tasks := []SubCollectionTask{
		{Name: "cluster", Fn: func() (map[string]interface{}, error) {
			return a.apiGet("/api/nutanix/v2/cluster/")
		}},
		{Name: "hosts", Fn: func() (map[string]interface{}, error) {
			return a.apiGet("/api/nutanix/v2/hosts/")
		}},
		{Name: "containers", Fn: func() (map[string]interface{}, error) {
			return a.apiGet("/api/nutanix/v2/storage_containers/")
		}},
		{Name: "vms", Fn: func() (map[string]interface{}, error) {
			return a.apiGet("/api/nutanix/v2/vms/?include_vm_disk_config=false&include_vm_nic_config=false")
		}},
		{Name: "alerts", Fn: func() (map[string]interface{}, error) {
			return a.apiGet("/api/nutanix/v2/alerts/?resolved=false")
		}},
	}

	// Run with bounded concurrency (4 concurrent calls)
	result := RunConcurrentCollection(tasks, 4)

	// Log partial failures explicitly
	if len(result.FailedSections) > 0 {
		log.Printf("[nutanix:%s] Partial collection: %d/%d sections failed: %v",
			a.profile.Name, len(result.FailedSections), result.TotalSections, result.FailedSections)
	}

	// If everything failed, return error
	if result.Status() == "error" {
		return nil, fmt.Errorf("all %d sub-collections failed", result.TotalSections)
	}

	// Build snapshot from successful sections
	snapshotData := map[string]interface{}{}
	if cluster, ok := result.Sections["cluster"]; ok {
		snapshotData["cluster"] = cluster
	}
	if hosts, ok := result.Sections["hosts"]; ok {
		snapshotData["hosts"] = extractEntities(hosts.(map[string]interface{}))
	}
	if containers, ok := result.Sections["containers"]; ok {
		snapshotData["containers"] = extractEntities(containers.(map[string]interface{}))
	}
	if vms, ok := result.Sections["vms"]; ok {
		snapshotData["vms"] = extractEntities(vms.(map[string]interface{}))
	}

	// Add degraded marker if partial
	if marker := result.DegradedMarker(); marker != nil {
		snapshotData["_collection_status"] = marker
	}

	// Extract alerts from the alerts section
	var alertList []map[string]interface{}
	if alerts, ok := result.Sections["alerts"]; ok {
		alertList = extractAlerts(alerts.(map[string]interface{}))
	}

	return map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": snapshotData,
		"alerts":       alertList,
		"collectedAt":  now,
		"_subCalls":    result.SubCalls,
	}, nil
}

func (a *NutanixAdapter) Capabilities() []string {
	return []string{
		"nutanix.read.health",
		"nutanix.read.hosts",
		"nutanix.read.storage",
		"nutanix.read.workloads",
		"nutanix.read.alerts",
	}
}

func (a *NutanixAdapter) HealthCheck() error {
	_, err := a.apiGet("/api/nutanix/v2/cluster/")
	return err
}

func (a *NutanixAdapter) Close() error {
	a.client = nil
	return nil
}

func (a *NutanixAdapter) apiGet(path string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if a.authHeader != "" {
		req.Header.Set("Authorization", a.authHeader)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body[:min(200, len(body))]))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func extractEntities(data map[string]interface{}) []interface{} {
	if data == nil {
		return nil
	}
	if entities, ok := data["entities"].([]interface{}); ok {
		return entities
	}
	return nil
}

func extractAlerts(data map[string]interface{}) []map[string]interface{} {
	if data == nil {
		return nil
	}
	entities, ok := data["entities"].([]interface{})
	if !ok {
		return nil
	}
	var alerts []map[string]interface{}
	for _, e := range entities {
		if a, ok := e.(map[string]interface{}); ok {
			severity := "info"
			if s, ok := a["severity"].(string); ok {
				severity = s
			}
			message := ""
			if m, ok := a["message"].(string); ok {
				message = m
			}
			alerts = append(alerts, map[string]interface{}{
				"severity": severity,
				"source":   "nutanix",
				"message":  message,
			})
		}
	}
	return alerts
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
