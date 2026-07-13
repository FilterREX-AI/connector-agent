// ForgeAI Connector Host — PowerFlex Adapter (read-only)
//
// Collects cluster/system health, storage capacity, alerts, and
// inventory from Dell PowerFlex (VxFlex OS) Gateway REST API.
// Produces normalized snapshot data aligned to the frontend
// PowerFlexSnapshotData model.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type PowerFlexAdapter struct {
	profile   *TargetProfile
	client    *http.Client
	baseURL   string
	authToken string
}

func NewPowerFlexAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &PowerFlexAdapter{profile: profile}, nil
}

func (a *PowerFlexAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	a.profile = profile
	a.baseURL = profile.Endpoint

	timeout := 15 * time.Second
	if profile.ResourceLimits.TimeoutSecs > 0 {
		timeout = time.Duration(profile.ResourceLimits.TimeoutSecs) * time.Second
	}
	a.client = NewHTTPClientFromProfile(profile, timeout)

	// PowerFlex uses POST /api/login with Basic auth to get a token
	username := creds["username"]
	password := creds["password"]
	if username != "" && password != "" {
		if err := a.authenticate(username, password); err != nil {
			return fmt.Errorf("PowerFlex authentication failed: %w", err)
		}
	}

	log.Printf("[powerflex:%s] Verifying API access at %s...", profile.Name, a.baseURL)
	_, err := a.apiGet("/api/version")
	if err != nil {
		return fmt.Errorf("PowerFlex API verification failed: %w", err)
	}
	log.Printf("[powerflex:%s] Connected", profile.Name)
	return nil
}

func (a *PowerFlexAdapter) authenticate(username, password string) error {
	payload, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	req, err := http.NewRequest("POST", a.baseURL+"/api/login", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(username, password)

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("login HTTP %d: %s", resp.StatusCode, string(body[:min(200, len(body))]))
	}

	token := string(bytes.Trim(body, "\""))
	if token != "" {
		a.authToken = token
	}
	return nil
}

func (a *PowerFlexAdapter) Collect() (map[string]interface{}, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	version, _ := a.apiGet("/api/version")
	systems, _ := a.apiGetList("/api/types/System/instances")
	sdsNodes, _ := a.apiGetList("/api/types/Sds/instances")
	sdcNodes, _ := a.apiGetList("/api/types/Sdc/instances")
	pools, _ := a.apiGetList("/api/types/StoragePool/instances")
	volumes, _ := a.apiGetList("/api/types/Volume/instances")
	devices, _ := a.apiGetList("/api/types/Device/instances")
	protectionDomains, _ := a.apiGetList("/api/types/ProtectionDomain/instances")
	alerts, _ := a.apiGetList("/api/types/Alert/instances")

	// Build normalized snapshot
	systemInfo := a.extractSystemInfo(version, systems)
	capacity := a.extractCapacity(systems)
	poolSummaries := a.extractStoragePools(pools)
	components := a.extractComponents(sdsNodes, sdcNodes, protectionDomains, pools, volumes, devices)
	alertList := a.extractAlerts(alerts)

	healthy := components["sdsDegraded"].(int) == 0 &&
		len(alertList) == 0 || !a.hasCriticalAlerts(alertList)

	criticalCount := 0
	for _, al := range alertList {
		if al["severity"] == "critical" {
			criticalCount++
		}
	}

	totalTB := float64(0)
	if tb, ok := capacity["totalCapacityBytes"].(float64); ok && tb > 0 {
		totalTB = tb / 1e12
	}

	summary := map[string]interface{}{
		"healthy":        healthy,
		"systemName":     systemInfo["systemName"],
		"version":        systemInfo["version"],
		"utilizationPct": capacity["utilizationPct"],
		"totalCapacityTB": totalTB,
		"sdsCount":       components["sdsCount"],
		"sdcCount":       components["sdcCount"],
		"activeAlerts":   len(alertList),
		"criticalAlerts": criticalCount,
	}

	snapshotData := map[string]interface{}{
		"system":       systemInfo,
		"capacity":     capacity,
		"storagePools": poolSummaries,
		"components":   components,
		"alerts":       alertList,
		"summary":      summary,
	}

	return map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": snapshotData,
		"alerts":       alertList,
		"collectedAt":  now,
	}, nil
}

func (a *PowerFlexAdapter) Capabilities() []string {
	return []string{
		"powerflex.read.health",
		"powerflex.read.capacity",
		"powerflex.read.alerts",
		"powerflex.read.inventory",
	}
}

func (a *PowerFlexAdapter) HealthCheck() error {
	_, err := a.apiGet("/api/version")
	return err
}

func (a *PowerFlexAdapter) Close() error {
	a.client = nil
	return nil
}

// ── Normalization helpers ──

func (a *PowerFlexAdapter) extractSystemInfo(version map[string]interface{}, systems []interface{}) map[string]interface{} {
	info := map[string]interface{}{
		"systemName": nil,
		"systemId":   nil,
		"version":    nil,
		"installId":  nil,
		"endpoint":   a.baseURL,
	}

	if version != nil {
		if v, ok := version["version"].(string); ok {
			info["version"] = v
		}
	}

	if len(systems) > 0 {
		if sys, ok := systems[0].(map[string]interface{}); ok {
			if n, ok := sys["name"].(string); ok {
				info["systemName"] = n
			}
			if id, ok := sys["id"].(string); ok {
				info["systemId"] = id
			}
			if iid, ok := sys["installId"].(string); ok {
				info["installId"] = iid
			}
			// Fallback version from system object
			if info["version"] == nil {
				if sv, ok := sys["mdmClusterState"].(string); ok {
					info["version"] = sv
				}
			}
		}
	}
	return info
}

func (a *PowerFlexAdapter) extractCapacity(systems []interface{}) map[string]interface{} {
	cap := map[string]interface{}{
		"totalCapacityBytes":         nil,
		"usedCapacityBytes":          nil,
		"freeCapacityBytes":          nil,
		"utilizationPct":             nil,
		"thinCapacityAllocatedBytes": nil,
		"spareCapacityBytes":         nil,
	}

	if len(systems) == 0 {
		return cap
	}

	sys, ok := systems[0].(map[string]interface{})
	if !ok {
		return cap
	}

	// PowerFlex reports capacity in KB in the system statistics
	totalKB := getFloatVal(sys, "maxCapacityInKb")
	usedKB := getFloatVal(sys, "capacityInUseInKb")
	spareKB := getFloatVal(sys, "spareCapacityInKb")
	thinKB := getFloatVal(sys, "thinCapacityAllocatedInKb")

	if totalKB > 0 {
		total := totalKB * 1024
		used := usedKB * 1024
		free := total - used
		cap["totalCapacityBytes"] = total
		cap["usedCapacityBytes"] = used
		cap["freeCapacityBytes"] = free
		if total > 0 {
			cap["utilizationPct"] = (used / total) * 100
		}
	}
	if spareKB > 0 {
		cap["spareCapacityBytes"] = spareKB * 1024
	}
	if thinKB > 0 {
		cap["thinCapacityAllocatedBytes"] = thinKB * 1024
	}

	return cap
}

func (a *PowerFlexAdapter) extractStoragePools(pools []interface{}) []map[string]interface{} {
	var result []map[string]interface{}
	for _, item := range pools {
		p, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		totalKB := getFloatVal(p, "maxCapacityInKb")
		usedKB := getFloatVal(p, "capacityInUseInKb")
		var utilizationPct interface{} = nil
		if totalKB > 0 {
			utilizationPct = (usedKB / totalKB) * 100
		}

		entry := map[string]interface{}{
			"id":                 getStringVal(p, "id"),
			"name":               getStringVal(p, "name"),
			"totalCapacityBytes": nilIfZero(totalKB * 1024),
			"usedCapacityBytes":  nilIfZero(usedKB * 1024),
			"utilizationPct":     utilizationPct,
			"mediaType":          getStringVal(p, "mediaType"),
			"state":              getStringVal(p, "persistentChecksumState"),
		}
		result = append(result, entry)
	}
	return result
}

func (a *PowerFlexAdapter) extractComponents(
	sdsNodes, sdcNodes, protectionDomains, pools, volumes, devices []interface{},
) map[string]interface{} {
	sdsHealthy, sdsDegraded := 0, 0
	for _, item := range sdsNodes {
		if s, ok := item.(map[string]interface{}); ok {
			state := getStringVal(s, "sdsState")
			if state == "Normal" || state == "normal" {
				sdsHealthy++
			} else {
				sdsDegraded++
			}
		}
	}

	sdcConnected, sdcDisconnected := 0, 0
	for _, item := range sdcNodes {
		if s, ok := item.(map[string]interface{}); ok {
			state := getStringVal(s, "sdcApproved")
			mdmState := getStringVal(s, "mdmConnectionState")
			if state == "true" && mdmState == "Connected" {
				sdcConnected++
			} else {
				sdcDisconnected++
			}
		}
	}

	return map[string]interface{}{
		"sdsCount":              len(sdsNodes),
		"sdsHealthy":            sdsHealthy,
		"sdsDegraded":           sdsDegraded,
		"sdcCount":              len(sdcNodes),
		"sdcConnected":          sdcConnected,
		"sdcDisconnected":       sdcDisconnected,
		"protectionDomainCount": len(protectionDomains),
		"storagePoolCount":      len(pools),
		"volumeCount":           len(volumes),
		"deviceCount":           len(devices),
	}
}

func (a *PowerFlexAdapter) extractAlerts(data []interface{}) []map[string]interface{} {
	if data == nil {
		return nil
	}
	var result []map[string]interface{}
	for _, item := range data {
		al, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		severity := "warning"
		if s := getStringVal(al, "severityString"); s != "" {
			switch s {
			case "CRITICAL", "critical":
				severity = "critical"
			case "WARNING", "warning":
				severity = "warning"
			default:
				severity = "info"
			}
		}

		result = append(result, map[string]interface{}{
			"severity":  severity,
			"alertType": getStringVal(al, "alertTypeString"),
			"message":   getStringVal(al, "alertTypeString"),
			"component": getStringVal(al, "objectType"),
			"startTime": getStringVal(al, "startTime"),
		})
	}
	return result
}

func (a *PowerFlexAdapter) hasCriticalAlerts(alerts []map[string]interface{}) bool {
	for _, al := range alerts {
		if al["severity"] == "critical" {
			return true
		}
	}
	return false
}

// ── HTTP helpers ──

func (a *PowerFlexAdapter) apiGet(path string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if a.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+a.authToken)
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

func (a *PowerFlexAdapter) apiGetList(path string) ([]interface{}, error) {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if a.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+a.authToken)
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

	var result []interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		var single map[string]interface{}
		if err2 := json.Unmarshal(body, &single); err2 == nil {
			return []interface{}{single}, nil
		}
		return nil, err
	}
	return result, nil
}

// ── Utility functions ──

func getStringVal(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getFloatVal(m map[string]interface{}, key string) float64 {
	if v, ok := m[key].(float64); ok {
		return v
	}
	return 0
}

func nilIfZero(v float64) interface{} {
	if v == 0 {
		return nil
	}
	return v
}
