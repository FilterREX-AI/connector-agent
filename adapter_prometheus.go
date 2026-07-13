// ForgeAI Connector Host — Prometheus Adapter (read-only)
//
// Collects target health, basic metadata, and runtime posture from
// a Prometheus server via its HTTP API. No admin mutations.
//
// Snapshot contract: the snapshotData object emitted by Collect()
// matches the canonical PrometheusSnapshotData shape expected by
// the frontend. All keys are camelCase, arrays are flat, and
// summaries are pre-computed.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type PrometheusAdapter struct {
	profile *TargetProfile
	client  *http.Client
	baseURL string
	headers map[string]string
}

func NewPrometheusAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &PrometheusAdapter{profile: profile}, nil
}

func (a *PrometheusAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	a.profile = profile
	a.baseURL = profile.Endpoint
	a.headers = make(map[string]string)

	timeout := 10 * time.Second
	if profile.ResourceLimits.TimeoutSecs > 0 {
		timeout = time.Duration(profile.ResourceLimits.TimeoutSecs) * time.Second
	}
	a.client = NewHTTPClientFromProfile(profile, timeout)

	// Auth: header-based or username/password (basic auth)
	if name := creds["header_name"]; name != "" {
		a.headers[name] = creds["header_value"]
	}
	if user := creds["username"]; user != "" {
		// Basic auth handled per-request
		a.headers["_basic_user"] = user
		a.headers["_basic_pass"] = creds["password"]
	}

	log.Printf("[prometheus:%s] Verifying at %s...", profile.Name, a.baseURL)
	_, err := a.apiGet("/api/v1/status/buildinfo")
	if err != nil {
		return fmt.Errorf("Prometheus API verification failed: %w", err)
	}
	log.Printf("[prometheus:%s] Connected", profile.Name)
	return nil
}

func (a *PrometheusAdapter) Collect() (map[string]interface{}, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	buildInfoRaw, _ := a.apiGet("/api/v1/status/buildinfo")
	runtimeInfoRaw, _ := a.apiGet("/api/v1/status/runtimeinfo")
	targetsRaw, _ := a.apiGet("/api/v1/targets?state=active")
	rulesRaw, _ := a.apiGet("/api/v1/rules?type=alert")

	// Normalize into the canonical PrometheusSnapshotData shape
	buildInfo := normalizeBuildInfo(buildInfoRaw)
	runtimeInfo := normalizeRuntimeInfo(runtimeInfoRaw)
	targets, targetSummary := normalizeTargets(targetsRaw)
	alertSummary, firingAlerts := normalizeAlertRules(rulesRaw)

	snapshotData := map[string]interface{}{
		"buildInfo":     buildInfo,
		"runtimeInfo":   runtimeInfo,
		"targets":       targets,
		"targetSummary": targetSummary,
		"alertSummary":  alertSummary,
		"firingAlerts":  firingAlerts,
	}

	return map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": snapshotData,
		"alerts":       firingAlerts,
		"collectedAt":  now,
	}, nil
}

func (a *PrometheusAdapter) Capabilities() []string {
	return []string{
		"prometheus.read.health",
		"prometheus.read.targets",
		"prometheus.read.alerts",
		"prometheus.read.metadata",
	}
}

func (a *PrometheusAdapter) HealthCheck() error {
	_, err := a.apiGet("/api/v1/status/buildinfo")
	return err
}

func (a *PrometheusAdapter) Close() error {
	a.client = nil
	return nil
}

func (a *PrometheusAdapter) apiGet(path string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range a.headers {
		if k[0] == '_' {
			continue // internal markers
		}
		req.Header.Set(k, v)
	}
	if user, ok := a.headers["_basic_user"]; ok && user != "" {
		req.SetBasicAuth(user, a.headers["_basic_pass"])
	}
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
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

// ── Normalizers: coerce raw Prometheus API responses into canonical shape ──

func normalizeBuildInfo(resp map[string]interface{}) map[string]interface{} {
	result := map[string]interface{}{
		"version":   nil,
		"revision":  nil,
		"branch":    nil,
		"goVersion": nil,
	}
	if resp == nil {
		return result
	}
	data := extractDataMap(resp)
	if data == nil {
		return result
	}
	result["version"] = data["version"]
	result["revision"] = data["revision"]
	result["branch"] = data["branch"]
	result["goVersion"] = data["goVersion"]
	return result
}

func normalizeRuntimeInfo(resp map[string]interface{}) map[string]interface{} {
	result := map[string]interface{}{
		"storageRetention":  nil,
		"tsdbDir":           nil,
		"walCompression":    nil,
		"alertmanagerCount": 0,
	}
	if resp == nil {
		return result
	}
	data := extractDataMap(resp)
	if data == nil {
		return result
	}
	if v, ok := data["storageRetention"]; ok {
		result["storageRetention"] = v
	}
	// TSDB info may be nested
	if tsdb, ok := data["TSDB"].(map[string]interface{}); ok {
		if dir, ok := tsdb["dir"]; ok {
			result["tsdbDir"] = dir
		}
		if wal, ok := tsdb["wal"].(map[string]interface{}); ok {
			if comp, ok := wal["compression"]; ok {
				result["walCompression"] = comp
			}
		}
	}
	// Count configured alertmanagers
	if amConfigured, ok := data["alertmanagersConfigured"].(float64); ok {
		result["alertmanagerCount"] = int(amConfigured)
	}
	return result
}

func normalizeTargets(resp map[string]interface{}) ([]map[string]interface{}, map[string]interface{}) {
	summary := map[string]interface{}{
		"totalUp":      0,
		"totalDown":    0,
		"totalUnknown": 0,
	}

	var targets []map[string]interface{}
	if resp == nil {
		return targets, summary
	}

	data := extractDataMap(resp)
	if data == nil {
		return targets, summary
	}

	active, _ := data["activeTargets"].([]interface{})
	up, down, unknown := 0, 0, 0
	for _, t := range active {
		tm, ok := t.(map[string]interface{})
		if !ok {
			continue
		}
		labels, _ := tm["labels"].(map[string]interface{})
		job := "unknown"
		if labels != nil {
			if j, ok := labels["job"].(string); ok {
				job = j
			}
		}

		healthRaw, _ := tm["health"].(string)
		health := "unknown"
		switch healthRaw {
		case "up":
			health = "up"
			up++
		case "down":
			health = "down"
			down++
		default:
			unknown++
		}

		scrapeUrl, _ := tm["scrapeUrl"].(string)
		lastError, _ := tm["lastError"].(string)

		targets = append(targets, map[string]interface{}{
			"job":       job,
			"health":    health,
			"scrapeUrl": scrapeUrl,
			"lastError": nilIfEmpty(lastError),
		})
	}

	summary["totalUp"] = up
	summary["totalDown"] = down
	summary["totalUnknown"] = unknown
	return targets, summary
}

func normalizeAlertRules(resp map[string]interface{}) (map[string]interface{}, []map[string]interface{}) {
	alertSummary := map[string]interface{}{
		"totalRules":  0,
		"firingCount": 0,
	}
	var firingAlerts []map[string]interface{}

	if resp == nil {
		return alertSummary, firingAlerts
	}

	data := extractDataMap(resp)
	if data == nil {
		return alertSummary, firingAlerts
	}

	groups, _ := data["groups"].([]interface{})
	totalRules, firingCount := 0, 0

	for _, g := range groups {
		gm, _ := g.(map[string]interface{})
		if gm == nil {
			continue
		}
		rules, _ := gm["rules"].([]interface{})
		for _, r := range rules {
			rm, _ := r.(map[string]interface{})
			if rm == nil {
				continue
			}
			totalRules++
			state, _ := rm["state"].(string)
			if state == "firing" {
				firingCount++
				name, _ := rm["name"].(string)
				labels, _ := rm["labels"].(map[string]interface{})
				severity := "warning"
				if labels != nil {
					if s, ok := labels["severity"].(string); ok {
						severity = s
					}
				}
				firingAlerts = append(firingAlerts, map[string]interface{}{
					"name":     name,
					"severity": severity,
					"state":    "firing",
					"message":  fmt.Sprintf("Alert firing: %s", name),
				})
			}
		}
	}

	alertSummary["totalRules"] = totalRules
	alertSummary["firingCount"] = firingCount
	return alertSummary, firingAlerts
}

// ── Helpers ──

func extractDataMap(resp map[string]interface{}) map[string]interface{} {
	if d, ok := resp["data"].(map[string]interface{}); ok {
		return d
	}
	return resp
}

func nilIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
