// ForgeAI Connector Host — Grafana Adapter (read-only)
//
// Collects health, datasource inventory, dashboard summary, and alert
// posture from Grafana via its HTTP API using a service-account token.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type GrafanaAdapter struct {
	profile *TargetProfile
	client  *http.Client
	baseURL string
	token   string
}

func NewGrafanaAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &GrafanaAdapter{profile: profile}, nil
}

func (a *GrafanaAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	a.profile = profile
	a.baseURL = profile.Endpoint

	timeout := 15 * time.Second
	if profile.ResourceLimits.TimeoutSecs > 0 {
		timeout = time.Duration(profile.ResourceLimits.TimeoutSecs) * time.Second
	}
	a.client = NewHTTPClientFromProfile(profile, timeout)

	// Auth: API token or header-based
	if t := creds["api_token"]; t != "" {
		a.token = t
	} else if v := creds["header_value"]; v != "" {
		a.token = v
	}

	log.Printf("[grafana:%s] Verifying at %s...", profile.Name, a.baseURL)
	_, err := a.apiGet("/api/health")
	if err != nil {
		return fmt.Errorf("Grafana API verification failed: %w", err)
	}
	log.Printf("[grafana:%s] Connected", profile.Name)
	return nil
}

func (a *GrafanaAdapter) Collect() (map[string]interface{}, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	health, _ := a.apiGet("/api/health")
	org, _ := a.apiGet("/api/org/")
	datasources, _ := a.apiGetArray("/api/datasources")
	dashboardSearch, _ := a.apiGetArray("/api/search?type=dash-db&limit=200")
	alertRules, _ := a.apiGetArray("/api/v1/provisioning/alert-rules")

	// Summarize
	dsCount := len(datasources)
	dbCount := len(dashboardSearch)
	alertCount := len(alertRules)

	firingAlerts := []map[string]interface{}{}
	for _, r := range alertRules {
		if rm, ok := r.(map[string]interface{}); ok {
			// Grafana alert rules don't have state in provisioning API
			// but we include them for posture summary
			_ = rm
		}
	}

	snapshotData := map[string]interface{}{
		"health":      health,
		"org":         org,
		"datasources": datasources,
		"dashboards":  dashboardSearch,
		"alertRules":  alertRules,
		"summary": map[string]interface{}{
			"datasource_count": dsCount,
			"dashboard_count":  dbCount,
			"alert_rule_count": alertCount,
		},
	}

	return map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": snapshotData,
		"alerts":       firingAlerts,
		"collectedAt":  now,
	}, nil
}

func (a *GrafanaAdapter) Capabilities() []string {
	return []string{
		"grafana.read.health",
		"grafana.read.datasources",
		"grafana.read.dashboards",
		"grafana.read.alerts",
	}
}

func (a *GrafanaAdapter) HealthCheck() error {
	_, err := a.apiGet("/api/health")
	return err
}

func (a *GrafanaAdapter) Close() error {
	a.client = nil
	return nil
}

func (a *GrafanaAdapter) apiGet(path string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
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

func (a *GrafanaAdapter) apiGetArray(path string) ([]interface{}, error) {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
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

	var result []interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result, nil
}
