// ForgeAI Connector Host — PowerStore Adapter (read-only)
//
// Collects appliance health, capacity posture, alerts, and inventory
// from Dell PowerStore REST API.

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

type PowerStoreAdapter struct {
	profile    *TargetProfile
	client     *http.Client
	baseURL    string
	authHeader string
}

func NewPowerStoreAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &PowerStoreAdapter{profile: profile}, nil
}

func (a *PowerStoreAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	a.profile = profile
	a.baseURL = profile.Endpoint

	timeout := 15 * time.Second
	if profile.ResourceLimits.TimeoutSecs > 0 {
		timeout = time.Duration(profile.ResourceLimits.TimeoutSecs) * time.Second
	}
	a.client = NewHTTPClientFromProfile(profile, timeout)

	// Auth: username/password via Basic auth
	username := creds["username"]
	password := creds["password"]
	if username != "" && password != "" {
		a.authHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	} else if token := creds["api_token"]; token != "" {
		a.authHeader = "Bearer " + token
	}

	log.Printf("[powerstore:%s] Verifying API access at %s...", profile.Name, a.baseURL)
	_, err := a.apiGet("/api/version")
	if err != nil {
		return fmt.Errorf("PowerStore API verification failed: %w", err)
	}
	log.Printf("[powerstore:%s] Connected", profile.Name)
	return nil
}

func (a *PowerStoreAdapter) Collect() (map[string]interface{}, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	cluster, _ := a.apiGet("/api/version")
	appliances, _ := a.apiGetList("/api/v1/appliance")
	capacity, _ := a.apiGetList("/api/v1/metrics/capacity/appliance")
	alerts, _ := a.apiGetList("/api/v1/alert?severity=neq.info")
	hardware, _ := a.apiGetList("/api/v1/hardware")

	snapshotData := map[string]interface{}{
		"version":    cluster,
		"appliances": appliances,
		"capacity":   capacity,
		"hardware":   hardware,
	}

	alertList := extractPowerStoreAlerts(alerts)

	return map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": snapshotData,
		"alerts":       alertList,
		"collectedAt":  now,
	}, nil
}

func (a *PowerStoreAdapter) Capabilities() []string {
	return []string{
		"powerstore.read.health",
		"powerstore.read.capacity",
		"powerstore.read.alerts",
		"powerstore.read.inventory",
	}
}

func (a *PowerStoreAdapter) HealthCheck() error {
	_, err := a.apiGet("/api/version")
	return err
}

func (a *PowerStoreAdapter) Close() error {
	a.client = nil
	return nil
}

func (a *PowerStoreAdapter) apiGet(path string) (map[string]interface{}, error) {
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

func (a *PowerStoreAdapter) apiGetList(path string) ([]interface{}, error) {
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

	var result []interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		// Might be a single object
		var single map[string]interface{}
		if err2 := json.Unmarshal(body, &single); err2 == nil {
			return []interface{}{single}, nil
		}
		return nil, err
	}
	return result, nil
}

func extractPowerStoreAlerts(data []interface{}) []map[string]interface{} {
	if data == nil {
		return nil
	}
	var alerts []map[string]interface{}
	for _, item := range data {
		if a, ok := item.(map[string]interface{}); ok {
			severity := "warning"
			if s, ok := a["severity"].(string); ok {
				severity = s
			}
			desc := ""
			if d, ok := a["description_l10n"].(string); ok {
				desc = d
			} else if d, ok := a["description"].(string); ok {
				desc = d
			}
			alerts = append(alerts, map[string]interface{}{
				"severity": severity,
				"source":   "powerstore",
				"message":  desc,
			})
		}
	}
	return alerts
}
