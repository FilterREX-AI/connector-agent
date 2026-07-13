// ForgeAI Connector Host — Pure Storage Adapter (read-only)
//
// Collects array health, capacity posture, alerts, and system inventory
// from Pure Storage FlashArray via REST API v2.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type PureStorageAdapter struct {
	profile    *TargetProfile
	client     *http.Client
	baseURL    string
	authHeader string
	apiToken   string
}

func NewPureStorageAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &PureStorageAdapter{profile: profile}, nil
}

func (a *PureStorageAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	a.profile = profile
	a.baseURL = profile.Endpoint

	timeout := 15 * time.Second
	if profile.ResourceLimits.TimeoutSecs > 0 {
		timeout = time.Duration(profile.ResourceLimits.TimeoutSecs) * time.Second
	}
	a.client = NewHTTPClientFromProfile(profile, timeout)

	a.apiToken = creds["api_token"]

	// Authenticate — Pure Storage uses POST /api/login with api-token header
	if a.apiToken != "" {
		if err := a.authenticate(); err != nil {
			return fmt.Errorf("Pure Storage authentication failed: %w", err)
		}
	}

	log.Printf("[pure-storage:%s] Verifying API access at %s...", profile.Name, a.baseURL)
	_, err := a.apiGet("/api/2.0/arrays")
	if err != nil {
		return fmt.Errorf("Pure Storage API verification failed: %w", err)
	}
	log.Printf("[pure-storage:%s] Connected", profile.Name)
	return nil
}

func (a *PureStorageAdapter) authenticate() error {
	req, err := http.NewRequest("POST", a.baseURL+"/api/login", nil)
	if err != nil {
		return err
	}
	req.Header.Set("api-token", a.apiToken)

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("login HTTP %d: %s", resp.StatusCode, string(body[:min(200, len(body))]))
	}

	// Extract session token from response header
	if token := resp.Header.Get("x-auth-token"); token != "" {
		a.authHeader = token
	}
	return nil
}

func (a *PureStorageAdapter) Collect() (map[string]interface{}, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	arrays, _ := a.apiGet("/api/2.0/arrays")
	space, _ := a.apiGet("/api/2.0/arrays?space=true")
	controllers, _ := a.apiGet("/api/2.0/controllers")
	alerts, _ := a.apiGet("/api/2.0/alerts?flagged=true")

	snapshotData := map[string]interface{}{
		"arrays":      extractItems(arrays),
		"space":       extractItems(space),
		"controllers": extractItems(controllers),
	}

	alertList := extractPureAlerts(alerts)

	return map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": snapshotData,
		"alerts":       alertList,
		"collectedAt":  now,
	}, nil
}

func (a *PureStorageAdapter) Capabilities() []string {
	return []string{
		"pure.read.health",
		"pure.read.capacity",
		"pure.read.alerts",
		"pure.read.inventory",
	}
}

func (a *PureStorageAdapter) HealthCheck() error {
	_, err := a.apiGet("/api/2.0/arrays")
	return err
}

func (a *PureStorageAdapter) Close() error {
	a.client = nil
	return nil
}

func (a *PureStorageAdapter) apiGet(path string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if a.authHeader != "" {
		req.Header.Set("x-auth-token", a.authHeader)
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

func extractItems(data map[string]interface{}) []interface{} {
	if data == nil {
		return nil
	}
	if items, ok := data["items"].([]interface{}); ok {
		return items
	}
	return nil
}

func extractPureAlerts(data map[string]interface{}) []map[string]interface{} {
	if data == nil {
		return nil
	}
	items, ok := data["items"].([]interface{})
	if !ok {
		return nil
	}
	var alerts []map[string]interface{}
	for _, item := range items {
		if a, ok := item.(map[string]interface{}); ok {
			severity := "warning"
			if s, ok := a["severity"].(string); ok {
				severity = s
			}
			summary := ""
			if s, ok := a["summary"].(string); ok {
				summary = s
			}
			alerts = append(alerts, map[string]interface{}{
				"severity": severity,
				"source":   "pure-storage",
				"message":  summary,
			})
		}
	}
	return alerts
}
