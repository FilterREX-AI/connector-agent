// ForgeAI Connector Host — Open WebUI Adapter (read-only)
//
// Collects service health, backend/provider posture, model inventory,
// and configuration from an Open WebUI instance. Designed for companion
// monitoring alongside Ollama in homelab AI stacks.
//
// Auth: Bearer API key or optional custom header auth for proxied setups.
// Endpoints: /api/version, /api/config, /api/models

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

type OpenWebuiAdapter struct {
	profile *TargetProfile
	client  *http.Client
	baseURL string
	headers map[string]string
}

func NewOpenwebuiAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &OpenWebuiAdapter{profile: profile}, nil
}

func (a *OpenWebuiAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	a.profile = profile
	a.baseURL = strings.TrimRight(profile.Endpoint, "/")
	a.headers = make(map[string]string)

	timeout := 15 * time.Second
	if profile.ResourceLimits.TimeoutSecs > 0 {
		timeout = time.Duration(profile.ResourceLimits.TimeoutSecs) * time.Second
	}
	a.client = NewHTTPClientFromProfile(profile, timeout)

	// Bearer token auth (primary)
	if apiKey := creds["api_key"]; apiKey != "" {
		a.headers["Authorization"] = "Bearer " + apiKey
	}

	// Optional custom header auth (for proxied setups)
	if name := creds["header_name"]; name != "" {
		a.headers[name] = creds["header_value"]
	}

	log.Printf("[open-webui:%s] Verifying at %s...", profile.Name, a.baseURL)
	_, err := a.apiGet("/api/version")
	if err != nil {
		return fmt.Errorf("Open WebUI API verification failed: %w", err)
	}
	log.Printf("[open-webui:%s] Connected", profile.Name)
	return nil
}

func (a *OpenWebuiAdapter) Collect() (map[string]interface{}, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	// Collect from all endpoints; degrade gracefully on failures
	versionData, versionErr := a.apiGet("/api/version")
	configData, _ := a.apiGet("/api/config")
	modelsData, _ := a.apiGetArray("/api/models")

	healthy := versionErr == nil

	// ── service ──
	version := ""
	if versionData != nil {
		if v, ok := versionData["version"].(string); ok {
			version = v
		}
	}
	service := map[string]interface{}{
		"version":  version,
		"healthy":  healthy,
		"endpoint": a.baseURL,
	}

	// ── models ──
	var models []map[string]interface{}
	ownerCounts := make(map[string]int)
	for _, raw := range modelsData {
		m, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		id, _ := m["id"].(string)
		name, _ := m["name"].(string)
		ownedBy, _ := m["owned_by"].(string)
		if id == "" && name == "" {
			continue
		}
		models = append(models, map[string]interface{}{
			"id":       id,
			"name":     name,
			"owned_by": ownedBy,
		})
		if ownedBy != "" {
			ownerCounts[ownedBy]++
		}
	}
	if models == nil {
		models = []map[string]interface{}{}
	}

	// ── backends (inferred from model owners + config) ──
	backends := a.inferBackends(ownerCounts, configData)

	backendsHealthy := 0
	for _, b := range backends {
		if h, ok := b["healthy"].(bool); ok && h {
			backendsHealthy++
		}
	}

	// ── config ──
	config := a.extractConfig(configData)

	// ── summary ──
	summary := map[string]interface{}{
		"backendCount":    len(backends),
		"modelCount":      len(models),
		"backendsHealthy": backendsHealthy,
	}

	snapshotData := map[string]interface{}{
		"service":  service,
		"backends": backends,
		"models":   models,
		"config":   config,
		"summary":  summary,
	}

	return map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": snapshotData,
		"alerts":       []map[string]interface{}{},
		"collectedAt":  now,
		"_signals":     extractOpenWebuiSignals(snapshotData),
	}, nil
}

// extractOpenWebuiSignals mirrors frontend signal rules for Hybrid Mode rollup.
func extractOpenWebuiSignals(data map[string]interface{}) []SnapshotSignal {
	var sigs []SnapshotSignal

	if service, ok := data["service"].(map[string]interface{}); ok {
		if healthy, ok := service["healthy"].(bool); ok && !healthy {
			sigs = append(sigs, SnapshotSignal{
				Key: "service.unhealthy", Label: "Open WebUI service is unhealthy",
				Severity: "critical",
			})
			return sigs
		}
	}

	if models, ok := data["models"].([]map[string]interface{}); ok && len(models) == 0 {
		sigs = append(sigs, SnapshotSignal{
			Key: "models.empty", Label: "No models available",
			Severity: "warning",
		})
	}

	return sigs
}

func (a *OpenWebuiAdapter) Capabilities() []string {
	return []string{
		"openwebui.read.health",
		"openwebui.read.backends",
		"openwebui.read.models",
	}
}

func (a *OpenWebuiAdapter) HealthCheck() error {
	_, err := a.apiGet("/api/version")
	return err
}

func (a *OpenWebuiAdapter) Close() error {
	a.client = nil
	return nil
}

// ── Internal helpers ──

// inferBackends derives backend/provider entries from model ownership
// and config data since Open WebUI doesn't expose a dedicated backends
// endpoint in all versions.
func (a *OpenWebuiAdapter) inferBackends(ownerCounts map[string]int, configData map[string]interface{}) []map[string]interface{} {
	var backends []map[string]interface{}
	seen := make(map[string]bool)

	// Infer from model owners (e.g., "ollama", "openai")
	for owner := range ownerCounts {
		key := strings.ToLower(owner)
		if seen[key] {
			continue
		}
		seen[key] = true
		backends = append(backends, map[string]interface{}{
			"type":    key,
			"url":     "",
			"healthy": true, // models returned = backend reachable
			"name":    owner,
		})
	}

	// Check config for OLLAMA_BASE_URL or OPENAI_API_BASE_URL hints
	if configData != nil {
		if ollamaURL, ok := configData["ollama_base_url"].(string); ok && ollamaURL != "" && !seen["ollama"] {
			seen["ollama"] = true
			backends = append(backends, map[string]interface{}{
				"type":    "ollama",
				"url":     ollamaURL,
				"healthy": len(ownerCounts) > 0, // heuristic
				"name":    "Ollama",
			})
		}
	}

	if backends == nil {
		backends = []map[string]interface{}{}
	}
	return backends
}

// extractConfig pulls auth/signup/default-model settings from the config
// response, degrading gracefully when fields are absent.
func (a *OpenWebuiAdapter) extractConfig(configData map[string]interface{}) map[string]interface{} {
	cfg := map[string]interface{}{
		"authEnabled":   true,  // default assumption
		"signupEnabled": false, // conservative default
		"defaultModel":  "",
	}

	if configData == nil {
		return cfg
	}

	// Open WebUI config shape varies by version; try known keys
	if features, ok := configData["features"].(map[string]interface{}); ok {
		if auth, ok := features["auth"].(bool); ok {
			cfg["authEnabled"] = auth
		}
		if signup, ok := features["enable_signup"].(bool); ok {
			cfg["signupEnabled"] = signup
		}
	}
	// Fallback: top-level keys used in some versions
	if auth, ok := configData["auth"].(bool); ok {
		cfg["authEnabled"] = auth
	}
	if signup, ok := configData["enable_signup"].(bool); ok {
		cfg["signupEnabled"] = signup
	}
	if dm, ok := configData["default_models"].(string); ok && dm != "" {
		cfg["defaultModel"] = dm
	}

	return cfg
}

// apiGet performs a GET request and decodes the response as a JSON object.
func (a *OpenWebuiAdapter) apiGet(path string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range a.headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
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

// apiGetArray performs a GET request and decodes the response as a JSON
// array. Falls back to extracting a "data" key if the top-level response
// is an object (Open WebUI wraps model lists this way in some versions).
func (a *OpenWebuiAdapter) apiGetArray(path string) ([]interface{}, error) {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range a.headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body[:min(200, len(body))]))
	}

	// Try array first
	var arr []interface{}
	if err := json.Unmarshal(body, &arr); err == nil {
		return arr, nil
	}

	// Fall back to object with "data" key
	var obj map[string]interface{}
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, err
	}
	if data, ok := obj["data"].([]interface{}); ok {
		return data, nil
	}
	// Try "models" key as another common wrapper
	if models, ok := obj["models"].([]interface{}); ok {
		return models, nil
	}
	return nil, fmt.Errorf("unexpected response shape for %s", path)
}
