// ForgeAI Connector Host — Ollama Adapter (read-only)
//
// Collects model inventory, runtime health, and version info from
// a local Ollama instance. Designed for homelab AI server monitoring.
//
// Auth: typically none (local trusted). Optional header-based auth if
// Ollama is behind a reverse proxy.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type OllamaAdapter struct {
	profile *TargetProfile
	client  *http.Client
	baseURL string
	headers map[string]string
}

func NewOllamaAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &OllamaAdapter{profile: profile}, nil
}

func (a *OllamaAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	a.profile = profile
	a.baseURL = profile.Endpoint
	a.headers = make(map[string]string)

	timeout := 15 * time.Second
	if profile.ResourceLimits.TimeoutSecs > 0 {
		timeout = time.Duration(profile.ResourceLimits.TimeoutSecs) * time.Second
	}
	a.client = NewHTTPClientFromProfile(profile, timeout)

	// Optional header auth (for proxied setups)
	if name := creds["header_name"]; name != "" {
		a.headers[name] = creds["header_value"]
	}

	log.Printf("[ollama:%s] Verifying at %s...", profile.Name, a.baseURL)
	_, err := a.apiGet("/api/version")
	if err != nil {
		return fmt.Errorf("Ollama API verification failed: %w", err)
	}
	log.Printf("[ollama:%s] Connected", profile.Name)
	return nil
}

func (a *OllamaAdapter) Collect() (map[string]interface{}, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	version, _ := a.apiGet("/api/version")
	tags, _ := a.apiGet("/api/tags")
	ps, _ := a.apiGet("/api/ps")

	// Extract version string
	versionStr := ""
	if version != nil {
		if v, ok := version["version"].(string); ok {
			versionStr = v
		}
	}

	// Build runtime object matching OllamaSnapshotData.runtime
	healthy := versionStr != ""
	runtime := map[string]interface{}{
		"version":  versionStr,
		"healthy":  healthy,
		"endpoint": a.baseURL,
	}

	// Extract and normalize model list
	var models []interface{}
	if tags != nil {
		if m, ok := tags["models"].([]interface{}); ok {
			normalizedModels := make([]interface{}, 0, len(m))
			for _, raw := range m {
				if obj, ok := raw.(map[string]interface{}); ok {
					normalized := map[string]interface{}{
						"name":              obj["name"],
						"size":              obj["size"],
						"digest":            obj["digest"],
						"modifiedAt":        obj["modified_at"],
						"family":            getNestedDetail(obj, "family"),
						"parameterSize":     getNestedDetail(obj, "parameter_size"),
						"quantizationLevel": getNestedDetail(obj, "quantization_level"),
					}
					normalizedModels = append(normalizedModels, normalized)
				}
			}
			models = normalizedModels
		}
	}

	// Extract and normalize running models
	var running []interface{}
	if ps != nil {
		if m, ok := ps["models"].([]interface{}); ok {
			normalizedRunning := make([]interface{}, 0, len(m))
			for _, raw := range m {
				if obj, ok := raw.(map[string]interface{}); ok {
					normalized := map[string]interface{}{
						"name":      obj["name"],
						"size":      obj["size"],
						"digest":    obj["digest"],
						"expiresAt": obj["expires_at"],
						"sizeVram":  obj["size_vram"],
					}
					normalizedRunning = append(normalizedRunning, normalized)
				}
			}
			running = normalizedRunning
		}
	}

	snapshotData := map[string]interface{}{
		"runtime":       runtime,
		"models":        models,
		"runningModels": running,
		"summary": map[string]interface{}{
			"modelCount":   len(models),
			"runningCount": len(running),
		},
	}

	return map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": snapshotData,
		"alerts":       []map[string]interface{}{},
		"collectedAt":  now,
		"_signals":     extractOllamaSignals(snapshotData),
	}, nil
}

// extractOllamaSignals mirrors frontend signal rules for Hybrid Mode rollup.
func extractOllamaSignals(data map[string]interface{}) []SnapshotSignal {
	var sigs []SnapshotSignal

	if runtime, ok := data["runtime"].(map[string]interface{}); ok {
		if healthy, ok := runtime["healthy"].(bool); ok && !healthy {
			sigs = append(sigs, SnapshotSignal{
				Key: "runtime.unhealthy", Label: "Ollama runtime is unhealthy",
				Severity: "critical",
			})
			return sigs
		}
	}

	if models, ok := data["models"].([]interface{}); ok && len(models) == 0 {
		sigs = append(sigs, SnapshotSignal{
			Key: "models.empty", Label: "No models installed",
			Severity: "warning",
		})
	}

	return sigs
}

// getNestedDetail extracts a field from the Ollama "details" sub-object.
func getNestedDetail(obj map[string]interface{}, key string) interface{} {
	if details, ok := obj["details"].(map[string]interface{}); ok {
		return details[key]
	}
	return nil
}

func (a *OllamaAdapter) Capabilities() []string {
	return []string{
		"ollama.read.health",
		"ollama.read.models",
		"ollama.read.runtime",
	}
}

func (a *OllamaAdapter) HealthCheck() error {
	_, err := a.apiGet("/api/version")
	return err
}

func (a *OllamaAdapter) Close() error {
	a.client = nil
	return nil
}

func (a *OllamaAdapter) apiGet(path string) (map[string]interface{}, error) {
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
