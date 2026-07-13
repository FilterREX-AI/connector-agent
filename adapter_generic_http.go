// ForgeAI Connector Host — Generic HTTP Adapter (read-only, sandboxed)
//
// The most constrained adapter. Enforces hard guardrails:
//   - Methods: GET / HEAD / OPTIONS only
//   - allowedPaths required
//   - Timeout <= 10s
//   - Response size <= 1 MiB
//   - No redirect to disallowed hosts
//
// Designed for simple health/status endpoint monitoring.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	ghMaxTimeout      = 10 * time.Second
	ghMaxResponseSize = 1 * 1024 * 1024 // 1 MiB
)

type GenericHTTPAdapter struct {
	profile    *TargetProfile
	client     *http.Client
	baseURL    string
	headers    map[string]string
	guardrails GenericHTTPGuardrails
	allowedRe  []*regexp.Regexp
}

func NewGenericHTTPAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &GenericHTTPAdapter{profile: profile}, nil
}

func (a *GenericHTTPAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	a.profile = profile
	a.baseURL = strings.TrimRight(profile.Endpoint, "/")
	a.headers = make(map[string]string)

	// Parse guardrails from target_config
	a.guardrails = DefaultGenericHTTPGuardrails()
	if tc := profile.TargetConfig; tc != nil {
		if gh, ok := tc["guardrails"]; ok {
			if ghMap, ok := gh.(map[string]interface{}); ok {
				if paths, ok := ghMap["allowed_paths"].([]interface{}); ok {
					a.guardrails.AllowedPaths = make([]string, 0, len(paths))
					for _, p := range paths {
						if s, ok := p.(string); ok {
							a.guardrails.AllowedPaths = append(a.guardrails.AllowedPaths, s)
						}
					}
				}
				if t, ok := ghMap["timeout_secs"].(float64); ok && int(t) <= 10 {
					a.guardrails.TimeoutSecs = int(t)
				}
				if m, ok := ghMap["max_response_bytes"].(float64); ok && int64(m) <= ghMaxResponseSize {
					a.guardrails.MaxResponseBytes = int64(m)
				}
			}
		}
		if hdrs, ok := tc["headers"].(map[string]interface{}); ok {
			for k, v := range hdrs {
				if s, ok := v.(string); ok {
					a.headers[k] = s
				}
			}
		}
	}

	// Validate guardrails
	if len(a.guardrails.AllowedPaths) == 0 {
		return fmt.Errorf("generic-http requires at least one allowed path pattern")
	}

	// Compile allowed path regexes
	a.allowedRe = make([]*regexp.Regexp, 0, len(a.guardrails.AllowedPaths))
	for _, p := range a.guardrails.AllowedPaths {
		re, err := regexp.Compile(p)
		if err != nil {
			return fmt.Errorf("invalid allowed_path regex %q: %w", p, err)
		}
		a.allowedRe = append(a.allowedRe, re)
	}

	// Auth
	if name := creds["header_name"]; name != "" {
		a.headers[name] = creds["header_value"]
	}
	if token := creds["api_token"]; token != "" {
		a.headers["Authorization"] = "Bearer " + token
	}

	timeout := time.Duration(a.guardrails.TimeoutSecs) * time.Second
	if timeout > ghMaxTimeout {
		timeout = ghMaxTimeout
	}

	// No-redirect client to prevent unexpected host access
	client := NewHTTPClientFromProfile(profile, timeout)
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// Only allow same-host redirects
		if len(via) > 0 {
			origHost := via[0].URL.Host
			if req.URL.Host != origHost {
				return fmt.Errorf("redirect to different host blocked: %s", req.URL.Host)
			}
		}
		if len(via) >= 3 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	}
	a.client = client

	log.Printf("[generic-http:%s] Configured with %d allowed paths, timeout %ds",
		profile.Name, len(a.guardrails.AllowedPaths), a.guardrails.TimeoutSecs)
	return nil
}

func (a *GenericHTTPAdapter) Collect() (map[string]interface{}, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	results := make([]map[string]interface{}, 0, len(a.guardrails.AllowedPaths))

	for _, pathPattern := range a.guardrails.AllowedPaths {
		// Use first path as-is if it looks like a concrete path
		path := pathPattern
		if strings.ContainsAny(path, ".*+?[](){}|\\^$") {
			// It's a regex — skip direct fetching, use as filter only
			continue
		}

		result := a.fetchPath(path)
		results = append(results, result)
	}

	// If we only had regex patterns, try a root health check
	if len(results) == 0 {
		results = append(results, a.fetchPath("/"))
	}

	snapshotData := map[string]interface{}{
		"endpoints": results,
		"summary": map[string]interface{}{
			"total_endpoints": len(results),
			"healthy":         countHealthy(results),
			"unhealthy":       len(results) - countHealthy(results),
		},
	}

	return map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": snapshotData,
		"alerts":       []map[string]interface{}{},
		"collectedAt":  now,
	}, nil
}

func (a *GenericHTTPAdapter) fetchPath(path string) map[string]interface{} {
	if !a.isPathAllowed(path) {
		return map[string]interface{}{
			"path":   path,
			"ok":     false,
			"error":  "path not in allowed list",
			"status": 0,
		}
	}

	fullURL := a.baseURL + path
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return map[string]interface{}{"path": path, "ok": false, "error": err.Error()}
	}
	for k, v := range a.headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := a.client.Do(req)
	latencyMs := time.Since(start).Milliseconds()

	if err != nil {
		return map[string]interface{}{
			"path": path, "ok": false, "error": err.Error(), "latency_ms": latencyMs,
		}
	}
	defer resp.Body.Close()

	maxBytes := a.guardrails.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = ghMaxResponseSize
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))

	result := map[string]interface{}{
		"path":       path,
		"status":     resp.StatusCode,
		"ok":         resp.StatusCode >= 200 && resp.StatusCode < 400,
		"latency_ms": latencyMs,
	}

	if int64(len(body)) > maxBytes {
		result["truncated"] = true
		body = body[:maxBytes]
	}

	// Try to parse as JSON, otherwise store as string summary
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "json") {
		var parsed interface{}
		if json.Unmarshal(body, &parsed) == nil {
			result["body"] = parsed
		} else {
			result["body_preview"] = string(body[:min(500, len(body))])
		}
	} else {
		result["content_type"] = ct
		result["body_size"] = len(body)
	}

	return result
}

func (a *GenericHTTPAdapter) isPathAllowed(path string) bool {
	parsed, err := url.Parse(path)
	if err != nil {
		return false
	}
	cleanPath := parsed.Path
	if cleanPath == "" {
		cleanPath = "/"
	}

	for _, re := range a.allowedRe {
		if re.MatchString(cleanPath) {
			return true
		}
	}
	return false
}

func countHealthy(results []map[string]interface{}) int {
	count := 0
	for _, r := range results {
		if ok, _ := r["ok"].(bool); ok {
			count++
		}
	}
	return count
}

func (a *GenericHTTPAdapter) Capabilities() []string {
	return []string{
		"generic-http.read.health",
		"generic-http.read.endpoints",
	}
}

func (a *GenericHTTPAdapter) HealthCheck() error {
	if len(a.guardrails.AllowedPaths) == 0 {
		return fmt.Errorf("no allowed paths configured")
	}
	path := a.guardrails.AllowedPaths[0]
	if strings.ContainsAny(path, ".*+?[](){}|\\^$") {
		path = "/"
	}
	result := a.fetchPath(path)
	if ok, _ := result["ok"].(bool); !ok {
		errMsg, _ := result["error"].(string)
		return fmt.Errorf("health check failed: %s", errMsg)
	}
	return nil
}

func (a *GenericHTTPAdapter) Close() error {
	a.client = nil
	return nil
}
