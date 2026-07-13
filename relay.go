// ForgeAI Connector Host — Relay Execution Handler
//
// Handles live API relay commands received from the cloud via
// the desired-state polling loop. The agent executes the operation
// locally against the LAN-accessible target and posts the result
// back via the connector-api-response edge function.
//
// This file defines the relay handler, platform executor dispatch,
// and the response posting logic.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	defaultRelayResponsePath = "/functions/v1/connector-api-response"
)

// RelayCommand is a pending API execution command from the cloud.
type RelayCommand struct {
	ID              string                 `json:"id"`
	Method          string                 `json:"method"`
	Path            string                 `json:"path"`
	Body            map[string]interface{} `json:"body,omitempty"`
	Platform        string                 `json:"platform"`
	OperationID     string                 `json:"operation_id,omitempty"`
	TargetProfileID string                 `json:"target_profile_id"`
	SafetyLevel     string                 `json:"safety_level"`
}

// RelayResult is the response posted back to the cloud.
type RelayResult struct {
	ID             string                 `json:"id"`
	ResponseStatus int                    `json:"response_status"`
	ResponseData   map[string]interface{} `json:"response_data,omitempty"`
	ErrorMessage   string                 `json:"error_message,omitempty"`
	DurationMs     int64                  `json:"duration_ms,omitempty"`
}

// RelayHandler processes relay commands using local platform access.
type RelayHandler struct {
	supervisor *Supervisor
	backend    *BackendClient
	store      *Store

	// Safety allow-list: read-only is always allowed; "change" is policy-gated
	allowedSafetyLevels map[string]bool

	// Platform allow-list: only known platforms can be relayed
	allowedPlatforms map[string]bool

	// Change-operation policy — gates "change" safety level operations
	changePolicy ChangePolicyConfig
}

// NewRelayHandler creates a relay handler with change-operation policy.
func NewRelayHandler(supervisor *Supervisor, backend *BackendClient, store *Store, changePolicy ChangePolicyConfig) *RelayHandler {
	safetyLevels := map[string]bool{
		"read-only": true,
	}
	// If change policy is not deny, allow "change" safety level through to per-op authorization
	if changePolicy.Policy != ChangePolicyDeny {
		safetyLevels["change"] = true
	}

	return &RelayHandler{
		supervisor:          supervisor,
		backend:             backend,
		store:               store,
		changePolicy:        changePolicy,
		allowedSafetyLevels: safetyLevels,
		allowedPlatforms: map[string]bool{
			"ai-fabric":       true,
			"proxmox":         true,
			"ollama":          true,
			"nutanix":         true,
			"truenas":         true,
			"openwebui":       true,
			"prometheus":      true,
			"grafana":         true,
			"kubernetes":      true,
			"powermax":        true,
			"nexus":           true,
			"ndfc":            true,
			"brocade":         true,
			"powerswitch":     true,
			"infiniband":      true,
			"bluefield":       true,
			"dell-idrac":      true,
			"nvidia-sonic":    true,
			"sonic-community": true,
			"emulex":          true,
			"cisco-mds":       true,
			"docker":          true,
			"linux":           true,
			"pure-storage":    true,
			"netapp-ontap":    true,
			"powerstore":      true,
			"powerflex":       true,
			"generic-http":    true,
			"mikrotik":        true,
			"mikrotik-swos":   true,
		},

	}
}

// ProcessCommands handles a batch of relay commands.
// Called from the desired-state sync loop when pending_commands are present.
func (rh *RelayHandler) ProcessCommands(commands []RelayCommand) {
	if len(commands) == 0 {
		return
	}

	log.Printf("[relay] Processing %d pending command(s)", len(commands))

	// Check remote actions gate (system commands have their own granular gate)
	hostState := rh.supervisor.GetState()
	liveQueryEnabled := hostState != nil && hostState.Config.RemoteLiveQueryEnabled

	results := make([]RelayResult, 0, len(commands))
	for _, cmd := range commands {
		// System commands and ai-fabric probes bypass the live query gate —
		// they have their own granular checks (or none, since they don't touch targets).
		if cmd.Platform != "system" && cmd.Platform != "ai-fabric" && !liveQueryEnabled {
			log.Printf("[relay] REJECTED cmd=%s: remote Live Query is disabled on this host (set FORGEAI_REMOTE_LIVE_QUERY=true to enable)", cmd.ID)
			results = append(results, RelayResult{
				ID:           cmd.ID,
				ErrorMessage: "Remote Live Query is disabled on this host. Set FORGEAI_REMOTE_LIVE_QUERY=true or enable via host config.",
				DurationMs:   0,
			})
			continue
		}

		log.Printf("[relay] Executing cmd=%s platform=%s op=%s path=%s safety=%s",
			cmd.ID, cmd.Platform, cmd.OperationID, cmd.Path, cmd.SafetyLevel)
		result := rh.executeCommand(cmd)
		if result.ErrorMessage != "" {
			log.Printf("[relay] cmd=%s FAILED: %s (duration=%dms)", cmd.ID, result.ErrorMessage, result.DurationMs)
			// Audit change-op failures specifically
			if cmd.SafetyLevel == "change" {
				audit.Error("change_op.failed", "Change operation failed",
					F("cmd_id", cmd.ID), F("operation_id", cmd.OperationID),
					F("platform", cmd.Platform), F("error", result.ErrorMessage),
					F("duration_ms", result.DurationMs))
			}
		} else {
			log.Printf("[relay] cmd=%s OK: HTTP %d (duration=%dms)", cmd.ID, result.ResponseStatus, result.DurationMs)
			// Audit change-op success
			if cmd.SafetyLevel == "change" {
				audit.Info("change_op.executed", "Change operation executed successfully",
					F("cmd_id", cmd.ID), F("operation_id", cmd.OperationID),
					F("platform", cmd.Platform), F("http_status", result.ResponseStatus),
					F("duration_ms", result.DurationMs))
			}
		}
		results = append(results, result)
	}

	// Post all results back to the cloud
	rh.postResults(results)
}

// executeCommand runs a single relay command locally.
func (rh *RelayHandler) executeCommand(cmd RelayCommand) RelayResult {
	start := time.Now()

	// ── System commands (restart, etc.) ──
	if cmd.Platform == "system" {
		return rh.executeSystemCommand(cmd, start)
	}

	// ── AI Fabric probes — local HTTP reachability check, no target profile ──
	if cmd.Platform == "ai-fabric" {
		return rh.executeAIFabricProbe(cmd, start)
	}

	// Platform allow-list check
	if !rh.allowedPlatforms[cmd.Platform] {
		log.Printf("[relay] REJECTED cmd=%s: unknown platform %q", cmd.ID, cmd.Platform)
		return RelayResult{
			ID:           cmd.ID,
			ErrorMessage: fmt.Sprintf("platform %q not in agent allow-list", cmd.Platform),
			DurationMs:   time.Since(start).Milliseconds(),
		}
	}

	// Safety check — agent-side allow-list
	if !rh.allowedSafetyLevels[cmd.SafetyLevel] {
		audit.Warn("change_op.denied", "Safety level not allowed",
			F("cmd_id", cmd.ID), F("safety_level", cmd.SafetyLevel),
			F("operation_id", cmd.OperationID), F("platform", cmd.Platform))
		return RelayResult{
			ID:           cmd.ID,
			ErrorMessage: fmt.Sprintf("safety level %q not allowed on agent", cmd.SafetyLevel),
			DurationMs:   time.Since(start).Milliseconds(),
		}
	}

	// Change-operation policy gate — authorize by operation ID
	if cmd.SafetyLevel == "change" {
		audit.Info("change_op.requested", "Change operation requested",
			F("cmd_id", cmd.ID), F("operation_id", cmd.OperationID),
			F("platform", cmd.Platform), F("method", cmd.Method),
			F("path", cmd.Path), F("policy", string(rh.changePolicy.Policy)))

		allowed, reason := rh.changePolicy.IsChangeOpAllowed(cmd.OperationID)
		if !allowed {
			audit.Warn("change_op.denied", "Change operation denied by policy",
				F("cmd_id", cmd.ID), F("operation_id", cmd.OperationID),
				F("platform", cmd.Platform), F("reason", reason))
			return RelayResult{
				ID:           cmd.ID,
				ErrorMessage: reason,
				DurationMs:   time.Since(start).Milliseconds(),
			}
		}
		audit.Info("change_op.allowed", "Change operation authorized",
			F("cmd_id", cmd.ID), F("operation_id", cmd.OperationID),
			F("platform", cmd.Platform), F("policy", string(rh.changePolicy.Policy)))
	}

	// Method allow-list — POST is allowed for read-only ops and authorized change ops
	method := strings.ToUpper(cmd.Method)
	if method != "GET" && method != "POST" {
		log.Printf("[relay] REJECTED cmd=%s: method %q not allowed", cmd.ID, method)
		return RelayResult{
			ID:           cmd.ID,
			ErrorMessage: fmt.Sprintf("method %q not allowed", method),
			DurationMs:   time.Since(start).Milliseconds(),
		}
	}

	// Path validation — reject suspicious paths
	if cmd.Path == "" || strings.Contains(cmd.Path, "..") {
		log.Printf("[relay] REJECTED cmd=%s: invalid path %q", cmd.ID, cmd.Path)
		return RelayResult{
			ID:           cmd.ID,
			ErrorMessage: "invalid request path",
			DurationMs:   time.Since(start).Milliseconds(),
		}
	}

	// Find the target profile
	target := rh.supervisor.FindTarget(cmd.TargetProfileID)
	if target == nil {
		return RelayResult{
			ID:           cmd.ID,
			ErrorMessage: fmt.Sprintf("target profile %q not found on this agent", cmd.TargetProfileID),
			DurationMs:   time.Since(start).Milliseconds(),
		}
	}

	// Load credentials
	creds, err := rh.store.LoadSecret(cmd.TargetProfileID)
	if err != nil {
		return RelayResult{
			ID:           cmd.ID,
			ErrorMessage: fmt.Sprintf("failed to load credentials for target: %v", err),
			DurationMs:   time.Since(start).Milliseconds(),
		}
	}

	// Execute the HTTP call against the local target
	result := rh.executeHTTP(cmd, target, creds)
	result.DurationMs = time.Since(start).Milliseconds()
	return result
}

// executeHTTP performs the actual HTTP request against the target endpoint.
func (rh *RelayHandler) executeHTTP(cmd RelayCommand, target *TargetProfile, creds map[string]string) RelayResult {
	// Platform-specific dispatch — some platforms use non-REST transports
	// Check both target type and command platform for robustness
	normalizedTarget := strings.ToLower(strings.TrimSpace(target.TargetType))
	normalizedPlatform := strings.ToLower(strings.TrimSpace(cmd.Platform))
	if normalizedTarget == "truenas" || normalizedPlatform == "truenas" {
		return rh.executeTrueNAS(cmd, target, creds)
	}

	// Brocade: resolve the adapter's base URL (may have fallen back from HTTPS to HTTP)
	// and use the correct Accept header for FOS REST API
	baseEndpoint := target.Endpoint
	isBrocade := normalizedTarget == "brocade" || normalizedPlatform == "brocade"
	if isBrocade {
		if adapter := rh.supervisor.FindAdapter(cmd.TargetProfileID); adapter != nil {
			if ba, ok := adapter.(*BrocadeAdapter); ok && ba.baseURL != "" {
				baseEndpoint = ba.baseURL
			}
		}
	}

	fullURL := joinURL(baseEndpoint, cmd.Path)

	var bodyReader io.Reader
	if cmd.Body != nil && (strings.ToUpper(cmd.Method) == "POST" || strings.ToUpper(cmd.Method) == "PUT" || strings.ToUpper(cmd.Method) == "PATCH") {
		bodyBytes, err := json.Marshal(cmd.Body)
		if err != nil {
			return RelayResult{ID: cmd.ID, ErrorMessage: fmt.Sprintf("marshal request body: %v", err)}
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequest(strings.ToUpper(cmd.Method), fullURL, bodyReader)
	if err != nil {
		return RelayResult{ID: cmd.ID, ErrorMessage: fmt.Sprintf("create request: %v", err)}
	}

	// Brocade FOS requires YANG-data JSON content type
	if isBrocade {
		req.Header.Set("Accept", "application/yang-data+json")
		req.Header.Set("Content-Type", "application/yang-data+json")
	} else {
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
	}

	// Apply auth from credentials based on target auth type
	applyAuth(req, target, creds)

	// Use TLS-aware client from the target
	client := buildHTTPClient(target)

	resp, err := client.Do(req)
	if err != nil {
		return RelayResult{
			ID:           cmd.ID,
			ErrorMessage: fmt.Sprintf("execute request: %v", err),
		}
	}
	defer resp.Body.Close()

	// Read response (cap at 5MB)
	limited := io.LimitReader(resp.Body, 5*1024*1024)
	respBytes, err := io.ReadAll(limited)
	if err != nil {
		return RelayResult{
			ID:             cmd.ID,
			ResponseStatus: resp.StatusCode,
			ErrorMessage:   fmt.Sprintf("read response: %v", err),
		}
	}

	var respData map[string]interface{}
	if len(respBytes) == 0 {
		// Empty body (e.g. HTTP 204 No Content)
		if cmd.SafetyLevel == "change" && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			respData = map[string]interface{}{
				"status":     "success",
				"message":    "Action completed successfully",
				"httpStatus": float64(resp.StatusCode),
			}
		} else {
			respData = map[string]interface{}{
				"rawText": "",
			}
		}
	} else if err := json.Unmarshal(respBytes, &respData); err != nil {
		// Non-JSON response
		respData = map[string]interface{}{
			"rawText": string(respBytes),
		}
	}

	result := RelayResult{
		ID:             cmd.ID,
		ResponseStatus: resp.StatusCode,
		ResponseData:   respData,
	}

	if resp.StatusCode >= 400 {
		// For change operations, HTTP 409 (Conflict) means "already in requested state" — treat as success
		if cmd.SafetyLevel == "change" && resp.StatusCode == 409 {
			result.ResponseData = map[string]interface{}{
				"status":     "conflict",
				"message":    "Target is already in the requested state",
				"httpStatus": float64(409),
			}
			// No ErrorMessage — UI will treat this as success
		} else {
			result.ErrorMessage = fmt.Sprintf("upstream returned HTTP %d", resp.StatusCode)
		}
	}

	return result
}

// executeTrueNAS handles TrueNAS relay commands via the REST API.
// TrueNAS middleware method names (e.g. "system.info", "pool.query") are
// translated to REST paths: system.info → GET /api/v2.0/system/info,
// pool.query → GET /api/v2.0/pool.
func (rh *RelayHandler) executeTrueNAS(cmd RelayCommand, target *TargetProfile, creds map[string]string) RelayResult {
	method := cmd.Path // middleware method name, e.g. "system.info"

	// Map middleware method to REST API v2 path
	restPath := truenasMethodToREST(method)

	// For get_instance methods, extract the ID from JSON-RPC params and append /id/{id}
	if strings.HasSuffix(method, ".get_instance") {
		if id := extractTrueNASInstanceID(cmd.Body); id != "" {
			restPath = strings.TrimSuffix(restPath, "/get_instance") + "/id/" + id
		}
	}

	fullURL := joinURL(target.Endpoint, "/api/v2.0/"+restPath)

	audit.Debug("relay.truenas", "TrueNAS dispatch",
		F("cmd_id", cmd.ID),
		F("middleware_method", method),
		F("rest_path", restPath),
		F("resolved_url", fullURL))

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return RelayResult{ID: cmd.ID, ErrorMessage: fmt.Sprintf("create request: %v", err)}
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	applyAuth(req, target, creds)

	client := buildHTTPClient(target)

	resp, err := client.Do(req)
	if err != nil {
		return RelayResult{
			ID:           cmd.ID,
			ErrorMessage: fmt.Sprintf("execute request: %v", err),
		}
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, 5*1024*1024)
	respBytes, err := io.ReadAll(limited)
	if err != nil {
		return RelayResult{
			ID:             cmd.ID,
			ResponseStatus: resp.StatusCode,
			ErrorMessage:   fmt.Sprintf("read response: %v", err),
		}
	}

	// TrueNAS REST API can return arrays (query endpoints) or objects
	var respData map[string]interface{}
	if err := json.Unmarshal(respBytes, &respData); err != nil {
		// Try array response — wrap in a result envelope
		var arrData []interface{}
		if arrErr := json.Unmarshal(respBytes, &arrData); arrErr == nil {
			respData = map[string]interface{}{"result": arrData}
		} else {
			respData = map[string]interface{}{"rawText": string(respBytes)}
		}
	}

	result := RelayResult{
		ID:             cmd.ID,
		ResponseStatus: resp.StatusCode,
		ResponseData:   respData,
	}

	if resp.StatusCode >= 400 {
		result.ErrorMessage = fmt.Sprintf("upstream returned HTTP %d", resp.StatusCode)
	}

	return result
}

// truenasMethodToREST converts a TrueNAS middleware method name to a REST API v2 path.
// Examples:
//   system.info       → system/info
//   system.version    → system/version
//   pool.query        → pool
//   pool.dataset.query → pool/dataset
//   disk.query        → disk
//   sharing.smb.query → sharing/smb
//   service.query     → service
func truenasMethodToREST(method string) string {
	// Split on "." — the last segment is the verb (info, query, get_instance, etc.)
	parts := strings.Split(method, ".")
	if len(parts) < 2 {
		// Fallback: use as-is with slashes
		return strings.ReplaceAll(method, ".", "/")
	}

	verb := parts[len(parts)-1]
	resource := parts[:len(parts)-1]

	// For "query" verbs, the REST endpoint is the resource itself (GET /pool)
	// For "info", "version", etc., append the verb (GET /system/info)
	switch verb {
	case "query":
		return strings.Join(resource, "/")
	default:
		return strings.Join(parts, "/")
	}
}

// extractTrueNASInstanceID extracts the first positional ID from a JSON-RPC params array.
// The request body has shape: { "params": [id, ...], ... }
func extractTrueNASInstanceID(body map[string]interface{}) string {
	if body == nil {
		return ""
	}
	params, ok := body["params"]
	if !ok {
		return ""
	}
	arr, ok := params.([]interface{})
	if !ok || len(arr) == 0 {
		return ""
	}
	// ID can be numeric or string
	return fmt.Sprintf("%v", arr[0])
}

// joinURL safely joins a base endpoint URL and a path segment,
// ensuring exactly one "/" separator between them.
func joinURL(base, path string) string {
	base = strings.TrimRight(base, "/")
	if path == "" {
		return base
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}

// NOTE: executeSystemCommand is defined in system_commands.go



// applyAuth sets authentication headers based on target config.
func applyAuth(req *http.Request, target *TargetProfile, creds map[string]string) {
	// Platform-specific auth overrides
	if target.TargetType == "proxmox" {
		applyProxmoxAuth(req, target, creds)
		return
	}

	// Prometheus: support custom header-based auth (e.g. X-Token, Authorization via header_name/header_value)
	if target.TargetType == "prometheus" {
		applyPrometheusAuth(req, target, creds)
		return
	}

	switch target.AuthType {
	case "basic", "username_password":
		username := creds["username"]
		password := creds["password"]
		if username != "" && password != "" {
			req.SetBasicAuth(username, password)
		}
	case "bearer", "api_token", "api-key":
		token := creds["token"]
		if token == "" {
			token = creds["api_key"]
		}
		if token == "" {
			token = creds["api_token"]
		}
		if token == "" {
			token = creds["service_token"]
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
}

// applyPrometheusAuth handles Prometheus header-based or basic auth.
// Matches the adapter_prometheus.go Init() auth logic.
func applyPrometheusAuth(req *http.Request, target *TargetProfile, creds map[string]string) {
	// Custom header auth (e.g. header_name=Authorization, header_value=Bearer xxx)
	if headerName := creds["header_name"]; headerName != "" {
		req.Header.Set(headerName, creds["header_value"])
		log.Printf("[relay] Applied Prometheus custom header auth (%s)", headerName)
		return
	}

	// Basic auth fallback
	if username := creds["username"]; username != "" {
		req.SetBasicAuth(username, creds["password"])
		log.Printf("[relay] Applied Prometheus basic auth")
		return
	}

	// Bearer token fallback
	token := creds["token"]
	if token == "" {
		token = creds["api_token"]
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		log.Printf("[relay] Applied Prometheus bearer auth")
		return
	}

	log.Printf("[relay] WARNING: Prometheus target has no auth credentials configured")
}

// applyProxmoxAuth sets the Proxmox PVE API token header.
// Format: PVEAPIToken=user@realm!tokenid=secret
func applyProxmoxAuth(req *http.Request, target *TargetProfile, creds map[string]string) {
	// token_id is stored in target_config (e.g. "api@pam!forgeagent")
	// token_secret is stored in encrypted credentials
	var tokenID string
	if tc := target.TargetConfig; tc != nil {
		if v, ok := tc["token_id"].(string); ok {
			tokenID = v
		}
	}
	// Fallback: check creds for backward compatibility
	if tokenID == "" {
		tokenID = creds["token_id"]
	}
	tokenSecret := creds["token_secret"]

	if tokenID == "" {
		log.Printf("[relay] WARNING: Proxmox target missing token_id in target_config and creds")
		return
	}
	if tokenSecret == "" {
		log.Printf("[relay] WARNING: Proxmox target missing token_secret in credentials")
		return
	}

	// Format matches proxmox.go snapshot collector: PVEAPIToken=user@realm!tokenname=secret
	header := fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, tokenSecret)
	req.Header.Set("Authorization", header)
	log.Printf("[relay] Applied Proxmox API token auth from target_config + encrypted secret")
}

// buildHTTPClient creates an HTTP client respecting TLS and proxy config.
func buildHTTPClient(target *TargetProfile) *http.Client {
	return NewHTTPClientFromProfile(target, 60*time.Second)
}

// postResults sends relay results back to the cloud.
func (rh *RelayHandler) postResults(results []RelayResult) {
	token := rh.supervisor.GetConnectorToken()
	if token == "" {
		log.Printf("[relay] No connector token — cannot post results")
		return
	}

	payload := map[string]interface{}{
		"results": results,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[relay] Failed to marshal results: %v", err)
		return
	}

	url := rh.backend.BaseURL + defaultRelayResponsePath
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		log.Printf("[relay] Failed to create response request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Connector-Token", token)
	req.Header.Set("X-Agent-Version", HostVersion)

	client := NewHTTPClient(nil, nil, 15*time.Second)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[relay] Failed to post results: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		log.Printf("[relay] Response post returned HTTP %d: %s", resp.StatusCode, string(respBody))
	} else {
		log.Printf("[relay] Successfully posted %d result(s)", len(results))
	}
}
