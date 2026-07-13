// FilterREX Connector Host — Relay Execution Handler
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

// ── Vendor extension hooks ──
//
// The SAN-only public build compiles relay.go alone and handles only the
// Brocade + generic REST path. In the full (default) build, a vendor
// extension file's init() wires these hooks to add extra transports, auth
// overrides, probing, and platform allow-list entries.
//
// When a hook is nil the connector simply reports the capability as
// unsupported instead of linking any vendor-specific logic.
var (
	// vendorTransportHook handles non-REST vendor transports. Returns
	// (result, handled); handled=false falls back to the generic path.
	vendorTransportHook func(rh *RelayHandler, cmd RelayCommand, target *TargetProfile, creds map[string]string) (RelayResult, bool)

	// vendorAuthHook applies vendor-specific auth overrides. Returns true
	// when it handled auth.
	vendorAuthHook func(req *http.Request, target *TargetProfile, creds map[string]string) bool

	// aiFabricProbeHook performs a LAN AI-runtime reachability probe.
	aiFabricProbeHook func(rh *RelayHandler, cmd RelayCommand, start time.Time) RelayResult

	// vendorPlatforms lists additional non-SAN platforms permitted by the
	// full build. The SAN-only build allows only the SAN base set.
	vendorPlatforms []string
)

// buildAllowedPlatforms returns the relay platform allow-list. The base is
// SAN-only; the full build extends it via vendorPlatforms.
func buildAllowedPlatforms() map[string]bool {
	allowed := map[string]bool{
		"brocade": true,
	}
	for _, p := range vendorPlatforms {
		allowed[p] = true
	}
	return allowed
}

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
		allowedPlatforms:    buildAllowedPlatforms(),
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
			log.Printf("[relay] REJECTED cmd=%s: remote Live Query is disabled on this host (set FILTERREX_REMOTE_LIVE_QUERY=true to enable)", cmd.ID)
			results = append(results, RelayResult{
				ID:           cmd.ID,
				ErrorMessage: "Remote Live Query is disabled on this host. Set FILTERREX_REMOTE_LIVE_QUERY=true or enable via host config.",
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
		if aiFabricProbeHook != nil {
			return aiFabricProbeHook(rh, cmd, start)
		}
		return RelayResult{
			ID:           cmd.ID,
			ErrorMessage: "ai-fabric probing is not supported by this connector",
			DurationMs:   time.Since(start).Milliseconds(),
		}
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
	// Vendor-specific dispatch — some platforms use non-REST transports.
	// In the SAN-only build vendorTransportHook is nil and we fall straight
	// through to the generic/Brocade REST path.
	normalizedTarget := strings.ToLower(strings.TrimSpace(target.TargetType))
	normalizedPlatform := strings.ToLower(strings.TrimSpace(cmd.Platform))
	if vendorTransportHook != nil {
		if res, handled := vendorTransportHook(rh, cmd, target, creds); handled {
			return res
		}
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

// NOTE: non-REST vendor transports live in the vendor extension file, which
// is excluded from the SAN-only public build.



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
	// Vendor-specific auth overrides are wired only in the full build via
	// vendorAuthHook. In the SAN-only build the hook is nil and we use the
	// generic auth below.
	if vendorAuthHook != nil && vendorAuthHook(req, target, creds) {
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

// NOTE: vendor auth overrides live in the vendor extension file, which is
// excluded from the SAN-only public build.

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
