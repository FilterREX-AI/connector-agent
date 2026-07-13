// ForgeAI Connector Host — AI Fabric Probe
//
// Handles platform="ai-fabric" relay commands. The cloud cannot reach
// LAN-scoped Ollama / Open-WebUI / vLLM hosts, so the agent does the
// HTTP probe locally and posts the result back via the standard
// connector-api-response path (RelayResult).
//
// The DB trigger ai_fabric_command_to_ping turns the response into
// an ai_fabric_health_pings row and updates ai_fabric_hosts.status.
//
// Command shape (request_body in connector_api_commands):
//   {
//     "host_id":      "<uuid>",
//     "address":      "10.10.100.5",        // or "https://host:8080"
//     "runtime_type": "ollama" | "open-webui" | "vllm" | "..."
//   }
// platform = "ai-fabric"
// operation_id = "ai-fabric-probe"
// safety_level = "read-only"
// target_profile_id is unused (we don't tie probes to a target profile)

package main

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	aiFabricProbeTimeout = 4 * time.Second
	aiFabricSlowMs       = int64(1500)
)

var aiFabricPortRegex = regexp.MustCompile(`:\d+$`)

// executeAIFabricProbe performs the HTTP reachability check and returns a
// RelayResult whose ResponseData carries reachable / latency_ms / notes.
// The DB-side trigger interprets these fields.
func (rh *RelayHandler) executeAIFabricProbe(cmd RelayCommand, start time.Time) RelayResult {
	hostID, _ := cmd.Body["host_id"].(string)
	address, _ := cmd.Body["address"].(string)
	runtime, _ := cmd.Body["runtime_type"].(string)

	if hostID == "" || address == "" {
		return RelayResult{
			ID:           cmd.ID,
			ErrorMessage: "ai-fabric probe missing host_id or address",
			DurationMs:   time.Since(start).Milliseconds(),
		}
	}

	url := buildAIFabricProbeURL(address, runtime)

	ctx, cancel := context.WithTimeout(context.Background(), aiFabricProbeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return RelayResult{
			ID:             cmd.ID,
			ResponseStatus: 0,
			ResponseData: map[string]interface{}{
				"host_id":    hostID,
				"reachable":  false,
				"latency_ms": nil,
				"notes":      fmt.Sprintf("[agent] bad url: %s", err.Error()),
			},
			DurationMs: time.Since(start).Milliseconds(),
		}
	}

	client := &http.Client{Timeout: aiFabricProbeTimeout}
	t0 := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(t0).Milliseconds()

	reachable := false
	httpStatus := 0
	notes := ""
	if err != nil {
		notes = fmt.Sprintf("[agent] %s", truncate(err.Error(), 200))
	} else {
		defer resp.Body.Close()
		httpStatus = resp.StatusCode
		// 2xx/3xx/4xx all mean the host responded; 5xx still up but degraded
		reachable = resp.StatusCode >= 200 && resp.StatusCode < 500
		notes = fmt.Sprintf("[agent] HTTP %d via %s", resp.StatusCode, url)
	}

	respData := map[string]interface{}{
		"host_id":     hostID,
		"reachable":   reachable,
		"http_status": httpStatus,
		"probed_url":  url,
		"notes":       notes,
	}
	if reachable {
		respData["latency_ms"] = latency
	} else {
		respData["latency_ms"] = nil
	}

	return RelayResult{
		ID:             cmd.ID,
		ResponseStatus: 200, // command itself succeeded; reachable lives in body
		ResponseData:   respData,
		DurationMs:     time.Since(start).Milliseconds(),
	}
}

// buildAIFabricProbeURL adds scheme, default port, and runtime-specific path.
func buildAIFabricProbeURL(address, runtime string) string {
	base := strings.TrimRight(strings.TrimSpace(address), "/")
	rt := strings.ToLower(strings.TrimSpace(runtime))

	if !strings.HasPrefix(strings.ToLower(base), "http://") &&
		!strings.HasPrefix(strings.ToLower(base), "https://") {
		if !aiFabricPortRegex.MatchString(base) {
			switch rt {
			case "ollama":
				base = base + ":11434"
			case "open-webui", "openwebui":
				base = base + ":8080"
			case "vllm":
				base = base + ":8000"
			}
		}
		base = "http://" + base
	}

	switch rt {
	case "ollama":
		return base + "/api/tags"
	case "open-webui", "openwebui":
		return base + "/health"
	case "vllm":
		return base + "/v1/models"
	default:
		return base + "/"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
