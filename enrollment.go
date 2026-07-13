// ForgeAI Connector Host — Host Enrollment
//
// Implements one-time host enrollment against the ForgeAI backend.
// The host exchanges a bootstrap token for a persistent host identity
// and connector token. Re-enrollment requires explicit operator action.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"
)

// ── Enrollment request/response models ──

// EnrollmentRequest is sent from host → backend during bootstrap.
type EnrollmentRequest struct {
	BootstrapToken string            `json:"bootstrap_token"`
	Label          string            `json:"label,omitempty"`
	AgentVersion   string            `json:"agent_version"`
	OS             string            `json:"os"`
	Arch           string            `json:"arch"`
	Capabilities   []string          `json:"capabilities,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	HostPublicKey  string            `json:"host_public_key,omitempty"`
}

// EnrollmentResponse is returned from backend → host on successful enrollment.
type EnrollmentResponse struct {
	HostID         string `json:"host_id"`
	ConnectorToken string `json:"connector_token"`
	Label          string `json:"label"`
	BackendURL     string `json:"backend_url"`
	SyncIntervalS  int    `json:"sync_interval_secs,omitempty"`
}

// ── Enrollment logic ──

// EnrollHost performs first-time host enrollment with the ForgeAI backend.
func EnrollHost(store *Store, backendURL, bootstrapToken, label string) (*HostState, error) {
	// Guard: don't re-enroll if state already exists
	existing, err := store.LoadState()
	if err == nil && existing != nil && existing.Identity.ConnectorToken != "" {
		return nil, fmt.Errorf("host already enrolled as %s (ID: %s). Use --force-enroll to re-enroll",
			existing.Identity.Label, existing.Identity.HostID[:12])
	}

	if bootstrapToken == "" {
		return nil, fmt.Errorf("bootstrap token is required for enrollment")
	}

	if backendURL == "" {
		backendURL = defaultBackendBase
	}

	// Generate host keypair for asymmetric credential delivery
	audit.Info("enrollment.started", "Generating host keypair for secure credential delivery")
	keyPair, err := GenerateHostKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate host keypair: %w", err)
	}

	enrollURL := backendURL + "/functions/v1/connector-enroll"

	req := EnrollmentRequest{
		BootstrapToken: bootstrapToken,
		Label:          label,
		AgentVersion:   HostVersion,
		OS:             runtime.GOOS,
		Arch:           runtime.GOARCH,
		Capabilities:   registeredAdapterTypes(),
		HostPublicKey:  keyPair.PublicKeyBase64(),
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal enrollment request: %w", err)
	}

	audit.Info("enrollment.started", "Enrolling host with backend", F("url", enrollURL))

	httpReq, err := http.NewRequest("POST", enrollURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("enrollment request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	switch resp.StatusCode {
	case 200, 201:
		// success
	case 401:
		return nil, fmt.Errorf("enrollment failed: invalid or expired bootstrap token")
	case 409:
		return nil, fmt.Errorf("enrollment failed: bootstrap token already used")
	case 429:
		return nil, fmt.Errorf("enrollment failed: rate limited, try again later")
	default:
		return nil, fmt.Errorf("enrollment failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var enrollResp EnrollmentResponse
	if err := json.Unmarshal(respBody, &enrollResp); err != nil {
		return nil, fmt.Errorf("parse enrollment response: %w", err)
	}

	if enrollResp.ConnectorToken == "" {
		return nil, fmt.Errorf("enrollment response missing connector_token")
	}

	// Persist keypair in encrypted store
	if err := store.SaveKeyPair(keyPair); err != nil {
		return nil, fmt.Errorf("persist host keypair: %w", err)
	}
	audit.Info("security.key_generated", "Host keypair persisted (public key registered with backend)")

	// Build initial host state
	state := &HostState{
		Identity: HostIdentity{
			HostID:         enrollResp.HostID,
			Label:          enrollResp.Label,
			ConnectorToken: enrollResp.ConnectorToken,
			BackendURL:     enrollResp.BackendURL,
			EnrolledAt:     time.Now(),
			PublicKey:       keyPair.PublicKeyBase64(),
		},
		Config:  DefaultHostConfig(),
		Targets: []TargetProfile{},
		Version: 1,
	}

	if enrollResp.SyncIntervalS > 0 {
		state.Config.SyncIntervalSecs = enrollResp.SyncIntervalS
	}

	// Persist enrolled state
	if err := store.SaveState(state); err != nil {
		return nil, fmt.Errorf("persist enrollment state: %w", err)
	}

	audit.Info("enrollment.success", "Host enrolled",
		F("host_id_short", enrollResp.HostID[:12]),
		F("label", enrollResp.Label),
		F("keypair", true))

	return state, nil
}

// IsEnrolled checks whether the host has completed enrollment.
func IsEnrolled(store *Store) bool {
	state, err := store.LoadState()
	if err != nil || state == nil {
		return false
	}
	return state.Identity.ConnectorToken != "" && state.Identity.HostID != ""
}

// MustEnroll checks environment for enrollment token and attempts enrollment
// if the host is not already enrolled.
func MustEnroll(store *Store, backendURL string) (*HostState, error) {
	// Already enrolled? Just load state.
	state, err := store.LoadState()
	if err == nil && state != nil && state.Identity.ConnectorToken != "" {
		audit.Info("enrollment.success", "Existing enrollment detected",
			F("host_id_short", state.Identity.HostID[:12]),
			F("label", state.Identity.Label))
		if !state.Identity.EnrolledAt.IsZero() {
			audit.Info("enrollment.success", "Enrolled at",
				F("enrolled_at", state.Identity.EnrolledAt.Format(time.RFC3339)))
		}
		audit.Info("enrollment.success", "Reusing existing host identity and connector token")
		audit.Info("enrollment.success", "The FORGEAI_ENROLLMENT_TOKEN environment variable will NOT be used")
		audit.Warn("enrollment.success", "If the stored token is invalid or revoked, desired-state sync will fail")
		audit.Info("enrollment.success", "To force a clean re-enrollment, see --force-reset-state or manual reset steps")
		return state, nil
	}

	// Check for enrollment token in env
	bootstrapToken := os.Getenv("FORGEAI_ENROLLMENT_TOKEN")
	if bootstrapToken == "" {
		// Fall back to legacy CONNECTOR_TOKEN for backward compatibility
		bootstrapToken = os.Getenv("CONNECTOR_TOKEN")
	}

	if bootstrapToken == "" {
		return nil, fmt.Errorf("host not enrolled and no enrollment token provided. " +
			"Set FORGEAI_ENROLLMENT_TOKEN or run with --enroll-token")
	}

	label := os.Getenv("HOST_LABEL")
	if label == "" {
		hostname, _ := os.Hostname()
		if hostname != "" {
			label = fmt.Sprintf("forgeai-host-%s", hostname)
		} else {
			label = "forgeai-host"
		}
	}

	return EnrollHost(store, backendURL, bootstrapToken, label)
}

// registeredAdapterTypes returns the list of built-in adapter types.
func registeredAdapterTypes() []string {
	return []string{
		"proxmox",
		"truenas",
		// Future adapters registered here
	}
}
