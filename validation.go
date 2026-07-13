// ForgeAI Connector Host — Profile & Config Validation
//
// Validates target profiles, auth configurations, and enforces
// hard guardrails for dangerous adapter types (generic-http).

package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ── Profile Mode ──

// ProfileMode represents the operational mode of a target profile.
type ProfileMode string

const (
	ProfileModeReadOnly   ProfileMode = "readonly"
	ProfileModeOpsEnabled ProfileMode = "ops-enabled"
)

// IsValidProfileMode checks if a profile mode is recognized.
func IsValidProfileMode(mode string) bool {
	switch ProfileMode(mode) {
	case ProfileModeReadOnly, ProfileModeOpsEnabled:
		return true
	}
	return false
}

// ── Auth Type Registry ──

// AuthType represents the authentication method for a target.
type AuthType string

const (
	AuthTypeAPIToken       AuthType = "api_token"
	AuthTypeUserPassword   AuthType = "username_password"
	AuthTypeServiceAccount AuthType = "service_account"
	AuthTypeHeaderBased    AuthType = "header_based"
	AuthTypeLocalTrusted   AuthType = "local_trusted"
	AuthTypeNone           AuthType = "none"
)

// TargetAuthSpec defines the expected auth model for a target type.
type TargetAuthSpec struct {
	TargetType       string
	AllowedAuthTypes []AuthType
	RequiredCredKeys []string // credential keys that must be present
	DefaultMode      ProfileMode
	Description      string
}

// targetAuthRegistry maps target types to their auth specifications.
var targetAuthRegistry = map[string]TargetAuthSpec{
	"proxmox": {
		TargetType:       "proxmox",
		AllowedAuthTypes: []AuthType{AuthTypeAPIToken, AuthTypeUserPassword},
		RequiredCredKeys: []string{}, // varies by auth type
		DefaultMode:      ProfileModeReadOnly,
		Description:      "Proxmox VE hypervisor",
	},
	"truenas": {
		TargetType:       "truenas",
		AllowedAuthTypes: []AuthType{AuthTypeAPIToken},
		RequiredCredKeys: []string{"api_token"},
		DefaultMode:      ProfileModeReadOnly,
		Description:      "TrueNAS SCALE/CORE storage",
	},
	"nutanix": {
		TargetType:       "nutanix",
		AllowedAuthTypes: []AuthType{AuthTypeUserPassword},
		RequiredCredKeys: []string{"username", "password"},
		DefaultMode:      ProfileModeReadOnly,
		Description:      "Nutanix AHV/Prism",
	},
	"pure-storage": {
		TargetType:       "pure-storage",
		AllowedAuthTypes: []AuthType{AuthTypeAPIToken},
		RequiredCredKeys: []string{"api_token"},
		DefaultMode:      ProfileModeReadOnly,
		Description:      "Pure Storage FlashArray/FlashBlade",
	},
	"netapp-ontap": {
		TargetType:       "netapp-ontap",
		AllowedAuthTypes: []AuthType{AuthTypeUserPassword, AuthTypeAPIToken},
		RequiredCredKeys: []string{},
		DefaultMode:      ProfileModeReadOnly,
		Description:      "NetApp ONTAP",
	},
	"powerstore": {
		TargetType:       "powerstore",
		AllowedAuthTypes: []AuthType{AuthTypeUserPassword},
		RequiredCredKeys: []string{"username", "password"},
		DefaultMode:      ProfileModeReadOnly,
		Description:      "Dell PowerStore",
	},
	"powermax": {
		TargetType:       "powermax",
		AllowedAuthTypes: []AuthType{AuthTypeUserPassword, AuthTypeAPIToken},
		RequiredCredKeys: []string{},
		DefaultMode:      ProfileModeReadOnly,
		Description:      "Dell PowerMax (Unisphere)",
	},
	"powerflex": {
		TargetType:       "powerflex",
		AllowedAuthTypes: []AuthType{AuthTypeUserPassword},
		RequiredCredKeys: []string{"username", "password"},
		DefaultMode:      ProfileModeReadOnly,
		Description:      "Dell PowerFlex (VxFlex)",
	},
	"ollama": {
		TargetType:       "ollama",
		AllowedAuthTypes: []AuthType{AuthTypeLocalTrusted, AuthTypeNone},
		RequiredCredKeys: []string{},
		DefaultMode:      ProfileModeReadOnly,
		Description:      "Ollama local LLM inference",
	},
	"prometheus": {
		TargetType:       "prometheus",
		AllowedAuthTypes: []AuthType{AuthTypeNone, AuthTypeHeaderBased, AuthTypeUserPassword},
		RequiredCredKeys: []string{},
		DefaultMode:      ProfileModeReadOnly,
		Description:      "Prometheus monitoring",
	},
	"grafana": {
		TargetType:       "grafana",
		AllowedAuthTypes: []AuthType{AuthTypeAPIToken, AuthTypeServiceAccount},
		RequiredCredKeys: []string{"api_key"},
		DefaultMode:      ProfileModeReadOnly,
		Description:      "Grafana dashboards",
	},
	"generic-http": {
		TargetType:       "generic-http",
		AllowedAuthTypes: []AuthType{AuthTypeHeaderBased, AuthTypeAPIToken, AuthTypeNone},
		RequiredCredKeys: []string{},
		DefaultMode:      ProfileModeReadOnly,
		Description:      "Generic HTTP endpoint (guardrailed)",
	},
}

// GetTargetAuthSpec returns the auth spec for a target type, or nil if unknown.
func GetTargetAuthSpec(targetType string) *TargetAuthSpec {
	spec, ok := targetAuthRegistry[targetType]
	if !ok {
		return nil
	}
	return &spec
}

// ── Profile Validator ──

// ProfileValidator validates target profiles and enforces guardrails.
type ProfileValidator struct{}

// NewProfileValidator creates a new validator.
func NewProfileValidator() *ProfileValidator {
	return &ProfileValidator{}
}

// Validate checks a desired target profile for correctness and safety.
func (v *ProfileValidator) Validate(p *DesiredTargetProfile) error {
	// Required fields
	if p.TargetID == "" {
		return fmt.Errorf("target_id is required")
	}
	if p.Name == "" {
		return fmt.Errorf("name is required")
	}
	if p.TargetType == "" {
		return fmt.Errorf("target_type is required")
	}

	// Validate target type
	if !IsValidTargetType(p.TargetType) {
		return fmt.Errorf("unsupported target_type: %s", p.TargetType)
	}

	// Validate mode
	mode := p.Mode
	if mode == "" {
		mode = ProfileModeReadOnly
	}
	if !IsValidProfileMode(string(mode)) {
		return fmt.Errorf("invalid mode: %s (must be 'readonly' or 'ops-enabled')", mode)
	}

	// Ops-enabled mode requires explicit opt-in and is blocked in Phase 2
	if mode == ProfileModeOpsEnabled {
		return fmt.Errorf("ops-enabled mode is not yet supported (Phase 3)")
	}

	// Validate endpoint
	if p.Endpoint == "" && p.TargetType != "ollama" {
		return fmt.Errorf("endpoint is required for target type %s", p.TargetType)
	}

	// Validate auth type against registry
	if p.AuthType != "" {
		spec := GetTargetAuthSpec(p.TargetType)
		if spec != nil {
			if !isAuthTypeAllowed(spec, AuthType(p.AuthType)) {
				return fmt.Errorf("auth_type '%s' not allowed for target type '%s' (allowed: %v)",
					p.AuthType, p.TargetType, spec.AllowedAuthTypes)
			}
		}
	}

	// Poll interval bounds
	if p.PollIntervalSecs > 0 && p.PollIntervalSecs < 10 {
		return fmt.Errorf("poll_interval_secs must be >= 10 (got %d)", p.PollIntervalSecs)
	}

	// Generic-HTTP hard guardrails
	if p.TargetType == "generic-http" {
		if err := v.validateGenericHTTP(p); err != nil {
			return fmt.Errorf("generic-http guardrail violation: %w", err)
		}
	}

	return nil
}

// validateGenericHTTP enforces hard safety guardrails for generic-http targets.
func (v *ProfileValidator) validateGenericHTTP(p *DesiredTargetProfile) error {
	tc := p.TargetConfig
	if tc == nil {
		return fmt.Errorf("target_config with guardrails is required")
	}

	guardrails, ok := tc["guardrails"]
	if !ok {
		return fmt.Errorf("guardrails block is required in target_config")
	}

	g, ok := guardrails.(map[string]interface{})
	if !ok {
		return fmt.Errorf("guardrails must be an object")
	}

	// Validate allowed methods — hard limit to safe methods
	if methods, ok := g["allowed_methods"]; ok {
		methodList, ok := toStringSlice(methods)
		if !ok {
			return fmt.Errorf("allowed_methods must be a string array")
		}
		for _, m := range methodList {
			m = strings.ToUpper(m)
			if m != "GET" && m != "HEAD" && m != "OPTIONS" {
				return fmt.Errorf("method '%s' is not allowed (only GET, HEAD, OPTIONS)", m)
			}
		}
	} else {
		return fmt.Errorf("allowed_methods is required in guardrails")
	}

	// Validate allowed paths — must not be empty
	if paths, ok := g["allowed_paths"]; ok {
		pathList, ok := toStringSlice(paths)
		if !ok {
			return fmt.Errorf("allowed_paths must be a string array")
		}
		if len(pathList) == 0 {
			return fmt.Errorf("allowed_paths must not be empty (deny-by-default)")
		}
		// Block wildcard-everything patterns
		for _, p := range pathList {
			if p == "*" || p == "/**" || p == "/*" {
				return fmt.Errorf("wildcard-all path '%s' is not allowed", p)
			}
		}
	} else {
		return fmt.Errorf("allowed_paths is required in guardrails")
	}

	// Validate timeout — hard cap at 10s for Phase 2
	if timeout, ok := g["timeout_secs"]; ok {
		t, ok := toFloat64(timeout)
		if !ok {
			return fmt.Errorf("timeout_secs must be a number")
		}
		if t > 10 {
			return fmt.Errorf("timeout_secs must be <= 10 (got %.0f)", t)
		}
	}

	// Validate response size — hard cap at 1MiB
	if maxResp, ok := g["max_response_bytes"]; ok {
		m, ok := toFloat64(maxResp)
		if !ok {
			return fmt.Errorf("max_response_bytes must be a number")
		}
		if m > 1048576 {
			return fmt.Errorf("max_response_bytes must be <= 1048576 (1 MiB), got %.0f", m)
		}
	}

	return nil
}

// ── Helpers ──

func isAuthTypeAllowed(spec *TargetAuthSpec, authType AuthType) bool {
	for _, allowed := range spec.AllowedAuthTypes {
		if allowed == authType {
			return true
		}
	}
	return false
}

func toStringSlice(v interface{}) ([]string, bool) {
	switch arr := v.(type) {
	case []interface{}:
		result := make([]string, 0, len(arr))
		for _, item := range arr {
			s, ok := item.(string)
			if !ok {
				return nil, false
			}
			result = append(result, s)
		}
		return result, true
	case []string:
		return arr, true
	}
	return nil, false
}

func toFloat64(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}
