// ForgeAI Connector Host — Change Operation Policy
//
// Implements a policy-based authorization model for remote change operations.
// Three modes:
//   - deny     (default) — all change ops rejected
//   - explicit           — only allowlisted operation IDs permitted
//   - all                — all change-level ops permitted (lab/advanced)
//
// Configuration via environment variables:
//   FORGEAI_REMOTE_CHANGE_POLICY=deny|explicit|all
//   FORGEAI_REMOTE_ALLOWED_CHANGE_OPS=idrac-power-on,idrac-graceful-shutdown

package main

import (
	"os"
	"strings"
)

// ChangePolicy represents the change-operation authorization mode.
type ChangePolicy string

const (
	ChangePolicyDeny     ChangePolicy = "deny"
	ChangePolicyExplicit ChangePolicy = "explicit"
	ChangePolicyAll      ChangePolicy = "all"
)

// ChangePolicyConfig holds the parsed change-operation policy.
type ChangePolicyConfig struct {
	Policy          ChangePolicy
	AllowedOps      map[string]bool // normalized operation IDs
	AllowedOpsSlice []string        // for logging
}

// DefaultChangePolicyConfig returns the secure default: deny all change ops.
func DefaultChangePolicyConfig() ChangePolicyConfig {
	return ChangePolicyConfig{
		Policy:     ChangePolicyDeny,
		AllowedOps: map[string]bool{},
	}
}

// ParseChangePolicyFromEnv reads and validates change-operation policy from environment.
func ParseChangePolicyFromEnv() ChangePolicyConfig {
	cfg := DefaultChangePolicyConfig()

	policyStr := strings.ToLower(strings.TrimSpace(os.Getenv("FORGEAI_REMOTE_CHANGE_POLICY")))
	switch policyStr {
	case "explicit":
		cfg.Policy = ChangePolicyExplicit
	case "all":
		cfg.Policy = ChangePolicyAll
	case "deny", "":
		cfg.Policy = ChangePolicyDeny
	default:
		// Unknown value — default to deny for safety
		audit.Warn("change_policy.parse", "Unknown FORGEAI_REMOTE_CHANGE_POLICY value, defaulting to deny",
			F("raw_value", policyStr))
		cfg.Policy = ChangePolicyDeny
	}

	// Parse allowlist
	rawOps := os.Getenv("FORGEAI_REMOTE_ALLOWED_CHANGE_OPS")
	if rawOps != "" {
		seen := map[string]bool{}
		for _, op := range strings.Split(rawOps, ",") {
			op = strings.TrimSpace(op)
			if op != "" && !seen[op] {
				seen[op] = true
				cfg.AllowedOps[op] = true
				cfg.AllowedOpsSlice = append(cfg.AllowedOpsSlice, op)
			}
		}
	}

	return cfg
}

// IsChangeOpAllowed checks whether a specific change operation is authorized.
// Returns (allowed bool, reason string).
func (c *ChangePolicyConfig) IsChangeOpAllowed(operationID string) (bool, string) {
	switch c.Policy {
	case ChangePolicyDeny:
		return false, "remote change operations disabled by policy (FORGEAI_REMOTE_CHANGE_POLICY=deny)"
	case ChangePolicyAll:
		return true, ""
	case ChangePolicyExplicit:
		if operationID == "" {
			return false, "change operation has no operation ID — cannot authorize against allowlist"
		}
		if c.AllowedOps[operationID] {
			return true, ""
		}
		return false, "change operation \"" + operationID + "\" not allowlisted on agent (FORGEAI_REMOTE_ALLOWED_CHANGE_OPS)"
	default:
		return false, "unknown change policy"
	}
}

// LogStartupSummary emits a single structured log line summarizing the change-op policy.
func (c *ChangePolicyConfig) LogStartupSummary() {
	switch c.Policy {
	case ChangePolicyDeny:
		audit.Info("change_policy.startup", "Remote change operations: DISABLED (default deny)")
	case ChangePolicyExplicit:
		audit.Info("change_policy.startup", "Remote change operations: EXPLICIT allowlist",
			F("allowed_ops", c.AllowedOpsSlice),
			F("allowed_count", len(c.AllowedOpsSlice)))
	case ChangePolicyAll:
		audit.Warn("change_policy.startup", "Remote change operations: ALL ENABLED (advanced mode — use with caution)")
	}
}
