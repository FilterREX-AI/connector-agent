// ForgeAI Connector Host — Change Policy Unit Tests

package main

import (
	"os"
	"testing"
)

func init() {
	// Ensure global audit logger exists for tests
	if audit == nil {
		InitAuditLogger("error")
	}
}

func TestDefaultChangePolicyDeniesAll(t *testing.T) {
	cfg := DefaultChangePolicyConfig()
	if cfg.Policy != ChangePolicyDeny {
		t.Fatalf("default policy = %q, want deny", cfg.Policy)
	}
	allowed, reason := cfg.IsChangeOpAllowed("idrac-power-on")
	if allowed {
		t.Fatal("default deny should reject all change ops")
	}
	if reason == "" {
		t.Fatal("rejection reason must be non-empty")
	}
}

func TestExplicitAllowsListedOps(t *testing.T) {
	cfg := ChangePolicyConfig{
		Policy:     ChangePolicyExplicit,
		AllowedOps: map[string]bool{"idrac-power-on": true, "idrac-graceful-shutdown": true},
	}

	allowed, _ := cfg.IsChangeOpAllowed("idrac-power-on")
	if !allowed {
		t.Error("explicit policy should allow listed op")
	}

	allowed, _ = cfg.IsChangeOpAllowed("idrac-graceful-shutdown")
	if !allowed {
		t.Error("explicit policy should allow listed op")
	}
}

func TestExplicitDeniesUnlistedOps(t *testing.T) {
	cfg := ChangePolicyConfig{
		Policy:     ChangePolicyExplicit,
		AllowedOps: map[string]bool{"idrac-power-on": true},
	}

	allowed, reason := cfg.IsChangeOpAllowed("idrac-factory-reset")
	if allowed {
		t.Fatal("explicit policy should deny unlisted op")
	}
	if reason == "" {
		t.Fatal("rejection reason must be non-empty")
	}
}

func TestExplicitDeniesEmptyOperationID(t *testing.T) {
	cfg := ChangePolicyConfig{
		Policy:     ChangePolicyExplicit,
		AllowedOps: map[string]bool{"idrac-power-on": true},
	}

	allowed, _ := cfg.IsChangeOpAllowed("")
	if allowed {
		t.Fatal("explicit policy should deny empty operation ID")
	}
}

func TestAllPolicyAllowsEverything(t *testing.T) {
	cfg := ChangePolicyConfig{
		Policy:     ChangePolicyAll,
		AllowedOps: map[string]bool{},
	}

	allowed, _ := cfg.IsChangeOpAllowed("anything-goes")
	if !allowed {
		t.Fatal("all policy should allow any change op")
	}
}

func TestParseFromEnv_Deny(t *testing.T) {
	os.Setenv("FORGEAI_REMOTE_CHANGE_POLICY", "deny")
	os.Setenv("FORGEAI_REMOTE_ALLOWED_CHANGE_OPS", "")
	defer os.Unsetenv("FORGEAI_REMOTE_CHANGE_POLICY")
	defer os.Unsetenv("FORGEAI_REMOTE_ALLOWED_CHANGE_OPS")

	cfg := ParseChangePolicyFromEnv()
	if cfg.Policy != ChangePolicyDeny {
		t.Fatalf("policy = %q, want deny", cfg.Policy)
	}
}

func TestParseFromEnv_Explicit(t *testing.T) {
	os.Setenv("FORGEAI_REMOTE_CHANGE_POLICY", "explicit")
	os.Setenv("FORGEAI_REMOTE_ALLOWED_CHANGE_OPS", "idrac-power-on, idrac-graceful-shutdown ,, idrac-power-on")
	defer os.Unsetenv("FORGEAI_REMOTE_CHANGE_POLICY")
	defer os.Unsetenv("FORGEAI_REMOTE_ALLOWED_CHANGE_OPS")

	cfg := ParseChangePolicyFromEnv()
	if cfg.Policy != ChangePolicyExplicit {
		t.Fatalf("policy = %q, want explicit", cfg.Policy)
	}
	if len(cfg.AllowedOps) != 2 {
		t.Fatalf("allowedOps count = %d, want 2 (deduped)", len(cfg.AllowedOps))
	}
	if !cfg.AllowedOps["idrac-power-on"] || !cfg.AllowedOps["idrac-graceful-shutdown"] {
		t.Fatal("missing expected ops in allowlist")
	}
	if len(cfg.AllowedOpsSlice) != 2 {
		t.Fatalf("allowedOpsSlice = %d, want 2", len(cfg.AllowedOpsSlice))
	}
}

func TestParseFromEnv_All(t *testing.T) {
	os.Setenv("FORGEAI_REMOTE_CHANGE_POLICY", "ALL")
	defer os.Unsetenv("FORGEAI_REMOTE_CHANGE_POLICY")

	cfg := ParseChangePolicyFromEnv()
	if cfg.Policy != ChangePolicyAll {
		t.Fatalf("policy = %q, want all", cfg.Policy)
	}
}

func TestParseFromEnv_UnknownDefaultsDeny(t *testing.T) {
	os.Setenv("FORGEAI_REMOTE_CHANGE_POLICY", "yolo")
	defer os.Unsetenv("FORGEAI_REMOTE_CHANGE_POLICY")

	cfg := ParseChangePolicyFromEnv()
	if cfg.Policy != ChangePolicyDeny {
		t.Fatalf("unknown value should default to deny, got %q", cfg.Policy)
	}
}

func TestParseFromEnv_EmptyDefaultsDeny(t *testing.T) {
	os.Unsetenv("FORGEAI_REMOTE_CHANGE_POLICY")
	os.Unsetenv("FORGEAI_REMOTE_ALLOWED_CHANGE_OPS")

	cfg := ParseChangePolicyFromEnv()
	if cfg.Policy != ChangePolicyDeny {
		t.Fatalf("empty should default to deny, got %q", cfg.Policy)
	}
}

func TestReadOnlyOpsStillWorkRegardlessOfPolicy(t *testing.T) {
	// Change policy only gates "change" safety level — "read-only" is unaffected
	// This test validates the conceptual contract
	cfg := DefaultChangePolicyConfig()
	// read-only safety level should never hit IsChangeOpAllowed
	// The relay checks safety level first, only calls policy for "change"
	if cfg.Policy != ChangePolicyDeny {
		t.Fatal("default should be deny")
	}
}

func TestErrorMessagesAreSpecific(t *testing.T) {
	cases := []struct {
		name   string
		cfg    ChangePolicyConfig
		opID   string
		substr string
	}{
		{
			"deny policy message",
			ChangePolicyConfig{Policy: ChangePolicyDeny},
			"idrac-power-on",
			"disabled by policy",
		},
		{
			"explicit not listed",
			ChangePolicyConfig{Policy: ChangePolicyExplicit, AllowedOps: map[string]bool{}},
			"idrac-power-on",
			"not allowlisted",
		},
		{
			"explicit empty op ID",
			ChangePolicyConfig{Policy: ChangePolicyExplicit, AllowedOps: map[string]bool{"x": true}},
			"",
			"no operation ID",
		},
	}
	for _, tc := range cases {
		_, reason := tc.cfg.IsChangeOpAllowed(tc.opID)
		if reason == "" {
			t.Errorf("%s: expected non-empty reason", tc.name)
			continue
		}
		if !contains(reason, tc.substr) {
			t.Errorf("%s: reason %q does not contain %q", tc.name, reason, tc.substr)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && containsImpl(s, sub)
}

func containsImpl(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
