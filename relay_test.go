// ForgeAI Connector Host — Relay Unit Tests
//
// Focused regression tests for URL construction, TrueNAS method
// translation, and platform dispatch correctness.

package main

import (
	"strings"
	"testing"
)

// ── joinURL tests ──

func TestJoinURL_Basic(t *testing.T) {
	tests := []struct {
		base, path, want string
	}{
		{"https://192.168.40.88", "/api/v2.0/system/info", "https://192.168.40.88/api/v2.0/system/info"},
		{"https://192.168.40.88/", "/api/v2.0/system/info", "https://192.168.40.88/api/v2.0/system/info"},
		{"https://host", "api/v2.0/pool", "https://host/api/v2.0/pool"},
		{"https://host/", "", "https://host"},
		{"https://host", "", "https://host"},
	}
	for _, tt := range tests {
		got := joinURL(tt.base, tt.path)
		if got != tt.want {
			t.Errorf("joinURL(%q, %q) = %q, want %q", tt.base, tt.path, got, tt.want)
		}
	}
}

func TestJoinURL_RegressionMalformedConcat(t *testing.T) {
	// This is the exact regression case: direct string concatenation
	// without a separator produced "https://192.168.40.88system.info"
	got := joinURL("https://192.168.40.88", "system.info")
	if !strings.Contains(got, "/system.info") {
		t.Errorf("joinURL must insert separator: got %q", got)
	}
	if strings.Contains(got, "88system") {
		t.Fatalf("REGRESSION: malformed URL without separator: %q", got)
	}
}

// ── truenasMethodToREST tests ──

func TestTruenasMethodToREST(t *testing.T) {
	tests := []struct {
		method, want string
	}{
		{"system.info", "system/info"},
		{"system.version", "system/version"},
		{"pool.query", "pool"},
		{"pool.dataset.query", "pool/dataset"},
		{"pool.get_instance", "pool/get_instance"}, // ID appended at dispatch time via extractTrueNASInstanceID
		{"sharing.smb.query", "sharing/smb"},
		{"sharing.nfs.query", "sharing/nfs"},
		{"service.query", "service"},
		{"alert.list", "alert/list"},
		{"core.get_jobs", "core/get_jobs"},
		{"interface.query", "interface"},
	}
	for _, tt := range tests {
		got := truenasMethodToREST(tt.method)
		if got != tt.want {
			t.Errorf("truenasMethodToREST(%q) = %q, want %q", tt.method, got, tt.want)
		}
	}
}

// ── Full TrueNAS URL construction test ──

func TestTrueNAS_FullURLConstruction(t *testing.T) {
	endpoint := "https://192.168.40.88"
	method := "system.info"
	restPath := truenasMethodToREST(method)
	fullURL := joinURL(endpoint, "/api/v2.0/"+restPath)

	want := "https://192.168.40.88/api/v2.0/system/info"
	if fullURL != want {
		t.Errorf("full TrueNAS URL = %q, want %q", fullURL, want)
	}
}

func TestTrueNAS_FullURLConstruction_QueryVerb(t *testing.T) {
	endpoint := "https://nas.local:443"
	method := "pool.dataset.query"
	restPath := truenasMethodToREST(method)
	fullURL := joinURL(endpoint, "/api/v2.0/"+restPath)

	want := "https://nas.local:443/api/v2.0/pool/dataset"
	if fullURL != want {
		t.Errorf("full TrueNAS URL = %q, want %q", fullURL, want)
	}
}

// ── Platform dispatch normalization tests ──

func TestPlatformDispatch_NormalizedMatch(t *testing.T) {
	cases := []struct {
		targetType string
		platform   string
		wantTN     bool
	}{
		{"truenas", "truenas", true},
		{"TrueNAS", "truenas", true},
		{"truenas", "TrueNAS", true},
		{" truenas ", "other", true},
		{"other", "truenas", true},
		{"proxmox", "proxmox", false},
		{"", "", false},
	}
	for _, tc := range cases {
		normalizedTarget := strings.ToLower(strings.TrimSpace(tc.targetType))
		normalizedPlatform := strings.ToLower(strings.TrimSpace(tc.platform))
		isTN := normalizedTarget == "truenas" || normalizedPlatform == "truenas"
		if isTN != tc.wantTN {
			t.Errorf("dispatch(target=%q, platform=%q) truenas=%v, want %v",
				tc.targetType, tc.platform, isTN, tc.wantTN)
		}
	}
}

// ── extractTrueNASInstanceID tests ──

func TestExtractTrueNASInstanceID(t *testing.T) {
	cases := []struct {
		name string
		body map[string]interface{}
		want string
	}{
		{"numeric ID", map[string]interface{}{"params": []interface{}{float64(3)}}, "3"},
		{"string ID", map[string]interface{}{"params": []interface{}{"tank"}}, "tank"},
		{"nil body", nil, ""},
		{"no params", map[string]interface{}{}, ""},
		{"empty params", map[string]interface{}{"params": []interface{}{}}, ""},
	}
	for _, tc := range cases {
		got := extractTrueNASInstanceID(tc.body)
		if got != tc.want {
			t.Errorf("%s: extractTrueNASInstanceID = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// ── get_instance URL construction test ──

func TestTrueNAS_GetInstanceURL(t *testing.T) {
	endpoint := "https://192.168.40.88"
	method := "pool.get_instance"
	restPath := truenasMethodToREST(method)

	// Simulate what executeTrueNAS does
	body := map[string]interface{}{"params": []interface{}{float64(1)}}
	id := extractTrueNASInstanceID(body)
	if id != "" {
		restPath = strings.TrimSuffix(restPath, "/get_instance") + "/id/" + id
	}

	fullURL := joinURL(endpoint, "/api/v2.0/"+restPath)
	want := "https://192.168.40.88/api/v2.0/pool/id/1"
	if fullURL != want {
		t.Errorf("get_instance URL = %q, want %q", fullURL, want)
	}
}
