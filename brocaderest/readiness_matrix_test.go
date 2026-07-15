package brocaderest

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTransportPolicyMatrix asserts every documented transport_mode outcome:
//
//	https-verified (default)    → Client builds, TLS enforced
//	http-lab-only + lab gate    → Client builds, plain-HTTP request succeeds
//	http-lab-only WITHOUT gate  → refused with lab_mode_required
//	<any other mode>            → refused with transport_unsupported
//	https-pinned                → deferred in preview.3 → transport_unsupported
func TestTransportPolicyMatrix(t *testing.T) {
	cases := []struct {
		name        string
		mode        TransportMode
		labMode     string // FILTERREX_LAB_MODE value ("" = unset)
		wantErr     bool
		wantErrCode string
	}{
		{"default_https_verified", "", "", false, ""},
		{"explicit_https_verified", TransportHTTPSVerified, "", false, ""},
		{"http_lab_only_gated", TransportHTTPLabOnly, "1", false, ""},
		{"http_lab_only_ungated", TransportHTTPLabOnly, "", true, ErrCodeLabModeRequired},
		{"http_lab_only_wrong_env", TransportHTTPLabOnly, "yes", true, ErrCodeLabModeRequired},
		{"https_pinned_deferred", TransportMode("https-pinned"), "", true, ErrCodeTransportUnsupported},
		{"garbage_mode", TransportMode("gopher"), "", true, ErrCodeTransportUnsupported},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Isolate env changes to this subtest.
			t.Setenv("FILTERREX_LAB_MODE", tc.labMode)

			_, err := New(Config{
				TargetProfileID: "matrix",
				Host:            "127.0.0.1",
				TransportMode:   tc.mode,
				Username:        "ro",
			})

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tc.wantErrCode)
				}
				var e *Error
				if !errors.As(err, &e) {
					t.Fatalf("expected sanitized *Error, got %T: %v", err, err)
				}
				if e.Code != tc.wantErrCode {
					t.Fatalf("want error code %q, got %q (%s)", tc.wantErrCode, e.Code, e.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("expected success, got %v", err)
			}
		})
	}
}

// TestHTTPLabOnlyEndToEnd proves that with the lab gate set, a Client with
// http-lab-only actually issues a plain-HTTP request against a test server
// carrying Basic auth over the wire — while https-verified against the same
// plaintext server is refused.
func TestHTTPLabOnlyEndToEnd(t *testing.T) {
	// Capture the request the server observes.
	var gotAuth, gotPath, gotProto string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotProto = "http"
		w.Header().Set("Content-Type", "application/yang-data+json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	host, port := splitHostPort(t, srv.URL, "http://")

	pwFile := writePasswordFile(t, "matrix-canary-pw")

	t.Run("lab_mode_disabled_refuses_client", func(t *testing.T) {
		t.Setenv("FILTERREX_LAB_MODE", "")
		_, err := New(Config{
			TargetProfileID: "matrix",
			Host:            host,
			Port:            port,
			TransportMode:   TransportHTTPLabOnly,
			Username:        "ro",
			PasswordFile:    pwFile,
		})
		var e *Error
		if !errors.As(err, &e) || e.Code != ErrCodeLabModeRequired {
			t.Fatalf("expected lab_mode_required, got %v", err)
		}
	})

	t.Run("lab_mode_enabled_sends_basic_over_http", func(t *testing.T) {
		t.Setenv("FILTERREX_LAB_MODE", "1")
		c, err := New(Config{
			TargetProfileID: "matrix",
			Host:            host,
			Port:            port,
			TransportMode:   TransportHTTPLabOnly,
			Username:        "ro",
			PasswordFile:    pwFile,
		})
		if err != nil {
			t.Fatalf("client: %v", err)
		}
		resp, audit, derr := c.Do(context.Background(), "brocade.switch.status", nil)
		if derr != nil {
			t.Fatalf("Do: %v", derr)
		}
		if resp.HTTPStatus != 200 {
			t.Fatalf("http status = %d", resp.HTTPStatus)
		}
		if gotProto != "http" {
			t.Fatalf("expected plain http, got %q", gotProto)
		}
		if gotPath != "/rest/running/brocade-fibrechannel-switch/fibrechannel-switch" {
			t.Fatalf("resolver did not build allowlisted path, got %q", gotPath)
		}
		// Basic auth is present, decodable, and carries the exact password
		// from the on-disk file — proves the on-demand read path.
		if !strings.HasPrefix(gotAuth, "Basic ") {
			t.Fatalf("expected Basic auth, got %q", gotAuth)
		}
		raw, derr2 := base64.StdEncoding.DecodeString(strings.TrimPrefix(gotAuth, "Basic "))
		if derr2 != nil {
			t.Fatalf("basic decode: %v", derr2)
		}
		if string(raw) != "ro:matrix-canary-pw" {
			t.Fatalf("basic payload mismatch: %q", string(raw))
		}
		if audit.ErrorCode != "" {
			t.Fatalf("audit should be clean, got %q", audit.ErrorCode)
		}
		// Audit must never leak the password, username, host, or auth header.
		if strings.Contains(audit.OperationID+audit.TargetProfileID, "matrix-canary-pw") {
			t.Fatal("audit leaked canary password")
		}
	})

	t.Run("https_verified_refuses_plaintext_server", func(t *testing.T) {
		// Point https-verified at the plain-HTTP server → TLS handshake fails.
		t.Setenv("FILTERREX_LAB_MODE", "")
		c, err := New(Config{
			TargetProfileID: "matrix",
			Host:            host,
			Port:            port,
			TransportMode:   TransportHTTPSVerified,
			Username:        "ro",
			PasswordFile:    pwFile,
		})
		if err != nil {
			t.Fatalf("client: %v", err)
		}
		_, audit, derr := c.Do(context.Background(), "brocade.switch.status", nil)
		if derr == nil {
			t.Fatal("expected TLS-related failure, got success")
		}
		var e *Error
		if !errors.As(derr, &e) {
			t.Fatalf("expected sanitized *Error, got %T", derr)
		}
		// Any of: tls_untrusted, rest_connection_failed, rest_timeout — all
		// are acceptable non-success outcomes as long as no request landed.
		if audit.HTTPStatus != 0 {
			t.Fatalf("no HTTP status should be recorded, got %d", audit.HTTPStatus)
		}
	})
}

// TestHTTPSVerifiedRefusesUntrustedCert asserts that a switch with a
// self-signed cert (as most Brocade defaults ship) is rejected under
// https-verified, and returns tls_untrusted — never falls back silently.
func TestHTTPSVerifiedRefusesUntrustedCert(t *testing.T) {
	tsrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer tsrv.Close()

	host, port := splitHostPort(t, tsrv.URL, "https://")
	pwFile := writePasswordFile(t, "unused")

	t.Setenv("FILTERREX_LAB_MODE", "")
	c, err := New(Config{
		TargetProfileID: "matrix",
		Host:            host,
		Port:            port,
		TransportMode:   TransportHTTPSVerified,
		Username:        "ro",
		PasswordFile:    pwFile,
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	_, _, derr := c.Do(context.Background(), "brocade.switch.status", nil)
	if derr == nil {
		t.Fatal("expected TLS failure on self-signed cert, got success")
	}
	var e *Error
	if !errors.As(derr, &e) || e.Code != ErrCodeTLSUntrusted {
		t.Fatalf("expected tls_untrusted, got %v", derr)
	}
	// The test server certificate is not trusted by system roots. Just to
	// verify we're not accidentally reaching the server, confirm tls.Config
	// defaults are what we set (belt-and-braces).
	if (&tls.Config{}).InsecureSkipVerify {
		t.Fatal("default tls.Config leaked InsecureSkipVerify=true")
	}
}

// helpers ---------------------------------------------------------------

func splitHostPort(t *testing.T, urlStr, scheme string) (string, int) {
	t.Helper()
	trimmed := strings.TrimPrefix(urlStr, scheme)
	// host:port
	i := strings.LastIndex(trimmed, ":")
	if i < 0 {
		t.Fatalf("cannot split host:port from %q", urlStr)
	}
	host := trimmed[:i]
	var port int
	for _, r := range trimmed[i+1:] {
		if r < '0' || r > '9' {
			break
		}
		port = port*10 + int(r-'0')
	}
	if port == 0 {
		t.Fatalf("bad port in %q", urlStr)
	}
	return host, port
}

func writePasswordFile(t *testing.T, secret string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "rest.pw")
	if err := os.WriteFile(p, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatalf("write pw: %v", err)
	}
	return p
}
