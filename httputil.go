// FilterREX Connector Host — Centralized HTTP Client Factory
//
// Provides NewHTTPClient which clones http.DefaultTransport to preserve
// connection pooling, keepalives, and dial timeouts, then overlays
// TLS and proxy settings. All adapters and backend communication
// should use this instead of constructing transports directly.
//
// TLS policy model
// ================
// Per-target TLS behavior is selected by TLSConfig.Policy:
//
//   "modern" (default)
//     MinVersion TLS 1.2, Go's default (secure) cipher list.
//     Certificate + hostname verification ON.
//
//   "fos82-legacy"
//     MinVersion TLS 1.2, cipher list extended with the RSA-KEX / CBC
//     suites required by Brocade FOS 8.2's default seccryptocfg HTTPS
//     template. Certificate + hostname verification ON. Never sets
//     InsecureSkipVerify. Does not fall back to HTTP.
//
// InsecureSkipVerify is orthogonal to Policy — it is respected only
// when the caller explicitly sets it on TLSConfig.

package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// TLS policy identifiers. Keep the string values stable — they are
// serialized in target profiles and surfaced in structured logs / UI.
const (
	TLSPolicyModern      = "modern"
	TLSPolicyFOS82Legacy = "fos82-legacy"
)

// NormalizeTLSPolicy returns the canonical policy name for storage /
// logging. Unknown or empty values collapse to "modern" — the agent
// never silently downgrades TLS.
func NormalizeTLSPolicy(policy string) string {
	switch policy {
	case TLSPolicyFOS82Legacy:
		return TLSPolicyFOS82Legacy
	default:
		return TLSPolicyModern
	}
}

// tlsConfigForPolicy builds a fresh *tls.Config for the given policy.
// It never mutates a shared config. Returns an error if the policy is
// unrecognized (callers should always feed it a NormalizeTLSPolicy value).
func tlsConfigForPolicy(policy string, insecureSkipVerify bool) (*tls.Config, error) {
	switch NormalizeTLSPolicy(policy) {
	case TLSPolicyModern:
		return &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: insecureSkipVerify,
		}, nil
	case TLSPolicyFOS82Legacy:
		return &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: insecureSkipVerify,
			// Minimum FOS 8.2 compatibility set: ECDHE-RSA + RSA-KEX with
			// AES-CBC-SHA. These are the ciphers Go 1.22+ removed from its
			// secure defaults but FOS 8.2's default HTTPS seccryptocfg
			// template still requires. Keep this list tight — extend only
			// when a specific target proves it needs more.
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
		}, nil
	default:
		return nil, fmt.Errorf("unknown tls policy: %q", policy)
	}
}

// NewHTTPClient creates an *http.Client with proper TLS and proxy support.
// It clones http.DefaultTransport to preserve Go's default connection pooling,
// keepalive, and timeout behavior, then overlays the provided settings.
//
// Parameters:
//   - tlsCfg: per-target TLS settings (nil = use "modern" defaults)
//   - proxy: per-target proxy override (nil = use env vars HTTP_PROXY/HTTPS_PROXY/NO_PROXY)
//   - timeout: request timeout (0 = no timeout)
func NewHTTPClient(tlsCfg *TLSConfig, proxy *ProxyConfig, timeout time.Duration) *http.Client {
	// Clone the default transport to inherit connection pooling, keepalives,
	// dial timeouts, and proxy-from-environment behavior. Never mutate
	// http.DefaultTransport itself.
	base := http.DefaultTransport.(*http.Transport).Clone()

	policy := TLSPolicyModern
	insecure := false
	if tlsCfg != nil {
		policy = NormalizeTLSPolicy(tlsCfg.Policy)
		insecure = tlsCfg.InsecureSkipVerify
	}

	// tlsConfigForPolicy only errors on unknown policies, and we've
	// normalized above — so this cannot fail here. Fall back defensively.
	built, err := tlsConfigForPolicy(policy, insecure)
	if err != nil || built == nil {
		built = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure}
	}
	base.TLSClientConfig = built

	// Overlay proxy: per-target config takes precedence over env vars.
	// The cloned transport already has http.ProxyFromEnvironment set,
	// so env vars (HTTP_PROXY, HTTPS_PROXY, NO_PROXY) work automatically.
	if proxy != nil {
		proxyURL := proxy.HTTPSProxy
		if proxyURL == "" {
			proxyURL = proxy.HTTPProxy
		}
		if proxyURL != "" {
			if parsed, err := url.Parse(proxyURL); err == nil {
				base.Proxy = http.ProxyURL(parsed)
			}
		}
	}

	return &http.Client{
		Transport: base,
		Timeout:   timeout,
	}
}

// NewHTTPClientFromProfile is a convenience wrapper that extracts TLS and proxy
// config from a TargetProfile and creates an HTTP client with the given timeout.
func NewHTTPClientFromProfile(profile *TargetProfile, timeout time.Duration) *http.Client {
	return NewHTTPClient(&profile.TLS, &profile.Proxy, timeout)
}
