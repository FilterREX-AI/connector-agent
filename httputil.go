// ForgeAI Connector Host — Centralized HTTP Client Factory
//
// Provides NewHTTPClient which clones http.DefaultTransport to preserve
// connection pooling, keepalives, and dial timeouts, then overlays
// TLS and proxy settings. All adapters and backend communication
// should use this instead of constructing transports directly.

package main

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"time"
)

// NewHTTPClient creates an *http.Client with proper TLS and proxy support.
// It clones http.DefaultTransport to preserve Go's default connection pooling,
// keepalive, and timeout behavior, then overlays the provided settings.
//
// Parameters:
//   - tlsCfg: per-target TLS settings (nil = use defaults)
//   - proxy: per-target proxy override (nil = use env vars HTTP_PROXY/HTTPS_PROXY/NO_PROXY)
//   - timeout: request timeout (0 = no timeout)
func NewHTTPClient(tlsCfg *TLSConfig, proxy *ProxyConfig, timeout time.Duration) *http.Client {
	// Clone the default transport to inherit connection pooling, keepalives,
	// dial timeouts, and proxy-from-environment behavior.
	base := http.DefaultTransport.(*http.Transport).Clone()

	// Overlay TLS settings
	if tlsCfg != nil {
		if base.TLSClientConfig == nil {
			base.TLSClientConfig = &tls.Config{}
		}
		base.TLSClientConfig.InsecureSkipVerify = tlsCfg.InsecureSkipVerify
		// Future: CA cert, client cert support
		// if tlsCfg.CACertPath != "" { ... }
		// if tlsCfg.ClientCertPath != "" { ... }
	}

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
