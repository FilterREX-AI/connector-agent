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
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
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
			MaxVersion:         tls.VersionTLS12,
			InsecureSkipVerify: insecureSkipVerify,
			// FOS 8.2 default HTTPS seccryptocfg policy
			// (!ECDH:!DH:HIGH:-MD5:!CAMELLIA:!SRP:!PSK:!AESGCM:!SSLv3)
			// collapses HIGH to static-RSA + AES-CBC-SHA/SHA256. We also
			// keep the two ECDHE-RSA-CBC entries for FOS variants whose
			// policy still permits ECDHE.
			//
			// Explicitly listing static-RSA suites in CipherSuites is
			// sufficient on Go 1.22+ — the GODEBUG=tlsrsakex setting only
			// governs Go's *default* offer list, not an explicit one.
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
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

// tlsMaxVersionLabel returns a human-readable max version for the given
// policy, used in structured diagnostic logs.
func tlsMaxVersionLabel(policy string) string {
	if NormalizeTLSPolicy(policy) == TLSPolicyFOS82Legacy {
		return "TLS1.2"
	}
	return "TLS1.3"
}

// describeCipherSuites returns a comma-separated list of IANA cipher
// suite names for the given policy, or "(go defaults)" for policies
// that leave CipherSuites nil.
func describeCipherSuites(policy string) string {
	cfg, err := tlsConfigForPolicy(NormalizeTLSPolicy(policy), false)
	if err != nil || cfg == nil || len(cfg.CipherSuites) == 0 {
		return "(go defaults)"
	}
	names := make([]string, 0, len(cfg.CipherSuites))
	for _, id := range cfg.CipherSuites {
		names = append(names, tls.CipherSuiteName(id))
	}
	return strings.Join(names, ",")
}

type effectiveTLSConfig struct {
	Policy             string
	ServerName         string
	MinVersion         uint16
	MaxVersion         uint16
	CipherIDs          []uint16
	TrustRef           string
	InsecureSkipVerify bool
}

func effectiveTLSConfigFromProfile(profile *TargetProfile) effectiveTLSConfig {
	if profile == nil {
		return effectiveTLSConfig{Policy: TLSPolicyModern}
	}

	policy := NormalizeTLSPolicy(profile.TLS.Policy)
	cfg, err := tlsConfigForPolicy(policy, profile.TLS.InsecureSkipVerify)
	if err != nil || cfg == nil {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: profile.TLS.InsecureSkipVerify}
	}

	cipherIDs := append([]uint16(nil), cfg.CipherSuites...)
	sort.Slice(cipherIDs, func(i, j int) bool { return cipherIDs[i] < cipherIDs[j] })

	return effectiveTLSConfig{
		Policy:             policy,
		ServerName:         tlsServerNameFromEndpoint(profile.Endpoint),
		MinVersion:         cfg.MinVersion,
		MaxVersion:         cfg.MaxVersion,
		CipherIDs:          cipherIDs,
		TrustRef:           strings.Join([]string{profile.TLS.CACertPath, profile.TLS.ClientCertPath, profile.TLS.ClientKeyPath}, "\x00"),
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}
}

func effectiveTLSConfigsEqual(a, b effectiveTLSConfig) bool {
	if a.Policy != b.Policy || a.ServerName != b.ServerName || a.MinVersion != b.MinVersion ||
		a.MaxVersion != b.MaxVersion || a.TrustRef != b.TrustRef ||
		a.InsecureSkipVerify != b.InsecureSkipVerify || len(a.CipherIDs) != len(b.CipherIDs) {
		return false
	}
	for i := range a.CipherIDs {
		if a.CipherIDs[i] != b.CipherIDs[i] {
			return false
		}
	}
	return true
}

func tlsServerNameFromEndpoint(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	if u.Scheme != "https" {
		return ""
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return strings.ToLower(host)
}
