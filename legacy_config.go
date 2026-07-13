// FilterREX Connector Host — Legacy single-target config bridge
//
// The Config type supports the legacy single-target env-var mode and bridges
// the older per-vendor clients. It is vendor-agnostic plumbing kept in core so
// both the full and SAN-only builds link; new adapters use TargetProfile
// instead.

package main

// Config holds legacy single-target env-var configuration.
type Config struct {
	ConnectorToken string
	BackendURL     string
	TargetType     string

	// Proxmox (legacy env mode)
	ProxmoxBaseURL     string
	ProxmoxUsername    string
	ProxmoxPassword    string
	ProxmoxTokenID     string
	ProxmoxTokenSecret string
	ProxmoxNode        string

	// TrueNAS (legacy env mode)
	TrueNASURL    string
	TrueNASAPIKey string

	// Common
	PollIntervalSecs   int
	InsecureSkipVerify bool
	LogLevel           string
	TimeoutSecs        int // 0 = use adapter default
}

// legacyConfigFromEnv builds a Config from environment variables for backward compatibility.
func legacyConfigFromEnv() *Config {
	return loadLegacyConfig()
}

// loadLegacyConfig reads the old single-target env config.
// Returns an empty Config; it is populated by main.go only in legacy mode.
func loadLegacyConfig() *Config {
	return &Config{}
}
