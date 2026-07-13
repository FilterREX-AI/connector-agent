// ForgeAI Connector Host — Dell PowerSwitch Ethernet Adapter (read-only)
//
// Collects switch posture, interface status, VLAN/VRF inventory,
// port-channel health, transceiver/optics status, and environment
// data from Dell PowerSwitch (OS10) via its REST API.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type PowerSwitchAdapter struct {
	profile *TargetProfile
	client  *http.Client
	baseURL string
	user    string
	pass    string
	token   string
}

func NewPowerSwitchAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &PowerSwitchAdapter{profile: profile}, nil
}

func (a *PowerSwitchAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	a.profile = profile
	a.baseURL = profile.Endpoint

	timeout := 15 * time.Second
	if profile.ResourceLimits.TimeoutSecs > 0 {
		timeout = time.Duration(profile.ResourceLimits.TimeoutSecs) * time.Second
	}
	a.client = NewHTTPClientFromProfile(profile, timeout)

	a.user = creds["username"]
	a.pass = creds["password"]
	if t := creds["token"]; t != "" {
		a.token = t
	} else if t := creds["api_token"]; t != "" {
		a.token = t
	}

	log.Printf("[powerswitch:%s] Verifying OS10 REST API at %s...", profile.Name, a.baseURL)
	_, err := a.psGet("/restconf/data/system-sw-state/sw-version")
	if err != nil {
		return fmt.Errorf("PowerSwitch API verification failed: %w", err)
	}
	log.Printf("[powerswitch:%s] Connected", profile.Name)
	return nil
}

func (a *PowerSwitchAdapter) Collect() (map[string]interface{}, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	version, _ := a.psGet("/restconf/data/system-sw-state/sw-version")
	system, _ := a.psGet("/restconf/data/dell-system:system")
	interfaces, _ := a.psGet("/restconf/data/ietf-interfaces:interfaces")
	vlans, _ := a.psGet("/restconf/data/dell-vlan:vlans")
	portChannels, _ := a.psGet("/restconf/data/dell-lag:port-channels")
	environment, _ := a.psGet("/restconf/data/dell-environment:system-environment")
	bgp, _ := a.psGet("/restconf/data/dell-bgp:bgp")

	// Extract interface summary
	intfList := psExtractArray(interfaces, "ietf-interfaces:interface", "interface")
	intfUp, intfDown := 0, 0
	for _, item := range intfList {
		im, _ := item.(map[string]interface{})
		if im == nil {
			continue
		}
		if im["oper-status"] == "up" || im["admin-status"] == "up" {
			intfUp++
		} else {
			intfDown++
		}
	}

	// Extract VLAN count
	vlanList := psExtractArray(vlans, "dell-vlan:vlan", "vlan")

	// Extract port-channel summary
	pcList := psExtractArray(portChannels, "dell-lag:port-channel", "port-channel")

	var alerts []map[string]interface{}
	if intfDown > 5 {
		alerts = append(alerts, map[string]interface{}{
			"severity": "warning",
			"source":   "powerswitch",
			"message":  fmt.Sprintf("%d interfaces down", intfDown),
		})
	}

	summary := map[string]interface{}{
		"interfaceTotal":    len(intfList),
		"interfaceUp":       intfUp,
		"interfaceDown":     intfDown,
		"vlanCount":          len(vlanList),
		"portChannelCount":   len(pcList),
	}

	// Extract version info
	if version != nil {
		summary["swVersion"] = version["sw-version"]
	}

	snapshotData := map[string]interface{}{
		"version":      version,
		"system":       system,
		"interfaces":   interfaces,
		"vlans":        vlans,
		"portChannels": portChannels,
		"environment":  environment,
		"bgp":          bgp,
		"summary":      summary,
	}

	return map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": snapshotData,
		"alerts":       alerts,
		"collectedAt":  now,
	}, nil
}

func (a *PowerSwitchAdapter) Capabilities() []string {
	return []string{
		"powerswitch.read.system",
		"powerswitch.read.interfaces",
		"powerswitch.read.vlans",
		"powerswitch.read.portchannels",
		"powerswitch.read.environment",
		"powerswitch.read.bgp",
	}
}

func (a *PowerSwitchAdapter) HealthCheck() error {
	_, err := a.psGet("/restconf/data/system-sw-state/sw-version")
	return err
}

func (a *PowerSwitchAdapter) Close() error {
	a.client = nil
	return nil
}

func (a *PowerSwitchAdapter) psGet(path string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	} else if a.user != "" && a.pass != "" {
		req.SetBasicAuth(a.user, a.pass)
	}
	req.Header.Set("Accept", "application/yang-data+json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body[:min(200, len(body))]))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// psExtractArray extracts a list from RESTCONF-style JSON using multiple key attempts.
func psExtractArray(resp map[string]interface{}, keys ...string) []interface{} {
	if resp == nil {
		return nil
	}
	for _, key := range keys {
		if arr, ok := resp[key].([]interface{}); ok {
			return arr
		}
	}
	return nil
}
