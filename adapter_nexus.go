// ForgeAI Connector Host — Cisco Nexus / NX-OS Adapter (read-only)
//
// Collects switch posture, interface status, VLAN/VRF inventory, and
// BGP summary from Cisco Nexus switches via the NX-API REST interface.
// All operations are GET-only against the DME model objects.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type NexusAdapter struct {
	profile *TargetProfile
	client  *http.Client
	baseURL string
	token   string
	user    string
	pass    string
}

func NewNexusAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &NexusAdapter{profile: profile}, nil
}

func (a *NexusAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	a.profile = profile
	a.baseURL = profile.Endpoint

	timeout := 15 * time.Second
	if profile.ResourceLimits.TimeoutSecs > 0 {
		timeout = time.Duration(profile.ResourceLimits.TimeoutSecs) * time.Second
	}
	a.client = NewHTTPClientFromProfile(profile, timeout)

	// Auth: username/password (basic) or token
	a.user = creds["username"]
	a.pass = creds["password"]
	if t := creds["token"]; t != "" {
		a.token = t
	} else if t := creds["api_token"]; t != "" {
		a.token = t
	}

	log.Printf("[nexus:%s] Verifying NX-API at %s...", profile.Name, a.baseURL)
	_, err := a.nxGet("/api/mo/sys.json")
	if err != nil {
		return fmt.Errorf("NX-API verification failed: %w", err)
	}
	log.Printf("[nexus:%s] Connected", profile.Name)
	return nil
}

func (a *NexusAdapter) Collect() (map[string]interface{}, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	system, _ := a.nxGet("/api/mo/sys.json")
	interfaces, _ := a.nxGet("/api/mo/sys/intf.json")
	vlans, _ := a.nxGet("/api/mo/sys/bd.json")
	vrfs, _ := a.nxGet("/api/mo/sys/inst.json")
	bgp, _ := a.nxGet("/api/mo/sys/bgp.json")

	// Extract imdata arrays
	sysItems := nxImdata(system)
	intfItems := nxImdata(interfaces)
	vlanItems := nxImdata(vlans)
	vrfItems := nxImdata(vrfs)

	// Summarize interfaces
	intfUp, intfDown, intfTotal := 0, 0, 0
	for _, item := range intfItems {
		attrs := nxAttrs(item)
		if attrs == nil {
			continue
		}
		intfTotal++
		if attrs["operSt"] == "up" {
			intfUp++
		} else {
			intfDown++
		}
	}

	// Extract system info
	sysAttrs := map[string]interface{}{}
	if len(sysItems) > 0 {
		sysAttrs = nxAttrs(sysItems[0])
	}

	var alerts []map[string]interface{}
	if intfDown > 0 {
		alerts = append(alerts, map[string]interface{}{
			"severity": "warning",
			"source":   "nexus",
			"message":  fmt.Sprintf("%d interface(s) operationally down", intfDown),
		})
	}

	summary := map[string]interface{}{
		"hostname":       sysAttrs["name"],
		"model":          sysAttrs["model"],
		"version":        sysAttrs["version"],
		"uptime":         sysAttrs["systemUpTime"],
		"interfaceTotal": intfTotal,
		"interfaceUp":    intfUp,
		"interfaceDown":  intfDown,
		"vlanCount":      len(vlanItems),
		"vrfCount":       len(vrfItems),
	}

	snapshotData := map[string]interface{}{
		"system":     system,
		"interfaces": interfaces,
		"vlans":      vlans,
		"vrfs":       vrfs,
		"bgp":        bgp,
		"summary":    summary,
	}

	return map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": snapshotData,
		"alerts":       alerts,
		"collectedAt":  now,
	}, nil
}

func (a *NexusAdapter) Capabilities() []string {
	return []string{
		"nexus.read.system",
		"nexus.read.interfaces",
		"nexus.read.vlans",
		"nexus.read.vrfs",
		"nexus.read.bgp",
	}
}

func (a *NexusAdapter) HealthCheck() error {
	_, err := a.nxGet("/api/mo/sys.json")
	return err
}

func (a *NexusAdapter) Close() error {
	a.client = nil
	return nil
}

func (a *NexusAdapter) nxGet(path string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	} else if a.user != "" && a.pass != "" {
		req.SetBasicAuth(a.user, a.pass)
	}
	req.Header.Set("Accept", "application/json")

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

// nxImdata extracts the "imdata" array from NX-API responses.
func nxImdata(resp map[string]interface{}) []interface{} {
	if resp == nil {
		return nil
	}
	items, _ := resp["imdata"].([]interface{})
	return items
}

// nxAttrs extracts the first MO class attributes from an imdata element.
func nxAttrs(item interface{}) map[string]interface{} {
	m, _ := item.(map[string]interface{})
	if m == nil {
		return nil
	}
	for _, v := range m {
		vm, _ := v.(map[string]interface{})
		if vm == nil {
			continue
		}
		if attrs, ok := vm["attributes"].(map[string]interface{}); ok {
			return attrs
		}
	}
	return nil
}
