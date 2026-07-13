// ForgeAI Connector Host — Cisco NDFC / Nexus Dashboard Adapter (read-only)
//
// Collects fabric inventory, switch health, VRF/network posture, and
// alarms from Cisco Nexus Dashboard Fabric Controller via its REST API.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type NdfcAdapter struct {
	profile *TargetProfile
	client  *http.Client
	baseURL string
	token   string
	user    string
	pass    string
}

func NewNdfcAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &NdfcAdapter{profile: profile}, nil
}

func (a *NdfcAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	a.profile = profile
	a.baseURL = profile.Endpoint

	timeout := 20 * time.Second
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

	log.Printf("[ndfc:%s] Verifying NDFC API at %s...", profile.Name, a.baseURL)
	_, err := a.ndfcGet("/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics")
	if err != nil {
		return fmt.Errorf("NDFC API verification failed: %w", err)
	}
	log.Printf("[ndfc:%s] Connected", profile.Name)
	return nil
}

func (a *NdfcAdapter) Collect() (map[string]interface{}, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	fabrics, _ := a.ndfcGetArray("/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics")
	inventory, _ := a.ndfcGetArray("/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/inventory/switches")
	vrfs, _ := a.ndfcGetArray("/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/all/vrfs")
	networks, _ := a.ndfcGetArray("/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/all/networks")
	alarms, _ := a.ndfcGetArray("/appcenter/cisco/ndfc/api/v1/fm/fmrest/alarms")

	// Summarize
	fabricCount := len(fabrics)
	switchCount := len(inventory)
	vrfCount := len(vrfs)
	networkCount := len(networks)

	var alerts []map[string]interface{}
	for _, alarm := range alarms {
		am, _ := alarm.(map[string]interface{})
		if am == nil {
			continue
		}
		sev := "warning"
		if s, ok := am["severity"].(string); ok && (s == "MAJOR" || s == "CRITICAL") {
			sev = "critical"
		}
		msg, _ := am["message"].(string)
		alerts = append(alerts, map[string]interface{}{
			"severity": sev,
			"source":   "ndfc",
			"message":  msg,
		})
	}

	summary := map[string]interface{}{
		"fabricCount":  fabricCount,
		"switchCount":  switchCount,
		"vrfCount":     vrfCount,
		"networkCount": networkCount,
		"alarmCount":   len(alarms),
	}

	snapshotData := map[string]interface{}{
		"fabrics":   fabrics,
		"inventory": inventory,
		"vrfs":      vrfs,
		"networks":  networks,
		"alarms":    alarms,
		"summary":   summary,
	}

	return map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": snapshotData,
		"alerts":       alerts,
		"collectedAt":  now,
	}, nil
}

func (a *NdfcAdapter) Capabilities() []string {
	return []string{
		"ndfc.read.fabrics",
		"ndfc.read.inventory",
		"ndfc.read.vrfs",
		"ndfc.read.networks",
		"ndfc.read.alarms",
	}
}

func (a *NdfcAdapter) HealthCheck() error {
	_, err := a.ndfcGet("/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics")
	return err
}

func (a *NdfcAdapter) Close() error {
	a.client = nil
	return nil
}

func (a *NdfcAdapter) ndfcGet(path string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	a.applyNdfcAuth(req)
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

func (a *NdfcAdapter) ndfcGetArray(path string) ([]interface{}, error) {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	a.applyNdfcAuth(req)
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

	var result []interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		// Try object envelope
		var obj map[string]interface{}
		if err2 := json.Unmarshal(body, &obj); err2 == nil {
			for _, key := range []string{"DATA", "data", "items", "result"} {
				if arr, ok := obj[key].([]interface{}); ok {
					return arr, nil
				}
			}
			return []interface{}{obj}, nil
		}
		return nil, err
	}
	return result, nil
}

func (a *NdfcAdapter) applyNdfcAuth(req *http.Request) {
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	} else if a.user != "" && a.pass != "" {
		req.SetBasicAuth(a.user, a.pass)
	}
}
