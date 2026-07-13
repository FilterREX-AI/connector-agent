// ForgeAI Connector Host — InfiniBand Fabric Adapter (read-only)
//
// Collects fabric posture, switch inventory, port health, error
// counters, congestion summary, and alarms from an InfiniBand
// fabric manager (UFM-style REST API). Read-only only.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type InfiniBandAdapter struct {
	profile *TargetProfile
	client  *http.Client
	baseURL string
	user    string
	pass    string
	token   string
}

func NewInfiniBandAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &InfiniBandAdapter{profile: profile}, nil
}

func (a *InfiniBandAdapter) Init(profile *TargetProfile, creds map[string]string) error {
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

	log.Printf("[infiniband:%s] Verifying fabric manager API at %s...", profile.Name, a.baseURL)
	_, err := a.ibGet("/ufmRest/app/ufm_version")
	if err != nil {
		return fmt.Errorf("InfiniBand API verification failed: %w", err)
	}
	log.Printf("[infiniband:%s] Connected", profile.Name)
	return nil
}

func (a *InfiniBandAdapter) Collect() (map[string]interface{}, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	version, _ := a.ibGet("/ufmRest/app/ufm_version")
	health, _ := a.ibGet("/ufmRest/resources/health")
	switches, _ := a.ibGetArray("/ufmRest/resources/systems?type=switch")
	ports, _ := a.ibGetArray("/ufmRest/resources/ports")
	alarms, _ := a.ibGetArray("/ufmRest/app/events?level=critical,warning&max=200")
	links, _ := a.ibGetArray("/ufmRest/resources/links")

	// Summarize switches
	switchTotal := len(switches)
	switchHealthy, switchUnhealthy := 0, 0
	for _, s := range switches {
		sm, _ := s.(map[string]interface{})
		if sm == nil {
			continue
		}
		status, _ := sm["status"].(string)
		if status == "healthy" || status == "active" || status == "OK" {
			switchHealthy++
		} else {
			switchUnhealthy++
		}
	}

	// Summarize ports
	portTotal := len(ports)
	portActive, portDown, portHighError := 0, 0, 0
	for _, p := range ports {
		pm, _ := p.(map[string]interface{})
		if pm == nil {
			continue
		}
		state, _ := pm["logical_state"].(string)
		if state == "Active" || state == "active" {
			portActive++
		} else {
			portDown++
		}
		// Check for high error counters
		symErrs, _ := pm["symbol_errors"].(float64)
		rcvErrs, _ := pm["rcv_errors"].(float64)
		if symErrs > 100 || rcvErrs > 100 {
			portHighError++
		}
	}

	var alertList []map[string]interface{}
	for _, alarm := range alarms {
		am, _ := alarm.(map[string]interface{})
		if am == nil {
			continue
		}
		sev := "warning"
		if level, ok := am["level"].(string); ok && level == "critical" {
			sev = "critical"
		}
		msg, _ := am["description"].(string)
		if msg == "" {
			msg, _ = am["message"].(string)
		}
		alertList = append(alertList, map[string]interface{}{
			"severity": sev,
			"source":   "infiniband",
			"message":  msg,
		})
	}

	if switchUnhealthy > 0 {
		alertList = append(alertList, map[string]interface{}{
			"severity": "critical",
			"source":   "infiniband",
			"message":  fmt.Sprintf("%d switch(es) unhealthy", switchUnhealthy),
		})
	}

	summary := map[string]interface{}{
		"switchTotal":     switchTotal,
		"switchHealthy":   switchHealthy,
		"switchUnhealthy": switchUnhealthy,
		"portTotal":       portTotal,
		"portActive":      portActive,
		"portDown":        portDown,
		"portHighError":   portHighError,
		"linkCount":       len(links),
		"alarmCount":      len(alarms),
	}

	snapshotData := map[string]interface{}{
		"version":  version,
		"health":   health,
		"switches": switches,
		"ports":    ports,
		"links":    links,
		"alarms":   alarms,
		"summary":  summary,
	}

	return map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": snapshotData,
		"alerts":       alertList,
		"collectedAt":  now,
	}, nil
}

func (a *InfiniBandAdapter) Capabilities() []string {
	return []string{
		"infiniband.read.health",
		"infiniband.read.switches",
		"infiniband.read.ports",
		"infiniband.read.links",
		"infiniband.read.alarms",
	}
}

func (a *InfiniBandAdapter) HealthCheck() error {
	_, err := a.ibGet("/ufmRest/app/ufm_version")
	return err
}

func (a *InfiniBandAdapter) Close() error {
	a.client = nil
	return nil
}

func (a *InfiniBandAdapter) ibGet(path string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	a.applyIBAuth(req)
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

func (a *InfiniBandAdapter) ibGetArray(path string) ([]interface{}, error) {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	a.applyIBAuth(req)
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
		var obj map[string]interface{}
		if err2 := json.Unmarshal(body, &obj); err2 == nil {
			for _, key := range []string{"items", "data", "result"} {
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

func (a *InfiniBandAdapter) applyIBAuth(req *http.Request) {
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	} else if a.user != "" && a.pass != "" {
		req.SetBasicAuth(a.user, a.pass)
	}
}
