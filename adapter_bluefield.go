// ForgeAI Connector Host — NVIDIA BlueField DPU Adapter (read-only)
//
// Collects DPU posture, interface/link summary, offload/RDMA summary,
// system utilization, security posture, and telemetry provider status
// from a BlueField DPU via DTS/Prometheus-style endpoints. Read-only only.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type BlueFieldAdapter struct {
	profile *TargetProfile
	client  *http.Client
	baseURL string
	user    string
	pass    string
	token   string
}

func NewBlueFieldAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &BlueFieldAdapter{profile: profile}, nil
}

func (a *BlueFieldAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	a.profile = profile
	a.baseURL = profile.Endpoint

	timeout := 20 * time.Second
	if profile.ResourceLimits.TimeoutSecs > 0 {
		timeout = time.Duration(profile.ResourceLimits.TimeoutSecs) * time.Second
	}
	a.client = NewHTTPClientFromProfile(profile, timeout)

	a.user = creds["username"]
	a.pass = creds["password"]
	a.token = creds["token"]
	if a.token == "" {
		a.token = creds["api_key"]
	}

	log.Printf("[bluefield] Initialized adapter for %s (%s)", profile.Name, a.baseURL)
	return nil
}

func (a *BlueFieldAdapter) Collect() (map[string]interface{}, error) {
	result := map[string]interface{}{}

	// System info
	if sysInfo, err := a.bfGet("/api/v1/system/info"); err == nil {
		result["dpuName"] = bfStr(sysInfo, "hostname", "dpu_name", "name")
		result["model"] = bfStr(sysInfo, "model", "product_name")
		result["firmware"] = bfStr(sysInfo, "firmware_version", "fw_version")
		result["software"] = bfStr(sysInfo, "doca_version", "software_version")
		result["serial"] = bfStr(sysInfo, "serial_number", "serial")
		result["ovsMode"] = bfStr(sysInfo, "ovs_mode", "eswitch_mode")
		result["uptime"] = bfStr(sysInfo, "uptime")
	} else {
		log.Printf("[bluefield] system/info failed: %v", err)
	}

	// Interfaces
	if ifaces, err := a.bfGetArray("/api/v1/interfaces"); err == nil {
		ifaceList := make([]map[string]interface{}, 0, len(ifaces))
		for _, iface := range ifaces {
			ifaceList = append(ifaceList, map[string]interface{}{
				"name":     bfStr(iface, "name", "interface"),
				"state":    bfStr(iface, "state", "oper_state"),
				"speed":    bfStr(iface, "speed", "link_speed"),
				"mtu":      bfNum(iface, "mtu"),
				"rxErrors": bfNum(iface, "rx_errors", "rx_err"),
				"txErrors": bfNum(iface, "tx_errors", "tx_err"),
			})
		}
		result["interfaces"] = ifaceList
	} else {
		log.Printf("[bluefield] interfaces failed: %v", err)
	}

	// Offload / RDMA
	if rdma, err := a.bfGet("/api/v1/rdma/summary"); err == nil {
		result["offload"] = map[string]interface{}{
			"ovsOffload":     bfStr(rdma, "ovs_offload", "hw_offload"),
			"eswitchMode":    bfStr(rdma, "eswitch_mode"),
			"rdmaDevices":    bfNum(rdma, "rdma_device_count", "rdma_devices"),
			"activeQPs":      bfNum(rdma, "active_qps", "qp_count"),
			"rdmaErrors":     bfNum(rdma, "rdma_errors", "errors"),
			"offloadedFlows": bfNum(rdma, "offloaded_flows", "flow_count"),
		}
	} else {
		log.Printf("[bluefield] rdma/summary failed: %v", err)
	}

	// Utilization
	if util, err := a.bfGet("/api/v1/system/utilization"); err == nil {
		result["utilization"] = map[string]interface{}{
			"cpuCores":      bfNum(util, "cpu_cores", "cores"),
			"cpuPercent":    bfNum(util, "cpu_utilization", "cpu_percent"),
			"memoryTotalMB": bfNum(util, "memory_total", "mem_total"),
			"memoryUsedMB":  bfNum(util, "memory_used", "mem_used"),
			"memoryPercent": bfNum(util, "memory_percent", "mem_percent"),
			"loadAvg":       bfStr(util, "load_average", "load_avg"),
		}
	} else {
		log.Printf("[bluefield] system/utilization failed: %v", err)
	}

	// Security
	if sec, err := a.bfGet("/api/v1/security/posture"); err == nil {
		result["security"] = map[string]interface{}{
			"firewall":      bfStr(sec, "firewall", "firewall_state"),
			"ipsecTunnels":  bfNum(sec, "ipsec_tunnels", "ipsec_count"),
			"cryptoOffload": bfStr(sec, "crypto_offload"),
			"secureBoot":    bfStr(sec, "secure_boot"),
			"trustLevel":    bfStr(sec, "trust_level", "trust"),
		}
	} else {
		log.Printf("[bluefield] security/posture failed: %v", err)
	}

	// Telemetry providers
	if provs, err := a.bfGetArray("/api/v1/telemetry/providers"); err == nil {
		provList := make([]map[string]interface{}, 0, len(provs))
		for _, p := range provs {
			provList = append(provList, map[string]interface{}{
				"name":     bfStr(p, "name", "provider"),
				"status":   bfStr(p, "status", "state"),
				"counters": bfNum(p, "counter_count", "counters"),
			})
		}
		result["providers"] = provList
	} else {
		log.Printf("[bluefield] telemetry/providers failed: %v", err)
	}

	return result, nil
}

func (a *BlueFieldAdapter) HealthCheck() error {
	_, err := a.bfGet("/api/v1/system/info")
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	return nil
}

func (a *BlueFieldAdapter) Capabilities() []string {
	return []string{
		"bluefield.read.system",
		"bluefield.read.interfaces",
		"bluefield.read.offload",
		"bluefield.read.utilization",
		"bluefield.read.security",
		"bluefield.read.telemetry",
	}
}

func (a *BlueFieldAdapter) Close() error {
	return nil
}

// ── HTTP helpers ──

func (a *BlueFieldAdapter) bfGet(path string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	a.bfApplyAuth(req)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, path)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse JSON from %s: %w", path, err)
	}
	return result, nil
}

func (a *BlueFieldAdapter) bfGetArray(path string) ([]map[string]interface{}, error) {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	a.bfApplyAuth(req)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, path)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, err
	}

	// Try array first
	var arr []map[string]interface{}
	if err := json.Unmarshal(body, &arr); err == nil {
		return arr, nil
	}

	// Try envelope object with common wrapper keys
	var obj map[string]interface{}
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, fmt.Errorf("parse JSON array from %s: %w", path, err)
	}
	for _, key := range []string{"items", "data", "results", "interfaces", "providers", "devices"} {
		if items, ok := obj[key]; ok {
			if itemArr, ok := items.([]interface{}); ok {
				result := make([]map[string]interface{}, 0, len(itemArr))
				for _, item := range itemArr {
					if m, ok := item.(map[string]interface{}); ok {
						result = append(result, m)
					}
				}
				return result, nil
			}
		}
	}
	return nil, fmt.Errorf("no array found in response from %s", path)
}

func (a *BlueFieldAdapter) bfApplyAuth(req *http.Request) {
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	} else if a.user != "" && a.pass != "" {
		req.SetBasicAuth(a.user, a.pass)
	}
}

// ── Value extraction helpers (unique names to avoid Go namespace collisions) ──

func bfStr(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

func bfNum(m map[string]interface{}, keys ...string) float64 {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch n := v.(type) {
			case float64:
				return n
			case int:
				return float64(n)
			case int64:
				return float64(n)
			}
		}
	}
	return 0
}
