// ForgeAI Connector Host — Dell iDRAC Adapter (read-only)
//
// Collects system health, hardware inventory, thermal status, power,
// and SEL logs from Dell iDRAC via the standard DMTF Redfish v1 API.

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type IdracAdapter struct {
	profile    *TargetProfile
	client     *http.Client
	baseURL    string
	authHeader string
}

func NewIdracAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &IdracAdapter{profile: profile}, nil
}

func (a *IdracAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	a.profile = profile
	a.baseURL = profile.Endpoint

	timeout := 15 * time.Second
	if profile.ResourceLimits.TimeoutSecs > 0 {
		timeout = time.Duration(profile.ResourceLimits.TimeoutSecs) * time.Second
	}
	if timeout > 30*time.Second {
		timeout = 30 * time.Second
	}
	a.client = NewHTTPClientFromProfile(profile, timeout)

	// Auth: Basic auth from username/password
	username := creds["username"]
	password := creds["password"]
	if username == "" || password == "" {
		return fmt.Errorf("iDRAC requires username and password credentials")
	}
	a.authHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))

	log.Printf("[idrac:%s] Verifying Redfish API access at %s...", profile.Name, a.baseURL)
	_, err := a.apiGet("/redfish/v1/Systems/System.Embedded.1")
	if err != nil {
		return fmt.Errorf("iDRAC Redfish API verification failed: %w", err)
	}
	log.Printf("[idrac:%s] Connected", profile.Name)
	return nil
}

func (a *IdracAdapter) Collect() (map[string]interface{}, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	system, _ := a.apiGet("/redfish/v1/Systems/System.Embedded.1")
	power, _ := a.apiGet("/redfish/v1/Chassis/System.Embedded.1/Power")
	thermal, _ := a.apiGet("/redfish/v1/Chassis/System.Embedded.1/Thermal")
	processors, _ := a.apiGetMembers("/redfish/v1/Systems/System.Embedded.1/Processors")
	memory, _ := a.apiGetMembers("/redfish/v1/Systems/System.Embedded.1/Memory")
	storage, _ := a.apiGetMembers("/redfish/v1/Systems/System.Embedded.1/Storage")
	selEntries, _ := a.apiGetMembers("/redfish/v1/Systems/System.Embedded.1/LogServices/Sel/Entries")

	if len(selEntries) > 50 {
		selEntries = selEntries[:50]
	}

	snapshotData := normalizeIdracSnapshot(system, power, thermal, processors, memory, storage, selEntries)
	alertList := extractIdracAlerts(system, selEntries)

	return map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": snapshotData,
		"alerts":       alertList,
		"collectedAt":  now,
		"_signals":     extractIdracSignals(snapshotData),
	}, nil
}

// extractIdracSignals mirrors frontend signal rules for Hybrid Mode rollup.
func extractIdracSignals(data map[string]interface{}) []SnapshotSignal {
	var sigs []SnapshotSignal

	if h, _ := data["health"].(string); h != "" && h != "OK" {
		sigs = append(sigs, SnapshotSignal{
			Key: "health.degraded", Label: "System health degraded",
			Value: h, Severity: "warning",
		})
	}

	if p, _ := data["powerState"].(string); p != "" && p != "On" {
		sigs = append(sigs, SnapshotSignal{
			Key: "power.off", Label: "Server powered off",
			Value: p, Severity: "warning",
		})
	}

	// temperatures is []map[string]interface{} from normalizeIdracSnapshot
	if temps, ok := data["temperatures"].([]map[string]interface{}); ok {
		hot := 0
		for _, m := range temps {
			r, _ := m["readingCelsius"].(float64)
			th, _ := m["threshold"].(float64)
			if th > 0 && r >= th*0.9 {
				hot++
			}
		}
		if hot > 0 {
			sigs = append(sigs, SnapshotSignal{
				Key: "thermal.warning", Label: "Thermal sensors near threshold",
				Value: fmt.Sprintf("%d sensor(s)", hot), Severity: "warning",
			})
		}
	}

	// psuHealth is []string from normalizeIdracSnapshot
	if psus, ok := data["psuHealth"].([]string); ok {
		faulted := 0
		for _, s := range psus {
			if s != "OK" {
				faulted++
			}
		}
		if faulted > 0 {
			sigs = append(sigs, SnapshotSignal{
				Key: "psu.fault", Label: "PSU fault detected",
				Value: fmt.Sprintf("%d PSU(s)", faulted), Severity: "error",
			})
		}
	}

	// selEntries is []map[string]interface{} from normalizeIdracSnapshot
	if sel, ok := data["selEntries"].([]map[string]interface{}); ok {
		critical := 0
		for _, m := range sel {
			sev, _ := m["severity"].(string)
			if sev == "Critical" || sev == "Error" {
				critical++
			}
		}
		if critical > 0 {
			sigs = append(sigs, SnapshotSignal{
				Key: "sel.critical", Label: "Critical SEL events",
				Value: fmt.Sprintf("%d event(s)", critical), Severity: "error",
			})
		}
	}

	// memoryModules is []map[string]interface{} from normalizeIdracSnapshot
	if mods, ok := data["memoryModules"].([]map[string]interface{}); ok {
		bad := 0
		for _, mm := range mods {
			h, _ := mm["health"].(string)
			if h != "" && h != "OK" {
				bad++
			}
		}
		if bad > 0 {
			sigs = append(sigs, SnapshotSignal{
				Key: "dimm.fault", Label: "DIMM fault detected",
				Value: fmt.Sprintf("%d DIMM(s)", bad), Severity: "error",
			})
		}
	}

	return sigs
}

func (a *IdracAdapter) Capabilities() []string {
	return []string{
		"idrac.read.system",
		"idrac.read.health",
		"idrac.read.power",
		"idrac.read.thermal",
		"idrac.read.inventory",
		"idrac.read.logs",
	}
}

func (a *IdracAdapter) HealthCheck() error {
	_, err := a.apiGet("/redfish/v1/Systems/System.Embedded.1")
	return err
}

func (a *IdracAdapter) Close() error {
	a.client = nil
	return nil
}

// apiGet fetches a single Redfish JSON object.
func (a *IdracAdapter) apiGet(path string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", a.authHeader)
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
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

// apiGetMembers fetches a Redfish collection and returns the Members array.
func (a *IdracAdapter) apiGetMembers(path string) ([]interface{}, error) {
	collection, err := a.apiGet(path)
	if err != nil {
		return nil, err
	}

	members, ok := collection["Members"].([]interface{})
	if !ok {
		// Some endpoints return data directly without Members wrapper
		return []interface{}{collection}, nil
	}
	return members, nil
}

func normalizeIdracSnapshot(system, power, thermal map[string]interface{}, processors, memory, storage, selEntries []interface{}) map[string]interface{} {
	out := map[string]interface{}{}

	// System fields
	if system != nil {
		out["hostname"] = strField(system, "HostName")
		out["model"] = strField(system, "Model")
		out["serialNumber"] = strField(system, "SerialNumber")
		out["biosVersion"] = strField(system, "BiosVersion")
		out["powerState"] = strField(system, "PowerState")
		out["indicatorLED"] = strField(system, "IndicatorLED")
		if status, ok := system["Status"].(map[string]interface{}); ok {
			out["health"] = strField(status, "Health")
			out["healthRollup"] = strField(status, "HealthRollup")
		}
	}

	// Power
	if power != nil {
		if controls, ok := power["PowerControl"].([]interface{}); ok && len(controls) > 0 {
			if pc, ok := controls[0].(map[string]interface{}); ok {
				if w, ok := pc["PowerConsumedWatts"].(float64); ok {
					out["powerConsumedWatts"] = w
				}
			}
		}
		if psus, ok := power["PowerSupplies"].([]interface{}); ok {
			out["psuCount"] = len(psus)
			var psuHealth []string
			for _, p := range psus {
				if pm, ok := p.(map[string]interface{}); ok {
					h := "OK"
					if st, ok := pm["Status"].(map[string]interface{}); ok {
						if hv, ok := st["Health"].(string); ok {
							h = hv
						}
					}
					psuHealth = append(psuHealth, h)
				}
			}
			out["psuHealth"] = psuHealth
		}
	}

	// Thermal
	if thermal != nil {
		if temps, ok := thermal["Temperatures"].([]interface{}); ok {
			var tList []map[string]interface{}
			for _, t := range temps {
				if tm, ok := t.(map[string]interface{}); ok {
					entry := map[string]interface{}{
						"name":           strField(tm, "Name"),
						"readingCelsius": numField(tm, "ReadingCelsius"),
						"health":         statusHealth(tm),
					}
					if thresh, ok := tm["UpperThresholdCritical"].(float64); ok {
						entry["threshold"] = thresh
					}
					tList = append(tList, entry)
				}
			}
			out["temperatures"] = tList
		}
		if fans, ok := thermal["Fans"].([]interface{}); ok {
			var fList []map[string]interface{}
			for _, f := range fans {
				if fm, ok := f.(map[string]interface{}); ok {
					fList = append(fList, map[string]interface{}{
						"name":    strField(fm, "Name"),
						"reading": numField(fm, "Reading"),
						"health":  statusHealth(fm),
					})
				}
			}
			out["fans"] = fList
		}
	}

	// Processors
	if len(processors) > 0 {
		var pList []map[string]interface{}
		for _, p := range processors {
			if pm, ok := p.(map[string]interface{}); ok {
				pList = append(pList, map[string]interface{}{
					"id":     strField(pm, "Id"),
					"model":  strField(pm, "Name"),
					"cores":  numField(pm, "TotalCores"),
					"health": statusHealth(pm),
				})
			}
		}
		out["processors"] = pList
	}

	// Memory
	if len(memory) > 0 {
		var mList []map[string]interface{}
		for _, m := range memory {
			if mm, ok := m.(map[string]interface{}); ok {
				mList = append(mList, map[string]interface{}{
					"id":          strField(mm, "Id"),
					"capacityMiB": numField(mm, "CapacityMiB"),
					"health":      statusHealth(mm),
				})
			}
		}
		out["memoryModules"] = mList
	}

	// Storage
	if len(storage) > 0 {
		var sList []map[string]interface{}
		for _, s := range storage {
			if sm, ok := s.(map[string]interface{}); ok {
				sList = append(sList, map[string]interface{}{
					"id":     strField(sm, "Id"),
					"model":  strField(sm, "Name"),
					"health": statusHealth(sm),
				})
			}
		}
		out["storageControllers"] = sList
	}

	// SEL entries
	if len(selEntries) > 0 {
		var eList []map[string]interface{}
		for _, e := range selEntries {
			if em, ok := e.(map[string]interface{}); ok {
				eList = append(eList, map[string]interface{}{
					"severity": strField(em, "Severity"),
					"message":  strField(em, "Message"),
					"created":  strField(em, "Created"),
				})
			}
		}
		out["selEntries"] = eList
	}

	return out
}

func strField(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func numField(m map[string]interface{}, key string) float64 {
	if v, ok := m[key].(float64); ok {
		return v
	}
	return 0
}

func statusHealth(m map[string]interface{}) string {
	if st, ok := m["Status"].(map[string]interface{}); ok {
		if h, ok := st["Health"].(string); ok {
			return h
		}
	}
	return "OK"
}

func extractIdracAlerts(system map[string]interface{}, selEntries []interface{}) []map[string]interface{} {
	var alerts []map[string]interface{}

	// Check system health status
	if system != nil {
		if status, ok := system["Status"].(map[string]interface{}); ok {
			if health, ok := status["Health"].(string); ok && health != "OK" {
				alerts = append(alerts, map[string]interface{}{
					"severity": "warning",
					"source":   "dell-idrac",
					"message":  fmt.Sprintf("System health: %s", health),
				})
			}
		}
	}

	// Extract critical/error SEL entries
	for _, entry := range selEntries {
		e, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		severity, _ := e["Severity"].(string)
		if severity != "Critical" && severity != "Error" {
			continue
		}
		message, _ := e["Message"].(string)
		alertSev := "warning"
		if severity == "Critical" {
			alertSev = "error"
		}
		alerts = append(alerts, map[string]interface{}{
			"severity": alertSev,
			"source":   "dell-idrac",
			"message":  message,
		})
	}

	return alerts
}
