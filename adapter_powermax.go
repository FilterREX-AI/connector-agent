// ForgeAI Connector Host — PowerMax Adapter (read-only)
//
// Collects array health, capacity posture, SRDF summary, and alerts
// from Dell PowerMax Unisphere REST API.

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

type PowerMaxAdapter struct {
	profile    *TargetProfile
	client     *http.Client
	baseURL    string
	authHeader string
	symmetrixID string
}

func NewPowerMaxAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &PowerMaxAdapter{profile: profile}, nil
}

func (a *PowerMaxAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	a.profile = profile
	a.baseURL = profile.Endpoint

	timeout := 20 * time.Second
	if profile.ResourceLimits.TimeoutSecs > 0 {
		timeout = time.Duration(profile.ResourceLimits.TimeoutSecs) * time.Second
	}
	a.client = NewHTTPClientFromProfile(profile, timeout)

	username := creds["username"]
	password := creds["password"]
	if username != "" && password != "" {
		a.authHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	}

	// SymmetrixID from creds or target config
	a.symmetrixID = creds["symmetrix_id"]
	if a.symmetrixID == "" {
		if tc := profile.TargetConfig; tc != nil {
			if v, ok := tc["symmetrix_id"].(string); ok {
				a.symmetrixID = v
			}
		}
	}

	log.Printf("[powermax:%s] Verifying API access at %s...", profile.Name, a.baseURL)
	_, err := a.apiGet("/univmax/restapi/system/version")
	if err != nil {
		return fmt.Errorf("PowerMax API verification failed: %w", err)
	}
	log.Printf("[powermax:%s] Connected (symmetrix: %s)", profile.Name, a.symmetrixID)
	return nil
}

func (a *PowerMaxAdapter) Collect() (map[string]interface{}, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	tasks := []SubCollectionTask{
		{Name: "version", Fn: func() (map[string]interface{}, error) {
			return a.apiGet("/univmax/restapi/system/version")
		}},
	}

	if a.symmetrixID != "" {
		prefix := "/univmax/restapi/100/system/symmetrix/" + a.symmetrixID
		tasks = append(tasks,
			SubCollectionTask{Name: "health", Fn: func() (map[string]interface{}, error) {
				return a.apiGet(prefix + "/health")
			}},
			SubCollectionTask{Name: "srdf_groups", Fn: func() (map[string]interface{}, error) {
				return a.apiGet(prefix + "/rdf_group")
			}},
			SubCollectionTask{Name: "alerts", Fn: func() (map[string]interface{}, error) {
				return a.apiGet(prefix + "/alert?acknowledged=false")
			}},
		)
	}

	result := RunConcurrentCollection(tasks, 4)

	if len(result.FailedSections) > 0 {
		log.Printf("[powermax:%s] Partial collection: %d/%d sections failed: %v",
			a.profile.Name, len(result.FailedSections), result.TotalSections, result.FailedSections)
	}

	if result.Status() == "error" {
		return nil, fmt.Errorf("all %d sub-collections failed", result.TotalSections)
	}

	snapshotData := map[string]interface{}{}
	if version, ok := result.Sections["version"]; ok {
		snapshotData["version"] = version
	}
	if health, ok := result.Sections["health"]; ok {
		snapshotData["health"] = health
	}
	if srdf, ok := result.Sections["srdf_groups"]; ok {
		snapshotData["srdf_groups"] = extractNestedList(srdf.(map[string]interface{}), "rdfGroupID")
	}

	if marker := result.DegradedMarker(); marker != nil {
		snapshotData["_collection_status"] = marker
	}

	var alertList []map[string]interface{}
	if alerts, ok := result.Sections["alerts"]; ok {
		alertList = extractPowerMaxAlerts(alerts.(map[string]interface{}))
	}

	return map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": snapshotData,
		"alerts":       alertList,
		"collectedAt":  now,
		"_subCalls":    result.SubCalls,
	}, nil
}

func (a *PowerMaxAdapter) Capabilities() []string {
	return []string{
		"powermax.read.health",
		"powermax.read.capacity",
		"powermax.read.srdf",
		"powermax.read.alerts",
	}
}

func (a *PowerMaxAdapter) HealthCheck() error {
	_, err := a.apiGet("/univmax/restapi/system/version")
	return err
}

func (a *PowerMaxAdapter) Close() error {
	a.client = nil
	return nil
}

func (a *PowerMaxAdapter) apiGet(path string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if a.authHeader != "" {
		req.Header.Set("Authorization", a.authHeader)
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

func extractNestedList(data map[string]interface{}, key string) interface{} {
	if data == nil {
		return nil
	}
	if list, ok := data[key]; ok {
		return list
	}
	return nil
}

func extractPowerMaxAlerts(data map[string]interface{}) []map[string]interface{} {
	if data == nil {
		return nil
	}
	// Unisphere returns alerts in various structures
	var rawAlerts []interface{}
	if list, ok := data["alertId"].([]interface{}); ok {
		rawAlerts = list
	}
	var alerts []map[string]interface{}
	for _, item := range rawAlerts {
		if a, ok := item.(map[string]interface{}); ok {
			severity := "warning"
			if s, ok := a["severity"].(string); ok {
				severity = s
			}
			desc := ""
			if d, ok := a["description"].(string); ok {
				desc = d
			}
			alerts = append(alerts, map[string]interface{}{
				"severity": severity,
				"source":   "powermax",
				"message":  desc,
			})
		}
	}
	return alerts
}
