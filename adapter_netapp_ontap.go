// ForgeAI Connector Host — NetApp ONTAP Adapter (read-only)
//
// Collects cluster health, aggregate/capacity posture, SVM summary,
// and alerts from ONTAP REST API (/api).

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

type NetAppONTAPAdapter struct {
	profile    *TargetProfile
	client     *http.Client
	baseURL    string
	authHeader string
}

func NewNetAppONTAPAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &NetAppONTAPAdapter{profile: profile}, nil
}

func (a *NetAppONTAPAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	a.profile = profile
	a.baseURL = profile.Endpoint

	timeout := 15 * time.Second
	if profile.ResourceLimits.TimeoutSecs > 0 {
		timeout = time.Duration(profile.ResourceLimits.TimeoutSecs) * time.Second
	}
	a.client = NewHTTPClientFromProfile(profile, timeout)

	// Auth: username/password (Basic) or token
	username := creds["username"]
	password := creds["password"]
	if username != "" && password != "" {
		a.authHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	} else if token := creds["api_token"]; token != "" {
		a.authHeader = "Bearer " + token
	}

	log.Printf("[netapp-ontap:%s] Verifying API access at %s...", profile.Name, a.baseURL)
	_, err := a.apiGet("/api/cluster")
	if err != nil {
		return fmt.Errorf("ONTAP API verification failed: %w", err)
	}
	log.Printf("[netapp-ontap:%s] Connected", profile.Name)
	return nil
}

func (a *NetAppONTAPAdapter) Collect() (map[string]interface{}, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	cluster, _ := a.apiGet("/api/cluster")
	nodes, _ := a.apiGet("/api/cluster/nodes")
	aggregates, _ := a.apiGet("/api/storage/aggregates")
	svms, _ := a.apiGet("/api/svm/svms")
	alerts, _ := a.apiGet("/api/support/ems/events?severity=alert,emergency,error&max_records=50")

	snapshotData := map[string]interface{}{
		"cluster":    cluster,
		"nodes":      extractONTAPRecords(nodes),
		"aggregates": extractONTAPRecords(aggregates),
		"svms":       extractONTAPRecords(svms),
	}

	alertList := extractONTAPAlerts(alerts)

	return map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": snapshotData,
		"alerts":       alertList,
		"collectedAt":  now,
	}, nil
}

func (a *NetAppONTAPAdapter) Capabilities() []string {
	return []string{
		"ontap.read.health",
		"ontap.read.capacity",
		"ontap.read.svm",
		"ontap.read.alerts",
	}
}

func (a *NetAppONTAPAdapter) HealthCheck() error {
	_, err := a.apiGet("/api/cluster")
	return err
}

func (a *NetAppONTAPAdapter) Close() error {
	a.client = nil
	return nil
}

func (a *NetAppONTAPAdapter) apiGet(path string) (map[string]interface{}, error) {
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

func extractONTAPRecords(data map[string]interface{}) []interface{} {
	if data == nil {
		return nil
	}
	if records, ok := data["records"].([]interface{}); ok {
		return records
	}
	return nil
}

func extractONTAPAlerts(data map[string]interface{}) []map[string]interface{} {
	if data == nil {
		return nil
	}
	records, ok := data["records"].([]interface{})
	if !ok {
		return nil
	}
	var alerts []map[string]interface{}
	for _, r := range records {
		if rec, ok := r.(map[string]interface{}); ok {
			severity := "warning"
			if s, ok := rec["severity"].(string); ok {
				severity = s
			}
			message := ""
			if m, ok := rec["message_name"].(string); ok {
				message = m
			}
			alerts = append(alerts, map[string]interface{}{
				"severity": severity,
				"source":   "netapp-ontap",
				"message":  message,
			})
		}
	}
	return alerts
}
