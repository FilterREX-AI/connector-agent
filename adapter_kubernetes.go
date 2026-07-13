// ForgeAI Connector Host — Kubernetes Adapter (read-only)
//
// Collects cluster health, node status, workload posture, and events
// from a Kubernetes API server. Read-only — no exec, log streaming,
// or mutation operations.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type KubernetesAdapter struct {
	profile *TargetProfile
	client  *http.Client
	baseURL string
	token   string
}

func NewKubernetesAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &KubernetesAdapter{profile: profile}, nil
}

func (a *KubernetesAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	a.profile = profile
	a.baseURL = profile.Endpoint

	timeout := 15 * time.Second
	if profile.ResourceLimits.TimeoutSecs > 0 {
		timeout = time.Duration(profile.ResourceLimits.TimeoutSecs) * time.Second
	}
	a.client = NewHTTPClientFromProfile(profile, timeout)

	// Auth: bearer token (service account) or api_token
	if t := creds["token"]; t != "" {
		a.token = t
	} else if t := creds["api_token"]; t != "" {
		a.token = t
	} else if t := creds["service_token"]; t != "" {
		a.token = t
	}

	log.Printf("[kubernetes:%s] Verifying API access at %s...", profile.Name, a.baseURL)
	_, err := a.k8sGet("/api/v1/namespaces?limit=1")
	if err != nil {
		return fmt.Errorf("Kubernetes API verification failed: %w", err)
	}
	log.Printf("[kubernetes:%s] Connected", profile.Name)
	return nil
}

func (a *KubernetesAdapter) Collect() (map[string]interface{}, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	nodes, _ := a.k8sGet("/api/v1/nodes")
	namespaces, _ := a.k8sGet("/api/v1/namespaces")
	pods, _ := a.k8sGet("/api/v1/pods?limit=500")
	deployments, _ := a.k8sGet("/apis/apps/v1/deployments?limit=500")
	events, _ := a.k8sGet("/api/v1/events?limit=200&fieldSelector=type=Warning")

	nodeList := k8sItems(nodes)
	podList := k8sItems(pods)
	deployList := k8sItems(deployments)
	eventList := k8sItems(events)

	// Summarize nodes
	nodesReady, nodesNotReady := 0, 0
	for _, n := range nodeList {
		if k8sNodeReady(n) {
			nodesReady++
		} else {
			nodesNotReady++
		}
	}

	// Summarize pods
	podsRunning, podsPending, podsFailed, podsCrashlooping := 0, 0, 0, 0
	for _, p := range podList {
		pm, _ := p.(map[string]interface{})
		if pm == nil {
			continue
		}
		status, _ := pm["status"].(map[string]interface{})
		phase, _ := status["phase"].(string)
		switch phase {
		case "Running":
			podsRunning++
		case "Pending":
			podsPending++
		case "Failed":
			podsFailed++
		}
		// Check for CrashLoopBackOff
		containerStatuses, _ := status["containerStatuses"].([]interface{})
		for _, cs := range containerStatuses {
			csm, _ := cs.(map[string]interface{})
			if csm == nil {
				continue
			}
			waiting, _ := csm["state"].(map[string]interface{})["waiting"].(map[string]interface{})
			if reason, _ := waiting["reason"].(string); reason == "CrashLoopBackOff" {
				podsCrashlooping++
			}
		}
	}

	// Summarize deployments
	deploysAvailable, deploysUnavailable := 0, 0
	for _, d := range deployList {
		dm, _ := d.(map[string]interface{})
		if dm == nil {
			continue
		}
		status, _ := dm["status"].(map[string]interface{})
		unavail, _ := status["unavailableReplicas"].(float64)
		if unavail > 0 {
			deploysUnavailable++
		} else {
			deploysAvailable++
		}
	}

	// Warning events as alerts
	var alerts []map[string]interface{}
	for _, e := range eventList {
		em, _ := e.(map[string]interface{})
		if em == nil {
			continue
		}
		msg, _ := em["message"].(string)
		reason, _ := em["reason"].(string)
		involvedObj, _ := em["involvedObject"].(map[string]interface{})
		objName := ""
		if involvedObj != nil {
			objName, _ = involvedObj["name"].(string)
		}
		alerts = append(alerts, map[string]interface{}{
			"severity": "warning",
			"source":   "kubernetes",
			"message":  fmt.Sprintf("[%s] %s: %s", objName, reason, msg),
		})
		if len(alerts) >= 20 {
			break
		}
	}

	summary := map[string]interface{}{
		"nodesReady":          nodesReady,
		"nodesNotReady":       nodesNotReady,
		"namespaceCount":      len(k8sItems(namespaces)),
		"podsRunning":         podsRunning,
		"podsPending":         podsPending,
		"podsFailed":          podsFailed,
		"podsCrashlooping":    podsCrashlooping,
		"deploymentsTotal":    len(deployList),
		"deploysAvailable":    deploysAvailable,
		"deploysUnavailable":  deploysUnavailable,
		"warningEventCount":   len(eventList),
	}

	snapshotData := map[string]interface{}{
		"nodes":       nodes,
		"pods":        pods,
		"deployments": deployments,
		"events":      events,
		"summary":     summary,
	}

	return map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": snapshotData,
		"alerts":       alerts,
		"collectedAt":  now,
	}, nil
}

func (a *KubernetesAdapter) Capabilities() []string {
	return []string{
		"kubernetes.read.nodes",
		"kubernetes.read.pods",
		"kubernetes.read.deployments",
		"kubernetes.read.events",
	}
}

func (a *KubernetesAdapter) HealthCheck() error {
	_, err := a.k8sGet("/api/v1/namespaces?limit=1")
	return err
}

func (a *KubernetesAdapter) Close() error {
	a.client = nil
	return nil
}

func (a *KubernetesAdapter) k8sGet(path string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
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

// k8sItems extracts the .items array from a Kubernetes list response.
func k8sItems(resp map[string]interface{}) []interface{} {
	if resp == nil {
		return nil
	}
	items, _ := resp["items"].([]interface{})
	return items
}

// k8sNodeReady checks if a node has condition type=Ready status=True.
func k8sNodeReady(node interface{}) bool {
	nm, _ := node.(map[string]interface{})
	if nm == nil {
		return false
	}
	status, _ := nm["status"].(map[string]interface{})
	conditions, _ := status["conditions"].([]interface{})
	for _, c := range conditions {
		cm, _ := c.(map[string]interface{})
		if cm == nil {
			continue
		}
		if cm["type"] == "Ready" {
			return cm["status"] == "True"
		}
	}
	return false
}
