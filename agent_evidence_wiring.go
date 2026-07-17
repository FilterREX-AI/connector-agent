// FilterREX Connector Host — Agent Evidence collection wiring.
//
// Bridges the `agentevidence` handler to concrete host resources:
//   - Loads the local Brocade export config from disk.
//   - Reports which capabilities the BINARY supports and which
//     TARGET PROFILES are locally configured (separated so the
//     dispatch RPC can distinguish agent_update_required from
//     agent_configuration_required).
//   - Runs a single-target read-only Brocade collection when a
//     dispatched job is claimed.
//   - Emits the stage-specific audit events
//     agent_evidence.poll / .claimed / .readiness_failed /
//     .bundle_produced / .uploaded / .completed / .failed
//     (see agentevidence.Handler).
//
// Runs from the existing outbound relay poll — no second polling
// goroutine. See supervisor.RegisterAgentEvidenceHook.

package main

import (
	"context"
	"fmt"

	"os"
	"strings"
	"sync"
	"time"

	"github.com/filterrex-ai/connector-agent/agentevidence"
	"github.com/filterrex-ai/connector-agent/brocadeexport"
	"github.com/filterrex-ai/connector-agent/evidencebundle"
)


// CapabilityCollectBrocadeEvidenceBundleV1 is the binary-capability string
// this build advertises to the control plane. Never rename without matching
// the server-side dispatch guard.
const CapabilityCollectBrocadeEvidenceBundleV1 = "collect_brocade_evidence_bundle_v1"

// CapabilityProbeBrocadeSshReadinessV1 advertises that this build participates
// in remote-triggered SSH readiness probes for Brocade targets. The app gates
// the "Test from agent now" affordance on this capability appearing in the
// heartbeat manifest; advertising it here does not by itself execute a probe
// (that wiring lands in a later release). Must match the string checked in
// src/config/connectorCapabilities.ts.
const CapabilityProbeBrocadeSshReadinessV1 = "probe_brocade_ssh_readiness_v1"

// defaultBrocadeExportConfigPath is the operator-facing convention. It can be
// overridden via FILTERREX_BROCADE_EXPORT_CONFIG for advanced installs.
const defaultBrocadeExportConfigPath = "/etc/filterrex/brocade-export.json"

// brocadeExportConfigPath returns the operator-facing config location.
func brocadeExportConfigPath() string {
	if p := strings.TrimSpace(os.Getenv("FILTERREX_BROCADE_EXPORT_CONFIG")); p != "" {
		return p
	}
	return defaultBrocadeExportConfigPath
}

// codedError wraps a public error code for agentevidence.Handler.
type codedErr struct {
	code string
	msg  string
}

func (e *codedErr) Error() string { return e.msg }
func (e *codedErr) Code() string  { return e.code }

func newCodedErr(code, msg string) error { return &codedErr{code: code, msg: msg} }

// brocadeReadiness is the LocalReadinessChecker for agentevidence.
type brocadeReadiness struct {
	configPath string
}

func (r *brocadeReadiness) Check(targetProfileID string) error {
	if _, statErr := os.Stat(r.configPath); os.IsNotExist(statErr) {
		return newCodedErr("credential_profile_missing",
			fmt.Sprintf("local Brocade export config not present at %s", r.configPath))
	}
	cfg, err := brocadeexport.LoadConfig(r.configPath)
	if err != nil {
		return newCodedErr("configuration_invalid", "invalid brocade-export config")
	}

	if !cfg.Enabled {
		return newCodedErr("capability_disabled",
			"brocade_bundle_export capability is disabled in local config")
	}
	// Known-hosts must exist for host-key verification.
	kh := strings.TrimSpace(cfg.KnownHostsPath)
	if kh == "" {
		return newCodedErr("known_hosts_missing", "known_hosts_path is required in local config")
	}
	if _, err := os.Stat(kh); err != nil {
		return newCodedErr("known_hosts_missing",
			fmt.Sprintf("known_hosts not readable at %s", kh))
	}
	// Find the matching target.
	tgt, ok := findTargetByProfileID(cfg, targetProfileID)
	if !ok {
		return newCodedErr("target_mapping_missing",
			"no local Brocade target maps to this target_profile_id")
	}
	if _, err := os.Stat(tgt.SSHKeyPath); err != nil {
		if os.IsNotExist(err) {
			return newCodedErr("ssh_key_missing", "ssh key file not found")
		}
		return newCodedErr("ssh_key_unreadable", "ssh key file not readable")
	}
	return nil
}

// brocadeProducer is the BundleProducer for agentevidence.
type brocadeProducer struct {
	configPath string
}

func (p *brocadeProducer) Produce(ctx context.Context, targetProfileID string) (string, string, error) {
	cfg, err := brocadeexport.LoadConfig(p.configPath)
	if err != nil {
		return "", "", newCodedErr("configuration_invalid", err.Error())
	}
	// Narrow to the single target the dispatched job asked for.
	tgt, ok := findTargetByProfileID(cfg, targetProfileID)
	if !ok {
		return "", "", newCodedErr("target_mapping_missing", "no local target for this profile")
	}
	scoped := *cfg
	scoped.Targets = []brocadeexport.TargetConfig{tgt}

	req := brocadeexport.RequestMeta{
		RequesterType: "agent_evidence",
		Requester:     "agent-evidence-dispatch",
		ConfigPath:    p.configPath,
	}
	res, err := brocadeexport.RunExportWithSSH(ctx, &scoped, req)
	if err != nil {
		// Map the small set we can classify; everything else is generic.
		msg := err.Error()
		switch {
		case strings.Contains(msg, "known_hosts"):
			return "", "", newCodedErr("host_key_verification_failed", "host-key verification failed")
		case strings.Contains(msg, "ssh: handshake failed"),
			strings.Contains(msg, "authentication"):
			return "", "", newCodedErr("ssh_auth_failed", "ssh authentication failed")
		default:
			return "", "", newCodedErr("bundle_generation_failed", msg)
		}
	}
	return res.Path, evidencebundle.ProfileVersion(), nil
}

// findTargetByProfileID returns the first target whose TargetProfileID matches.
func findTargetByProfileID(cfg *brocadeexport.ExportConfig, id string) (brocadeexport.TargetConfig, bool) {
	for _, t := range cfg.Targets {
		if strings.EqualFold(strings.TrimSpace(t.TargetProfileID), strings.TrimSpace(id)) {
			return t, true
		}
	}
	return brocadeexport.TargetConfig{}, false
}

// evaluateBrocadeCapabilityStatus inspects the local Brocade export config and
// produces the per-capability readiness struct reported in heartbeats.
//
// It NEVER opens key material or attempts SSH; it only stats files and reads
// the config, so it is safe to call on every capability-manifest build.
func evaluateBrocadeCapabilityStatus(lanOnly bool) CapabilityStatusInfo {
	if lanOnly {
		return CapabilityStatusInfo{
			Enabled:            false,
			ConfigurationState: "lan_only",
			Reason:             "LAN-only mode refuses server-initiated collection",
		}
	}
	path := brocadeExportConfigPath()
	if _, err := os.Stat(path); err != nil {
		return CapabilityStatusInfo{
			Enabled:            false,
			ConfigurationState: "not_configured",
			Reason:             fmt.Sprintf("no config at %s", path),
		}
	}
	cfg, err := brocadeexport.LoadConfig(path)
	if err != nil {
		return CapabilityStatusInfo{
			Enabled:            false,
			ConfigurationState: "invalid",
			Reason:             "config parse failed",
		}
	}
	if !cfg.Enabled {
		return CapabilityStatusInfo{
			Enabled:            false,
			ConfigurationState: "not_configured",
			Reason:             "brocade_bundle_export is false in local config",
		}
	}
	if strings.TrimSpace(cfg.KnownHostsPath) == "" {
		return CapabilityStatusInfo{
			Enabled:            false,
			ConfigurationState: "invalid",
			Reason:             "known_hosts_path is required",
		}
	}
	if _, err := os.Stat(cfg.KnownHostsPath); err != nil {
		return CapabilityStatusInfo{
			Enabled:            false,
			ConfigurationState: "invalid",
			Reason:             "known_hosts file not readable",
		}
	}
	ready := make([]string, 0, len(cfg.Targets))
	for _, t := range cfg.Targets {
		if strings.TrimSpace(t.TargetProfileID) == "" {
			continue
		}
		if _, err := os.Stat(t.SSHKeyPath); err != nil {
			continue
		}
		ready = append(ready, t.TargetProfileID)
	}
	if len(ready) == 0 {
		return CapabilityStatusInfo{
			Enabled:            true,
			ConfigurationState: "not_configured",
			Reason:             "no target_profile_id has a readable SSH key on this host",
		}
	}
	return CapabilityStatusInfo{
		Enabled:               true,
		ConfigurationState:    "ready",
		ReadyTargetProfileIDs: ready,
	}
}

// ── Handler runner (invoked from the existing outbound poll) ───────

// agentEvidenceRunner is a package-level singleton so the existing
// commandPollLoop can safely tick it without allocating a new client each poll.
type agentEvidenceRunner struct {
	mu       sync.Mutex
	handler  *agentevidence.Handler
	inFlight bool
	lastPoll time.Time
}

var agentEvidence agentEvidenceRunner

// initAgentEvidenceRunner wires up the handler with the concrete producer,
// readiness checker, and audit sink. Called once during startup from main.go.
func initAgentEvidenceRunner(backendURL string, connectorToken func() string, agentVersion string, lanOnly func() bool) {
	agentEvidence.mu.Lock()
	defer agentEvidence.mu.Unlock()
	if agentEvidence.handler != nil {
		return
	}
	cfgPath := brocadeExportConfigPath()

	client := &agentevidence.Client{
		BaseURL:      strings.TrimRight(backendURL, "/"),
		AgentVersion: agentVersion,
	}
	// The token is injected per-request via a closure so token rotation
	// (re-enrollment / --force-reset-state) is picked up automatically.
	client.TokenProvider = connectorToken

	agentEvidence.handler = &agentevidence.Handler{
		Client:    client,
		Producer:  &brocadeProducer{configPath: cfgPath},
		Readiness: &brocadeReadiness{configPath: cfgPath},
		LANOnly:   lanOnly,
		AuditLog: func(event string, fields map[string]any) {
			// Every audit line goes through the structured logger. Event
			// names originate in the handler (agent_evidence.*).
			afields := make([]Field, 0, len(fields))
			for k, v := range fields {
				afields = append(afields, F(k, v))
			}
			audit.Info(event, event, afields...)
		},

	}
	audit.Info("agent_evidence.wire",
		"Agent evidence collection wired",
		F("config_path", cfgPath))
}

// tickAgentEvidence is called from the existing outbound poll loop. It is a
// non-blocking, single-flight tick: if a bundle is currently being produced,
// we skip so the poll cadence never queues up SSH work.
func tickAgentEvidence(ctx context.Context) {
	agentEvidence.mu.Lock()
	if agentEvidence.handler == nil {
		agentEvidence.mu.Unlock()
		return
	}
	if agentEvidence.inFlight {
		agentEvidence.mu.Unlock()
		return
	}
	// Throttle the debug-level poll marker to at most once per 5 minutes so
	// a healthy idle agent doesn't spam the log every 3 seconds.
	if time.Since(agentEvidence.lastPoll) > 5*time.Minute {
		agentEvidence.lastPoll = time.Now()
		audit.Debug("agent_evidence.poll", "Polling for evidence collection jobs")
	}
	agentEvidence.inFlight = true
	h := agentEvidence.handler
	agentEvidence.mu.Unlock()

	go func() {
		defer func() {
			agentEvidence.mu.Lock()
			agentEvidence.inFlight = false
			agentEvidence.mu.Unlock()
		}()
		// Bound this claim/produce/upload cycle so it can't outlive the
		// supervisor's shutdown context.
		rctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
		defer cancel()
		if _, err := h.Run(rctx); err != nil {
			audit.Warn("agent_evidence.failed",
				"Evidence collection cycle failed",
				F("error", err.Error()))
		}
	}()
}


