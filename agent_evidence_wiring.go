// FilterREX Connector Host — Agent Evidence collection wiring (preview.22).
//
// Bridges the `agentevidence` handler to concrete host resources by consuming
// the SAME targets.json + runtime-readiness sidecar the wizard writes and the
// heartbeat/probe path reads. There is no longer a second /etc/filterrex/
// brocade-export.json config; if the operator has proven SSH via the wizard
// or `target probe`, agent-evidence collection is ready by construction.
//
// Emits the stage-specific audit events
//   agent_evidence.poll / .claimed / .readiness_failed /
//   .bundle_produced / .uploaded / .completed / .failed
// (see agentevidence.Handler).
//
// Runs from the existing outbound relay poll — no second polling goroutine.

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/filterrex-ai/connector-agent/agentevidence"
	"github.com/filterrex-ai/connector-agent/brocadeexport"
	"github.com/filterrex-ai/connector-agent/evidencebundle"
	"github.com/filterrex-ai/connector-agent/targetconfigure"
)

// CapabilityCollectBrocadeEvidenceBundleV1 is the binary-capability string
// this build advertises to the control plane. Never rename without matching
// the server-side dispatch guard.
const CapabilityCollectBrocadeEvidenceBundleV1 = "collect_brocade_evidence_bundle_v1"

// CapabilityProbeBrocadeSshReadinessV1 advertises that this build participates
// in remote-triggered SSH readiness probes for Brocade targets.
const CapabilityProbeBrocadeSshReadinessV1 = "probe_brocade_ssh_readiness_v1"

// codedError wraps a public error code for agentevidence.Handler.
type codedErr struct {
	code string
	msg  string
}

func (e *codedErr) Error() string { return e.msg }
func (e *codedErr) Code() string  { return e.code }

func newCodedErr(code, msg string) error { return &codedErr{code: code, msg: msg} }

// codedFromReadinessErr maps a targetconfigure loader sentinel to a public
// error code from the fixed allowlist in agentevidence/handler.go.
func codedFromReadinessErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, targetconfigure.ErrTargetConfigMissing):
		return newCodedErr("target_configuration_missing",
			"connector has no targets.json — run `target configure`")
	case errors.Is(err, targetconfigure.ErrTargetConfigUnreadable):
		return newCodedErr("target_configuration_invalid",
			"connector cannot read targets.json")
	case errors.Is(err, targetconfigure.ErrTargetNotConfigured):
		return newCodedErr("target_not_configured",
			"no local target maps to this target_profile_id")
	case errors.Is(err, targetconfigure.ErrDuplicateTargetID):
		return newCodedErr("target_not_configured",
			"multiple local targets share this target_profile_id")
	case errors.Is(err, targetconfigure.ErrInvalidTargetID):
		return newCodedErr("target_configuration_invalid",
			"target_profile_id is not a valid UUID")
	case errors.Is(err, targetconfigure.ErrSSHSetupPending):
		return newCodedErr("ssh_setup_pending",
			"SSH has never been proven for this target — run `target probe`")
	case errors.Is(err, targetconfigure.ErrSSHProbeStale):
		return newCodedErr("ssh_probe_stale",
			"last successful SSH probe is older than the freshness window")
	case errors.Is(err, targetconfigure.ErrSSHNotReady):
		return newCodedErr("ssh_not_ready",
			"connector has not reported fresh SSH readiness for this target")
	}
	// Bounded fall-back — never leak arbitrary text.
	msg := err.Error()
	switch msg {
	case "ssh_key_missing", "ssh_key_unreadable", "known_hosts_missing":
		return newCodedErr(msg, msg)
	}
	return newCodedErr("target_configuration_invalid", msg)
}

// brocadeReadiness is the LocalReadinessChecker for agentevidence. It uses the
// wizard-owned targets.json + runtime sidecar as the single source of truth
// AND verifies the local artifact directory is writable BEFORE any SSH work
// happens — a snapshot we cannot persist should never be collected.
type brocadeReadiness struct {
	targetsDir      string
	runtimeStateDir string
	artifactDir     string
	lanOnly         func() bool
}

func (r *brocadeReadiness) Check(targetProfileID string) error {
	if r.lanOnly != nil && r.lanOnly() {
		return newCodedErr("lan_only_mode",
			"connector is in LAN-only mode; server-initiated collection refused")
	}
	_, readiness, err := targetconfigure.LoadResolvedBrocadeTarget(
		r.targetsDir, r.runtimeStateDir, targetProfileID)
	if err != nil {
		return codedFromReadinessErr(err)
	}
	if gateErr := targetconfigure.ReadinessGateError(readiness); gateErr != nil {
		return codedFromReadinessErr(gateErr)
	}
	if r.artifactDir != "" {
		if werr := brocadeexport.VerifyWritableDirectory(r.artifactDir); werr != nil {
			// Log the full local reason for operators; return a bounded
			// public sentence that never leaks the OS error.
			audit.Warn("agent_evidence.artifact_dir_unwritable",
				"Agent evidence artifact directory is not writable",
				F("path", r.artifactDir),
				F("error", werr.Error()))
			return newCodedErr(brocadeexport.ArtifactDirNotWritableCode,
				"connector cannot write its evidence artifact directory; recreate the container so /etc/filterrex is mounted read-write")
		}
	}
	return nil
}

// brocadeProducer is the BundleProducer for agentevidence.
type brocadeProducer struct {
	targetsDir      string
	runtimeStateDir string
	artifactDir     string
}

func (p *brocadeProducer) Produce(ctx context.Context, targetProfileID string) (string, string, error) {
	resolved, readiness, err := targetconfigure.LoadResolvedBrocadeTarget(
		p.targetsDir, p.runtimeStateDir, targetProfileID)
	if err != nil {
		return "", "", codedFromReadinessErr(err)
	}
	if gateErr := targetconfigure.ReadinessGateError(readiness); gateErr != nil {
		return "", "", codedFromReadinessErr(gateErr)
	}

	// Assemble a single-target, ephemeral export config from the resolved
	// projection. The wizard/probe path is authoritative; this config only
	// carries the artifact paths the SSH runner needs. ArtifactDir is
	// explicitly the daemon-resolved location — not the local CLI default —
	// so the container's read-only /var/lib is never touched.
	scoped := brocadeexport.ExportConfig{
		Enabled:        true,
		ArtifactDir:    p.artifactDir,
		KnownHostsPath: resolved.KnownHostsPath,
		SSHPort:        resolved.SSHPort,
		Targets: []brocadeexport.TargetConfig{{
			SwitchName: nonEmpty(resolved.ProfileName, resolved.TargetID),
			Host:       resolved.Host,
			Username:   resolved.SSHUsername,
			SSHKeyPath: resolved.PrivateKeyPath,
		}},
	}

	req := brocadeexport.RequestMeta{
		RequesterType: "agent_evidence",
		Requester:     "agent-evidence-dispatch",
		ConfigPath:    "", // no on-disk config used; runtime-materialized
	}
	res, err := brocadeexport.RunExportWithSSH(ctx, &scoped, req)
	if err != nil {
		msg := err.Error()
		switch {
		case errors.Is(err, brocadeexport.ErrArtifactDirNotWritable),
			strings.Contains(msg, "read-only file system"):
			return "", "", newCodedErr(brocadeexport.ArtifactDirNotWritableCode,
				"connector cannot write its evidence artifact directory")
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

func nonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// evaluateBrocadeCapabilityStatus derives per-capability readiness from the
// wizard-owned targets.json + runtime-state sidecar — the same source the
// heartbeat SSH-readiness merge already consumes.
//
// It NEVER opens key material or attempts SSH; it only stats files and reads
// the config, so it is safe to call on every capability-manifest build.
func evaluateBrocadeCapabilityStatus(targetsDir, runtimeStateDir string, lanOnly bool) CapabilityStatusInfo {
	if lanOnly {
		return CapabilityStatusInfo{
			Enabled:            false,
			ConfigurationState: "lan_only",
			Reason:             "LAN-only mode refuses server-initiated collection",
		}
	}
	inv := targetconfigure.InspectTargetConfigDir(targetsDir)
	if !inv.FileReadable {
		return CapabilityStatusInfo{
			Enabled:            false,
			ConfigurationState: "not_configured",
			Reason: fmt.Sprintf("no targets.json at %s — run `target configure` on the connector host",
				inv.File),
		}
	}
	if !inv.ParseSuccessful {
		return CapabilityStatusInfo{
			Enabled:            false,
			ConfigurationState: "invalid",
			Reason:             "targets.json failed to parse",
		}
	}
	ready := collectReadyBrocadeTargetIDs(targetsDir, runtimeStateDir)
	if len(ready) == 0 {
		return CapabilityStatusInfo{
			Enabled:            true,
			ConfigurationState: "not_configured",
			Reason:             "no Brocade target has a fresh successful SSH probe on this host",
		}
	}
	return CapabilityStatusInfo{
		Enabled:               true,
		ConfigurationState:    "ready",
		ReadyTargetProfileIDs: ready,
	}
}

// collectReadyBrocadeTargetIDs enumerates target UUIDs whose merged readiness
// (record + runtime sidecar) is Ready + Fresh. Used by the manifest to make
// the capability's ReadyTargetProfileIDs the same set the collection path
// will actually accept.
func collectReadyBrocadeTargetIDs(targetsDir, runtimeStateDir string) []string {
	snap, _, err := targetconfigure.LoadSSHReadinessSnapshotWithRuntime(targetsDir, runtimeStateDir)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(snap))
	now := time.Now().UTC()
	for id, r := range snap {
		if !r.SSHReady {
			continue
		}
		if strings.TrimSpace(r.LastSuccessfulProbeAt) == "" {
			continue
		}
		t, terr := time.Parse(time.RFC3339, r.LastSuccessfulProbeAt)
		if terr != nil {
			continue
		}
		if now.Sub(t.UTC()) > targetconfigure.ReadinessFreshWindow {
			continue
		}
		out = append(out, id)
	}
	return out
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
func initAgentEvidenceRunner(
	backendURL string,
	connectorToken func() string,
	agentVersion string,
	lanOnly func() bool,
	targetsDir string,
	runtimeStateDir string,
) {
	agentEvidence.mu.Lock()
	defer agentEvidence.mu.Unlock()
	if agentEvidence.handler != nil {
		return
	}

	// Resolve + probe the artifact directory ONCE at startup. Failures do not
	// abort startup — the handler still runs so the app can surface the
	// specific artifact_dir_not_writable code — but every dispatch will
	// re-probe via the readiness check.
	artifactDir, artifactSource, resolveErr := brocadeexport.ResolveAgentEvidenceArtifactDir()
	if resolveErr != nil {
		audit.Warn("agent_evidence.artifact_dir_unwritable",
			"Agent evidence artifact directory could not be resolved",
			F("error", resolveErr.Error()))
	} else if err := brocadeexport.VerifyWritableDirectory(artifactDir); err != nil {
		audit.Warn("agent_evidence.artifact_dir_unwritable",
			"Agent evidence artifact directory is not writable at startup",
			F("path", artifactDir),
			F("source", artifactSource),
			F("error", err.Error()))
	} else {
		audit.Info("agent_evidence.artifact_dir_ready",
			"Agent evidence artifact directory ready",
			F("path", artifactDir),
			F("source", artifactSource))
	}

	client := &agentevidence.Client{
		BaseURL:      strings.TrimRight(backendURL, "/"),
		AgentVersion: agentVersion,
	}
	client.TokenProvider = connectorToken

	agentEvidence.handler = &agentevidence.Handler{
		Client: client,
		Producer: &brocadeProducer{
			targetsDir:      targetsDir,
			runtimeStateDir: runtimeStateDir,
			artifactDir:     artifactDir,
		},
		Readiness: &brocadeReadiness{
			targetsDir:      targetsDir,
			runtimeStateDir: runtimeStateDir,
			artifactDir:     artifactDir,
			lanOnly:         lanOnly,
		},
		LANOnly: lanOnly,
		AuditLog: func(event string, fields map[string]any) {
			afields := make([]Field, 0, len(fields))
			for k, v := range fields {
				afields = append(afields, F(k, v))
			}
			audit.Info(event, event, afields...)
		},
	}
	audit.Info("agent_evidence.wire",
		"Agent evidence collection wired",
		F("targets_dir", targetsDir),
		F("runtime_state_dir", runtimeStateDir),
		F("artifact_dir", artifactDir),
		F("artifact_dir_source", artifactSource))
}

// tickAgentEvidence is called from the existing outbound poll loop. Non-blocking
// and single-flight.
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
		rctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
		defer cancel()
		if _, err := h.Run(rctx); err != nil {
			audit.Warn("agent_evidence.failed",
				"Evidence collection cycle failed",
				F("error", err.Error()))
		}
	}()
}
