// FilterREX Connector Host — Remote SSH readiness probe handler (preview.16).
//
// Handles relay commands with platform="brocade-probe" and
// operation_id="probe.ssh.readiness". Delegates to the single canonical
// probe implementation in targetconfigure so the CLI (`target probe`) and
// the remote path share bytes.
//
// Safety contract:
//   - Method MUST be POST, safety_level MUST be read-only.
//   - The command carries ONLY a target UUID; there is no free-form command
//     string, no key path, no address/port override.
//   - LAN-only mode refuses the probe as defense in depth (edge should
//     already reject; we never rely on that alone).
//   - Ready=false with a bounded reason is a SUCCESSFUL command result — the
//     probe ran and produced negative readiness. Only genuine execution
//     failures (missing target, lock timeout, write error) set an ErrorMessage.
package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/filterrex-ai/connector-agent/targetconfigure"
)

// SyncTrigger is the minimal interface probeHandler needs to force an
// immediate heartbeat republication of the fresh per-target readiness.
type SyncTrigger interface {
	TriggerSync()
}

const (
	// PlatformBrocadeProbe is the relay platform string routed to the SSH
	// readiness probe. Must match the edge function that enqueues it and
	// the browser capability guard.
	PlatformBrocadeProbe = "brocade-probe"

	// OperationProbeSSHReadiness is the fixed operation id every probe
	// command MUST carry. Any other operation on this platform is rejected.
	OperationProbeSSHReadiness = "probe.ssh.readiness"
)

// SetProbeContext wires the target-config directory, the writable
// runtime-state directory used for the readiness sidecar, and the
// heartbeat trigger. Advertising `probe_brocade_ssh_readiness_v1` is gated
// on all three being set (see Supervisor.BuildCapabilityManifest).
func (rh *RelayHandler) SetProbeContext(targetsDir, runtimeStateDir string, trigger SyncTrigger) {
	rh.probeConfigDir = strings.TrimSpace(targetsDir)
	rh.probeRuntimeStateDir = strings.TrimSpace(runtimeStateDir)
	rh.probeSyncTrigger = trigger
}

// ProbeReady returns true when the handler has everything it needs to execute
// a remote probe. Supervisor uses this to conditionally advertise the
// capability so a stale binary cannot enable the UI button.
func (rh *RelayHandler) ProbeReady() bool {
	return rh != nil && rh.probeConfigDir != "" && rh.probeRuntimeStateDir != "" && rh.probeSyncTrigger != nil
}

// executeProbeSSHReadiness is invoked by RelayHandler.executeCommand when
// cmd.Platform == PlatformBrocadeProbe. It is single-flight per (connector,
// target) at the DB layer; local concurrency is bounded by the on-disk
// advisory lock in targetconfigure.RunProbeForTarget.
func (rh *RelayHandler) executeProbeSSHReadiness(cmd RelayCommand, start time.Time) RelayResult {
	elapsed := func() int64 { return time.Since(start).Milliseconds() }

	// Fixed-contract validation. Anything unexpected is rejected here so
	// the probe never runs against a synthetic payload.
	if strings.ToUpper(cmd.Method) != "POST" {
		return RelayResult{ID: cmd.ID, ErrorMessage: "probe_method_not_allowed", DurationMs: elapsed()}
	}
	if cmd.SafetyLevel != "" && cmd.SafetyLevel != "read-only" {
		return RelayResult{ID: cmd.ID, ErrorMessage: "probe_safety_level_not_allowed", DurationMs: elapsed()}
	}
	if cmd.OperationID != OperationProbeSSHReadiness {
		return RelayResult{ID: cmd.ID, ErrorMessage: "probe_operation_not_allowed", DurationMs: elapsed()}
	}
	if strings.TrimSpace(cmd.TargetProfileID) == "" {
		return RelayResult{ID: cmd.ID, ErrorMessage: "target_profile_id_required", DurationMs: elapsed()}
	}
	if !rh.ProbeReady() {
		return RelayResult{ID: cmd.ID, ErrorMessage: "probe_handler_not_configured", DurationMs: elapsed()}
	}

	// LAN-only defense in depth: refuse remote probes when the connector is
	// running in LAN-only mode, regardless of what the edge allowed.
	if rh.supervisor != nil {
		if st := rh.supervisor.GetState(); st != nil && st.Config.LanOnly {
			return RelayResult{ID: cmd.ID, ErrorMessage: "lan_only_mode", DurationMs: elapsed()}
		}
	}

	audit.Info("probe.ssh.received",
		"Remote SSH readiness probe received",
		F("cmd_id", cmd.ID), F("target_profile_id", cmd.TargetProfileID))

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	outcome, err := targetconfigure.RunProbeForTargetSidecar(ctx, rh.probeConfigDir, rh.probeRuntimeStateDir, cmd.TargetProfileID)
	if err != nil {
		// Bounded, code-level errors are surfaced verbatim so the UI can
		// map them to operator copy. Everything else collapses to a
		// generic infrastructure code — details stay in local logs.
		code := "probe_execution_failed"
		switch {
		case errors.Is(err, targetconfigure.ErrTargetNotConfigured):
			code = "target_not_configured"
		case errors.Is(err, targetconfigure.ErrTargetConfigMissing):
			code = targetconfigure.TargetConfigMissing
		case errors.Is(err, targetconfigure.ErrTargetConfigUnreadable):
			code = targetconfigure.TargetConfigUnreadable
		case errors.Is(err, targetconfigure.ErrDuplicateTargetID):
			code = "duplicate_target_id"
		case errors.Is(err, targetconfigure.ErrInvalidTargetID):
			code = "invalid_target_id"
		case errors.Is(err, targetconfigure.ErrProbeLockFailed):
			code = "probe_lock_timeout"
		case errors.Is(err, targetconfigure.ErrRuntimeStateLockFailed):
			code = "runtime_state_lock_timeout"
		case errors.Is(err, targetconfigure.ErrRuntimeStateUnwritable):
			code = "runtime_state_unwritable"
		case errors.Is(err, targetconfigure.ErrConfigDirRequired):
			code = "probe_handler_not_configured"
		}
		inv := targetconfigure.InspectTargetConfigForTarget(rh.probeConfigDir, cmd.TargetProfileID)
		audit.Warn("probe.ssh.failed",
			"Remote SSH readiness probe failed",
			F("cmd_id", cmd.ID), F("target_profile_id", cmd.TargetProfileID),
			F("code", code), F("error", err.Error()),
			F("targets_dir", inv.Dir), F("targets_file", inv.File),
			F("directory_present", inv.DirectoryPresent),
			F("directory_readable", inv.DirectoryReadable),
			F("targets_present", inv.FilePresent),
			F("targets_readable", inv.FileReadable),
			F("records_loaded", inv.RecordsLoaded),
			F("target_match_count", inv.TargetMatchCount),
			F("target_status", inv.ResolvedStatus),
			F("ssh_username_present", inv.SSHUsernamePresent),
			F("private_key_present", inv.PrivateKeyPresent),
			F("private_key_readable", inv.PrivateKeyReadable),
			F("known_hosts_present", inv.KnownHostsPresent),
			F("known_hosts_readable", inv.KnownHostsReadable),
			F("known_hosts_entry_found", inv.KnownHostsEntryFound))
		return RelayResult{
			ID:             cmd.ID,
			ResponseStatus: 200,
			ErrorMessage:   code,
			DurationMs:     elapsed(),
		}
	}

	// Force an immediate heartbeat so the app sees the fresh readiness on
	// the very next poll — for both positive AND negative outcomes.
	rh.probeSyncTrigger.TriggerSync()

	audit.Info("probe.ssh.completed",
		"Remote SSH readiness probe completed",
		F("cmd_id", cmd.ID),
		F("target_profile_id", cmd.TargetProfileID),
		F("ready", outcome.Ready),
		F("stage", outcome.Stage))

	return RelayResult{
		ID:             cmd.ID,
		ResponseStatus: 200,
		ResponseData: map[string]interface{}{
			"ready":                          outcome.Ready,
			"stage":                          outcome.Stage,
			"reason":                         outcome.Reason,
			"lastProbeAt":                    outcome.LastProbeAt,
			"lastSuccessfulProbeAt":          outcome.LastSuccessfulProbeAt,
			"sshKeyAlgorithm":                outcome.SSHKeyAlgorithm,
			"sshKeyBits":                     outcome.SSHKeyBits,
			"sshKeyOrigin":                   outcome.SSHKeyOrigin,
			"sshKeyFingerprintSha256":        outcome.SSHKeyFingerprintSHA256,
			"switchHostKeyFingerprintSha256": outcome.SwitchHostKeyFingerprint,
			"sshUsername":                    outcome.SSHUsername,
			"summary": fmt.Sprintf("probe %s (%s)",
				map[bool]string{true: "succeeded", false: "did not authenticate"}[outcome.Ready],
				outcome.Stage),
		},
		DurationMs: elapsed(),
	}
}
