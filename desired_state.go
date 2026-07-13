// ForgeAI Connector Host — Desired-State Sync
//
// Implements polling-based desired-state synchronization from the
// ForgeAI backend. The host periodically fetches its desired target
// profiles and reconciles them against running workers.
//
// The sync payload is config-only — no executable code, no task
// payloads, no arbitrary plugin references.

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// contains is a case-insensitive substring check for error classification.
func contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// ── Desired-State Payload Model ──

// DesiredStatePayload is the backend → host config-only payload.
type DesiredStatePayload struct {
	Revision        int64                `json:"revision"`
	RevisionHash    string               `json:"revision_hash,omitempty"`
	HostConfig      *HostConfigOverride  `json:"host_config,omitempty"`
	Targets         []DesiredTargetProfile `json:"targets"`
	Policy          *HostPolicy          `json:"policy,omitempty"`
	WipeInstruction *WipeInstruction     `json:"wipe_instruction,omitempty"`
	PendingCommands []RelayCommand       `json:"pending_commands,omitempty"`
}

type WipeInstruction struct {
	Action      string `json:"action"`
	RequestedAt string `json:"requested_at"`
	RequestedBy string `json:"requested_by"`
}

type HostConfigOverride struct {
	LogLevel             string `json:"log_level,omitempty"`
	SyncIntervalSecs     int    `json:"sync_interval_secs,omitempty"`
	MaxConcurrentWorkers int    `json:"max_concurrent_workers,omitempty"`
	// DisplayMode from control plane. "lan-only" activates local-only mode.
	DisplayMode string `json:"display_mode,omitempty"`
}

type HostPolicy struct {
	AutoUpdatePolicy       string `json:"auto_update_policy,omitempty"`
	CredentialRotationDays int    `json:"credential_rotation_days,omitempty"`
	MaintenanceWindow      string `json:"maintenance_window,omitempty"`
}

type DesiredTargetProfile struct {
	TargetID               string                 `json:"target_id"`
	Name                   string                 `json:"name"`
	TargetType             string                 `json:"target_type"`
	Mode                   ProfileMode            `json:"mode"`
	Enabled                bool                   `json:"enabled"`
	Status                 TargetStatus           `json:"status,omitempty"`
	Endpoint               string                 `json:"endpoint"`
	TLS                    TLSConfig              `json:"tls"`
	PollIntervalSecs       int                    `json:"poll_interval_secs"`
	Labels                 map[string]string      `json:"labels,omitempty"`
	Capabilities           []string               `json:"capabilities,omitempty"`
	ResourceLimits         ResourceLimits         `json:"resource_limits,omitempty"`
	Paused                 bool                   `json:"paused"`
	MaintenanceReason      string                 `json:"maintenance_reason,omitempty"`
	AuthType               string                 `json:"auth_type"`
	CredentialPayload      *CredentialPayload     `json:"credential_payload,omitempty"`
	CredentialRotationDays int                    `json:"credential_rotation_days,omitempty"`
	TargetConfig           map[string]interface{} `json:"target_config,omitempty"`
	ConfigVersion          int                    `json:"config_version"`
}

type CredentialPayload struct {
	EncryptionMethod string             `json:"encryption_method"`
	Credentials      map[string]string  `json:"credentials,omitempty"`
	EncryptedBlob    string             `json:"encrypted_blob,omitempty"`
	Envelope         *CredentialEnvelope `json:"envelope,omitempty"`
}

type CredentialEnvelope struct {
	Format          string `json:"format"`
	TargetID        string `json:"target_id"`
	Algorithm       string `json:"algorithm"`
	SenderPublicKey string `json:"sender_public_key"`
	Nonce           string `json:"nonce"`
	Ciphertext      string `json:"ciphertext"`
}

type WipeAckPayload struct {
	Status       string `json:"status"`
	Error        string `json:"error,omitempty"`
	WipedTargets int    `json:"wiped_targets"`
}

// ── Desired-State Sync Loop ──

type SyncManager struct {
	backend      *BackendClient
	store        *Store
	supervisor   *Supervisor
	validator    *ProfileValidator
	hostKeyPair  *HostKeyPair
	relayHandler *RelayHandler
	interval     time.Duration
	fastInterval time.Duration
	cancel       context.CancelFunc
	done             chan struct{}
	triggerCh        chan struct{}
	fastPollUntil    time.Time
	lastRejected     []RejectedProfile
	lastStatusPushAt time.Time
	statusPushInterval time.Duration
}

func NewSyncManager(backend *BackendClient, store *Store, supervisor *Supervisor, changePolicy ChangePolicyConfig) *SyncManager {
	kp, err := store.LoadKeyPair()
	if err != nil {
		audit.Warn("sync.error", "Failed to load host keypair", Err(err))
	}
	if kp != nil {
		audit.Info("sync.reconciled", "Host keypair loaded for credential decryption")
	}

	return &SyncManager{
		backend:            backend,
		store:              store,
		supervisor:         supervisor,
		validator:          NewProfileValidator(),
		hostKeyPair:        kp,
		relayHandler:       NewRelayHandler(supervisor, backend, store, changePolicy),
		interval:           60 * time.Second,
		fastInterval:       5 * time.Second,
		statusPushInterval: 2 * time.Minute,
		done:               make(chan struct{}),
		triggerCh:           make(chan struct{}, 1),
	}
}

func (sm *SyncManager) Start(interval time.Duration) {
	if interval > 0 {
		sm.interval = interval
	}

	ctx, cancel := context.WithCancel(context.Background())
	sm.cancel = cancel

	go sm.run(ctx)
	go sm.commandPollLoop(ctx)
	audit.Info("sync.reconciled", "Desired-state sync started",
		F("interval", sm.interval.String()), F("fast_interval", sm.fastInterval.String()))
}

func (sm *SyncManager) Stop() {
	if sm.cancel != nil {
		sm.cancel()
		<-sm.done
	}
}

// TriggerSync wakes the sync loop immediately
// for an out-of-band desired-state fetch.
// Non-blocking: if a trigger is already pending,
// this is a no-op.
func (sm *SyncManager) TriggerSync() {
	select {
	case sm.triggerCh <- struct{}{}:
	default:
	}
}

func (sm *SyncManager) commandPollLoop(ctx context.Context) {
	audit.Debug("sync.reconciled", "Command poll loop started")

	const idleInterval = 3 * time.Second
	const fastInterval = 1 * time.Second
	const fastDuration = 15 * time.Second

	pollInterval := idleInterval
	var fastUntil time.Time
	var lastErrLog time.Time

	for {
		select {
		case <-ctx.Done():
			audit.Debug("sync.reconciled", "Command poll loop stopped")
			return
		case <-time.After(pollInterval):
		}

		token := sm.supervisor.GetConnectorToken()
		if token == "" {
			continue
		}

		commands, err := sm.backend.CheckCommands(token)
		if err != nil {
			if time.Since(lastErrLog) > 30*time.Second {
				audit.Warn("sync.error", "CheckCommands error", Err(err))
				lastErrLog = time.Now()
			}
			continue
		}

		if len(commands) > 0 {
			audit.Info("sync.reconciled", "Found pending commands", F("count", len(commands)))
			sm.relayHandler.ProcessCommands(commands)
			fastUntil = time.Now().Add(fastDuration)
		}

		if time.Now().Before(fastUntil) {
			pollInterval = fastInterval
		} else {
			pollInterval = idleInterval
		}
	}
}

func (sm *SyncManager) run(ctx context.Context) {
	defer close(sm.done)

	sm.fetchAndReconcile()

	for {
		pollInterval := sm.interval
		if time.Now().Before(sm.fastPollUntil) {
			pollInterval = sm.fastInterval
		}

		select {
		case <-ctx.Done():
			return
		case <-sm.triggerCh:
			sm.fetchAndReconcile()
		case <-time.After(pollInterval):
			sm.fetchAndReconcile()
		}
	}
}

func (sm *SyncManager) fetchAndReconcile() {
	token := sm.supervisor.GetConnectorToken()
	if token == "" {
		audit.Warn("sync.error", "No connector token — skipping sync")
		return
	}

	manifest := sm.supervisor.BuildCapabilityManifest()
	manifestJSON, _ := json.Marshal(manifest)

	pubKey := ""
	if sm.hostKeyPair != nil {
		pubKey = sm.hostKeyPair.PublicKeyBase64()
	}

	payload, err := sm.backend.FetchDesiredState(token, string(manifestJSON), pubKey)
	if err != nil {
		audit.Error("sync.error", "Desired-state fetch failed", Err(err))

		errStr := err.Error()
		if contains(errStr, "token invalid") || contains(errStr, "revoked") || contains(errStr, "authentication failed") {
			audit.Error("sync.error", "Stored connector token appears invalid or revoked — see --force-reset-state for recovery")
		} else {
			audit.Info("sync.reconciled", "Preserving existing local state (safe degradation)")
		}
		return
	}

	if payload == nil {
		audit.Debug("sync.reconciled", "Empty desired-state — no changes")
		// Even with no config changes, periodically push all target statuses
		// so the backend clears stale failed/error rows after recovery.
		sm.maybeStatusPush()
		return
	}

	// ── Check for wipe instruction BEFORE normal reconciliation ──
	if payload.WipeInstruction != nil && payload.WipeInstruction.Action == "wipe_local_credentials" {
		audit.Warn("security.decommission", "WIPE INSTRUCTION received from control plane",
			F("requested_at", payload.WipeInstruction.RequestedAt))
		wipeAck := sm.executeLocalWipe()
		sm.sendWipeAck(payload.Revision, wipeAck)
		sm.sendAck(payload.Revision, "applied")
		return
	}

	// ── Process pending relay commands ──
	if len(payload.PendingCommands) > 0 {
		audit.Info("sync.reconciled", "Received pending relay commands — entering fast-poll mode",
			F("count", len(payload.PendingCommands)))
		sm.fastPollUntil = time.Now().Add(30 * time.Second)
		go sm.relayHandler.ProcessCommands(payload.PendingCommands)
	}

	// Validate all target profiles
	validTargets, rejected := sm.validateProfiles(payload.Targets)
	if len(rejected) > 0 {
		audit.Warn("sync.error", "Rejected invalid target profiles", F("count", len(rejected)))
		for _, r := range rejected {
			audit.Warn("sync.error", "Profile rejected",
				F("target_id", r.TargetID), F("name", r.Name), F("reason", r.Reason))
		}
	}

	sm.lastRejected = rejected

	if payload.HostConfig != nil {
		sm.applyHostConfig(payload.HostConfig)
	}
	if payload.Policy != nil {
		sm.applyHostPolicy(payload.Policy)
	}

	// Process credential payloads
	for i := range validTargets {
		if validTargets[i].CredentialPayload != nil {
			if err := sm.processCredentials(&validTargets[i]); err != nil {
				audit.Error("sync.error", "Credential processing failed",
					F("target_name", validTargets[i].Name), Err(err))
			}
		}
	}

	ackStatus := sm.applyDesiredTargets(validTargets, payload.Revision)
	sm.sendAck(payload.Revision, ackStatus)
}

func (sm *SyncManager) validateProfiles(profiles []DesiredTargetProfile) ([]DesiredTargetProfile, []RejectedProfile) {
	var valid []DesiredTargetProfile
	var rejected []RejectedProfile

	for _, p := range profiles {
		if err := sm.validator.Validate(&p); err != nil {
			rejected = append(rejected, RejectedProfile{
				TargetID: p.TargetID,
				Name:     p.Name,
				Reason:   err.Error(),
			})
			continue
		}
		valid = append(valid, p)
	}

	return valid, rejected
}

type RejectedProfile struct {
	TargetID string
	Name     string
	Reason   string
}

func (sm *SyncManager) processCredentials(target *DesiredTargetProfile) error {
	cp := target.CredentialPayload
	if cp == nil {
		return nil
	}

	switch cp.EncryptionMethod {
	case "host-keypair":
		if sm.hostKeyPair == nil {
			return fmt.Errorf("host keypair not available for decryption")
		}

		if cp.Envelope != nil {
			return sm.processEnvelope(cp.Envelope, target.TargetID)
		}

		if cp.EncryptedBlob == "" {
			return fmt.Errorf("empty encrypted blob and no envelope")
		}
		plaintext, err := DecryptCredentialPayload(cp.EncryptedBlob, sm.hostKeyPair)
		if err != nil {
			return fmt.Errorf("decrypt credentials: %w", err)
		}
		var creds map[string]string
		if err := json.Unmarshal(plaintext, &creds); err != nil {
			return fmt.Errorf("unmarshal decrypted credentials: %w", err)
		}
		return sm.store.SaveSecret(target.TargetID, creds)

	case "token-scoped", "plaintext":
		audit.Warn("sync.reconciled", "Received deprecated token-scoped credentials — migrate host to enable encrypted delivery",
			F("target_name", target.Name))
		if len(cp.Credentials) == 0 {
			return fmt.Errorf("empty credential payload")
		}
		return sm.store.SaveSecret(target.TargetID, cp.Credentials)

	case "unavailable":
		audit.Warn("sync.error", "Backend withheld credentials — host public key not registered",
			F("target_name", target.Name))
		return fmt.Errorf("credentials unavailable: %s", cp.EncryptionMethod)

	case "error":
		audit.Error("sync.error", "Backend credential encryption error",
			F("target_name", target.Name))
		return fmt.Errorf("backend credential encryption error")

	default:
		return fmt.Errorf("unknown encryption method: %s", cp.EncryptionMethod)
	}
}

func (sm *SyncManager) processEnvelope(env *CredentialEnvelope, targetID string) error {
	if env.Format != "ecpv1" {
		return fmt.Errorf("unsupported credential envelope format: %s", env.Format)
	}
	if env.Algorithm != "x25519-xsalsa20-poly1305" {
		return fmt.Errorf("unsupported envelope algorithm: %s", env.Algorithm)
	}

	senderPub, err := base64Decode(env.SenderPublicKey)
	if err != nil {
		return fmt.Errorf("decode sender public key: %w", err)
	}
	nonce, err := base64Decode(env.Nonce)
	if err != nil {
		return fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64Decode(env.Ciphertext)
	if err != nil {
		return fmt.Errorf("decode ciphertext: %w", err)
	}

	if len(senderPub) != 32 {
		return fmt.Errorf("invalid sender public key length: %d", len(senderPub))
	}
	if len(nonce) != 24 {
		return fmt.Errorf("invalid nonce length: %d", len(nonce))
	}

	blob := make([]byte, 0, 32+24+len(ciphertext))
	blob = append(blob, senderPub...)
	blob = append(blob, nonce...)
	blob = append(blob, ciphertext...)

	blobB64 := base64Encode(blob)
	plaintext, err := DecryptCredentialPayload(blobB64, sm.hostKeyPair)
	if err != nil {
		return fmt.Errorf("decrypt envelope: %w", err)
	}

	var creds map[string]string
	if err := json.Unmarshal(plaintext, &creds); err != nil {
		return fmt.Errorf("unmarshal envelope credentials: %w", err)
	}

	audit.Info("security.creds_decrypted", "Decrypted credentials via ecpv1 envelope",
		F("target_id", targetID))
	return sm.store.SaveSecret(targetID, creds)
}

func base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func (sm *SyncManager) sendAck(revision int64, status string) {
	token := sm.supervisor.GetConnectorToken()
	if token == "" {
		return
	}

	targetStatuses := make(map[string]TargetAckStatus)
	workerStates := sm.supervisor.Status()
	for _, t := range sm.supervisor.GetTargets() {
		ts := TargetAckStatus{Status: string(t.Status)}
		// HARD RULE: only include error text for non-healthy states.
		// Active/running targets must never carry stale error strings.
		if t.Status == TargetStatusError || t.Status == TargetStatusDegraded {
			for _, ws := range workerStates {
				if ws.TargetID == t.TargetID && ws.LastError != "" {
					ts.Error = ws.LastError
					break
				}
			}
		}
		targetStatuses[t.TargetID] = ts
	}

	for _, r := range sm.lastRejected {
		targetStatuses[r.TargetID] = TargetAckStatus{
			Status: "error",
			Error:  fmt.Sprintf("rejected: %s", r.Reason),
		}
	}

	if len(sm.lastRejected) > 0 && status == "applied" {
		if len(sm.supervisor.GetTargets()) > 0 {
			status = "partial"
		} else {
			status = "failed"
		}
	}

	ack := AckPayload{
		Revision:       revision,
		Status:         status,
		AgentVersion:   HostVersion,
		TargetStatuses: targetStatuses,
	}

	sm.backend.SendAcknowledgement(token, ack)

	if state := sm.supervisor.GetState(); state != nil {
		state.LastSyncRevision = revision
		state.LastSyncAt = time.Now()
		state.LastAckStatus = status
		sm.store.SaveState(state)
	}
}

// maybeStatusPush sends a consolidated target-status push to the backend
// on a cadence (statusPushInterval), even when desired-state returns 204.
// This ensures recovered targets clear stale failed/error rows promptly.
func (sm *SyncManager) maybeStatusPush() {
	if time.Since(sm.lastStatusPushAt) < sm.statusPushInterval {
		return
	}

	token := sm.supervisor.GetConnectorToken()
	if token == "" {
		return
	}

	targets := sm.supervisor.GetTargets()
	if len(targets) == 0 {
		return
	}

	targetStatuses := make(map[string]TargetAckStatus)
	workerStates := sm.supervisor.Status()
	for _, t := range targets {
		ts := TargetAckStatus{Status: string(t.Status)}
		// HARD RULE: only include error text for non-healthy states.
		// Active/running targets must never carry stale error strings.
		if t.Status == TargetStatusError || t.Status == TargetStatusDegraded {
			for _, ws := range workerStates {
				if ws.TargetID == t.TargetID && ws.LastError != "" {
					ts.Error = ws.LastError
					break
				}
			}
		}
		targetStatuses[t.TargetID] = ts
	}

	// Use last known revision — this is a status-only push, not a config ack
	state := sm.supervisor.GetState()
	revision := int64(0)
	if state != nil {
		revision = state.LastSyncRevision
	}

	ack := AckPayload{
		Revision:       revision,
		Status:         "applied",
		AgentVersion:   HostVersion,
		TargetStatuses: targetStatuses,
	}

	if err := sm.backend.SendAcknowledgement(token, ack); err != nil {
		audit.Warn("sync.error", "Status push failed", Err(err))
		return
	}

	sm.lastStatusPushAt = time.Now()

	// Log status payload at debug level for recovery diagnostics
	for tid, ts := range targetStatuses {
		audit.Debug("sync.status_push", "Target status in push",
			F("target_id", tid), F("status", ts.Status), F("has_error", ts.Error != ""))
	}

	audit.Info("sync.reconciled", "Periodic status push sent",
		F("targets", len(targetStatuses)))
}

func (sm *SyncManager) executeLocalWipe() WipeAckPayload {
	targets := sm.supervisor.GetTargets()
	wipedCount := 0

	audit.Warn("security.decommission", "Stopping all workers for wipe")
	sm.supervisor.Shutdown()

	audit.Warn("security.decommission", "Removing per-target credentials and state")
	for _, t := range targets {
		if err := sm.store.DeleteSecret(t.CredentialRef); err != nil {
			audit.Error("security.decommission", "Failed to delete credentials",
				F("target_name", t.Name), Err(err))
		} else {
			audit.Info("security.decommission", "Deleted credentials for target",
				F("target_name", t.Name))
			wipedCount++
		}
	}

	state := sm.supervisor.GetState()
	if state != nil {
		state.Targets = []TargetProfile{}
		if err := sm.store.SaveState(state); err != nil {
			audit.Error("security.decommission", "Failed to save cleared state", Err(err))
			return WipeAckPayload{Status: "failed", Error: fmt.Sprintf("state save failed: %v", err), WipedTargets: wipedCount}
		}
		audit.Info("security.decommission", "Cleared target profiles from local state")
	}

	audit.Info("security.decommission", "Local wipe complete", F("wiped_targets", wipedCount))
	return WipeAckPayload{Status: "completed", WipedTargets: wipedCount}
}

func (sm *SyncManager) sendWipeAck(revision int64, wipeResult WipeAckPayload) {
	token := sm.supervisor.GetConnectorToken()
	if token == "" {
		audit.Warn("security.decommission", "Cannot send wipe ack — no connector token")
		return
	}

	ack := AckPayload{
		Revision:     revision,
		Status:       "applied",
		AgentVersion: HostVersion,
		WipeAck:      &wipeResult,
	}

	if err := sm.backend.SendAcknowledgement(token, ack); err != nil {
		audit.Error("security.decommission", "Failed to send wipe ack", Err(err))
	} else {
		audit.Info("security.decommission", "Wipe acknowledgement sent to control plane")
	}
}

func (sm *SyncManager) applyHostConfig(override *HostConfigOverride) {
	state := sm.supervisor.GetState()
	if state == nil {
		return
	}

	changed := false
	if override.LogLevel != "" && isValidLogLevel(override.LogLevel) {
		state.Config.LogLevel = override.LogLevel
		audit.SetLevel(parseLogLevel(override.LogLevel))
		changed = true
	}
	if override.SyncIntervalSecs > 0 && override.SyncIntervalSecs >= 15 {
		state.Config.SyncIntervalSecs = override.SyncIntervalSecs
		changed = true
	}
	if override.MaxConcurrentWorkers >= 0 {
		state.Config.MaxConcurrentWorkers = override.MaxConcurrentWorkers
		changed = true
	}

	// Apply display_mode → LanOnly flag
	if override.DisplayMode == "lan-only" || override.DisplayMode == "hybrid" {
		newLanOnly := override.DisplayMode == "lan-only"
		if state.Config.LanOnly != newLanOnly {
			state.Config.LanOnly = newLanOnly
			changed = true
			if newLanOnly {
				audit.Info("security.lan_only", "LAN only mode activated — cloud snapshot uploads suppressed")
			} else {
				audit.Info("security.lan_only", "LAN only mode deactivated — cloud uploads resumed")
			}
		}
	}

	// Propagate to running workers immediately so the next collection
	// cycle picks up the change without restarting workers.
	if override.DisplayMode == "lan-only" || override.DisplayMode == "hybrid" {
		sm.supervisor.SetLanOnly(override.DisplayMode == "lan-only")
	}

	if changed {
		audit.Info("sync.reconciled", "Applied host config overrides")
	}
}

func (sm *SyncManager) applyHostPolicy(policy *HostPolicy) {
	state := sm.supervisor.GetState()
	if state == nil {
		return
	}

	if policy.AutoUpdatePolicy != "" {
		state.Config.AutoUpdatePolicy = policy.AutoUpdatePolicy
	}
	audit.Info("sync.reconciled", "Applied host policy")
}

func (sm *SyncManager) applyDesiredTargets(desired []DesiredTargetProfile, revision int64) string {
	desiredIDs := make(map[string]bool)
	for _, d := range desired {
		desiredIDs[d.TargetID] = true
	}

	currentTargets := sm.supervisor.GetTargets()
	currentMap := make(map[string]*TargetProfile)
	for i := range currentTargets {
		currentMap[currentTargets[i].TargetID] = &currentTargets[i]
	}

	errors := 0
	applied := 0

	for _, d := range desired {
		profile := desiredToInternal(d)

		current, exists := currentMap[d.TargetID]
		if !exists {
			audit.Info("target.added", "Adding new target",
				Target(d.TargetID, d.TargetType, d.Name)...)
			creds := extractCredsFromPayload(d.CredentialPayload)
			if err := sm.supervisor.AddTarget(profile, creds); err != nil {
				audit.Error("sync.error", "Failed to add target",
					append(Target(d.TargetID, d.TargetType, d.Name), Err(err))...)
				errors++
			} else {
				applied++
			}
			continue
		}

		if d.ConfigVersion > current.ConfigVersion || profileChanged(current, &profile) {
			audit.Info("target.updated", "Updating target",
				append(Target(d.TargetID, d.TargetType, d.Name),
					F("old_version", current.ConfigVersion),
					F("new_version", d.ConfigVersion))...)
			sm.supervisor.UpdateTarget(profile)
			applied++
			continue
		}

		if d.Enabled != current.Enabled || d.Paused != current.Paused {
			audit.Info("target.updated", "State change",
				append(Target(d.TargetID, d.TargetType, d.Name),
					F("enabled", d.Enabled), F("paused", d.Paused))...)
			sm.supervisor.UpdateTarget(profile)
			applied++
		} else {
			applied++
		}
	}

	for id, current := range currentMap {
		if !desiredIDs[id] {
			audit.Info("target.removed", "Removing target no longer in desired state",
				Target(id, current.TargetType, current.Name)...)
			if err := sm.supervisor.RemoveTarget(id); err != nil {
				audit.Error("sync.error", "Failed to remove target",
					append(Target(id, current.TargetType, current.Name), Err(err))...)
				errors++
			} else {
				applied++
			}
		}
	}

	audit.Info("sync.reconciled", "Reconciliation complete",
		F("revision", revision), F("targets", len(desired)), F("errors", errors))

	if errors > 0 && applied > 0 {
		return "partial"
	}
	if errors > 0 {
		return "failed"
	}
	return "applied"
}

func desiredToInternal(d DesiredTargetProfile) TargetProfile {
	return TargetProfile{
		TargetID:               d.TargetID,
		Name:                   d.Name,
		TargetType:             d.TargetType,
		Mode:                   string(d.Mode),
		Enabled:                d.Enabled,
		// Only carry over status values that are
		// meaningful for agent lifecycle decisions.
		// "paused" echoed from the cloud is only
		// valid when target.Paused is also true —
		// otherwise the agent treats it as pending
		// so Reconcile() will start the worker.
		Status: func() TargetStatus {
			if d.Status == TargetStatusPaused && !d.Paused {
				return TargetStatusPending
			}
			return d.Status
		}(),
		Endpoint:               d.Endpoint,
		TLS:                    d.TLS,
		Labels:                 d.Labels,
		Capabilities:           d.Capabilities,
		PollIntervalSecs:       d.PollIntervalSecs,
		ResourceLimits:         d.ResourceLimits,
		Paused:                 d.Paused,
		MaintenanceReason:      d.MaintenanceReason,
		CredentialRef:          d.TargetID,
		CredentialRotationDays: d.CredentialRotationDays,
		ConfigVersion:          d.ConfigVersion,
		UpdatedAt:              time.Now(),
		TargetConfig:           d.TargetConfig,
		AuthType:               d.AuthType,
	}
}

func extractCredsFromPayload(cp *CredentialPayload) map[string]string {
	if cp == nil {
		return map[string]string{}
	}
	if cp.EncryptionMethod == "token-scoped" || cp.EncryptionMethod == "plaintext" {
		return cp.Credentials
	}
	return map[string]string{}
}

func profileChanged(current *TargetProfile, desired *TargetProfile) bool {
	if current.Endpoint != desired.Endpoint {
		return true
	}
	if current.PollIntervalSecs != desired.PollIntervalSecs {
		return true
	}
	if current.Mode != desired.Mode {
		return true
	}
	if current.AuthType != desired.AuthType {
		return true
	}
	return false
}

func isValidLogLevel(level string) bool {
	switch level {
	case "debug", "info", "warn", "error":
		return true
	}
	return false
}

// ── JSON helpers ──

func parseDesiredState(data []byte) (*DesiredStatePayload, error) {
	var payload DesiredStatePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("parse desired state: %w", err)
	}
	return &payload, nil
}
