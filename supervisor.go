// ForgeAI Connector Host — Supervisor & Reconciler
//
// The Supervisor is the long-running host process that manages
// per-target workers. It reconciles desired state (target profiles)
// against actual state (running workers) and handles the full lifecycle.

package main

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"
)

// Supervisor manages the lifecycle of all target workers.
type Supervisor struct {
	mu            sync.RWMutex
	store         *Store
	state         *HostState
	workers       map[string]*Worker // targetID -> worker
	adapters      map[string]AdapterFactory
	backend       *BackendClient
	policy        RetryPolicy
	uploadQueue   *UploadQueue           // shared upload queue (nil = inline)
	localDB       *LocalDB               // hybrid mode local DB (nil = disabled)
	localAPIURL   string                 // LAN URL for local API server
	localAPIToken string                 // pre-shared token for local API
	failedRetryAt map[string]time.Time   // targetID -> next allowed retry time
	failedRetries map[string]int         // targetID -> consecutive retry count
	// lastDegradedLog rate-limits the agent.degraded
	// warning so it fires at most once per 5 minutes
	// instead of every watchdog scan.
	lastDegradedLog time.Time
}

// NewSupervisor creates a new supervisor with the given store and backend.
func NewSupervisor(store *Store, backend *BackendClient) *Supervisor {
	return &Supervisor{
		store:         store,
		workers:       make(map[string]*Worker),
		adapters:      make(map[string]AdapterFactory),
		backend:       backend,
		policy:        DefaultRetryPolicy(),
		localDB:       store.LocalDB(),
		failedRetryAt: make(map[string]time.Time),
		failedRetries: make(map[string]int),
	}
}

// RegisterAdapter registers an adapter factory for a target type.
func (s *Supervisor) RegisterAdapter(targetType string, factory AdapterFactory) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.adapters[targetType] = factory
}

// SetUploadQueue sets the shared upload queue for all workers.
func (s *Supervisor) SetUploadQueue(q *UploadQueue) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.uploadQueue = q
}

// SetLocalAPIURL registers the LAN URL for heartbeat advertisement.
func (s *Supervisor) SetLocalAPIURL(url string) {
	s.mu.Lock()
	s.localAPIURL = url
	s.mu.Unlock()
	audit.Info("local_api.start",
		"LAN URL registered", F("url", url))
}

// GetLocalAPIURL returns the advertised LAN URL.
func (s *Supervisor) GetLocalAPIURL() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.localAPIURL
}

// SetLocalAPIToken stores the pre-shared local API token.
func (s *Supervisor) SetLocalAPIToken(token string) {
	s.mu.Lock()
	s.localAPIToken = token
	s.mu.Unlock()
}

// GetLocalAPIToken returns the local API token.
func (s *Supervisor) GetLocalAPIToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.localAPIToken
}

// Initialize loads or creates host state, handles legacy migration.
func (s *Supervisor) Initialize(legacyCfg *Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Try loading existing state
	state, err := s.store.LoadState()
	if err != nil {
		audit.Warn("host.config_loaded", "Failed to load state, starting fresh", Err(err))
	}

	if state != nil {
		s.state = state
		audit.Info("host.config_loaded", "Loaded host state",
			F("label", state.Identity.Label), F("targets", len(state.Targets)))
		return nil
	}

	// No existing state — check for legacy env config
	if legacyCfg != nil && legacyCfg.ConnectorToken != "" {
		audit.Info("host.config_loaded", "Migrating legacy config to host model",
			F("target_type", legacyCfg.TargetType))
		state, creds := ImportLegacyEnvConfig(legacyCfg)
		s.state = state

		// Store credentials for the migrated target
		if len(state.Targets) > 0 {
			target := state.Targets[0]
			if err := s.store.SaveSecret(target.TargetID, creds); err != nil {
				return fmt.Errorf("save migrated credentials: %w", err)
			}
		}

		// Persist the new state
		if err := s.store.SaveState(state); err != nil {
			return fmt.Errorf("save initial state: %w", err)
		}

		audit.Info("host.config_loaded", "Migration complete",
			F("host_id_short", state.Identity.HostID[:12]), F("targets", len(state.Targets)))
		return nil
	}

	// Fresh install with no config — will be enrolled via enrollment flow
	s.state = &HostState{
		Identity: HostIdentity{
			HostID: generateID(),
			Label:  "forgeai-host",
		},
		Config:  DefaultHostConfig(),
		Targets: []TargetProfile{},
		Version: 1,
	}

	return s.store.SaveState(s.state)
}

// InitializeWithState sets the supervisor state directly (used by enrollment).
func (s *Supervisor) InitializeWithState(state *HostState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
}

// Reconcile compares desired target profiles against running workers
// and starts/stops/updates workers as needed.
func (s *Supervisor) Reconcile() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == nil {
		return fmt.Errorf("supervisor not initialized")
	}

	audit.Info("sync.reconciled", "Reconciling targets",
		F("desired", len(s.state.Targets)), F("running", len(s.workers)))

	desiredIDs := map[string]bool{}

	for i := range s.state.Targets {
		target := &s.state.Targets[i]
		desiredIDs[target.TargetID] = true

		existing, hasWorker := s.workers[target.TargetID]

		// Case 1: Target disabled or revoked — stop worker if running
		if !target.Enabled || target.Status == TargetStatusRevoked {
			if hasWorker {
				audit.Info("target.removed", "Stopping disabled/revoked target",
					Target(target.TargetID, target.TargetType, target.Name)...)
				existing.Stop()
				delete(s.workers, target.TargetID)
			}
			continue
		}

		// Case 2: Target explicitly paused by user.
		// Only target.Paused (the boolean flag) is
		// authoritative — Status="paused" from cloud
		// echo or from a previous stopped worker must
		// not prevent startup.
		if target.Paused {
			if hasWorker {
				ws := existing.State()
				if ws.Status == WorkerStatusRunning {
					audit.Info("worker.stopped", "Pausing target",
						Target(target.TargetID, target.TargetType, target.Name)...)
					existing.Pause()
				}
			}
			continue
		}

		// Case 3: Worker already running — check if failed and needs retry
		if hasWorker {
			ws := existing.State()
			if ws.Status == WorkerStatusFailed {
				// Check if enough time has passed for a retry
				retryAt, hasRetryTime := s.failedRetryAt[target.TargetID]
				if hasRetryTime && time.Now().Before(retryAt) {
					continue // too soon to retry
				}

				audit.Info("worker.retry", "Retrying failed worker",
					Target(target.TargetID, target.TargetType, target.Name)...)
				existing.Stop()
				delete(s.workers, target.TargetID)

			// Calculate next retry backoff: 30s, 60s, capped at 60s
				retryCount := s.failedRetries[target.TargetID] + 1
				s.failedRetries[target.TargetID] = retryCount
				backoff := time.Duration(30) * time.Second
				for i := 1; i < retryCount && backoff < 5*time.Minute; i++ {
					backoff *= 2
				}
				if backoff > 5*time.Minute {
					backoff = 5 * time.Minute
				}
				jitter := time.Duration(float64(backoff) * (0.8 + 0.4*rand.Float64()))
				s.failedRetryAt[target.TargetID] = time.Now().Add(jitter)
				// Fall through to Case 4 to start a fresh worker
			} else {
				// Clear retry tracking on healthy workers
				delete(s.failedRetryAt, target.TargetID)
				delete(s.failedRetries, target.TargetID)
				continue
			}
		}

		// Case 4: No worker — start one
		if err := s.startWorkerLocked(target); err != nil {
			audit.Error("worker.failed", "Failed to start worker",
				append(Target(target.TargetID, target.TargetType, target.Name), Err(err))...)
			target.Status = TargetStatusError
		}
	}

	// Case 5: Workers running for targets no longer in desired state — stop them
	for targetID, worker := range s.workers {
		if !desiredIDs[targetID] {
			audit.Info("target.removed", "Stopping orphaned worker", F("target_id", targetID))
			worker.Stop()
			delete(s.workers, targetID)
		}
	}

	// Persist state after reconciliation
	return s.store.SaveState(s.state)
}

// startWorkerLocked starts a worker for the given target. Caller must hold s.mu.
func (s *Supervisor) startWorkerLocked(target *TargetProfile) error {
	// Check max concurrent workers
	if s.state.Config.MaxConcurrentWorkers > 0 &&
		len(s.workers) >= s.state.Config.MaxConcurrentWorkers {
		return fmt.Errorf("max concurrent workers (%d) reached", s.state.Config.MaxConcurrentWorkers)
	}

	// Copy profile so the worker owns its data independent of slice mutations.
	// Without this copy, workers hold pointers into s.state.Targets; when
	// RemoveTarget shifts the slice or AddTarget triggers reallocation,
	// surviving workers' profile pointers silently alias the wrong target.
	profileCopy := *target

	// Look up adapter factory
	factory, ok := s.adapters[profileCopy.TargetType]
	if !ok {
		return fmt.Errorf("no adapter registered for target type: %s", profileCopy.TargetType)
	}

	// Create adapter
	adapter, err := factory(&profileCopy)
	if err != nil {
		return fmt.Errorf("create adapter for %s: %w", profileCopy.Name, err)
	}

	// Load credentials
	creds, err := s.store.LoadSecret(profileCopy.CredentialRef)
	if err != nil {
		adapter.Close()
		return fmt.Errorf("load credentials for %s: %w", profileCopy.Name, err)
	}
	if creds == nil {
		creds = map[string]string{}
	}

	// Create and start worker
	worker := NewWorker(WorkerConfig{
		Profile:     &profileCopy,
		Adapter:     adapter,
		Creds:       creds,
		Policy:      s.policy,
		Backend:     s.backend,
		HostToken:   s.state.Identity.ConnectorToken,
		UploadQueue: s.uploadQueue,
		LocalDB:     s.localDB,
		LocalAPIURL:   s.localAPIURL,
		LocalAPIToken: s.localAPIToken,
		LanOnly:     s.state.Config.LanOnly,
		OnStateChange: func(targetID string, status WorkerStatus) {
			s.onWorkerStateChange(targetID, status)
		},
	})

	if err := worker.Start(); err != nil {
		adapter.Close()
		return err
	}

	s.workers[target.TargetID] = worker
	target.Status = TargetStatusActive

	audit.Info("worker.started", "Started worker",
		append(Target(target.TargetID, target.TargetType, target.Name),
			F("poll_interval_secs", target.PollIntervalSecs))...)

	return nil
}

// onWorkerStateChange handles worker status transitions.
func (s *Supervisor) onWorkerStateChange(targetID string, status WorkerStatus) {
	go func() {
		s.mu.Lock()
		defer s.mu.Unlock()

		for i := range s.state.Targets {
			if s.state.Targets[i].TargetID == targetID {
			switch status {
				case WorkerStatusDegraded:
					s.state.Targets[i].Status = TargetStatusDegraded
				case WorkerStatusRunning:
					s.state.Targets[i].Status = TargetStatusActive
					// Clear retry tracking on recovery
					delete(s.failedRetryAt, targetID)
					delete(s.failedRetries, targetID)
			case WorkerStatusStopped:
				// Graceful system stop — preserve active
				// status so next Reconcile() restarts the
				// worker. TargetStatusPaused is reserved for
				// explicit user-initiated pauses only
				// (target.Paused == true).
				if s.state.Targets[i].Status != TargetStatusPaused {
					s.state.Targets[i].Status = TargetStatusActive
				}
				case WorkerStatusFailed:
					s.state.Targets[i].Status = TargetStatusError
				}
				break
			}
		}
	}()
}

// AddTarget adds a new target profile and triggers reconciliation.
func (s *Supervisor) AddTarget(profile TargetProfile, creds map[string]string) error {
	s.mu.Lock()

	// Check for duplicate
	for _, t := range s.state.Targets {
		if t.TargetID == profile.TargetID {
			s.mu.Unlock()
			return fmt.Errorf("target %s already exists", profile.TargetID)
		}
	}

	// Store credentials
	if len(creds) > 0 {
		if err := s.store.SaveSecret(profile.CredentialRef, creds); err != nil {
			s.mu.Unlock()
			return fmt.Errorf("save credentials: %w", err)
		}
	}

	profile.UpdatedAt = time.Now()
	if profile.Status == "" {
		profile.Status = TargetStatusPending
	}
	s.state.Targets = append(s.state.Targets, profile)
	s.mu.Unlock()

	audit.Info("target.added", "Target added",
		Target(profile.TargetID, profile.TargetType, profile.Name)...)

	// Reconcile will start the worker
	return s.Reconcile()
}

// UpdateTarget updates an existing target profile in place and reconciles.
func (s *Supervisor) UpdateTarget(profile TargetProfile) error {
	s.mu.Lock()

	found := false
	for i := range s.state.Targets {
		if s.state.Targets[i].TargetID == profile.TargetID {
			// Stop existing worker if running
			if worker, ok := s.workers[profile.TargetID]; ok {
				worker.Stop()
				delete(s.workers, profile.TargetID)
			}

			// Preserve credential ref if not provided
			if profile.CredentialRef == "" {
				profile.CredentialRef = s.state.Targets[i].CredentialRef
			}

			// Clear failed/paused status so reconciler starts a fresh worker.
			// A config update is an explicit signal to retry, regardless of
			// the previous worker state or cloud-side status field.
			if profile.Status == TargetStatusError || profile.Status == TargetStatusPaused ||
				profile.Status == TargetStatusDegraded {
				profile.Status = TargetStatusPending
			}
			profile.Paused = false

			// Clear retry backoff tracking so reconciler doesn't skip this target
			delete(s.failedRetryAt, profile.TargetID)
			delete(s.failedRetries, profile.TargetID)

			profile.UpdatedAt = time.Now()
			s.state.Targets[i] = profile
			found = true
			break
		}
	}

	s.mu.Unlock()

	if !found {
		return fmt.Errorf("target %s not found for update", profile.TargetID)
	}

	audit.Info("target.updated", "Target updated",
		Target(profile.TargetID, profile.TargetType, profile.Name)...)

	return s.Reconcile()
}

// RemoveTarget stops and removes a target.
func (s *Supervisor) RemoveTarget(targetID string) error {
	s.mu.Lock()

	// Stop worker if running
	if worker, ok := s.workers[targetID]; ok {
		worker.Stop()
		delete(s.workers, targetID)
	}

	// Remove from state
	found := false
	var credRef string
	var targetName string
	for i, t := range s.state.Targets {
		if t.TargetID == targetID {
			credRef = t.CredentialRef
			targetName = t.Name
			s.state.Targets = append(s.state.Targets[:i], s.state.Targets[i+1:]...)
			found = true
			break
		}
	}

	s.mu.Unlock()

	if !found {
		return fmt.Errorf("target %s not found", targetID)
	}

	audit.Info("target.removed", "Target removed",
		F("target_id", targetID), F("target_name", targetName))

	// Clean up credentials
	if credRef != "" {
		s.store.DeleteSecret(credRef)
	}

	// Persist
	return s.store.SaveState(s.state)
}

// GetConnectorToken returns the host's connector token for backend auth.
func (s *Supervisor) GetConnectorToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return ""
	}
	return s.state.Identity.ConnectorToken
}

// GetState returns the current host state (for sync manager).
func (s *Supervisor) GetState() *HostState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// GetTargets returns a copy of current target profiles.
func (s *Supervisor) GetTargets() []TargetProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil
	}
	targets := make([]TargetProfile, len(s.state.Targets))
	copy(targets, s.state.Targets)
	return targets
}

// FindTarget returns a pointer to a target profile by ID, or nil.
func (s *Supervisor) FindTarget(targetID string) *TargetProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil
	}
	for i := range s.state.Targets {
		if s.state.Targets[i].TargetID == targetID {
			profileCopy := s.state.Targets[i]
			return &profileCopy
		}
	}
	return nil
}

// FindAdapter returns the live adapter instance for a target by ID, or nil.
func (s *Supervisor) FindAdapter(targetID string) TargetAdapter {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if w, ok := s.workers[targetID]; ok {
		return w.Adapter()
	}
	return nil
}

// Status returns a summary of all workers.
func (s *Supervisor) Status() []WorkerState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	states := make([]WorkerState, 0, len(s.workers))
	for _, w := range s.workers {
		states = append(states, w.State())
	}
	return states
}

// BroadcastHeartbeat triggers an immediate
// heartbeat from every running worker so the
// backend gets current status after reconnect.
// Safe to call from any goroutine.
func (s *Supervisor) BroadcastHeartbeat() {
	s.mu.RLock()
	workers := make([]*Worker, 0, len(s.workers))
	for _, w := range s.workers {
		workers = append(workers, w)
	}
	s.mu.RUnlock()

	for _, w := range workers {
		// Run in goroutine so a slow heartbeat
		// on one target does not block others.
		go w.sendHeartbeat()
	}
}

// SetLanOnly propagates a runtime LAN-only mode change to all running workers.
// Safe to call from any goroutine.
func (s *Supervisor) SetLanOnly(lanOnly bool) {
	s.mu.RLock()
	workers := make([]*Worker, 0, len(s.workers))
	for _, w := range s.workers {
		workers = append(workers, w)
	}
	s.mu.RUnlock()

	for _, w := range workers {
		w.SetLanOnly(lanOnly)
	}
}

// AgentHealthSummary returns a quick overview of aggregate worker health for diagnostics.
func (s *Supervisor) AgentHealthSummary() map[string]interface{} {
	s.mu.RLock()
	total := len(s.workers)
	s.mu.RUnlock()

	counts := map[string]int{}
	var totalRestarts int
	for _, w := range s.workers {
		ws := w.State()
		counts[string(ws.Status)]++
		totalRestarts += ws.RestartCount
	}

	return map[string]interface{}{
		"total_workers":  total,
		"by_status":      counts,
		"total_restarts": totalRestarts,
		"scanned_at":     time.Now().UTC(),
	}
}

// Shutdown gracefully stops all workers.
func (s *Supervisor) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()

	audit.Info("host.shutdown", "Shutting down workers", F("count", len(s.workers)))
	var wg sync.WaitGroup
	for id, w := range s.workers {
		wg.Add(1)
		go func(id string, w *Worker) {
			defer wg.Done()
			w.Stop()
		}(id, w)
	}
	wg.Wait()
	s.workers = make(map[string]*Worker)

	// Persist final state
	if s.state != nil {
		s.store.SaveState(s.state)
	}

	audit.Info("host.shutdown", "All workers stopped")
}

// RunWatchdog starts the supervisor-level watchdog loop. It runs
// independently of the per-collection watchdog in worker.run() —
// that watchdog handles hung collect() calls, this one handles
// workers that are frozen between cycles or mid-stage beyond
// their expected duration.
//
// Call in a goroutine after Reconcile():
//
//	go supervisor.RunWatchdog(ctx)
func (s *Supervisor) RunWatchdog(ctx context.Context) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.watchdogScan()
		}
	}
}

// RunLocalReconcile runs a periodic local reconcile loop that retries
// failed workers without requiring cloud connectivity. This covers the
// edge case where the agent starts while targets are unreachable and
// the cloud sync loop is also down (e.g. DNS failure).
//
// Call in a goroutine after Reconcile():
//
//	go supervisor.RunLocalReconcile(ctx)
func (s *Supervisor) RunLocalReconcile(ctx context.Context) {
	// Initial grace period so cloud sync has a chance to run first.
	select {
	case <-ctx.Done():
		return
	case <-time.After(45 * time.Second):
	}

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Only run if there are actually failed workers to retry.
			hasFailed := false
			s.mu.RLock()
			for _, w := range s.workers {
				if w.State().Status == WorkerStatusFailed {
					hasFailed = true
					break
				}
			}
			s.mu.RUnlock()

			if !hasFailed {
				continue
			}

		audit.Info("sync.reconciled",
			"Local reconcile — retrying failed workers (cloud sync may be unavailable)")
		if err := s.Reconcile(); err != nil {
			audit.Warn("sync.error", "Local reconcile failed", Err(err))
		} else {
			// After reconcile, broadcast current
			// worker status. If cloud is available
			// this updates the DB immediately.
			// If not, the reconnect callback will
			// fire the broadcast when it recovers.
			s.BroadcastHeartbeat()
		}
		}
	}
}

func (s *Supervisor) watchdogScan() {
	s.mu.RLock()
	workers := make(map[string]*Worker, len(s.workers))
	for k, v := range s.workers {
		workers[k] = v
	}
	s.mu.RUnlock()

	now := time.Now()

	for targetID, w := range workers {
		ws := w.State()

		// Skip workers in terminal / inactive states
		if ws.Status == WorkerStatusStopped ||
			ws.Status == WorkerStatusPaused ||
			ws.Status == WorkerStatusFailed {
			continue
		}

		// Skip workers intentionally sleeping — they are not frozen.
		if ws.Status == WorkerStatusIdle || ws.CurrentStage == "sleep" {
			// Grace: allow 2× poll interval past NextScheduledAt
			if !ws.NextScheduledAt.IsZero() &&
				now.Before(ws.NextScheduledAt.Add(120*time.Second)) {
				continue
			}
		}

		// No progress timestamp yet (just started) — initial grace
		if ws.LastProgressAt.IsZero() {
			if now.Sub(ws.StartedAt) < 60*time.Second {
				continue
			}
		}

		// Stage-aware stuck thresholds
		softThreshold, hardThreshold := stageThresholds(ws.CurrentStage)
		progressAge := now.Sub(ws.LastProgressAt)

		if progressAge < softThreshold {
			continue // healthy
		}

		if progressAge < hardThreshold {
			// Suspect — log but don't restart yet
			audit.Warn("worker.watchdog_suspect",
				"Worker progress stalled",
				append(
					Target(ws.TargetID, "", ""),
					F("stage", ws.CurrentStage),
					F("progress_age_secs", int(progressAge.Seconds())),
					F("soft_threshold_secs", int(softThreshold.Seconds())),
				)...)
			if ws.Status == WorkerStatusRunning {
				w.setStatus(WorkerStatusDegraded)
			}
			continue
		}

		// Hard threshold exceeded — mark stuck and restart
		audit.Warn("worker.watchdog_stuck",
			"Worker stuck — triggering restart",
			append(
				Target(ws.TargetID, "", ""),
				F("stage", ws.CurrentStage),
				F("progress_age_secs", int(progressAge.Seconds())),
				F("restart_count", ws.RestartCount),
			)...)

		// Escalation: if this worker has restarted repeatedly in a short
		// window, stop trying and mark it failed instead.
		const (
			maxRestartsInWindow = 3
			restartWindow       = 30 * time.Minute
		)
		if ws.RestartCount >= maxRestartsInWindow &&
			!ws.LastRestartAt.IsZero() &&
			now.Sub(ws.LastRestartAt) < restartWindow {
			audit.Error("worker.watchdog_escalated",
				"Worker restart limit reached — marking failed",
				append(
					Target(ws.TargetID, "", ""),
					F("restart_count", ws.RestartCount),
					F("window_mins", 30),
				)...)
			w.setStatus(WorkerStatusFailed)
			w.sendHeartbeat()
			continue // skip restart
		}

		w.setStatus(WorkerStatusStuck)
		w.sendHeartbeat()

		go func(w *Worker, tid string) {
			if err := w.Restart(); err != nil {
				audit.Error("worker.watchdog_restart_failed",
					"Watchdog restart failed",
					append(Target(tid, "", ""), Err(err))...)
			} else {
				audit.Info("worker.watchdog_restarted",
					"Worker restarted by watchdog",
					Target(tid, "", "")...)
			}
		}(w, targetID)
	}

	// Agent-level health check: surface degraded state when
	// too many workers are simultaneously unhealthy.
	s.mu.RLock()
	total := len(s.workers)
	s.mu.RUnlock()
	if total == 0 {
		return
	}
	unhealthy := 0
	for _, w := range workers {
		ws := w.State()
		if ws.Status == WorkerStatusDegraded ||
			ws.Status == WorkerStatusStuck ||
			ws.Status == WorkerStatusFailed {
			unhealthy++
		}
	}
	pct := float64(unhealthy) / float64(total)
	if pct >= 0.40 {
		s.mu.Lock()
		shouldLog := time.Since(s.lastDegradedLog) > 5*time.Minute
		if shouldLog {
			s.lastDegradedLog = time.Now()
		}
		s.mu.Unlock()
		if shouldLog {
			audit.Warn("agent.degraded",
				"Agent health degraded — majority of workers unhealthy",
				F("unhealthy_workers", unhealthy),
				F("total_workers", total),
				F("pct", int(pct*100)),
			)
		}
	}
}

// stageThresholds returns soft and hard stuck detection thresholds for a stage.
func stageThresholds(stage string) (soft, hard time.Duration) {
	switch stage {
	case "connect", "upload":
		return 90 * time.Second, 3 * time.Minute
	case "fetch", "parse":
		return 3 * time.Minute, 8 * time.Minute
	default:
		return 2 * time.Minute, 5 * time.Minute
	}
}

// TargetCount returns the number of configured targets.
func (s *Supervisor) TargetCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return 0
	}
	return len(s.state.Targets)
}

// WorkerCount returns the number of active workers.
func (s *Supervisor) WorkerCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.workers)
}

// SupportedAdapterTypes returns the list of target types this host can run.
func (s *Supervisor) SupportedAdapterTypes() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	types := make([]string, 0, len(s.adapters))
	for t := range s.adapters {
		types = append(types, t)
	}
	return types
}

// IsAdapterSupported checks if a target type has a registered adapter.
func (s *Supervisor) IsAdapterSupported(targetType string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.adapters[targetType]
	return ok
}

// BuildCapabilityManifest produces the runtime capability manifest for control-plane reporting.
func (s *Supervisor) BuildCapabilityManifest() HostCapabilityManifest {
	s.mu.RLock()
	defer s.mu.RUnlock()

	adapters := make([]AdapterCapabilityInfo, 0, len(s.adapters))
	for targetType, factory := range s.adapters {
		dummyProfile := &TargetProfile{TargetType: targetType, Name: "probe"}
		adapter, err := factory(dummyProfile)
		var caps []string
		if err == nil {
			caps = adapter.Capabilities()
			adapter.Close()
		}
		adapters = append(adapters, AdapterCapabilityInfo{
			TargetType:   targetType,
			Capabilities: caps,
			OpsSupported: false,
		})
	}

	updatePolicy := "none"
	if s.state != nil && s.state.Update.UpdatePolicy != "" {
		updatePolicy = s.state.Update.UpdatePolicy
	}

	return HostCapabilityManifest{
		AgentVersion:      HostVersion,
		SupportedAdapters: adapters,
		UpdatePolicy:      updatePolicy,
		OpsEnabledRuntime: false,
	}
}
