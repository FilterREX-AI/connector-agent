// ForgeAI Connector Host — Worker Lifecycle Manager
//
// Each target profile gets an independent worker goroutine.
// Workers are started, stopped, restarted, paused, and degraded
// independently. A single failing target never takes down the host.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sync"
	"time"
)

// Worker represents a per-target collection worker.
type Worker struct {
	mu       sync.RWMutex
	profile  *TargetProfile
	adapter  TargetAdapter
	creds    map[string]string
	state    WorkerState
	policy   RetryPolicy
	cancel   context.CancelFunc
	ctx      context.Context
	done     chan struct{}
	stopped  bool // guarded by mu — prevents double-close of done
	backend  *BackendClient
	hostToken string

	// Upload queue (nil = inline upload for backward compat)
	uploadQueue *UploadQueue

	// Local DB for hybrid mode (nil = disabled)
	localDB *LocalDB

	// LAN URL for local API (empty = not advertised)
	localAPIURL   string
	localAPIToken string

	// lanOnly suppresses cloud snapshot uploads (read per-cycle)
	lanOnly bool

	// lastHeartbeatWarn is the time of the last
	// heartbeat.failed log. Used to suppress
	// repeated failure logs during known cloud
	// outages — one log per 5 minutes is enough.
	lastHeartbeatWarn time.Time

	// Callbacks
	onStateChange func(targetID string, status WorkerStatus)
}

// WorkerConfig bundles everything needed to create a worker.
type WorkerConfig struct {
	Profile       *TargetProfile
	Adapter       TargetAdapter
	Creds         map[string]string
	Policy        RetryPolicy
	Backend       *BackendClient
	HostToken     string
	UploadQueue   *UploadQueue
	LocalDB       *LocalDB
	LocalAPIURL   string
	LocalAPIToken string
	LanOnly       bool // skip cloud uploads when true
	OnStateChange func(targetID string, status WorkerStatus)
}

// NewWorker creates a new worker for a target profile.
func NewWorker(cfg WorkerConfig) *Worker {
	ctx, cancel := context.WithCancel(context.Background())
	return &Worker{
		profile:       cfg.Profile,
		adapter:       cfg.Adapter,
		creds:         cfg.Creds,
		policy:        cfg.Policy,
		ctx:           ctx,
		cancel:        cancel,
		done:          make(chan struct{}),
		backend:       cfg.Backend,
		hostToken:     cfg.HostToken,
		uploadQueue:   cfg.UploadQueue,
		localDB:       cfg.LocalDB,
		localAPIURL:   cfg.LocalAPIURL,
		localAPIToken: cfg.LocalAPIToken,
		lanOnly:       cfg.LanOnly,
		onStateChange: cfg.OnStateChange,
		state: WorkerState{
			TargetID: cfg.Profile.TargetID,
			Status:   WorkerStatusIdle,
		},
	}
}

// targetFields returns audit fields for this worker's target.
func (w *Worker) targetFields() []Field {
	return Target(w.profile.TargetID, w.profile.TargetType, w.profile.Name)
}

// Start begins the worker's collection loop.
func (w *Worker) Start() error {
	w.mu.Lock()
	if w.state.Status == WorkerStatusRunning {
		w.mu.Unlock()
		return fmt.Errorf("worker %s already running", w.profile.TargetID)
	}
	w.state.Status = WorkerStatusStarting
	w.state.StartedAt = time.Now()
	w.state.ConsecutiveErrors = 0
	w.mu.Unlock()

	go w.run()
	return nil
}

// Stop gracefully stops the worker. Idempotent — safe to call multiple times.
func (w *Worker) Stop() {
	w.cancel()

	// Wait for run() to finish, but only if it hasn't already closed done.
	w.mu.RLock()
	alreadyStopped := w.stopped
	w.mu.RUnlock()

	if !alreadyStopped {
		<-w.done
	}

	if w.adapter != nil {
		w.adapter.Close()
	}
	w.setStatus(WorkerStatusStopped)
	audit.Info("worker.stopped", "Worker stopped", w.targetFields()...)
}

// Pause marks the worker as paused (stops collection but keeps adapter alive).
func (w *Worker) Pause() {
	w.cancel()
	<-w.done
	w.setStatus(WorkerStatusPaused)
}

// Restart stops and restarts the worker with a fresh context.
func (w *Worker) Restart() error {
	w.mu.Lock()
	w.state.RestartCount++
	w.state.LastRestartAt = time.Now()
	w.mu.Unlock()

	w.Stop()

	// Reset context and done channel under lock
	w.mu.Lock()
	w.ctx, w.cancel = context.WithCancel(context.Background())
	w.done = make(chan struct{})
	w.stopped = false
	w.mu.Unlock()

	return w.Start()
}
// Adapter returns the live adapter instance for relay access.
func (w *Worker) Adapter() TargetAdapter {
	return w.adapter
}


func (w *Worker) State() WorkerState {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.state
}

// run is the main collection loop.
func (w *Worker) run() {
	defer func() {
		w.mu.Lock()
		w.stopped = true
		w.mu.Unlock()
		close(w.done)
	}()
	// Initialize adapter
	if err := w.adapter.Init(w.profile, w.creds); err != nil {
		w.mu.Lock()
		w.state.ConsecutiveErrors = 1
		w.state.LastErrorAt = time.Now()
		w.state.LastError = err.Error()
		w.mu.Unlock()

		audit.Error("adapter.init_failed", "Adapter init failed",
			append(w.targetFields(), Err(err))...)
		w.setStatus(WorkerStatusFailed)
		return
	}

	audit.Info("adapter.init", "Adapter initialized", w.targetFields()...)
	w.setStage("idle")
	w.setStatus(WorkerStatusRunning)
	audit.Info("worker.started", "Worker running", w.targetFields()...)

	interval := time.Duration(w.profile.PollIntervalSecs) * time.Second
	if interval < 10*time.Second {
		interval = 30 * time.Second
	}

	// Send initial heartbeat
	w.sendHeartbeat()

	// Collect immediately (with watchdog)
	initialDone := make(chan struct{})
	go func() {
		defer close(initialDone)
		w.collect()
	}()
	initialWatchdog := time.Duration(w.policy.WatchdogTimeoutSecs) * time.Second
	if initialWatchdog <= 0 {
		initialWatchdog = 300 * time.Second
	}
	select {
	case <-initialDone:
	case <-time.After(initialWatchdog):
		audit.Warn("worker.watchdog",
			"Initial collection hung — watchdog fired",
			w.targetFields()...)
	case <-w.ctx.Done():
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	heartbeatTicker := time.NewTicker(60 * time.Second)
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-heartbeatTicker.C:
			w.sendHeartbeat()
		case <-ticker.C:
			if w.profile.Paused {
				continue
			}
			// Mark cycle start and stage
			w.mu.Lock()
			w.state.CycleStartedAt = time.Now()
			w.mu.Unlock()
			w.setStage("scheduled")

			// Run collect with watchdog timeout.
			// If adapter hangs (e.g. network dropped),
			// cancel it after WatchdogTimeoutSecs.
			watchdog := time.Duration(w.policy.WatchdogTimeoutSecs) * time.Second
			if watchdog <= 0 {
				watchdog = 300 * time.Second
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				w.collect()
			}()
			select {
			case <-done:
				// Normal completion — enter sleep stage
				w.mu.Lock()
				w.state.NextScheduledAt = time.Now().Add(interval)
				w.mu.Unlock()
				w.setStage("sleep")
			case <-time.After(watchdog):
				audit.Warn("worker.watchdog",
					"Collection hung — watchdog fired, restarting worker",
					append(w.targetFields(),
						F("watchdog_secs", w.policy.WatchdogTimeoutSecs))...)
				w.handleError(fmt.Errorf(
					"collection watchdog timeout after %v", watchdog))
				w.sendHeartbeat()
				// Signal restart request — supervisor will handle it.
				// We must NOT call w.Restart() from inside run() because
				// Restart() calls Stop() which blocks on <-w.done, but
				// run() owns done and hasn't returned yet → deadlock or
				// double-close panic.
				w.setStatus(WorkerStatusStuck)
				return
			case <-w.ctx.Done():
				return
			}
		}
	}
}

// collect performs one collection cycle with retry/backoff handling.
func (w *Worker) collect() {
	// Pre-flight health check — fast connectivity validation
	w.setStage("connect")
	if err := w.adapter.HealthCheck(); err != nil {
		audit.Warn("healthcheck.failed", "Target health check failed",
			append(w.targetFields(), Err(err))...)
		w.handleError(fmt.Errorf("health check failed: %w", err))
		w.sendHeartbeat()
		return
	}

	w.setStage("fetch")
	collectStart := time.Now()
	payload, err := w.adapter.Collect()
	collectDuration := time.Since(collectStart)

	if err != nil {
		// Record failed collection metrics
		agentMetrics.RecordCollection(
			w.profile.TargetID, w.profile.TargetType, w.profile.Name,
			collectDuration, 0, "error", nil,
		)
		audit.Error("collection.error", "Collection failed",
			append(w.targetFields(),
				Err(err),
				F("duration_ms", collectDuration.Milliseconds()),
			)...)
		w.handleError(err)
		w.sendHeartbeat()
		return
	}

	// Extract sub-call metrics if present
	var subCalls []SubCallMetric
	if sc, ok := payload["_subCalls"]; ok {
		if scList, ok := sc.([]SubCallMetric); ok {
			subCalls = scList
		}
		delete(payload, "_subCalls")
	}

	// Determine collection status from payload
	collectionStatus := "ok"
	if sd, ok := payload["snapshotData"].(map[string]interface{}); ok {
		if cs, ok := sd["_collection_status"].(map[string]interface{}); ok {
			if _, degraded := cs["degraded"]; degraded {
				collectionStatus = "partial"
			}
		}
	}

	// Calculate payload size
	var payloadBytes int64
	if data, e := json.Marshal(payload); e == nil {
		payloadBytes = int64(len(data))
	}

	// Record collection metrics
	agentMetrics.RecordCollection(
		w.profile.TargetID, w.profile.TargetType, w.profile.Name,
		collectDuration, payloadBytes, collectionStatus, subCalls,
	)

	// Reset error state on success — clear the full failure envelope
	w.mu.Lock()
	prevStatus := w.state.Status
	hadError := w.state.LastError != ""
	w.state.ConsecutiveErrors = 0
	w.state.LastError = ""
	w.state.LastErrorAt = time.Time{}
	w.state.LastCollectionAt = time.Now()
	w.state.TotalCollections++
	if prevStatus == WorkerStatusDegraded || prevStatus == WorkerStatusFailed {
		w.state.Status = WorkerStatusRunning
		w.mu.Unlock()
		w.notifyStateChange(WorkerStatusRunning)
		audit.Info("worker.recovered", "Recovered from degraded/failed state — stale error cleared",
			append(w.targetFields(), F("prev_status", string(prevStatus)))...)
		// Immediate heartbeat on recovery so backend sees healthy status quickly
		w.sendHeartbeat()
	} else {
		w.mu.Unlock()
		if hadError {
			audit.Debug("worker.recovery", "Cleared stale error after successful collection",
				w.targetFields()...)
		}
	}

	if collectionStatus == "partial" {
		audit.Warn("collection.partial", "Partial collection",
			append(w.targetFields(),
				F("duration_ms", collectDuration.Milliseconds()),
				F("payload_bytes", payloadBytes),
			)...)
	} else {
		audit.Info("collection.success", "Snapshot collected",
			append(w.targetFields(),
				F("duration_ms", collectDuration.Milliseconds()),
				F("payload_bytes", payloadBytes),
			)...)
	}

	// Enrich payload with common fields
	payload["type"] = "snapshot"
	payload["schemaVersion"] = 1
	payload["agentVersion"] = HostVersion
	payload["targetId"] = w.profile.TargetID
	payload["targetType"] = w.profile.TargetType

	// ── Hybrid Mode: write full payload to local DB ──
	w.setStage("parse")
	if w.localDB != nil {
		snapshotID := generateID()
		// Extract signals from payload if present.
		// Adapters may include a "_signals" key; fall back
		// to empty slice if not present.
		var signals []SnapshotSignal
		if raw, ok := payload["_signals"]; ok {
			if sl, ok := raw.([]SnapshotSignal); ok {
				signals = sl
			}
		}
		if err := w.localDB.WriteSnapshot(
			snapshotID,
			w.profile.TargetID,
			w.profile.TargetType,
			time.Now(),
			payload,
			signals,
		); err != nil {
			audit.Warn("local_db.write",
				"Failed to write snapshot to local DB",
				append(w.targetFields(), Err(err))...)
			// Non-fatal: continue with cloud upload
		} else {
			// Tag the payload with the local snapshot ID
			// so the cloud summary can reference it
			payload["_localSnapshotId"] = snapshotID

		}
	}

	// ── Cloud upload ──
	// Full payload is sent to cloud for all platforms.
	// Local DB still serves as the primary fast-access store.
	uploadPayload := payload

	// Include local API coordinates on snapshot uploads too,
	// so backend metadata recovers even if heartbeats were missed.
	if w.localAPIURL != "" {
		uploadPayload["localApiUrl"] = w.localAPIURL
		uploadPayload["localApiToken"] = w.localAPIToken
	}

	// ── Cloud upload ──
	// Skipped entirely in LAN only mode — snapshots are local DB only.
	w.mu.RLock()
	lanOnly := w.lanOnly
	w.mu.RUnlock()

	if lanOnly {
		audit.Debug("upload.skipped", "LAN only mode — snapshot not sent to cloud",
			w.targetFields()...)
	} else {
		w.setStage("upload")
		if w.uploadQueue != nil {
			priority := ClassifySnapshotPriority(uploadPayload)
			if !w.uploadQueue.Enqueue(w.hostToken, uploadPayload, priority) {
				audit.Error("upload.dropped", "Snapshot dropped by upload queue", w.targetFields()...)
			}
		} else {
			if err := w.backend.Post(w.hostToken, uploadPayload); err != nil {
				audit.Warn("upload.failed", "Snapshot delivery failed",
					append(w.targetFields(), Err(err))...)
			}
		}
	}

	w.setStage("complete")
}

// handleError records an error and applies backoff/degradation policy.
func (w *Worker) handleError(err error) {
	w.mu.Lock()
	w.state.ConsecutiveErrors++
	w.state.LastErrorAt = time.Now()
	w.state.LastError = err.Error()
	consecutive := w.state.ConsecutiveErrors
	w.mu.Unlock()

	audit.Error("collection.error", fmt.Sprintf("Collection error (%d/%d)",
		consecutive, w.policy.MaxConsecutiveErrors),
		append(w.targetFields(), Err(err))...)

	// Escalate to failed after sustained errors — signals supervisor to retry
	if w.policy.FailedAfterErrors > 0 && consecutive >= w.policy.FailedAfterErrors {
		w.setStatus(WorkerStatusFailed)
		audit.Error("worker.failed", fmt.Sprintf("Marked FAILED after %d consecutive errors — worker exiting for supervisor retry", consecutive),
			w.targetFields()...)
		// Cancel our own context to exit the run() loop
		w.cancel()
		return
	}

	if consecutive >= w.policy.MaxConsecutiveErrors {
		w.setStatus(WorkerStatusDegraded)
		audit.Warn("worker.degraded", fmt.Sprintf("Marked DEGRADED after %d consecutive errors", consecutive),
			w.targetFields()...)

		// Apply backoff sleep
		backoff := w.calculateBackoff(consecutive)
		audit.Info("worker.degraded", "Backing off", append(w.targetFields(), F("backoff", backoff.String()))...)

		select {
		case <-time.After(backoff):
		case <-w.ctx.Done():
		}
	}
}

// calculateBackoff computes exponential backoff duration.
func (w *Worker) calculateBackoff(consecutive int) time.Duration {
	backoff := float64(w.policy.InitialBackoff) *
		math.Pow(w.policy.BackoffMultiplier, float64(consecutive-w.policy.MaxConsecutiveErrors))
	if backoff > float64(w.policy.MaxBackoff) {
		backoff = float64(w.policy.MaxBackoff)
	}
	return time.Duration(backoff)
}

// sendHeartbeat sends a heartbeat for this worker's target,
// including current worker health state so the backend can
// track target-level health independently of agent liveness.
//
// Status vocabulary mapping (agent → backend):
//   running  → active
//   degraded → degraded
//   failed   → failed
func (w *Worker) sendHeartbeat() {
	// Capture state under lock, release before network I/O
	w.mu.RLock()
	workerStatus := string(w.state.Status)
	lastErr := w.state.LastError
	consecutiveErrors := w.state.ConsecutiveErrors
	w.mu.RUnlock()

	// HARD RULE: never include stale error text for healthy workers
	if workerStatus == string(WorkerStatusRunning) || workerStatus == string(WorkerStatusIdle) {
		lastErr = ""
		consecutiveErrors = 0
	}

	payload := map[string]interface{}{
		"type":              "heartbeat",
		"agentVersion":      HostVersion,
		"targetId":          w.profile.TargetID,
		"targetType":        w.profile.TargetType,
		"capabilities":      w.adapter.Capabilities(),
		"workerStatus":      workerStatus,
		"consecutiveErrors": consecutiveErrors,
	}
	if lastErr != "" {
		payload["lastError"] = lastErr
	}

	// Include stage tracking fields and last collection timestamp
	w.mu.RLock()
	currentStage := w.state.CurrentStage
	restartCount := w.state.RestartCount
	progressAge := time.Since(w.state.LastProgressAt)
	lastCollAt := w.state.LastCollectionAt
	w.mu.RUnlock()

	payload["currentStage"] = currentStage
	payload["restartCount"] = restartCount
	payload["progressAgeSecs"] = int(progressAge.Seconds())

	// Include last collection timestamp so cloud tracks freshness
	// even when cloud uploads are suppressed (LAN-only mode)
	if !lastCollAt.IsZero() {
		payload["lastCollectedAt"] = lastCollAt.UTC().Format(time.RFC3339)
	}

	if w.localAPIURL != "" {
		payload["localApiUrl"] = w.localAPIURL
		payload["localApiToken"] = w.localAPIToken
	}

	if err := w.backend.Post(w.hostToken, payload); err != nil {
		// Suppress repeated failure logs during a
		// known cloud outage. The upload queue's probe
		// loop will detect recovery and broadcast
		// heartbeats. One log per 5 minutes is enough.
		isKnownOutage := w.uploadQueue != nil &&
			!w.uploadQueue.IsBackendOnline()
		w.mu.Lock()
		shouldLog := !isKnownOutage ||
			time.Since(w.lastHeartbeatWarn) > 5*time.Minute
		if shouldLog {
			w.lastHeartbeatWarn = time.Now()
		}
		w.mu.Unlock()
		if shouldLog {
			audit.Warn("heartbeat.failed",
				"Heartbeat failed",
				append(w.targetFields(), Err(err))...)
		}
	} else {
		audit.Debug("heartbeat.sent", "Heartbeat delivered",
			append(w.targetFields(), F("workerStatus", workerStatus))...)
	}
}

// setStage updates CurrentStage and LastProgressAt atomically.
func (w *Worker) setStage(stage string) {
	w.mu.Lock()
	w.state.CurrentStage = stage
	w.state.LastProgressAt = time.Now()
	w.mu.Unlock()
}

func (w *Worker) setStatus(status WorkerStatus) {
	w.mu.Lock()
	prev := w.state.Status
	w.state.Status = status
	w.mu.Unlock()

	w.notifyStateChange(status)

	// Send an immediate heartbeat on real state transitions into
	// degraded/failed (so the backend learns quickly) and on recovery
	// back to running (so stale error state clears promptly).
	// Only fires on actual changes to avoid heartbeat spam.
	if prev != status {
		switch status {
		case WorkerStatusDegraded, WorkerStatusFailed, WorkerStatusRunning:
			w.sendHeartbeat()
		}
	}
}

func (w *Worker) notifyStateChange(status WorkerStatus) {
	if w.onStateChange != nil {
		w.onStateChange(w.profile.TargetID, status)
	}
}

// SetLanOnly updates the worker's cloud upload suppression flag at runtime.
// Called when the host display_mode changes via desired-state sync without
// restarting workers. Thread-safe.
func (w *Worker) SetLanOnly(v bool) {
	w.mu.Lock()
	prev := w.lanOnly
	w.lanOnly = v
	w.mu.Unlock()

	if prev != v {
		if v {
			audit.Info("security.lan_only", "Worker switched to LAN only mode — cloud uploads suppressed",
				w.targetFields()...)
		} else {
			audit.Info("security.lan_only", "Worker switched to hybrid mode — cloud uploads resumed",
				w.targetFields()...)
		}
	}
}

