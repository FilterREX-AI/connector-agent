// ForgeAI Connector Host — Snapshot Upload Queue
//
// Decouples collection from upload with a bounded in-memory queue,
// async uploader worker(s), retry with backoff, and priority-based
// eviction under pressure.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// UploadPriority determines eviction order under pressure.
type UploadPriority int

const (
	PriorityHigh   UploadPriority = 0
	PriorityMedium UploadPriority = 1
	PriorityLow    UploadPriority = 2
)

// QueuedSnapshot is a snapshot waiting to be uploaded.
type QueuedSnapshot struct {
	Token      string
	Payload    map[string]interface{}
	Priority   UploadPriority
	TargetID   string
	TargetType string
	EnqueuedAt time.Time
	Retries    int
	SizeBytes  int64
}

// UploadQueue is a bounded in-memory queue with priority-aware eviction.
type UploadQueue struct {
	mu       sync.Mutex
	items    []*QueuedSnapshot
	maxSize  int
	maxRetries int

	backend  *BackendClient
	localDB  *LocalDB

	stopCh   chan struct{}
	notifyCh chan struct{}
	wg       sync.WaitGroup

	workerCount   int
	retryBackoff  time.Duration
	maxBackoff    time.Duration

	// Reconnect-aware state
	backendOnline   bool
	backendOnlineMu sync.Mutex
	offlineSince    time.Time // zero = online
	onReconnect     func()    // called once on first success after outage

	// Token for replayed snapshots
	connectorToken string
}

// UploadQueueConfig configures the upload queue.
type UploadQueueConfig struct {
	MaxSize      int
	MaxRetries   int
	WorkerCount  int
	RetryBackoff time.Duration
	MaxBackoff   time.Duration
	LocalDB      *LocalDB
}

func DefaultUploadQueueConfig() UploadQueueConfig {
	return UploadQueueConfig{
		MaxSize:      100,
		MaxRetries:   3,
		WorkerCount:  2,
		RetryBackoff: 5 * time.Second,
		MaxBackoff:   60 * time.Second,
	}
}

func NewUploadQueue(backend *BackendClient, cfg UploadQueueConfig) *UploadQueue {
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = 100
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = 2
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = 5 * time.Second
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = 60 * time.Second
	}

	return &UploadQueue{
		items:        make([]*QueuedSnapshot, 0, cfg.MaxSize),
		maxSize:      cfg.MaxSize,
		maxRetries:   cfg.MaxRetries,
		backend:      backend,
		localDB:      cfg.LocalDB,
		stopCh:       make(chan struct{}),
		notifyCh:     make(chan struct{}, 1),
		workerCount:  cfg.WorkerCount,
		retryBackoff: cfg.RetryBackoff,
		maxBackoff:   cfg.MaxBackoff,
	}
}

func (q *UploadQueue) Start() {
	for i := 0; i < q.workerCount; i++ {
		q.wg.Add(1)
		go q.uploadWorker(i)
	}
	// Probe loop: detects backend recovery
	// independently of upload worker retries.
	q.wg.Add(1)
	go q.probeLoop()
	audit.Info("upload.success", "Upload queue started",
		F("workers", q.workerCount), F("max_queue", q.maxSize), F("max_retries", q.maxRetries))
}

func (q *UploadQueue) Stop() {
	close(q.stopCh)
	q.wg.Wait()

	q.mu.Lock()
	remaining := len(q.items)
	q.mu.Unlock()

	if remaining > 0 {
		audit.Warn("upload.failed", "Upload queue stopped with undelivered snapshots",
			F("remaining", remaining))
	} else {
		audit.Info("upload.success", "Upload queue stopped cleanly")
	}
}

func (q *UploadQueue) Enqueue(token string, payload map[string]interface{}, priority UploadPriority) bool {
	payloadBytes, _ := json.Marshal(payload)
	sizeBytes := int64(len(payloadBytes))

	targetID, _ := payload["targetId"].(string)
	targetType, _ := payload["targetType"].(string)

	item := &QueuedSnapshot{
		Token:      token,
		Payload:    payload,
		Priority:   priority,
		TargetID:   targetID,
		TargetType: targetType,
		EnqueuedAt: time.Now(),
		SizeBytes:  sizeBytes,
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.items) >= q.maxSize {
		evicted := q.evictLowestPriority(priority)
		if !evicted {
			agentMetrics.RecordUploadDropped()
			audit.Error("upload.dropped", "Snapshot dropped (queue full, no lower priority to evict)",
				F("target_id", targetID), F("target_type", targetType), F("priority", int(priority)))
			return false
		}
	}

	q.items = append(q.items, item)
	agentMetrics.SetQueueDepth(len(q.items))

	// Notify waiting workers
	select {
	case q.notifyCh <- struct{}{}:
	default:
	}

	return true
}

func (q *UploadQueue) evictLowestPriority(incomingPriority UploadPriority) bool {
	lowestIdx := -1
	lowestPri := incomingPriority

	for i, item := range q.items {
		if item.Priority > lowestPri {
			lowestPri = item.Priority
			lowestIdx = i
		} else if item.Priority == lowestPri && lowestIdx >= 0 {
			if item.EnqueuedAt.Before(q.items[lowestIdx].EnqueuedAt) {
				lowestIdx = i
			}
		}
	}

	if lowestIdx < 0 {
		return false
	}

	evicted := q.items[lowestIdx]
	q.items = append(q.items[:lowestIdx], q.items[lowestIdx+1:]...)
	agentMetrics.RecordUploadDropped()
	audit.Warn("upload.dropped", "Evicted snapshot to make room",
		F("target_id", evicted.TargetID), F("priority", int(evicted.Priority)),
		F("age", time.Since(evicted.EnqueuedAt).Round(time.Second).String()))

	return true
}

func (q *UploadQueue) uploadWorker(workerID int) {
	defer q.wg.Done()

	for {
		select {
		case <-q.stopCh:
			return
		default:
		}

		item := q.dequeue()
		if item == nil {
			select {
			case <-q.stopCh:
				return
			case <-q.notifyCh:
				continue
			}
		}

		err := q.backend.Post(item.Token, item.Payload)
		if err != nil {
			agentMetrics.RecordUploadFailure()

			// Only mark offline for connectivity errors, NOT auth errors.
			// Auth errors (401/403) mean the backend is reachable.
			var authErr *AuthError
			if !errors.As(err, &authErr) {
				q.markOffline()
			}

			item.Retries++

			if item.Retries >= q.maxRetries {
				// Don't drop — leave unsynced in local DB for replay on reconnect
				audit.Warn("upload.deferred", fmt.Sprintf("Deferred snapshot after %d retries (will replay on reconnect)", item.Retries),
					F("target_id", item.TargetID), F("worker", workerID), Err(err))
				continue
			}

			backoff := q.calculateRetryBackoff(item.Retries)
			audit.Warn("upload.failed", "Upload retry scheduled",
				F("target_id", item.TargetID), F("worker", workerID),
				F("retry", item.Retries), F("max_retries", q.maxRetries),
				F("backoff", backoff.String()), Err(err))

			select {
			case <-q.stopCh:
				return
			case <-time.After(backoff):
			}

			q.mu.Lock()
			if len(q.items) < q.maxSize {
				q.items = append(q.items, item)
				agentMetrics.SetQueueDepth(len(q.items))
			} else {
				agentMetrics.RecordUploadDropped()
				audit.Error("upload.dropped", "Dropped retry snapshot (queue full)",
					F("target_id", item.TargetID), F("worker", workerID))
			}
			q.mu.Unlock()
	} else {
			agentMetrics.RecordUploadSuccess(item.SizeBytes)
			q.markOnline()
			// Mark synced in local DB if this was a
			// Hybrid Mode summary upload
			if q.localDB != nil {
				if id, ok := item.Payload["_localSnapshotId"]; ok {
					if snapshotID, ok := id.(string); ok && snapshotID != "" {
						if err := q.localDB.MarkSynced(snapshotID); err != nil {
							audit.Warn("local_db.sync",
								"Failed to mark snapshot synced",
								F("snapshot_id", snapshotID), Err(err))
						} else {
							audit.Debug("local_db.sync",
								"Snapshot marked synced",
								F("snapshot_id", snapshotID))
						}
					}
				}
			}
		}
	}
}

func (q *UploadQueue) dequeue() *QueuedSnapshot {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.items) == 0 {
		return nil
	}

	bestIdx := 0
	for i := 1; i < len(q.items); i++ {
		if q.items[i].Priority < q.items[bestIdx].Priority {
			bestIdx = i
		} else if q.items[i].Priority == q.items[bestIdx].Priority &&
			q.items[i].EnqueuedAt.Before(q.items[bestIdx].EnqueuedAt) {
			bestIdx = i
		}
	}

	item := q.items[bestIdx]
	q.items = append(q.items[:bestIdx], q.items[bestIdx+1:]...)
	agentMetrics.SetQueueDepth(len(q.items))

	return item
}

func (q *UploadQueue) calculateRetryBackoff(retries int) time.Duration {
	backoff := q.retryBackoff
	for i := 1; i < retries; i++ {
		backoff *= 2
	}
	if backoff > q.maxBackoff {
		backoff = q.maxBackoff
	}
	return backoff
}

func (q *UploadQueue) Depth() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

// SetOnReconnect sets a callback fired once when backend connectivity
// is restored after an outage. Used by the supervisor to trigger
// catch-up (replay unsynced, resend heartbeats, refresh desired state).
func (q *UploadQueue) SetOnReconnect(fn func()) {
	q.backendOnlineMu.Lock()
	defer q.backendOnlineMu.Unlock()
	q.onReconnect = fn
}

// markOnline is called after a successful upload. Fires the reconnect
// callback exactly once per outage→recovery transition.
func (q *UploadQueue) markOnline() {
	q.backendOnlineMu.Lock()
	wasOffline := !q.backendOnline
	q.backendOnline = true
	q.offlineSince = time.Time{} // clear
	fn := q.onReconnect
	q.backendOnlineMu.Unlock()

	if wasOffline && fn != nil {
		audit.Info("upload.reconnect", "Backend connectivity restored — triggering catch-up")
		go fn()
	}
}

// IsBackendOnline returns whether the upload
// queue believes the backend is reachable.
// Workers use this to suppress repeated
// heartbeat failure logs during known outages.
func (q *UploadQueue) IsBackendOnline() bool {
	q.backendOnlineMu.Lock()
	defer q.backendOnlineMu.Unlock()
	return q.backendOnline
}

// markOffline records that backend is unreachable.
func (q *UploadQueue) markOffline() {
	q.backendOnlineMu.Lock()
	if q.backendOnline {
		q.offlineSince = time.Now()
	}
	q.backendOnline = false
	q.backendOnlineMu.Unlock()
}

// probeLoop runs when the backend is offline.
// It periodically probes connectivity so the reconnect
// callback fires as soon as DNS or network access is
// restored, even when the upload queue has no pending
// items to retry.
func (q *UploadQueue) probeLoop() {
	defer q.wg.Done()

	// Initial delay — let the upload workers
	// exhaust their retries first.
	select {
	case <-q.stopCh:
		return
	case <-time.After(45 * time.Second):
	}

	backoff := 30 * time.Second
	const maxProbeBackoff = 5 * time.Minute
	const transportResetThreshold = 2 * time.Minute

	for {
		select {
		case <-q.stopCh:
			return
		default:
		}

		// Only probe when offline.
		q.backendOnlineMu.Lock()
		online := q.backendOnline
		since := q.offlineSince
		q.backendOnlineMu.Unlock()

		if online {
			// Backend is up — sleep and re-check.
			select {
			case <-q.stopCh:
				return
			case <-time.After(15 * time.Second):
			}
			backoff = 30 * time.Second // reset on recovery
			continue
		}

		// If DNS has been failing for >2 minutes,
		// replace the transport to clear stale
		// DNS entries from the connection pool.
		if !since.IsZero() &&
			time.Since(since) > transportResetThreshold {
			q.backend.ResetTransport()
		}

		err := q.backend.Probe(q.connectorToken)
		if err == nil {
			audit.Info("upload.reconnect",
				"Backend connectivity restored "+
					"via probe — triggering catch-up")
			q.markOnline()
			backoff = 30 * time.Second
		} else {
			audit.Debug("backend.probe_failed",
				"Connectivity probe failed",
				Err(err))
			// Exponential backoff, capped at 5m
			if backoff < maxProbeBackoff {
				backoff *= 2
				if backoff > maxProbeBackoff {
					backoff = maxProbeBackoff
				}
			}
		}

		select {
		case <-q.stopCh:
			return
		case <-time.After(backoff):
		}
	}
}

// ReplayUnsynced reads unsynced snapshots from the local DB and
// re-enqueues them for upload. Called on reconnect.
func (q *UploadQueue) ReplayUnsynced() {
	if q.localDB == nil {
		return
	}

	snapshots, err := q.localDB.UnsyncedSnapshots(50)
	if err != nil {
		audit.Warn("upload.replay", "Failed to read unsynced snapshots", Err(err))
		return
	}

	if len(snapshots) == 0 {
		return
	}

	audit.Info("upload.replay", "Replaying unsynced snapshots",
		F("count", len(snapshots)))

	for _, snap := range snapshots {
		snap.Payload["_localSnapshotId"] = snap.ID
		snap.Payload["type"] = "snapshot"
		snap.Payload["targetId"] = snap.TargetID
		snap.Payload["targetType"] = snap.TargetType
		q.Enqueue(q.connectorToken, snap.Payload, PriorityLow)
	}
}

// ── Priority Classification Helpers ──

func ClassifySnapshotPriority(payload map[string]interface{}) UploadPriority {
	if payloadType, _ := payload["type"].(string); payloadType == "heartbeat" {
		return PriorityHigh
	}

	if alerts, ok := payload["alerts"]; ok {
		if alertList, ok := alerts.([]map[string]interface{}); ok && len(alertList) > 0 {
			return PriorityHigh
		}
		if alertList, ok := alerts.([]interface{}); ok && len(alertList) > 0 {
			return PriorityHigh
		}
	}

	if snapshotData, ok := payload["snapshotData"].(map[string]interface{}); ok {
		if _, hasDegraded := snapshotData["_collection_status"]; hasDegraded {
			return PriorityHigh
		}
	}

	if data, err := json.Marshal(payload); err == nil {
		if len(data) > 500*1024 {
			return PriorityLow
		}
	}

	return PriorityMedium
}
