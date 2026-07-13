// ForgeAI Connector Host — Metrics & Instrumentation
//
// Lightweight, lock-free metrics for collection timing, upload stats,
// payload sizes, per-subcall tracking, and queue depth. Designed to be
// read via structured log dumps or an optional /debug/metrics endpoint.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// ── Global metrics singleton ──

var agentMetrics = NewMetricsRegistry()

// MetricsRegistry holds all agent-level metrics.
type MetricsRegistry struct {
	mu sync.RWMutex

	// Per-target collection metrics (targetID -> latest)
	collections map[string]*CollectionMetrics

	// Upload aggregate counters
	uploadsTotal    atomic.Int64
	uploadsSuccess  atomic.Int64
	uploadsFailed   atomic.Int64
	uploadsDropped  atomic.Int64
	uploadBytesTotal atomic.Int64

	// Queue depth (set by upload queue)
	queueDepth atomic.Int32

	// Boot time for uptime calculation
	bootTime time.Time
}

// CollectionMetrics records per-target collection stats.
type CollectionMetrics struct {
	TargetID     string        `json:"target_id"`
	TargetType   string        `json:"target_type"`
	TargetName   string        `json:"target_name"`

	// Latest cycle
	LastDuration     time.Duration `json:"last_duration_ms"`
	LastPayloadBytes int64         `json:"last_payload_bytes"`
	LastStatus       string        `json:"last_status"` // ok, partial, error
	LastCollectedAt  time.Time     `json:"last_collected_at"`

	// Sub-call breakdown (latest cycle)
	SubCalls []SubCallMetric `json:"sub_calls,omitempty"`

	// Aggregates
	TotalCycles       int64         `json:"total_cycles"`
	TotalErrors       int64         `json:"total_errors"`
	TotalPartial      int64         `json:"total_partial"`
	ConsecutiveErrors int           `json:"consecutive_errors"`
	AvgDuration       time.Duration `json:"avg_duration_ms"`

	// Running average tracking
	durationSum time.Duration
}

// SubCallMetric records timing and status for one API sub-call within a collection cycle.
type SubCallMetric struct {
	Name     string        `json:"name"`
	Duration time.Duration `json:"duration_ms"`
	Status   string        `json:"status"` // ok, error, timeout
	Error    string        `json:"error,omitempty"`
	Bytes    int64         `json:"bytes,omitempty"`
}

func NewMetricsRegistry() *MetricsRegistry {
	return &MetricsRegistry{
		collections: make(map[string]*CollectionMetrics),
		bootTime:    time.Now(),
	}
}

// ── Collection Recording ──

// RecordCollection records the result of a complete collection cycle.
func (m *MetricsRegistry) RecordCollection(targetID, targetType, targetName string, duration time.Duration, payloadBytes int64, status string, subCalls []SubCallMetric) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cm, ok := m.collections[targetID]
	if !ok {
		cm = &CollectionMetrics{
			TargetID:   targetID,
			TargetType: targetType,
			TargetName: targetName,
		}
		m.collections[targetID] = cm
	}

	cm.LastDuration = duration
	cm.LastPayloadBytes = payloadBytes
	cm.LastStatus = status
	cm.LastCollectedAt = time.Now()
	cm.SubCalls = subCalls
	cm.TotalCycles++

	switch status {
	case "error":
		cm.TotalErrors++
		cm.ConsecutiveErrors++
	case "partial":
		cm.TotalPartial++
		cm.ConsecutiveErrors = 0
	default:
		cm.ConsecutiveErrors = 0
	}

	cm.durationSum += duration
	cm.AvgDuration = cm.durationSum / time.Duration(cm.TotalCycles)
}

// ── Upload Recording ──

func (m *MetricsRegistry) RecordUploadSuccess(bytes int64) {
	m.uploadsTotal.Add(1)
	m.uploadsSuccess.Add(1)
	m.uploadBytesTotal.Add(bytes)
}

func (m *MetricsRegistry) RecordUploadFailure() {
	m.uploadsTotal.Add(1)
	m.uploadsFailed.Add(1)
}

func (m *MetricsRegistry) RecordUploadDropped() {
	m.uploadsDropped.Add(1)
}

func (m *MetricsRegistry) SetQueueDepth(depth int) {
	m.queueDepth.Store(int32(depth))
}

// ── Snapshot Summary ──

// MetricsSummary is a JSON-serializable snapshot of all metrics.
type MetricsSummary struct {
	Uptime          string                        `json:"uptime"`
	UploadsTotal    int64                         `json:"uploads_total"`
	UploadsSuccess  int64                         `json:"uploads_success"`
	UploadsFailed   int64                         `json:"uploads_failed"`
	UploadsDropped  int64                         `json:"uploads_dropped"`
	UploadBytesMB   float64                       `json:"upload_bytes_mb"`
	QueueDepth      int                           `json:"queue_depth"`
	Targets         map[string]*CollectionMetrics `json:"targets"`
}

func (m *MetricsRegistry) Summary() MetricsSummary {
	m.mu.RLock()
	targets := make(map[string]*CollectionMetrics, len(m.collections))
	for k, v := range m.collections {
		cp := *v
		targets[k] = &cp
	}
	m.mu.RUnlock()

	return MetricsSummary{
		Uptime:         time.Since(m.bootTime).Round(time.Second).String(),
		UploadsTotal:   m.uploadsTotal.Load(),
		UploadsSuccess: m.uploadsSuccess.Load(),
		UploadsFailed:  m.uploadsFailed.Load(),
		UploadsDropped: m.uploadsDropped.Load(),
		UploadBytesMB:  float64(m.uploadBytesTotal.Load()) / (1024 * 1024),
		QueueDepth:     int(m.queueDepth.Load()),
		Targets:        targets,
	}
}

// DumpToLog writes a structured metrics summary to the log.
func (m *MetricsRegistry) DumpToLog() {
	summary := m.Summary()
	data, err := json.Marshal(summary)
	if err != nil {
		log.Printf("[metrics] Failed to marshal summary: %v", err)
		return
	}
	log.Printf("[metrics] %s", string(data))
}

// DumpTargetSummary logs a one-line summary per target.
func (m *MetricsRegistry) DumpTargetSummary() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, cm := range m.collections {
		log.Printf("[metrics] target=%s type=%s status=%s cycles=%d errors=%d partial=%d avg=%v last=%v payload=%.1fKB subcalls=%d",
			cm.TargetName, cm.TargetType, cm.LastStatus,
			cm.TotalCycles, cm.TotalErrors, cm.TotalPartial,
			cm.AvgDuration.Round(time.Millisecond),
			cm.LastDuration.Round(time.Millisecond),
			float64(cm.LastPayloadBytes)/1024,
			len(cm.SubCalls),
		)
	}
}

// ── Sub-Call Timing Helper ──

// TimeSubCall is a convenience function for timing a sub-call within an adapter.
// Usage:
//
//	result, metric := TimeSubCall("hosts", func() (map[string]interface{}, error) {
//	    return a.apiGet("/api/nutanix/v2/hosts/")
//	})
func TimeSubCall(name string, fn func() (map[string]interface{}, error)) (map[string]interface{}, SubCallMetric) {
	start := time.Now()
	result, err := fn()
	duration := time.Since(start)

	metric := SubCallMetric{
		Name:     name,
		Duration: duration,
		Status:   "ok",
	}

	if err != nil {
		metric.Status = "error"
		metric.Error = err.Error()
	}

	if result != nil {
		if data, e := json.Marshal(result); e == nil {
			metric.Bytes = int64(len(data))
		}
	}

	return result, metric
}

// ── Metrics Log Ticker ──

// StartMetricsLogger starts a goroutine that periodically dumps metrics.
func StartMetricsLogger(interval time.Duration, stopCh <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				summary := agentMetrics.Summary()
				log.Printf("[metrics] uptime=%s uploads=%d/%d/%d (ok/fail/drop) queue=%d bytes=%.1fMB",
					summary.Uptime,
					summary.UploadsSuccess, summary.UploadsFailed, summary.UploadsDropped,
					summary.QueueDepth, summary.UploadBytesMB,
				)
				agentMetrics.DumpTargetSummary()
			}
		}
	}()
}

// ── Partial Collection Result ──

// PartialCollectionResult tracks which sections succeeded/failed in a multi-call collect.
type PartialCollectionResult struct {
	Sections      map[string]interface{}   `json:"sections"`
	SubCalls      []SubCallMetric          `json:"sub_calls"`
	FailedSections []string                `json:"failed_sections,omitempty"`
	TotalSections  int                     `json:"total_sections"`
	OKSections     int                     `json:"ok_sections"`
}

func NewPartialCollectionResult() *PartialCollectionResult {
	return &PartialCollectionResult{
		Sections: make(map[string]interface{}),
	}
}

func (p *PartialCollectionResult) AddSection(name string, data interface{}, metric SubCallMetric) {
	p.TotalSections++
	p.SubCalls = append(p.SubCalls, metric)

	if metric.Status == "ok" && data != nil {
		p.Sections[name] = data
		p.OKSections++
	} else {
		p.FailedSections = append(p.FailedSections, name)
	}
}

func (p *PartialCollectionResult) Status() string {
	if p.OKSections == 0 {
		return "error"
	}
	if len(p.FailedSections) > 0 {
		return "partial"
	}
	return "ok"
}

func (p *PartialCollectionResult) DegradedMarker() map[string]interface{} {
	if len(p.FailedSections) == 0 {
		return nil
	}
	return map[string]interface{}{
		"degraded":        true,
		"failed_sections": p.FailedSections,
		"ok_sections":     p.OKSections,
		"total_sections":  p.TotalSections,
		"message":         fmt.Sprintf("%d/%d sections collected successfully", p.OKSections, p.TotalSections),
	}
}
