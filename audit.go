// ForgeAI Connector Host — Structured Audit Logger
//
// Provides machine-parseable JSON audit logging with severity levels,
// event taxonomy, and consistent field schemas. Designed for log
// aggregation, SIEM integration, and compliance-grade event trails.
//
// Usage:
//   audit.Info("worker.started", "Worker running", Target(id, typ, name)...)
//   audit.Error("collection.error", "Collection failed", Err(err), F("retries", 3))
//
// Output format (LOG_FORMAT=json):
//   {"ts":"2026-03-26T14:30:00.123Z","level":"info","event":"worker.started","msg":"Worker running",...}
//
// When LOG_FORMAT is unset or "text", falls back to human-readable log.Printf.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// ── Severity Levels ──

type LogLevel int

const (
	LevelDebug    LogLevel = 0
	LevelInfo     LogLevel = 1
	LevelWarn     LogLevel = 2
	LevelError    LogLevel = 3
	LevelCritical LogLevel = 4
)

var levelNames = map[LogLevel]string{
	LevelDebug:    "debug",
	LevelInfo:     "info",
	LevelWarn:     "warn",
	LevelError:    "error",
	LevelCritical: "critical",
}

func parseLogLevel(s string) LogLevel {
	switch strings.ToLower(s) {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	case "critical":
		return LevelCritical
	default:
		return LevelInfo
	}
}

// ── Field type for structured key-value pairs ──

// Field is a key-value pair attached to an audit log entry.
type Field struct {
	Key   string
	Value interface{}
}

// F creates a Field with an arbitrary key and value.
func F(key string, val interface{}) Field {
	return Field{Key: key, Value: val}
}

// Err creates an "error" field from an error value.
func Err(err error) Field {
	if err == nil {
		return Field{Key: "error", Value: nil}
	}
	return Field{Key: "error", Value: err.Error()}
}

// Target creates fields for target_id, target_type, and target_name.
func Target(id, typ, name string) []Field {
	return []Field{
		{Key: "target_id", Value: id},
		{Key: "target_type", Value: typ},
		{Key: "target_name", Value: name},
	}
}

// ── Audit Logger ──

// AuditLogger emits structured audit events as JSON or human-readable text.
type AuditLogger struct {
	mu           sync.Mutex
	minLevel     LogLevel
	jsonMode     bool
	writer       io.Writer
	hostID       string
	agentVersion string
}

// Global audit logger instance — initialized in main().
var audit *AuditLogger

// NewAuditLogger creates a new audit logger.
func NewAuditLogger(minLevel LogLevel, jsonMode bool) *AuditLogger {
	return &AuditLogger{
		minLevel:     minLevel,
		jsonMode:     jsonMode,
		writer:       os.Stderr,
		agentVersion: HostVersion,
	}
}

// SetHostID sets the host_id field emitted in every log entry.
// Called after enrollment when the host ID becomes available.
func (a *AuditLogger) SetHostID(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.hostID = id
}

// SetLevel changes the minimum log level at runtime.
func (a *AuditLogger) SetLevel(level LogLevel) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.minLevel = level
}

// ── Logging Methods ──

func (a *AuditLogger) Debug(event, msg string, fields ...Field) {
	a.emit(LevelDebug, event, msg, fields)
}

func (a *AuditLogger) Info(event, msg string, fields ...Field) {
	a.emit(LevelInfo, event, msg, fields)
}

func (a *AuditLogger) Warn(event, msg string, fields ...Field) {
	a.emit(LevelWarn, event, msg, fields)
}

func (a *AuditLogger) Error(event, msg string, fields ...Field) {
	a.emit(LevelError, event, msg, fields)
}

func (a *AuditLogger) Critical(event, msg string, fields ...Field) {
	a.emit(LevelCritical, event, msg, fields)
}

// ── Internal emit ──

func (a *AuditLogger) emit(level LogLevel, event, msg string, fields []Field) {
	if level < a.minLevel {
		return
	}

	if a.jsonMode {
		a.emitJSON(level, event, msg, fields)
	} else {
		a.emitText(level, event, msg, fields)
	}
}

func (a *AuditLogger) emitJSON(level LogLevel, event, msg string, fields []Field) {
	entry := map[string]interface{}{
		"ts":            time.Now().UTC().Format(time.RFC3339Nano),
		"level":         levelNames[level],
		"event":         event,
		"msg":           msg,
		"agent_version": a.agentVersion,
	}

	a.mu.Lock()
	if a.hostID != "" {
		entry["host_id"] = a.hostID
	}
	a.mu.Unlock()

	for _, f := range fields {
		if f.Value != nil {
			entry[f.Key] = f.Value
		}
	}

	data, err := json.Marshal(entry)
	if err != nil {
		log.Printf("[audit] JSON marshal error: %v", err)
		return
	}

	a.mu.Lock()
	fmt.Fprintf(a.writer, "%s\n", data)
	a.mu.Unlock()
}

func (a *AuditLogger) emitText(level LogLevel, event, msg string, fields []Field) {
	// Build a human-readable line: [event] msg key=value key=value ...
	var b strings.Builder
	b.WriteString(fmt.Sprintf("[%s] %s", event, msg))

	for _, f := range fields {
		if f.Value != nil {
			b.WriteString(fmt.Sprintf(" %s=%v", f.Key, f.Value))
		}
	}

	log.Println(b.String())
}

// ── Initialization helper ──

// InitAuditLogger creates and sets the global audit logger from environment/config.
// Call this early in main() before any audit.* calls.
func InitAuditLogger(configLevel string) {
	level := parseLogLevel(configLevel)

	logFormat := os.Getenv("LOG_FORMAT")
	jsonMode := logFormat == "json"

	audit = NewAuditLogger(level, jsonMode)
}
