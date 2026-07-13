// ForgeAI Connector Host — Local Authoritative SQLite Database
//
// Implements the local authoritative store for Hybrid Mode.
// Snapshot payloads are encrypted at rest using the Store's AES-256-GCM key.
// Signals and summaries are stored as plaintext for local queryability.
// Only summaries (never raw payloads) are synced to the cloud relay.
//
// Schema:
//   snapshots  — encrypted full payloads + plaintext summaries
//   signals    — queryable signal rows derived from each snapshot
//   db_meta    — schema version tracking

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const localDBFileName = "local.db"

const localDBSchema = `
CREATE TABLE IF NOT EXISTS snapshots (
  id               TEXT PRIMARY KEY,
  target_id        TEXT NOT NULL,
  target_type      TEXT NOT NULL,
  collected_at     DATETIME NOT NULL,
  payload_enc      BLOB NOT NULL,
  summary_json     TEXT,
  synced_at        DATETIME,
  schema_version   INTEGER NOT NULL DEFAULT 1,
  created_at       DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_snapshots_target
  ON snapshots(target_id, collected_at DESC);

CREATE INDEX IF NOT EXISTS idx_snapshots_unsynced
  ON snapshots(synced_at) WHERE synced_at IS NULL;

CREATE TABLE IF NOT EXISTS signals (
  id           TEXT PRIMARY KEY,
  snapshot_id  TEXT NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
  target_id    TEXT NOT NULL,
  signal_key   TEXT NOT NULL,
  severity     TEXT NOT NULL,
  entity       TEXT,
  value        TEXT,
  detected_at  DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_signals_snapshot
  ON signals(snapshot_id);

CREATE INDEX IF NOT EXISTS idx_signals_target
  ON signals(target_id, detected_at DESC);

CREATE TABLE IF NOT EXISTS db_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

INSERT OR IGNORE INTO db_meta(key, value)
  VALUES('schema_version', '1');
`

// LocalDB is the authoritative local store for Hybrid Mode.
// Snapshot payloads are stored encrypted; signals and
// summaries are stored as plaintext for queryability.
type LocalDB struct {
	mu      sync.Mutex
	db      *sql.DB
	store   *Store // for encryption/decryption
	enabled bool
}

// SnapshotSignal mirrors the signal shape used by the frontend.
type SnapshotSignal struct {
	Key      string `json:"key"`
	Severity string `json:"severity"`
	Label    string `json:"label"`
	Entity   string `json:"entity,omitempty"`
	Value    string `json:"value,omitempty"`
}

// SnapshotSummary is the cloud-safe summary derived from a
// full payload. Raw data never leaves the host in Hybrid Mode.
type SnapshotSummary struct {
	Verdict      string           `json:"verdict"`
	SignalCount  int              `json:"signal_count"`
	BlockerCount int              `json:"blocker_count"`
	CautionCount int              `json:"caution_count"`
	TopSignals   []SnapshotSignal `json:"top_signals"`
}

// NewLocalDB opens (or creates) the local SQLite database.
// dir should be the same configDir used by Store.
// The store is used for payload encryption.
func NewLocalDB(dir string, store *Store) (*LocalDB, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("local_db: create dir: %w", err)
	}

	path := filepath.Join(dir, localDBFileName)

	// journal_mode=WAL for concurrent reads during writes.
	// foreign_keys=ON enforces signal → snapshot cascade deletes.
	dsn := fmt.Sprintf(
		"file:%s?_journal_mode=WAL&_foreign_keys=ON&_busy_timeout=5000",
		path,
	)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("local_db: open: %w", err)
	}

	// Single writer to avoid SQLITE_BUSY contention.
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(localDBSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("local_db: schema init: %w", err)
	}

	if audit != nil {
		audit.Info("local_db.open", "Local DB opened",
			F("path", path))
	}

	return &LocalDB{db: db, store: store, enabled: true}, nil
}

// Close shuts down the database connection cleanly.
func (d *LocalDB) Close() error {
	if d == nil || !d.enabled {
		return nil
	}
	return d.db.Close()
}

// ── Write ──

// WriteSnapshot persists a collected payload and its derived
// signals. The full payload is encrypted before storage.
func (d *LocalDB) WriteSnapshot(
	snapshotID string,
	targetID string,
	targetType string,
	collectedAt time.Time,
	payload map[string]interface{},
	signals []SnapshotSignal,
) error {
	if d == nil || !d.enabled {
		return nil
	}

	// Marshal and encrypt the full payload.
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("local_db: marshal payload: %w", err)
	}

	enc, err := d.store.encrypt(raw)
	if err != nil {
		return fmt.Errorf("local_db: encrypt payload: %w", err)
	}

	// Derive summary from signals.
	summary := buildSummary(signals)
	summaryJSON, err := json.Marshal(summary)
	if err != nil {
		return fmt.Errorf("local_db: marshal summary: %w", err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("local_db: begin tx: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.Exec(`
		INSERT INTO snapshots
		  (id, target_id, target_type, collected_at,
		   payload_enc, summary_json, schema_version)
		VALUES (?, ?, ?, ?, ?, ?, 1)
	`, snapshotID, targetID, targetType,
		collectedAt.UTC().Format(time.RFC3339Nano),
		enc, string(summaryJSON))
	if err != nil {
		return fmt.Errorf("local_db: insert snapshot: %w", err)
	}

	for _, sig := range signals {
		sigID := generateID()
		_, err = tx.Exec(`
			INSERT INTO signals
			  (id, snapshot_id, target_id, signal_key,
			   severity, entity, value, detected_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`, sigID, snapshotID, targetID, sig.Key,
			sig.Severity, sig.Entity, sig.Value,
			collectedAt.UTC().Format(time.RFC3339Nano))
		if err != nil {
			return fmt.Errorf("local_db: insert signal: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("local_db: commit: %w", err)
	}

	if audit != nil {
		audit.Debug("local_db.write", "Snapshot written",
			F("snapshot_id", snapshotID),
			F("target_id", targetID),
			F("signals", len(signals)))
	}

	return nil
}

// ── Read ──

// LatestSnapshot returns the most recent snapshot payload
// for a target, decrypted. Returns nil if none exists.
func (d *LocalDB) LatestSnapshot(
	targetID string,
) (map[string]interface{}, time.Time, error) {
	if d == nil || !d.enabled {
		return nil, time.Time{}, nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	var enc []byte
	var collectedAtStr string

	err := d.db.QueryRow(`
		SELECT payload_enc, collected_at
		FROM snapshots
		WHERE target_id = ?
		ORDER BY collected_at DESC
		LIMIT 1
	`, targetID).Scan(&enc, &collectedAtStr)

	if err == sql.ErrNoRows {
		return nil, time.Time{}, nil
	}
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("local_db: query: %w", err)
	}

	raw, err := d.store.decrypt(enc)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("local_db: decrypt: %w", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, time.Time{}, fmt.Errorf("local_db: unmarshal: %w", err)
	}

	collectedAt, _ := time.Parse(time.RFC3339Nano, collectedAtStr)

	return payload, collectedAt, nil
}

// ── Sync ──

// MarkSynced records that a snapshot summary has been
// successfully delivered to the cloud.
func (d *LocalDB) MarkSynced(snapshotID string) error {
	if d == nil || !d.enabled {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		UPDATE snapshots
		SET synced_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
		WHERE id = ?
	`, snapshotID)
	return err
}

// MarkLegacySynced is deprecated — retained as a no-op for
// backward compatibility. Unsynced snapshots are now replayed
// on reconnect instead of being discarded.
func (d *LocalDB) MarkLegacySynced(
	startTime time.Time,
) (int64, error) {
	return 0, nil
}

// UnsyncedSnapshots returns up to `limit` snapshots that have
// not been marked as synced, ordered oldest-first. Each row
// includes the decrypted payload so the upload queue can
// replay them to the cloud.
type UnsyncedSnapshot struct {
	ID          string
	TargetID    string
	TargetType  string
	CollectedAt time.Time
	Payload     map[string]interface{}
}

func (d *LocalDB) UnsyncedSnapshots(limit int) ([]UnsyncedSnapshot, error) {
	if d == nil || !d.enabled {
		return nil, nil
	}
	if limit <= 0 {
		limit = 50
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.db.Query(`
		SELECT id, target_id, target_type, collected_at, payload_enc
		FROM snapshots
		WHERE synced_at IS NULL
		ORDER BY collected_at ASC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("local_db: query unsynced: %w", err)
	}
	defer rows.Close()

	var results []UnsyncedSnapshot
	for rows.Next() {
		var id, targetID, targetType, collectedAtStr string
		var enc []byte
		if err := rows.Scan(&id, &targetID, &targetType, &collectedAtStr, &enc); err != nil {
			return nil, fmt.Errorf("local_db: scan unsynced: %w", err)
		}
		raw, err := d.store.decrypt(enc)
		if err != nil {
			// Skip corrupted rows
			continue
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(raw, &payload); err != nil {
			continue
		}
		collectedAt, _ := time.Parse(time.RFC3339Nano, collectedAtStr)
		results = append(results, UnsyncedSnapshot{
			ID:          id,
			TargetID:    targetID,
			TargetType:  targetType,
			CollectedAt: collectedAt,
			Payload:     payload,
		})
	}
	return results, nil
}

// UnsyncedCount returns the number of snapshots not yet synced.
func (d *LocalDB) UnsyncedCount() int64 {
	if d == nil || !d.enabled {
		return 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var count int64
	d.db.QueryRow("SELECT COUNT(*) FROM snapshots WHERE synced_at IS NULL").Scan(&count)
	return count
}

// GetSnapshotSummary returns the pre-computed
// SnapshotSummary for a given snapshot ID,
// read from the summary_json column (written during
// WriteSnapshot). Returns nil if no summary exists.
func (d *LocalDB) GetSnapshotSummary(
	snapshotID string,
) (*SnapshotSummary, error) {
	if d == nil || !d.enabled {
		return nil, nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	var raw sql.NullString
	err := d.db.QueryRow(`
		SELECT summary_json FROM snapshots
		WHERE id = ?
	`, snapshotID).Scan(&raw)
	if err != nil || !raw.Valid || raw.String == "" {
		return nil, err
	}

	var summary SnapshotSummary
	if err := json.Unmarshal([]byte(raw.String), &summary); err != nil {
		return nil, fmt.Errorf("local_db: unmarshal summary: %w", err)
	}

	// Always return the summary — even with 0 signals — so the cloud
	// receives a verdict (healthy) and the target appears on Unified Ops.
	return &summary, nil
}

// ── Retention ──

// RunRetention deletes snapshots older than maxAgeDays.
// Should be called periodically (e.g. once per hour from
// a background goroutine). Signals cascade-delete.
func (d *LocalDB) RunRetention(maxAgeDays int) (int64, error) {
	if d == nil || !d.enabled {
		return 0, nil
	}

	if maxAgeDays <= 0 {
		maxAgeDays = 7
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	cutoff := time.Now().UTC().
		AddDate(0, 0, -maxAgeDays).
		Format(time.RFC3339Nano)

	res, err := d.db.Exec(`
		DELETE FROM snapshots WHERE collected_at < ?
	`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("local_db: retention: %w", err)
	}

	n, _ := res.RowsAffected()

	if n > 0 && audit != nil {
		audit.Info("local_db.retention", "Snapshots pruned",
			F("count", n), F("max_age_days", maxAgeDays))
	}

	return n, nil
}

// ── Summary Builder ──

// buildSummary derives a SnapshotSummary from a signal list.
// Called during WriteSnapshot — keeps summary in sync with
// the signals that were actually persisted.
func buildSummary(signals []SnapshotSignal) SnapshotSummary {
	s := SnapshotSummary{}
	s.SignalCount = len(signals)

	for _, sig := range signals {
		switch sig.Severity {
		case "critical", "error":
			s.BlockerCount++
		case "warning":
			s.CautionCount++
		}
	}

	// Verdict: worst severity wins.
	switch {
	case s.BlockerCount > 0:
		s.Verdict = "critical"
	case s.CautionCount > 0:
		s.Verdict = "warning"
	default:
		s.Verdict = "healthy"
	}

	// Top signals: up to 10, errors first then warnings.
	top := make([]SnapshotSignal, 0, 10)
	for _, sig := range signals {
		if sig.Severity == "critical" || sig.Severity == "error" {
			top = append(top, sig)
			if len(top) >= 10 {
				break
			}
		}
	}
	for _, sig := range signals {
		if len(top) >= 10 {
			break
		}
		if sig.Severity == "warning" {
			top = append(top, sig)
		}
	}

	s.TopSignals = top
	return s
}

// ── Stats ──

// Stats returns basic DB health metrics for the audit log.
func (d *LocalDB) Stats() map[string]interface{} {
	if d == nil || !d.enabled {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	var snapshotCount, unsyncedCount int64
	d.db.QueryRow(
		"SELECT COUNT(*) FROM snapshots",
	).Scan(&snapshotCount)
	d.db.QueryRow(
		"SELECT COUNT(*) FROM snapshots WHERE synced_at IS NULL",
	).Scan(&unsyncedCount)

	return map[string]interface{}{
		"snapshot_count":  snapshotCount,
		"unsynced_count":  unsyncedCount,
	}
}
