// Package store is the local-first persistence layer: one SQLite file.
// Solo mode is the default; a Postgres implementation can be added behind
// the same interface (flag stubbed in v1). All secrets are redacted by the
// collector before they ever reach this package.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Store wraps a SQLite database holding runs, spans, events, alerts,
// receipts, kill audit records, approvals, and kill-state.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the SQLite database at path and applies
// migrations. Use ":memory:" for tests.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1) // serialize writes; WAL keeps readers flowing
	// busy_timeout FIRST: every later statement (including the journal-mode
	// switch) must wait for a competing writer instead of failing at once.
	// Fleets run many short-lived `warden hook` processes against one file;
	// before this ordering, ~20% of calls under 8-way concurrency failed with
	// "database is locked" and were denied fail-closed.
	for _, p := range []string{"PRAGMA busy_timeout=5000", "PRAGMA foreign_keys=ON", "PRAGMA synchronous=NORMAL"} {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("pragma %q: %w", p, err)
		}
	}
	if err := ensureWAL(db); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// ensureWAL switches the database to WAL mode only when it is not already in
// it (the switch needs an exclusive lock; a no-op check does not), retrying
// while another process holds the lock. ":memory:" databases stay as they are.
func ensureWAL(db *sql.DB) error {
	var mode string
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := db.QueryRow("PRAGMA journal_mode").Scan(&mode)
		if err == nil && (strings.EqualFold(mode, "wal") || strings.EqualFold(mode, "memory")) {
			return nil
		}
		if err == nil {
			err = db.QueryRow("PRAGMA journal_mode=WAL").Scan(&mode)
			if err == nil {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("pragma journal_mode=WAL: %w", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

// DB exposes the raw handle for tests and advanced queries.
func (s *Store) DB() *sql.DB { return s.db }

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTS(v sql.NullString) (time.Time, error) {
	if !v.Valid || v.String == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, v.String)
}

var migrations = []string{schemaV1, schemaV2, schemaV3, schemaV4, schemaV5}

// currentVersion reads the schema version without taking a write lock.
func (s *Store) currentVersion() (int, error) {
	var v int
	err := s.db.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_version`).Scan(&v)
	return v, err
}

// migrate brings the schema forward. The common case (already current) takes
// no write lock at all, so a burst of hook processes does not serialize on it.
// When work is needed it runs inside BEGIN IMMEDIATE and re-reads the version
// under the lock, so two processes opening a fresh database cannot both apply
// the same migration (the second sees the first's work and does nothing).
func (s *Store) migrate() error {
	if v, err := s.currentVersion(); err == nil && v >= len(migrations) {
		return nil
	}
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, `ROLLBACK`)
		}
	}()
	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)`); err != nil {
		return err
	}
	var v int
	if err := conn.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0) FROM schema_version`).Scan(&v); err != nil {
		return err
	}
	for i, m := range migrations {
		if i+1 <= v {
			continue
		}
		if _, err := conn.ExecContext(ctx, m); err != nil {
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := conn.ExecContext(ctx, `INSERT INTO schema_version(version) VALUES(?)`, i+1); err != nil {
			return err
		}
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return err
	}
	committed = true
	return nil
}

const schemaV1 = `
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY,
  parent_run_id TEXT,
  agent_id TEXT NOT NULL,
  fleet_id TEXT NOT NULL,
  operator TEXT NOT NULL DEFAULT '',
  started_at TEXT NOT NULL,
  ended_at TEXT,
  status TEXT NOT NULL,
  model TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL DEFAULT '',
  tokens_in INTEGER NOT NULL DEFAULT 0,
  tokens_out INTEGER NOT NULL DEFAULT 0,
  tokens_cached INTEGER NOT NULL DEFAULT 0,
  cost_usd REAL NOT NULL DEFAULT 0,
  cost_saved_usd REAL NOT NULL DEFAULT 0,
  tool_calls INTEGER NOT NULL DEFAULT 0,
  files_touched INTEGER NOT NULL DEFAULT 0,
  net_egress_hosts INTEGER NOT NULL DEFAULT 0,
  subagents_spawned INTEGER NOT NULL DEFAULT 0,
  approvals_requested INTEGER NOT NULL DEFAULT 0,
  approvals_denied INTEGER NOT NULL DEFAULT 0,
  kill_source TEXT,
  kill_reason TEXT,
  killed_by TEXT,
  receipt_ref TEXT NOT NULL DEFAULT '',
  command TEXT NOT NULL DEFAULT '',
  pid INTEGER NOT NULL DEFAULT 0,
  cost_source TEXT NOT NULL DEFAULT 'spans'
);
CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(status);
CREATE INDEX IF NOT EXISTS idx_runs_agent ON runs(agent_id);
CREATE INDEX IF NOT EXISTS idx_runs_fleet ON runs(fleet_id);
CREATE INDEX IF NOT EXISTS idx_runs_started ON runs(started_at);

CREATE TABLE IF NOT EXISTS spans (
  span_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  agent_id TEXT NOT NULL DEFAULT '',
  fleet_id TEXT NOT NULL DEFAULT '',
  started_at TEXT NOT NULL,
  ended_at TEXT,
  status TEXT NOT NULL DEFAULT '',
  model TEXT NOT NULL DEFAULT '',
  tokens_in INTEGER NOT NULL DEFAULT 0,
  tokens_out INTEGER NOT NULL DEFAULT 0,
  tokens_cached INTEGER NOT NULL DEFAULT 0,
  cost_usd REAL NOT NULL DEFAULT 0,
  cache_hit INTEGER NOT NULL DEFAULT 0,
  tool TEXT NOT NULL DEFAULT '',
  tool_server TEXT NOT NULL DEFAULT '',
  args_summary TEXT NOT NULL DEFAULT '',
  arg_hash TEXT NOT NULL DEFAULT '',
  exit_status INTEGER NOT NULL DEFAULT 0,
  output_bytes INTEGER NOT NULL DEFAULT 0,
  path TEXT NOT NULL DEFAULT '',
  op TEXT NOT NULL DEFAULT '',
  count INTEGER NOT NULL DEFAULT 0,
  bytes INTEGER NOT NULL DEFAULT 0,
  host TEXT NOT NULL DEFAULT '',
  port INTEGER NOT NULL DEFAULT 0,
  net_bytes INTEGER NOT NULL DEFAULT 0,
  child_run_id TEXT NOT NULL DEFAULT '',
  spawn_reason TEXT NOT NULL DEFAULT '',
  gate TEXT NOT NULL DEFAULT '',
  decision TEXT NOT NULL DEFAULT '',
  approver TEXT NOT NULL DEFAULT '',
  decision_latency_ms INTEGER NOT NULL DEFAULT 0,
  policy_decision TEXT NOT NULL DEFAULT '',
  policy_reason TEXT NOT NULL DEFAULT '',
  policy_version TEXT NOT NULL DEFAULT '',
  redacted INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_spans_run ON spans(run_id);
CREATE INDEX IF NOT EXISTS idx_spans_kind ON spans(kind);
CREATE INDEX IF NOT EXISTS idx_spans_tool ON spans(tool);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL DEFAULT '',
  span_id TEXT NOT NULL DEFAULT '',
  at TEXT NOT NULL,
  severity TEXT NOT NULL,
  kind TEXT NOT NULL,
  message TEXT NOT NULL,
  data_json TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id);
CREATE INDEX IF NOT EXISTS idx_events_at ON events(at);

CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rule TEXT NOT NULL,
  severity TEXT NOT NULL,
  agent_id TEXT NOT NULL DEFAULT '',
  fleet_id TEXT NOT NULL DEFAULT '',
  run_id TEXT NOT NULL DEFAULT '',
  message TEXT NOT NULL,
  threshold TEXT NOT NULL DEFAULT '',
  observed TEXT NOT NULL DEFAULT '',
  at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  fingerprint TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_fp ON alerts(fingerprint);

CREATE TABLE IF NOT EXISTS receipts (
  run_id TEXT PRIMARY KEY,
  body TEXT NOT NULL,
  body_hash TEXT NOT NULL,
  prev_hash TEXT NOT NULL DEFAULT '',
  signature TEXT NOT NULL,
  key_id TEXT NOT NULL,
  sealed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS kill_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  actor TEXT NOT NULL,
  scope TEXT NOT NULL,
  target TEXT NOT NULL,
  reason TEXT NOT NULL,
  result TEXT NOT NULL DEFAULT '',
  details TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS approvals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  gate TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  decision TEXT NOT NULL DEFAULT '',
  approver TEXT NOT NULL DEFAULT '',
  decided_at TEXT,
  reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);

CREATE TABLE IF NOT EXISTS kill_state (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT '',
  expires_at TEXT
);
`
