package store

import (
	"database/sql"

	"warden/internal/model"
)

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// InsertSpan records one span. The caller must have redacted it first.
func (s *Store) InsertSpan(sp *model.Span) error {
	var ended any
	if sp.EndedAt != nil {
		ended = ts(*sp.EndedAt)
	}
	_, err := s.db.Exec(`INSERT INTO spans(span_id,run_id,kind,name,agent_id,fleet_id,started_at,ended_at,status,
		model,tokens_in,tokens_out,tokens_cached,cost_usd,cache_hit,
		tool,tool_server,args_summary,arg_hash,exit_status,output_bytes,
		path,op,count,bytes,host,port,net_bytes,child_run_id,spawn_reason,
		gate,decision,approver,decision_latency_ms,
		policy_decision,policy_reason,policy_version,redacted)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		sp.SpanID, sp.RunID, string(sp.Kind), sp.Name, sp.AgentID, sp.FleetID, ts(sp.StartedAt), ended, sp.Status,
		sp.Model, sp.TokensIn, sp.TokensOut, sp.TokensCached, sp.CostUSD, boolInt(sp.CacheHit),
		sp.Tool, sp.ToolServer, sp.ArgsSummary, sp.ArgHash, sp.ExitStatus, sp.OutputBytes,
		sp.Path, sp.Op, sp.Count, sp.Bytes, sp.Host, sp.Port, sp.NetBytes, sp.ChildRunID, sp.SpawnReason,
		sp.Gate, sp.Decision, sp.Approver, sp.DecisionLatencyMs,
		sp.PolicyDecision, sp.PolicyReason, sp.PolicyVersion, boolInt(sp.Redacted))
	return err
}

// SpansForRun returns a run's spans oldest-first (the trace waterfall order).
func (s *Store) SpansForRun(runID string) ([]*model.Span, error) {
	rows, err := s.db.Query(`SELECT span_id,run_id,kind,name,agent_id,fleet_id,started_at,ended_at,status,
		model,tokens_in,tokens_out,tokens_cached,cost_usd,cache_hit,
		tool,tool_server,args_summary,arg_hash,exit_status,output_bytes,
		path,op,count,bytes,host,port,net_bytes,child_run_id,spawn_reason,
		gate,decision,approver,decision_latency_ms,
		policy_decision,policy_reason,policy_version,redacted
		FROM spans WHERE run_id=? ORDER BY started_at ASC, rowid ASC`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Span
	for rows.Next() {
		sp, err := scanSpan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sp)
	}
	return out, rows.Err()
}

func scanSpan(row rowScanner) (*model.Span, error) {
	var sp model.Span
	var started, ended sql.NullString
	var kind string
	var cacheHit, redacted int
	err := row.Scan(&sp.SpanID, &sp.RunID, &kind, &sp.Name, &sp.AgentID, &sp.FleetID, &started, &ended, &sp.Status,
		&sp.Model, &sp.TokensIn, &sp.TokensOut, &sp.TokensCached, &sp.CostUSD, &cacheHit,
		&sp.Tool, &sp.ToolServer, &sp.ArgsSummary, &sp.ArgHash, &sp.ExitStatus, &sp.OutputBytes,
		&sp.Path, &sp.Op, &sp.Count, &sp.Bytes, &sp.Host, &sp.Port, &sp.NetBytes, &sp.ChildRunID, &sp.SpawnReason,
		&sp.Gate, &sp.Decision, &sp.Approver, &sp.DecisionLatencyMs,
		&sp.PolicyDecision, &sp.PolicyReason, &sp.PolicyVersion, &redacted)
	if err != nil {
		return nil, err
	}
	sp.Kind = model.SpanKind(kind)
	sp.StartedAt, err = parseTS(started)
	if err != nil {
		return nil, err
	}
	if ended.Valid {
		t, err := parseTS(ended)
		if err != nil {
			return nil, err
		}
		sp.EndedAt = &t
	}
	sp.CacheHit = cacheHit == 1
	sp.Redacted = redacted == 1
	return &sp, nil
}

// InsertEvent appends one event to the run event stream (append-only).
func (s *Store) InsertEvent(e *model.Event) error {
	res, err := s.db.Exec(`INSERT INTO events(run_id,span_id,at,severity,kind,message,data_json)
		VALUES(?,?,?,?,?,?,?)`, e.RunID, e.SpanID, ts(e.At), e.Severity, e.Kind, e.Message, e.DataJSON)
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	e.ID = id
	return nil
}

// EventsForRun returns a run's events newest-first.
func (s *Store) EventsForRun(runID string, limit int) ([]*model.Event, error) {
	q := `SELECT id,run_id,span_id,at,severity,kind,message,data_json FROM events WHERE run_id=? ORDER BY id DESC`
	var args []any
	args = append(args, runID)
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func scanEvent(row rowScanner) (*model.Event, error) {
	var e model.Event
	var at sql.NullString
	if err := row.Scan(&e.ID, &e.RunID, &e.SpanID, &at, &e.Severity, &e.Kind, &e.Message, &e.DataJSON); err != nil {
		return nil, err
	}
	t, err := parseTS(at)
	if err != nil {
		return nil, err
	}
	e.At = t
	return &e, nil
}

// InsertAlert records an anomaly alert (alert-only-on-transition is enforced
// by the anomaly engine, not here).
func (s *Store) InsertAlert(a *model.Alert) error {
	res, err := s.db.Exec(`INSERT INTO alerts(rule,severity,agent_id,fleet_id,run_id,message,threshold,observed,at,status,fingerprint)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		a.Rule, a.Severity, a.AgentID, a.FleetID, a.RunID, a.Message, a.Threshold, a.Observed, ts(a.At), a.Status, a.Fingerprint)
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	a.ID = id
	return nil
}

// ActiveAlertFingerprints returns fingerprints of currently active alerts
// (used for transition-only alerting).
func (s *Store) ActiveAlertFingerprints() (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT DISTINCT fingerprint FROM alerts WHERE status='active'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return nil, err
		}
		out[fp] = true
	}
	return out, rows.Err()
}

// ResolveAlertsByFingerprint marks active alerts with the fingerprint recovered.
func (s *Store) ResolveAlertsByFingerprint(fp string) error {
	_, err := s.db.Exec(`UPDATE alerts SET status='recovered' WHERE fingerprint=? AND status='active'`, fp)
	return err
}

// ListAlerts returns alerts newest-first, optionally filtered by status.
func (s *Store) ListAlerts(status string, limit int) ([]*model.Alert, error) {
	q := `SELECT id,rule,severity,agent_id,fleet_id,run_id,message,threshold,observed,at,status,fingerprint
		FROM alerts WHERE 1=1`
	var args []any
	if status != "" {
		q += ` AND status=?`
		args = append(args, status)
	}
	q += ` ORDER BY id DESC`
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Alert
	for rows.Next() {
		var a model.Alert
		var at sql.NullString
		if err := rows.Scan(&a.ID, &a.Rule, &a.Severity, &a.AgentID, &a.FleetID, &a.RunID,
			&a.Message, &a.Threshold, &a.Observed, &at, &a.Status, &a.Fingerprint); err != nil {
			return nil, err
		}
		t, err := parseTS(at)
		if err != nil {
			return nil, err
		}
		a.At = t
		out = append(out, &a)
	}
	return out, rows.Err()
}
