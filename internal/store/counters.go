package store

import (
	"time"

	"github.com/calasdan-sketch/warden/internal/model"
)

// schemaV2 adds the heartbeat column used to detect runs that died without
// sealing (host crash, SIGKILL of the shim).
const schemaV2 = `ALTER TABLE runs ADD COLUMN last_heartbeat TEXT;`

// schemaV3 stores the sealed status on the receipt row for cheap reads
// (the canonical status also lives inside the signed body).
const schemaV3 = `ALTER TABLE receipts ADD COLUMN status TEXT NOT NULL DEFAULT '';`

// schemaV4 marks spans that arrived after their run was sealed: they stay in
// the audit trail but are not covered by the receipt's signed trace digest.
const schemaV4 = `ALTER TABLE spans ADD COLUMN late INTEGER NOT NULL DEFAULT 0;`

// schemaV5 stores the harness tool-use id (exported as gen_ai.tool.call.id).
const schemaV5 = `ALTER TABLE spans ADD COLUMN tool_call_id TEXT NOT NULL DEFAULT '';`

// TouchHeartbeat marks a run alive.
func (s *Store) TouchHeartbeat(runID string) error {
	_, err := s.db.Exec(`UPDATE runs SET last_heartbeat=? WHERE run_id=?`, ts(time.Now().UTC()), runID)
	return err
}

// StaleLiveRuns returns runs still marked running whose heartbeat (or start,
// if never heartbeated) is older than d.
func (s *Store) StaleLiveRuns(d time.Duration) ([]*model.Run, error) {
	cutoff := ts(time.Now().UTC().Add(-d))
	rows, err := s.db.Query(`SELECT `+runColumns+` FROM runs
		WHERE status='running' AND COALESCE(last_heartbeat, started_at) < ?
		ORDER BY started_at ASC`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// IncRunCounters bumps live counters (dashboard burn bar). Called per span.
func (s *Store) IncRunCounters(runID string, toolCalls, ti, to, tcached int64, cost float64) (int64, error) {
	res, err := s.db.Exec(`UPDATE runs SET tool_calls=tool_calls+?,tokens_in=tokens_in+?,
		tokens_out=tokens_out+?,tokens_cached=tokens_cached+?,cost_usd=cost_usd+?,
		last_heartbeat=? WHERE run_id=?`,
		toolCalls, ti, to, tcached, cost, ts(time.Now().UTC()), runID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// IncRunSubagents bumps the spawn counter.
func (s *Store) IncRunSubagents(runID string, n int64) error {
	_, err := s.db.Exec(`UPDATE runs SET subagents_spawned=subagents_spawned+?,last_heartbeat=? WHERE run_id=?`,
		n, ts(time.Now().UTC()), runID)
	return err
}

// IncRunApprovals bumps approval counters.
func (s *Store) IncRunApprovals(runID string, req, denied int64) error {
	_, err := s.db.Exec(`UPDATE runs SET approvals_requested=approvals_requested+?,
		approvals_denied=approvals_denied+?,last_heartbeat=? WHERE run_id=?`,
		req, denied, ts(time.Now().UTC()), runID)
	return err
}

// SpanTotals recomputes ground-truth totals from spans (used at seal time).
func (s *Store) SpanTotals(runID string) (toolCalls, ti, to, tcached int64, cost float64, err error) {
	err = s.db.QueryRow(`SELECT COUNT(*) FROM spans WHERE run_id=? AND kind='tool.call'`, runID).Scan(&toolCalls)
	if err != nil {
		return
	}
	err = s.db.QueryRow(`SELECT COALESCE(SUM(tokens_in),0),COALESCE(SUM(tokens_out),0),
		COALESCE(SUM(tokens_cached),0),COALESCE(SUM(cost_usd),0) FROM spans WHERE run_id=? AND kind='llm.call'`,
		runID).Scan(&ti, &to, &tcached, &cost)
	return
}

// DistinctCount counts distinct non-empty values of col for a span kind.
func (s *Store) DistinctCount(runID string, kind model.SpanKind, col string) (int64, error) {
	allowed := map[string]bool{"path": true, "host": true, "child_run_id": true, "tool": true}
	if !allowed[col] {
		return 0, nil
	}
	var n int64
	q := `SELECT COUNT(DISTINCT ` + col + `) FROM spans WHERE run_id=? AND kind=? AND ` + col + ` != ''`
	err := s.db.QueryRow(q, runID, string(kind)).Scan(&n)
	return n, err
}

// ApprovalTotals counts human.approval spans and denials.
func (s *Store) ApprovalTotals(runID string) (req, denied int64, err error) {
	err = s.db.QueryRow(`SELECT COUNT(*),COALESCE(SUM(CASE WHEN decision='denied' THEN 1 ELSE 0 END),0)
		FROM spans WHERE run_id=? AND kind='human.approval'`, runID).Scan(&req, &denied)
	return
}
