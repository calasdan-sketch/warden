package store

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/calasdan-sketch/warden/internal/model"
)

func nullStr(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

// runColumns is the full column list for runs (kept in one place so new
// columns can't drift out of sync across queries).
const runColumns = `run_id,parent_run_id,agent_id,fleet_id,operator,started_at,ended_at,status,
		model,provider,tokens_in,tokens_out,tokens_cached,cost_usd,cost_saved_usd,
		tool_calls,files_touched,net_egress_hosts,subagents_spawned,approvals_requested,approvals_denied,
		kill_source,kill_reason,killed_by,receipt_ref,command,pid,cost_source`

// CreateRun inserts a new run envelope.
func (s *Store) CreateRun(r *model.Run) error {
	var parent any
	if r.ParentRunID != nil {
		parent = *r.ParentRunID
	}
	var ended any
	if r.EndedAt != nil {
		ended = ts(*r.EndedAt)
	}
	costSource := r.CostSource
	if costSource == "" {
		costSource = "spans"
	}
	_, err := s.db.Exec(`INSERT INTO runs(`+runColumns+`)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.RunID, parent, r.AgentID, r.FleetID, r.Operator, ts(r.StartedAt), ended, string(r.Status),
		r.Model, r.Provider, r.TokensIn, r.TokensOut, r.TokensCached, r.CostUSD, r.CostSavedUSD,
		r.ToolCalls, r.FilesTouched, r.NetEgressHosts, r.SubagentsSpawned, r.ApprovalsRequested, r.ApprovalsDenied,
		nullStr(r.KillSource), nullStr(r.KillReason), nullStr(r.KilledBy), r.ReceiptRef, r.Command, r.PID, costSource)
	return err
}

// UpdateRun writes back a (usually sealed) run envelope.
func (s *Store) UpdateRun(r *model.Run) error {
	var ended any
	if r.EndedAt != nil {
		ended = ts(*r.EndedAt)
	}
	costSource := r.CostSource
	if costSource == "" {
		costSource = "spans"
	}
	res, err := s.db.Exec(`UPDATE runs SET ended_at=?,status=?,tokens_in=?,tokens_out=?,tokens_cached=?,
		cost_usd=?,cost_saved_usd=?,tool_calls=?,files_touched=?,net_egress_hosts=?,subagents_spawned=?,
		approvals_requested=?,approvals_denied=?,kill_source=?,kill_reason=?,killed_by=?,receipt_ref=?,pid=?,
		cost_source=?
		WHERE run_id=?`,
		ended, string(r.Status), r.TokensIn, r.TokensOut, r.TokensCached,
		r.CostUSD, r.CostSavedUSD, r.ToolCalls, r.FilesTouched, r.NetEgressHosts, r.SubagentsSpawned,
		r.ApprovalsRequested, r.ApprovalsDenied, nullStr(r.KillSource), nullStr(r.KillReason),
		nullStr(r.KilledBy), r.ReceiptRef, r.PID, costSource, r.RunID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("run %s not found", r.RunID)
	}
	return nil
}

// GetRun fetches one run by ID.
func (s *Store) GetRun(id string) (*model.Run, error) {
	row := s.db.QueryRow(`SELECT `+runColumns+` FROM runs WHERE run_id=?`, id)
	return scanRun(row)
}

type rowScanner interface{ Scan(...any) error }

func scanRun(row rowScanner) (*model.Run, error) {
	var r model.Run
	var parent, started, ended, ks, kr, kb sql.NullString
	var status string
	err := row.Scan(&r.RunID, &parent, &r.AgentID, &r.FleetID, &r.Operator, &started,
		&ended, &status, &r.Model, &r.Provider, &r.TokensIn, &r.TokensOut, &r.TokensCached,
		&r.CostUSD, &r.CostSavedUSD, &r.ToolCalls, &r.FilesTouched, &r.NetEgressHosts,
		&r.SubagentsSpawned, &r.ApprovalsRequested, &r.ApprovalsDenied,
		&ks, &kr, &kb, &r.ReceiptRef, &r.Command, &r.PID, &r.CostSource)
	if err != nil {
		return nil, err
	}
	r.StartedAt, err = parseTS(started)
	if err != nil {
		return nil, fmt.Errorf("bad started_at: %w", err)
	}
	if parent.Valid {
		r.ParentRunID = &parent.String
	}
	if ended.Valid {
		t, err := parseTS(ended)
		if err != nil {
			return nil, fmt.Errorf("bad ended_at: %w", err)
		}
		r.EndedAt = &t
	}
	r.Status = model.RunStatus(status)
	if ks.Valid {
		r.KillSource = &ks.String
	}
	if kr.Valid {
		r.KillReason = &kr.String
	}
	if kb.Valid {
		r.KilledBy = &kb.String
	}
	return &r, nil
}

// RunFilter narrows ListRuns.
type RunFilter struct {
	Status   model.RunStatus
	FleetID  string
	AgentID  string
	Limit    int
	LiveOnly bool
	Since    time.Time // started_at >= Since (zero = no bound)
}

// ListRuns returns runs newest-first matching the filter.
func (s *Store) ListRuns(f RunFilter) ([]*model.Run, error) {
	q := `SELECT ` + runColumns + ` FROM runs WHERE 1=1`
	var args []any
	if f.Status != "" {
		q += ` AND status=?`
		args = append(args, string(f.Status))
	}
	if f.LiveOnly {
		q += ` AND status='running'`
	}
	if f.FleetID != "" {
		q += ` AND fleet_id=?`
		args = append(args, f.FleetID)
	}
	if f.AgentID != "" {
		q += ` AND agent_id=?`
		args = append(args, f.AgentID)
	}
	if !f.Since.IsZero() {
		q += ` AND started_at >= ?`
		args = append(args, ts(f.Since))
	}
	q += ` ORDER BY started_at DESC`
	if f.Limit > 0 {
		q += ` LIMIT ?`
		args = append(args, f.Limit)
	}
	rows, err := s.db.Query(q, args...)
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

// ListRunsPage returns one page of runs newest-first (for streaming export
// without materializing the whole table: export walks offset pages until a
// short page).
func (s *Store) ListRunsPage(limit, offset int) ([]*model.Run, error) {
	if limit <= 0 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.Query(`SELECT `+runColumns+` FROM runs ORDER BY started_at DESC LIMIT ? OFFSET ?`, limit, offset)
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

// CountLive returns the number of runs currently marked running.
func (s *Store) CountLive() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM runs WHERE status='running'`).Scan(&n)
	return n, err
}

// CountGuardTrips counts guard_trip events in a fleet since t.
func (s *Store) CountGuardTrips(fleetID string, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM events e JOIN runs r ON e.run_id=r.run_id
		WHERE r.fleet_id=? AND e.kind='guard_trip' AND e.at >= ?`, fleetID, ts(since)).Scan(&n)
	return n, err
}

// DayCache is one day of fleet cache stats for the savings-collapse rule.
type DayCache struct {
	Day    string
	Cached int64
	Total  int64
}

// FleetDailyCache returns per-day cached vs total tokens for llm.call spans.
func (s *Store) FleetDailyCache(fleetID string, since time.Time) ([]DayCache, error) {
	rows, err := s.db.Query(`SELECT substr(started_at,1,10),
		COALESCE(SUM(tokens_cached),0), COALESCE(SUM(tokens_in+tokens_out),0)
		FROM spans WHERE fleet_id=? AND kind='llm.call' AND started_at >= ?
		GROUP BY substr(started_at,1,10) ORDER BY 1 ASC`, fleetID, ts(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DayCache
	for rows.Next() {
		var d DayCache
		if err := rows.Scan(&d.Day, &d.Cached, &d.Total); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// AgentHourlyCost returns per-hour gross cost for an agent since t.
func (s *Store) AgentHourlyCost(agentID string, since time.Time) ([]float64, error) {
	rows, err := s.db.Query(`SELECT COALESCE(SUM(cost_usd),0) FROM runs
		WHERE agent_id=? AND started_at >= ? GROUP BY substr(started_at,1,13) ORDER BY 1 ASC`,
		agentID, ts(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []float64
	for rows.Next() {
		var v float64
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// DistinctSpanValues returns distinct non-empty values of col for an agent/fleet scope.
// excludeRunID removes one run's spans from the baseline (so a run's own
// activity never counts as "already seen" — otherwise first-seen rules
// could never fire).
func (s *Store) DistinctSpanValues(kind model.SpanKind, col, scopeCol, scopeVal string, since time.Time, excludeRunID string) ([]string, error) {
	allowedCol := map[string]bool{"tool": true, "host": true, "path": true}
	allowedScope := map[string]bool{"agent_id": true, "fleet_id": true}
	if !allowedCol[col] || !allowedScope[scopeCol] {
		return nil, fmt.Errorf("bad column")
	}
	q := `SELECT DISTINCT ` + col + ` FROM spans WHERE kind=? AND ` + scopeCol + `=? AND ` + col + ` != '' AND started_at >= ?`
	var args []any
	args = append(args, string(kind), scopeVal, ts(since))
	if excludeRunID != "" {
		q += ` AND run_id != ?`
		args = append(args, excludeRunID)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ClaimForSeal atomically transitions a live run to the seal status.
// It returns claimed=false when another sealer already claimed or sealed it.
func (s *Store) ClaimForSeal(runID string, status model.RunStatus) (bool, *model.Run, error) {
	res, err := s.db.Exec(`UPDATE runs SET status=? WHERE run_id=? AND status IN ('running','awaiting_approval')`,
		string(status), runID)
	if err != nil {
		return false, nil, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return false, nil, nil
	}
	r, err := s.GetRun(runID)
	if err != nil {
		return false, nil, err
	}
	return true, r, nil
}

// UpdateRunPID records the child PID of a live run.
func (s *Store) UpdateRunPID(runID string, pid int) error {
	_, err := s.db.Exec(`UPDATE runs SET pid=? WHERE run_id=?`, pid, runID)
	return err
}
