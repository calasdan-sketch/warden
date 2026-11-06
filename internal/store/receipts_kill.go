package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/calasdan-sketch/warden/internal/model"
)

// StoreReceipt persists a sealed receipt (body is the canonical JSON).
func (s *Store) StoreReceipt(r *model.Receipt, body string) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO receipts(run_id,body,body_hash,prev_hash,signature,key_id,sealed_at,status)
		VALUES(?,?,?,?,?,?,?,?)`,
		r.RunID, body, r.BodyHash, r.PrevHash, r.Signature, r.KeyID, ts(r.SealedAt), string(r.Status))
	return err
}

// SealChained seals one receipt atomically: the chain head is read and the
// new receipt inserted inside a single BEGIN IMMEDIATE transaction. Two
// processes sealing concurrently can never fork the hash chain — the second
// blocks on the write lock until the first commits, then reads the fresh
// head. The seal callback builds (hashes + signs) the receipt for prev.
func (s *Store) SealChained(seal func(prev string) (*model.Receipt, string, error)) (*model.Receipt, error) {
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return nil, fmt.Errorf("seal tx begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()
	var h sql.NullString
	if err := conn.QueryRowContext(ctx,
		`SELECT body_hash FROM receipts ORDER BY sealed_at DESC, rowid DESC LIMIT 1`).Scan(&h); err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("seal tx head: %w", err)
	}
	prev := ""
	if h.Valid {
		prev = h.String
	}
	rec, body, err := seal(prev)
	if err != nil {
		return nil, err
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT OR REPLACE INTO receipts(run_id,body,body_hash,prev_hash,signature,key_id,sealed_at,status)
		VALUES(?,?,?,?,?,?,?,?)`,
		rec.RunID, body, rec.BodyHash, rec.PrevHash, rec.Signature, rec.KeyID, ts(rec.SealedAt), string(rec.Status)); err != nil {
		return nil, fmt.Errorf("seal tx insert: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return nil, fmt.Errorf("seal tx commit: %w", err)
	}
	committed = true
	return rec, nil
}

// GetReceipt fetches a sealed receipt by run ID.
func (s *Store) GetReceipt(runID string) (*model.Receipt, string, error) {
	var r model.Receipt
	var body, sealed, status sql.NullString
	err := s.db.QueryRow(`SELECT run_id,body,body_hash,prev_hash,signature,key_id,sealed_at,status
		FROM receipts WHERE run_id=?`, runID).
		Scan(&r.RunID, &body, &r.BodyHash, &r.PrevHash, &r.Signature, &r.KeyID, &sealed, &status)
	if err != nil {
		return nil, "", err
	}
	t, err := parseTS(sealed)
	if err != nil {
		return nil, "", err
	}
	r.SealedAt = t
	r.Status = model.RunStatus(status.String)
	return &r, body.String, nil
}

// LatestReceiptHash returns the body_hash of the most recently sealed receipt
// (the head of the hash chain; "" when none sealed yet).
func (s *Store) LatestReceiptHash() (string, error) {
	var h sql.NullString
	err := s.db.QueryRow(`SELECT body_hash FROM receipts ORDER BY sealed_at DESC, rowid DESC LIMIT 1`).Scan(&h)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return h.String, nil
}

// CountReceipts returns how many receipts are sealed.
func (s *Store) CountReceipts() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM receipts`).Scan(&n)
	return n, err
}

// SealedReceipt is one receipt with its canonical body.
type SealedReceipt struct {
	Receipt *model.Receipt
	Body    string
}

// AllReceipts returns every sealed receipt in seal order (for chain verification).
func (s *Store) AllReceipts() ([]SealedReceipt, error) {
	rows, err := s.db.Query(`SELECT run_id,body,body_hash,prev_hash,signature,key_id,sealed_at,status
		FROM receipts ORDER BY sealed_at ASC, rowid ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SealedReceipt
	for rows.Next() {
		var r model.Receipt
		var body, sealed, status sql.NullString
		if err := rows.Scan(&r.RunID, &body, &r.BodyHash, &r.PrevHash, &r.Signature,
			&r.KeyID, &sealed, &status); err != nil {
			return nil, err
		}
		t, err := parseTS(sealed)
		if err != nil {
			return nil, err
		}
		r.SealedAt = t
		r.Status = model.RunStatus(status.String)
		out = append(out, SealedReceipt{Receipt: &r, Body: body.String})
	}
	return out, rows.Err()
}

// InsertKill appends a kill audit record. Reason is required by the caller.
func (s *Store) InsertKill(k *model.KillRecord) error {
	res, err := s.db.Exec(`INSERT INTO kill_audit(at,actor,scope,target,reason,result,details)
		VALUES(?,?,?,?,?,?,?)`, ts(k.At), k.Actor, string(k.Scope), k.Target, k.Reason, k.Result, k.Details)
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	k.ID = id
	return nil
}

// ListKills returns kill audit records newest-first.
func (s *Store) ListKills(limit int) ([]*model.KillRecord, error) {
	q := `SELECT id,at,actor,scope,target,reason,result,details FROM kill_audit ORDER BY id DESC`
	var args []any
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.KillRecord
	for rows.Next() {
		var k model.KillRecord
		var at sql.NullString
		var scope string
		if err := rows.Scan(&k.ID, &at, &k.Actor, &scope, &k.Target, &k.Reason, &k.Result, &k.Details); err != nil {
			return nil, err
		}
		t, err := parseTS(at)
		if err != nil {
			return nil, err
		}
		k.At = t
		k.Scope = model.KillScope(scope)
		out = append(out, &k)
	}
	return out, rows.Err()
}

// RequestApproval records a pending human approval gate.
func (s *Store) RequestApproval(runID, gate string, at time.Time) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO approvals(run_id,gate,requested_at,status) VALUES(?,?,?,'pending')`,
		runID, gate, ts(at))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// DecideApproval records a human decision on a pending approval.
func (s *Store) DecideApproval(id int64, decision, approver, reason string, at time.Time) error {
	res, err := s.db.Exec(`UPDATE approvals SET status='decided',decision=?,approver=?,decided_at=?,reason=?
		WHERE id=? AND status='pending'`, decision, approver, ts(at), reason, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ApprovalDecision returns the recorded decision for an approval id.
func (s *Store) ApprovalDecision(id int64) (decision, approver, reason string, err error) {
	err = s.db.QueryRow(`SELECT decision,approver,reason FROM approvals WHERE id=?`, id).
		Scan(&decision, &approver, &reason)
	return
}

// PendingApprovals lists undecided approval requests.
func (s *Store) PendingApprovals() ([]Approval, error) {
	rows, err := s.db.Query(`SELECT id,run_id,gate,requested_at FROM approvals WHERE status='pending' ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Approval
	for rows.Next() {
		var a Approval
		var req sql.NullString
		if err := rows.Scan(&a.ID, &a.RunID, &a.Gate, &req); err != nil {
			return nil, err
		}
		t, err := parseTS(req)
		if err != nil {
			return nil, err
		}
		a.RequestedAt = t
		out = append(out, a)
	}
	return out, rows.Err()
}

// Approval is a pending (or decided) human approval request.
type Approval struct {
	ID          int64
	RunID       string
	Gate        string
	RequestedAt time.Time
}

// kill_state keys
const (
	keyAgentQuarantine = "quarantine:agent:"
	keyFleetFreeze     = "freeze:fleet:"
	keyToolDeny        = "deny:tool:"
)

func (s *Store) setKillState(key, value string, expires *time.Time) error {
	var exp any
	if expires != nil {
		exp = ts(*expires)
	}
	_, err := s.db.Exec(`INSERT OR REPLACE INTO kill_state(key,value,expires_at) VALUES(?,?,?)`, key, value, exp)
	return err
}

func (s *Store) getKillState(key string) (string, *time.Time, bool, error) {
	var value string
	var exp sql.NullString
	err := s.db.QueryRow(`SELECT value,expires_at FROM kill_state WHERE key=?`, key).Scan(&value, &exp)
	if err == sql.ErrNoRows {
		return "", nil, false, nil
	}
	if err != nil {
		return "", nil, false, err
	}
	var t *time.Time
	if exp.Valid {
		tt, err := parseTS(exp)
		if err != nil {
			return "", nil, false, err
		}
		t = &tt
	}
	return value, t, true, nil
}

// QuarantineAgent refuses new runs for agentID until the TTL expires (or it is cleared).
func (s *Store) QuarantineAgent(agentID string, until time.Time, reason string) error {
	return s.setKillState(keyAgentQuarantine+agentID, reason, &until)
}

// ClearAgentQuarantine lifts a quarantine early.
func (s *Store) ClearAgentQuarantine(agentID string) error {
	_, err := s.db.Exec(`DELETE FROM kill_state WHERE key=?`, keyAgentQuarantine+agentID)
	return err
}

// IsAgentQuarantined reports whether agentID is currently quarantined.
func (s *Store) IsAgentQuarantined(agentID string) (bool, string, error) {
	reason, exp, ok, err := s.getKillState(keyAgentQuarantine + agentID)
	if err != nil || !ok {
		return false, "", err
	}
	if exp != nil && time.Now().After(*exp) {
		_ = s.ClearAgentQuarantine(agentID)
		return false, "", nil
	}
	return true, reason, nil
}

// FreezeFleet blocks new runs for a fleet and records the soft-stop deadline.
// A zero until means "until manually unfrozen" (no expiry).
func (s *Store) FreezeFleet(fleetID string, until, hardDeadline time.Time, reason string) error {
	var exp *time.Time
	if !until.IsZero() {
		exp = &until
	}
	return s.setKillState(keyFleetFreeze+fleetID, reason+"|"+ts(hardDeadline), exp)
}

// FleetFreezeState returns the freeze reason and hard-stop deadline, if frozen.
func (s *Store) FleetFreezeState(fleetID string) (frozen bool, reason string, hardDeadline time.Time, err error) {
	v, exp, ok, err := s.getKillState(keyFleetFreeze + fleetID)
	if err != nil || !ok {
		return false, "", time.Time{}, err
	}
	if exp != nil && time.Now().After(*exp) {
		_, _ = s.db.Exec(`DELETE FROM kill_state WHERE key=?`, keyFleetFreeze+fleetID)
		return false, "", time.Time{}, nil
	}
	parts := splitOnce(v, "|")
	reason = parts[0]
	if len(parts) > 1 {
		if t, perr := parseTS(sql.NullString{String: parts[1], Valid: true}); perr == nil {
			hardDeadline = t
		}
	}
	return true, reason, hardDeadline, nil
}

// UnfreezeFleet lifts a fleet freeze.
func (s *Store) UnfreezeFleet(fleetID string) error {
	_, err := s.db.Exec(`DELETE FROM kill_state WHERE key=?`, keyFleetFreeze+fleetID)
	return err
}

// toolDenyKey builds the kill_state key for a tool deny entry. Tool names
// are case-insensitive everywhere in the policy engine (the static
// deny_tools/approval_tools sets are lowercased at parse time), so the
// dynamic deny-list lowercases too — otherwise `kill --scope tool --target
// Bash` would not stop a span reporting tool `bash`.
func toolDenyKey(tool, fleet string) string {
	tool = strings.ToLower(strings.TrimSpace(tool))
	key := keyToolDeny + tool
	if fleet != "" {
		key += ":" + fleet
	}
	return key
}

// DenyTool pushes a tool onto the deny-list (optionally scoped to a fleet).
// In-flight tool.call spans are allowed to complete — the deny applies to new calls.
func (s *Store) DenyTool(tool, fleet, reason string) error {
	return s.setKillState(toolDenyKey(tool, fleet), reason, nil)
}

// AllowTool removes a tool from the deny-list.
func (s *Store) AllowTool(tool, fleet string) error {
	_, err := s.db.Exec(`DELETE FROM kill_state WHERE key=?`, toolDenyKey(tool, fleet))
	return err
}

// IsToolDenied reports whether tool is denied (globally or for the fleet).
func (s *Store) IsToolDenied(tool, fleet string) (bool, string, error) {
	if fleet != "" {
		if reason, _, ok, err := s.getKillState(toolDenyKey(tool, fleet)); err != nil {
			return false, "", err
		} else if ok {
			return true, reason, nil
		}
	}
	reason, _, ok, err := s.getKillState(toolDenyKey(tool, ""))
	if err != nil {
		return false, "", err
	}
	return ok, reason, nil
}

// ListToolDenies returns all tool deny-list entries.
func (s *Store) ListToolDenies() ([]ToolDeny, error) {
	rows, err := s.db.Query(`SELECT key,value FROM kill_state WHERE key LIKE 'deny:tool:%'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ToolDeny
	for rows.Next() {
		var key, reason string
		if err := rows.Scan(&key, &reason); err != nil {
			return nil, err
		}
		rest := key[len(keyToolDeny):]
		td := ToolDeny{Reason: reason}
		if i := indexOf(rest, ":"); i >= 0 {
			td.Tool = rest[:i]
			td.Fleet = rest[i+1:]
		} else {
			td.Tool = rest
		}
		out = append(out, td)
	}
	return out, rows.Err()
}

// ToolDeny is one deny-list entry.
type ToolDeny struct {
	Tool   string
	Fleet  string
	Reason string
}

func splitOnce(s, sep string) []string {
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			return []string{s[:i], s[i+len(sep):]}
		}
	}
	return []string{s}
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
