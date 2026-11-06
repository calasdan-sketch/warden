package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/calasdan-sketch/warden/internal/model"
	"github.com/calasdan-sketch/warden/internal/policy"
	"github.com/calasdan-sketch/warden/internal/redact"
)

// maxSessionSegments bounds how many continuation runs one harness session
// may chain (each Stop/idle-seal starts a new one).
const maxSessionSegments = 10000

// SessionRunID is the deterministic run id of segment n of a harness
// session: hooks are short-lived processes, so the run must be derivable
// from what the harness sends (its session id) without shared state.
func SessionRunID(harness, sessionID string, n int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("warden-session-v1\x00%s\x00%s\x00%d", harness, sessionID, n)))
	return hex.EncodeToString(sum[:16])
}

// SessionState is the outcome of resolving a harness session to a run.
type SessionState struct {
	Run *model.Run
	// Blocked is set when no tool call may proceed: the session's run was
	// killed by an operator/guard, the agent is quarantined, or the fleet is
	// frozen. BlockReason says which, for the harness to show the user.
	Blocked     bool
	BlockReason string
}

// EnsureSessionRun returns the live run for a harness session, creating it
// (or a continuation segment linked by parent_run_id) as needed.
//
// Kill semantics: once any segment of a session is killed, the session
// stays blocked — the kill switch outlives the run it killed.
func (c *Collector) EnsureSessionRun(harness, sessionID string, opts RunOptions) (*SessionState, error) {
	if sessionID == "" {
		sessionID = "no-session-id"
	}
	if q, reason, err := c.store.IsAgentQuarantined(opts.AgentID); err != nil {
		return nil, err
	} else if q {
		return &SessionState{Blocked: true, BlockReason: fmt.Sprintf("agent %q is quarantined by warden: %s", opts.AgentID, reason)}, nil
	}
	if frozen, reason, _, err := c.store.FleetFreezeState(opts.FleetID); err != nil {
		return nil, err
	} else if frozen {
		return &SessionState{Blocked: true, BlockReason: fmt.Sprintf("fleet %q is frozen by warden: %s", opts.FleetID, reason)}, nil
	}
	// Segments are created strictly in order (0, 1, 2, …) and only after the
	// previous one is sealed, so "segment n exists" is monotonic in n: find
	// the first missing index with an exponential + binary search (O(log n)
	// lookups per hook call, even for a session with thousands of turns).
	exists := func(n int) bool {
		_, err := c.store.GetRun(SessionRunID(harness, sessionID, n))
		return err == nil
	}
	lo, hi := -1, 0 // invariant: exists(lo) (or lo == -1), hi is a probe
	for hi < maxSessionSegments && exists(hi) {
		lo, hi = hi, hi*2+1
	}
	if hi > maxSessionSegments {
		hi = maxSessionSegments
	}
	for hi-lo > 1 { // first missing index is in (lo, hi]
		mid := lo + (hi-lo)/2
		if exists(mid) {
			lo = mid
		} else {
			hi = mid
		}
	}
	for attempt := 0; attempt < 3; attempt++ {
		var parent *string
		if lo >= 0 {
			last, err := c.store.GetRun(SessionRunID(harness, sessionID, lo))
			if err != nil {
				return nil, err
			}
			switch last.Status {
			case model.RunRunning, model.RunAwaitingApproval:
				_ = c.store.TouchHeartbeat(last.RunID)
				return &SessionState{Run: last}, nil
			case model.RunKilledOperator, model.RunKilledGuard:
				reason := "killed"
				if last.KillReason != nil && *last.KillReason != "" {
					reason = *last.KillReason
				}
				by := ""
				if last.KilledBy != nil && *last.KilledBy != "" {
					by = " by " + *last.KilledBy
				}
				return &SessionState{Run: last, Blocked: true,
					BlockReason: fmt.Sprintf("this session was killed%s via warden (run %s): %s", by, last.RunID, reason)}, nil
			}
			// Sealed normally (Stop/SessionEnd, or idle-reconciled): continue
			// in a new segment linked to it.
			pid := last.RunID
			parent = &pid
		}
		n := lo + 1
		if n >= maxSessionSegments {
			return nil, fmt.Errorf("session %q exceeded %d run segments", sessionID, maxSessionSegments)
		}
		cmd, _ := redact.RedactString(opts.Command)
		nr := &model.Run{
			RunID: SessionRunID(harness, sessionID, n), AgentID: opts.AgentID, FleetID: opts.FleetID,
			Operator: opts.Operator, Model: opts.Model, Provider: opts.Provider, Command: truncate(cmd, 500),
			StartedAt: time.Now().UTC(), Status: model.RunRunning, ParentRunID: parent,
		}
		if err := c.store.CreateRun(nr); err == nil {
			_ = c.store.TouchHeartbeat(nr.RunID)
			return &SessionState{Run: nr}, nil
		}
		// A concurrent hook created segment n first: re-evaluate from it.
		lo = n
	}
	return nil, fmt.Errorf("session %q: could not resolve a run (contention)", sessionID)
}

// RecordDecision stores a span whose policy decision was already made by
// the caller (a harness hook evaluated it before the tool ran). Unlike
// EmitSpan it never re-evaluates, and when the decision is deferred to the
// harness's own permission prompt (deferred=true) it does not open a warden
// approval request that nobody would answer.
func (c *Collector) RecordDecision(sp *model.Span, res policy.Result, deferredTo string) error {
	if !sp.Kind.Valid() {
		return fmt.Errorf("invalid span kind %q", sp.Kind)
	}
	if sp.SpanID == "" {
		sp.SpanID = newID()
	}
	if sp.StartedAt.IsZero() {
		sp.StartedAt = time.Now().UTC()
	}
	redactSpan(sp)
	sp.PolicyDecision = res.Decision.String()
	sp.PolicyReason, _ = redact.RedactString(res.Reason)
	sp.PolicyVersion = res.Version
	switch res.Decision {
	case policy.Deny:
		sp.Status = "denied"
	case policy.RequireApproval:
		sp.Status = "awaiting_approval"
	}
	if deferredTo != "" {
		sp.PolicyReason = strings.TrimSpace(sp.PolicyReason + " [deferred to " + deferredTo + " permission prompt]")
	}
	if err := c.store.InsertSpan(sp); err != nil {
		return err
	}
	c.bumpCounters(sp)
	if res.Decision == policy.Allow {
		return nil
	}
	kind := "policy_deny"
	if res.Decision == policy.RequireApproval || deferredTo != "" {
		kind = "policy_approval_required"
	}
	return c.store.InsertEvent(&model.Event{
		RunID: sp.RunID, SpanID: sp.SpanID, At: time.Now().UTC(),
		Severity: "warning", Kind: kind,
		Message: fmt.Sprintf("policy %s: %s %s — %s", res.Decision, sp.Kind, sp.Name, sp.PolicyReason),
	})
}

// Evaluate runs the policy gate on a span (after redaction) without
// recording anything.
func (c *Collector) Evaluate(sp *model.Span) policy.Result {
	redactSpan(sp)
	res := c.eval.Evaluate(sp)
	res.Version = c.eval.Version()
	return res
}
