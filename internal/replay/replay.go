// Package replay turns a recorded run into something an incident responder
// can step through: an ordered timeline, the state of the world at any step,
// and a counterfactual ("what if this policy had been in force?").
//
// It only reads. Everything it prints from the trail is untrusted text (an
// agent produced it), so every string passes through redact.Sanitize and is
// escaped for its output format.
package replay

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/calasdan-sketch/warden/internal/model"
	"github.com/calasdan-sketch/warden/internal/policy"
	"github.com/calasdan-sketch/warden/internal/redact"
)

// Integrity says how far the recorded trail can be trusted.
type Integrity struct {
	Status  string   `json:"status"` // verified, tampered, unsealed, legacy
	Detail  string   `json:"detail"`
	Covered int64    `json:"covered_spans"`
	Late    int      `json:"late_spans"`
	Problem []string `json:"problems,omitempty"`
}

// Step is one span with its place in the run and the running state.
type Step struct {
	N        int           `json:"n"`
	OffsetMs int64         `json:"offset_ms"`
	Span     *model.Span   `json:"span"`
	What     string        `json:"what"`
	Verdict  string        `json:"verdict"` // allow, deny, ask, ok, error
	WhatIf   *WhatIfResult `json:"what_if,omitempty"`
	State    State         `json:"state"`
}

// State is the cumulative picture after a step.
type State struct {
	ToolCalls int64   `json:"tool_calls"`
	Denied    int64   `json:"denied"`
	Asked     int64   `json:"asked"`
	TokensIn  int64   `json:"tokens_in"`
	TokensOut int64   `json:"tokens_out"`
	CostUSD   float64 `json:"cost_usd"`
	// Distinct counts are always present. The lists (first 50, sorted) are
	// kept on every step of a run up to ListStepsMax steps; on longer runs
	// they are kept on the last step only, because per-step copies of the
	// sets would make the output grow with the square of the run. Use
	// Session.StateAt(n) to get them for any step.
	FilesN int      `json:"files_count"`
	HostsN int      `json:"hosts_count"`
	ToolsN int      `json:"tools_count"`
	Files  []string `json:"files_touched,omitempty"`
	Hosts  []string `json:"hosts_contacted,omitempty"`
	Tools  []string `json:"tools_used,omitempty"`
}

// ListStepsMax is the longest run whose every step carries the touched
// files, hosts and tools lists.
const ListStepsMax = 2000

// topSet is a set that remembers its 50 smallest cleaned members, so the
// state after each step costs O(50) instead of re-sorting the whole set.
type topSet struct {
	seen map[string]bool
	top  []string
}

const topN = 50

func (t *topSet) add(raw string) {
	if t.seen == nil {
		t.seen = map[string]bool{}
	}
	if t.seen[raw] {
		return
	}
	t.seen[raw] = true
	c := Clean(raw, 120)
	if len(t.top) >= topN && c >= t.top[len(t.top)-1] {
		return
	}
	i := sort.SearchStrings(t.top, c)
	t.top = append(t.top, "")
	copy(t.top[i+1:], t.top[i:])
	t.top[i] = c
	if len(t.top) > topN {
		t.top = t.top[:topN]
	}
}

func (t *topSet) n() int { return len(t.seen) }

// list returns a copy of the first 50 members plus a "+N more" marker.
func (t *topSet) list() []string {
	out := append([]string(nil), t.top...)
	if n := len(t.seen); n > len(t.top) {
		out = append(out, fmt.Sprintf("… +%d more", n-len(t.top)))
	}
	return out
}

// WhatIfResult is the candidate policy's verdict on a recorded call.
type WhatIfResult struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
	Changed  bool   `json:"changed"`
	Skipped  string `json:"skipped,omitempty"`
}

// Session is a whole replayable run.
type Session struct {
	Run       *model.Run `json:"run"`
	Integrity Integrity  `json:"integrity"`
	Steps     []*Step    `json:"steps"`
	WhatIf    *Summary   `json:"what_if,omitempty"`
}

// StateAt returns the full state (with the files, hosts and tools lists)
// after step n (1-based), whatever the run length.
func (s *Session) StateAt(n int) State {
	if n < 1 || n > len(s.Steps) {
		return State{}
	}
	st := s.Steps[n-1].State
	if st.Files != nil || (st.FilesN+st.HostsN+st.ToolsN == 0) {
		return st
	}
	var files, hosts, tools topSet
	for _, step := range s.Steps[:n] {
		sp := step.Span
		switch sp.Kind {
		case model.SpanToolCall:
			if sp.Tool != "" {
				tools.add(sp.Tool)
			}
		case model.SpanFileOp:
			if sp.Path != "" {
				files.add(sp.Path)
			}
		case model.SpanNetEgress:
			if sp.Host != "" {
				hosts.add(sp.Host)
			}
		}
	}
	st.Files, st.Hosts, st.Tools = files.list(), hosts.list(), tools.list()
	return st
}

// Summary totals a counterfactual.
type Summary struct {
	Policy         string `json:"policy"`
	Evaluated      int    `json:"evaluated"`
	NewlyBlocked   int    `json:"newly_blocked"`
	NewlyAllowed   int    `json:"newly_allowed"`
	Unchanged      int    `json:"unchanged"`
	SkippedNonPure int    `json:"skipped"`
}

// Clean makes untrusted text safe to print anywhere: no terminal escapes, no
// bidi or zero-width tricks, bounded length.
func Clean(s string, max int) string {
	s = redact.Sanitize(s)
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r", " "), "\n", " ⏎ ")
	if max > 0 && len([]rune(s)) > max {
		r := []rune(s)
		s = string(r[:max]) + "…"
	}
	return s
}

func describe(sp *model.Span) string {
	switch sp.Kind {
	case model.SpanToolCall:
		t := sp.Tool
		if sp.ToolServer != "" {
			t = sp.ToolServer + "/" + t
		}
		if sp.ArgsSummary != "" {
			return t + ": " + sp.ArgsSummary
		}
		if sp.Name != "" {
			return t + " (" + sp.Name + ")"
		}
		return t
	case model.SpanFileOp:
		return fmt.Sprintf("%s %s", orDash(sp.Op), sp.Path)
	case model.SpanNetEgress:
		return fmt.Sprintf("egress %s:%d", sp.Host, sp.Port)
	case model.SpanLLMCall:
		return fmt.Sprintf("%s in=%d out=%d $%.4f", orDash(sp.Model), sp.TokensIn, sp.TokensOut, sp.CostUSD)
	case model.SpanSubagentSpawn:
		return "spawn " + sp.ChildRunID + " " + sp.SpawnReason
	case model.SpanHumanApproval:
		return fmt.Sprintf("approval %s by %s: %s", orDash(sp.Gate), orDash(sp.Approver), orDash(sp.Decision))
	}
	return sp.Name
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func verdict(sp *model.Span) string {
	switch sp.PolicyDecision {
	case "deny":
		return "deny"
	case "require_approval":
		return "ask"
	}
	if sp.Status == "denied" {
		return "deny"
	}
	if sp.Status == "awaiting_approval" {
		return "ask"
	}
	if sp.Status == "error" {
		return "error"
	}
	if sp.PolicyDecision == "allow" {
		return "allow"
	}
	return "ok"
}

// Build orders spans, computes the running state and attaches integrity.
func Build(run *model.Run, spans []*model.Span, in Integrity) *Session {
	sorted := append([]*model.Span(nil), spans...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].StartedAt.Before(sorted[j].StartedAt) })
	start := run.StartedAt
	if len(sorted) > 0 && sorted[0].StartedAt.Before(start) {
		start = sorted[0].StartedAt
	}
	rc := *run
	for _, f := range []*string{&rc.RunID, &rc.AgentID, &rc.FleetID, &rc.Operator, &rc.Model, &rc.Provider, &rc.Command} {
		*f = redact.Sanitize(*f)
	}
	run = &rc
	in.Detail = redact.Sanitize(in.Detail)
	s := &Session{Run: run, Integrity: in}
	var st State
	var files, hosts, tools topSet
	for i, sp := range sorted {
		c := *sp
		for _, f := range []*string{&c.Name, &c.AgentID, &c.FleetID, &c.Model, &c.Tool, &c.ToolServer, &c.ArgsSummary, &c.ToolCallID,
			&c.Path, &c.Op, &c.Host, &c.ChildRunID, &c.SpawnReason, &c.Gate, &c.Decision, &c.Approver,
			&c.PolicyDecision, &c.PolicyReason, &c.PolicyVersion, &c.Status} {
			*f = redact.Sanitize(*f)
		}
		sp = &c
		v := verdict(sp)
		switch sp.Kind {
		case model.SpanToolCall:
			st.ToolCalls++
			if sp.Tool != "" {
				tools.add(sp.Tool)
			}
		case model.SpanFileOp:
			if sp.Path != "" {
				files.add(sp.Path)
			}
		case model.SpanNetEgress:
			if sp.Host != "" {
				hosts.add(sp.Host)
			}
		case model.SpanLLMCall:
			st.TokensIn += sp.TokensIn
			st.TokensOut += sp.TokensOut
			st.CostUSD += sp.CostUSD
		}
		if v == "deny" {
			st.Denied++
		}
		if v == "ask" {
			st.Asked++
		}
		cur := st
		cur.FilesN, cur.HostsN, cur.ToolsN = files.n(), hosts.n(), tools.n()
		if len(sorted) <= ListStepsMax || i == len(sorted)-1 {
			cur.Files, cur.Hosts, cur.Tools = files.list(), hosts.list(), tools.list()
		}
		s.Steps = append(s.Steps, &Step{
			N: i + 1, OffsetMs: sp.StartedAt.Sub(start).Milliseconds(), Span: sp,
			What: Clean(describe(sp), 200), Verdict: v, State: cur,
		})
	}
	return s
}

// notPure reports recorded decisions that came from live operator state, not
// from the policy file, so a policy re-run cannot reproduce them.
func notPure(sp *model.Span) string {
	r := strings.ToLower(sp.PolicyReason)
	for _, w := range []string{"killed", "quarantin", "frozen", "freeze", "disabled by operator", "operator"} {
		if strings.Contains(r, w) {
			return "decided by operator state (kill/quarantine/freeze), not by policy"
		}
	}
	return ""
}

func decisionName(d policy.Decision) string {
	switch d {
	case policy.Deny:
		return "deny"
	case policy.RequireApproval:
		return "ask"
	}
	return "allow"
}

// ApplyWhatIf re-judges every gated span under a candidate policy and records
// where the answer differs from what happened. name labels the policy.
func (s *Session) ApplyWhatIf(ev *policy.Evaluator, name string) {
	sum := &Summary{Policy: Clean(name, 80)}
	for _, stp := range s.Steps {
		sp := stp.Span
		if sp.Kind != model.SpanToolCall && sp.Kind != model.SpanNetEgress && sp.Kind != model.SpanFileOp {
			continue
		}
		if why := notPure(sp); why != "" {
			stp.WhatIf = &WhatIfResult{Skipped: why}
			sum.SkippedNonPure++
			continue
		}
		cp := *sp
		res := ev.Evaluate(&cp)
		was := "allow"
		switch stp.Verdict {
		case "deny":
			was = "deny"
		case "ask":
			was = "ask"
		}
		now := decisionName(res.Decision)
		w := &WhatIfResult{Decision: now, Reason: Clean(res.Reason, 200), Changed: now != was}
		stp.WhatIf = w
		sum.Evaluated++
		switch {
		case !w.Changed:
			sum.Unchanged++
		case was == "allow" && now != "allow":
			sum.NewlyBlocked++
		case was != "allow" && now == "allow":
			sum.NewlyAllowed++
		default:
			sum.Unchanged++ // deny <-> ask: stricter/looser but still gated
		}
	}
	s.WhatIf = sum
}

// Duration of the run for display.
func (s *Session) Duration() time.Duration {
	if s.Run.EndedAt != nil {
		return s.Run.EndedAt.Sub(s.Run.StartedAt)
	}
	if n := len(s.Steps); n > 0 {
		return time.Duration(s.Steps[n-1].OffsetMs) * time.Millisecond
	}
	return 0
}
