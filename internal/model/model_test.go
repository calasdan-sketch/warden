package model

import (
	"testing"
	"time"
)

func TestSpanKindValid(t *testing.T) {
	valid := []SpanKind{SpanLLMCall, SpanToolCall, SpanFileOp, SpanNetEgress, SpanSubagentSpawn, SpanHumanApproval}
	for _, k := range valid {
		if !k.Valid() {
			t.Errorf("span kind %q should be valid", k)
		}
	}
	for _, k := range []SpanKind{"", "http.request", "log.line", "custom"} {
		if k.Valid() {
			t.Errorf("span kind %q should NOT be valid", k)
		}
	}
}

func TestSpanKindWireValues(t *testing.T) {
	// The six kinds are stable API — they appear in JSONL, the DB, and the
	// --report-to contract. Changing them breaks joins.
	cases := map[SpanKind]string{
		SpanLLMCall:       "llm.call",
		SpanToolCall:      "tool.call",
		SpanFileOp:        "file.op",
		SpanNetEgress:     "net.egress",
		SpanSubagentSpawn: "subagent.spawn",
		SpanHumanApproval: "human.approval",
	}
	for kind, want := range cases {
		if string(kind) != want {
			t.Errorf("span kind wire value = %q, want %q", string(kind), want)
		}
	}
}

func TestKillScopeValid(t *testing.T) {
	for _, s := range []KillScope{KillScopeRun, KillScopeAgent, KillScopeFleet, KillScopeTool} {
		if !s.Valid() {
			t.Errorf("kill scope %q should be valid", s)
		}
	}
	for _, s := range []KillScope{"", "org", "all", "host"} {
		if s.Valid() {
			t.Errorf("kill scope %q should NOT be valid", s)
		}
	}
}

func TestRunNetCost(t *testing.T) {
	r := Run{CostUSD: 4.17, CostSavedUSD: 1.02}
	if got := r.NetCost(); got < 3.14 || got > 3.16 {
		t.Errorf("NetCost() = %v, want ~3.15", got)
	}
}

func TestRunStatusWireValues(t *testing.T) {
	cases := map[RunStatus]string{
		RunRunning:          "running",
		RunCompleted:        "completed",
		RunFailed:           "failed",
		RunKilledOperator:   "killed_operator",
		RunKilledGuard:      "killed_guard",
		RunTimedOut:         "timed_out",
		RunAwaitingApproval: "awaiting_approval",
	}
	for st, want := range cases {
		if string(st) != want {
			t.Errorf("run status wire value = %q, want %q", string(st), want)
		}
	}
}

func TestSpanZeroValueSane(t *testing.T) {
	s := Span{SpanID: "s1", RunID: "r1", Kind: SpanToolCall, StartedAt: time.Now()}
	if s.Redacted {
		t.Error("zero span must not be marked redacted")
	}
	if s.PolicyDecision != "" {
		t.Error("zero span must have no policy decision")
	}
}
