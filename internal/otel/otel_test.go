package otel

import (
	"testing"
	"time"

	"warden/internal/model"
)

func spans() []*model.Span {
	t := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	return []*model.Span{
		{SpanID: "aaaa0000bbbb1111cccc2222dddd3333", RunID: "run1run1run1run1run1run1run1run1", Kind: model.SpanLLMCall, AgentID: "a1", FleetID: "f1", Model: "m", TokensIn: 10, TokensOut: 5, StartedAt: t},
		{SpanID: "eeee0000ffff11112222333344445555", RunID: "run1run1run1run1run1run1run1run1", Kind: model.SpanToolCall, AgentID: "a1", FleetID: "f1", Tool: "bash", PolicyDecision: "deny", StartedAt: t},
	}
}

func TestToOTLPGroupsByRun(t *testing.T) {
	out := ToOTLP(spans())
	rss := out["resourceSpans"].([]any)
	if len(rss) != 1 {
		t.Fatalf("want 1 resourceSpans entry, got %d", len(rss))
	}
	rs := rss[0].(map[string]any)
	spans0 := rs["scopeSpans"].([]any)[0].(map[string]any)["spans"].([]any)
	if len(spans0) != 2 {
		t.Fatalf("want 2 spans, got %d", len(spans0))
	}
	s0 := spans0[0].(map[string]any)
	if s0["traceId"] != "run1run1run1run1run1run1run1run1" {
		t.Errorf("traceId = %v", s0["traceId"])
	}
	if s0["spanId"] != "aaaa0000bbbb1111" {
		t.Errorf("spanId = %v (want 16 hex chars)", s0["spanId"])
	}
	found := false
	for _, a := range s0["attributes"].([]any) {
		am := a.(map[string]any)
		if am["key"] == "gen_ai.usage.input_tokens" {
			found = true
		}
	}
	if !found {
		t.Error("llm span missing gen_ai.usage.input_tokens")
	}
	s1 := spans0[1].(map[string]any)
	st := s1["status"].(map[string]any)
	if st["code"] != 1 { // policy deny maps to OK with attribute; only errors map to 2
		t.Errorf("status code = %v", st["code"])
	}
}

func TestToOTLPEmpty(t *testing.T) {
	out := ToOTLP(nil)
	if len(out["resourceSpans"].([]any)) != 0 {
		t.Error("empty spans should yield empty resourceSpans")
	}
}
