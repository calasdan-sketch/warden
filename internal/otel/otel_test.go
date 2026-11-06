package otel

import (
	"testing"
	"time"

	"github.com/calasdan-sketch/warden/internal/model"
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
	// "run1…" is not hex: it must map to a valid, stable 32-hex trace id
	// (OTLP receivers reject non-hex ids).
	if s0["traceId"] != TraceID("run1run1run1run1run1run1run1run1") || !isHex(s0["traceId"].(string), 32) {
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

func attrMap(sp map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, a := range sp["attributes"].([]any) {
		am := a.(map[string]any)
		out[am["key"].(string)] = am["value"].(map[string]any)
	}
	return out
}

func TestGenAISemconvMapping(t *testing.T) {
	ts := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	runID := "0123456789abcdef0123456789abcdef"
	reason := "stop"
	run := &model.Run{RunID: runID, AgentID: "claude-code", FleetID: "laptop", Status: model.RunKilledOperator,
		StartedAt: ts, KillReason: &reason}
	sps := []*model.Span{
		{SpanID: "aaaa0000bbbb1111cccc2222dddd3333", RunID: runID, Kind: model.SpanLLMCall, Model: "claude-sonnet-4-5",
			TokensIn: 1200, TokensOut: 400, TokensCached: 800, CostUSD: 0.012, StartedAt: ts},
		{SpanID: "unattached-ish-id", RunID: runID, Kind: model.SpanToolCall, Tool: "Bash",
			ArgsSummary: "rm -rf /", Status: "denied", PolicyDecision: "deny", PolicyReason: "deny pattern", StartedAt: ts},
	}
	out := ToOTLPRuns([]RunTrace{{Run: run, Spans: sps}})
	rs := out["resourceSpans"].([]any)[0].(map[string]any)
	ss := rs["scopeSpans"].([]any)[0].(map[string]any)
	if ss["scope"].(map[string]any)["name"] != "warden" {
		t.Error("instrumentation scope missing")
	}
	got := ss["spans"].([]any)
	if len(got) != 3 {
		t.Fatalf("want root + 2 spans, got %d", len(got))
	}
	root := got[0].(map[string]any)
	if root["name"] != "invoke_agent claude-code" || root["parentSpanId"] != nil {
		t.Errorf("root span wrong: %v", root["name"])
	}
	if root["status"].(map[string]any)["code"] != 2 {
		t.Error("killed run should be ERROR")
	}
	llm := got[1].(map[string]any)
	if llm["name"] != "chat claude-sonnet-4-5" || llm["kind"] != kindClient || llm["parentSpanId"] != root["spanId"] {
		t.Errorf("llm span wrong: %v kind=%v parent=%v", llm["name"], llm["kind"], llm["parentSpanId"])
	}
	a := attrMap(llm)
	if a["gen_ai.operation.name"]["stringValue"] != "chat" || a["gen_ai.provider.name"]["stringValue"] != "anthropic" {
		t.Errorf("llm attrs: %v", a)
	}
	if a["gen_ai.usage.input_tokens"]["intValue"] != "1200" || a["gen_ai.usage.cache_read.input_tokens"]["intValue"] != "800" {
		t.Errorf("token usage must be integer-typed: %v", a["gen_ai.usage.input_tokens"])
	}
	tool := got[2].(map[string]any)
	ta := attrMap(tool)
	if tool["name"] != "execute_tool Bash" || ta["gen_ai.tool.name"]["stringValue"] != "Bash" || ta["error.type"]["stringValue"] != "policy_denied" {
		t.Errorf("tool span: %v %v", tool["name"], ta)
	}
	if !isHex(tool["spanId"].(string), 16) {
		t.Errorf("non-hex warden span id must be hashed to a valid span id: %v", tool["spanId"])
	}
}

func TestInferProvider(t *testing.T) {
	for m, want := range map[string]string{
		"claude-opus-4-1": "anthropic", "gpt-5": "openai", "o3-mini": "openai",
		"gemini-2.5-pro": "gcp.gemini", "llama3": "",
	} {
		if got := InferProvider(m); got != want {
			t.Errorf("InferProvider(%q) = %q, want %q", m, got, want)
		}
	}
}
