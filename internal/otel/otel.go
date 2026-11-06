// Package otel maps warden runs and spans to OTLP/HTTP JSON so existing
// Datadog/Honeycomb/Grafana/Jaeger/Langfuse/Phoenix investments can ingest
// warden telemetry.
//
// Warden stays bilingual: its first-class concept is the run envelope (which
// OTel doesn't model); this export is the bridge, not the product.
//
// Mapping (OpenTelemetry GenAI semantic conventions, which are still at
// "Development" stability upstream — attribute names may change there):
//
//   - One trace per run. trace_id = run_id when it is 32 lowercase hex chars,
//     otherwise the first 32 hex chars of sha256(run_id) (always valid).
//   - With run context (ToOTLPRuns), every run gets a root span
//     "invoke_agent {agent}" (gen_ai.operation.name=invoke_agent) and the
//     run's spans are its children.
//   - llm.call  -> "chat {model}", SPAN_KIND_CLIENT, gen_ai.operation.name=chat,
//     gen_ai.provider.name (inferred from the model when not recorded),
//     gen_ai.request.model, gen_ai.usage.input_tokens / output_tokens /
//     cache_read.input_tokens (integers).
//   - tool.call -> "execute_tool {tool}", gen_ai.operation.name=execute_tool,
//     gen_ai.tool.name.
//   - file.op, net.egress, subagent.spawn, human.approval keep warden.*
//     attributes (net.egress also sets server.address/server.port).
//   - Policy decisions and redaction flags are attributes, so the OTel side
//     sees exactly what the dashboard sees (redacted form only). Denied or
//     errored spans get status ERROR and error.type.
package otel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/calasdan-sketch/warden/internal/model"
)

// ScopeName / ScopeVersion identify warden as the instrumentation scope.
const ScopeName = "warden"

// ScopeVersion is set by the CLI at startup (build version).
var ScopeVersion = "dev"

// OTLP span kinds.
const (
	kindInternal = 1
	kindClient   = 3
)

// RunTrace is one run with its spans (the unit of OTLP export).
type RunTrace struct {
	Run   *model.Run
	Spans []*model.Span
}

// EncodeStream writes a single OTLP/HTTP JSON envelope to w, pulling span
// pages from next until it returns nil. Memory stays bounded by one page.
// Spans without run context get no synthetic root span; prefer
// EncodeRunsStream.
func EncodeStream(w io.Writer, next func() ([]*model.Span, error)) error {
	return encodeStream(w, func() ([]any, bool, error) {
		spans, err := next()
		if err != nil || spans == nil {
			return nil, false, err
		}
		rss, _ := ToOTLP(spans)["resourceSpans"].([]any)
		return rss, true, nil
	})
}

// EncodeRunsStream is EncodeStream with run context (root spans).
func EncodeRunsStream(w io.Writer, next func() ([]RunTrace, error)) error {
	return encodeStream(w, func() ([]any, bool, error) {
		runs, err := next()
		if err != nil || runs == nil {
			return nil, false, err
		}
		rss, _ := ToOTLPRuns(runs)["resourceSpans"].([]any)
		return rss, true, nil
	})
}

func encodeStream(w io.Writer, next func() ([]any, bool, error)) error {
	if _, err := io.WriteString(w, `{"resourceSpans":[`); err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	first := true
	for {
		rss, more, err := next()
		if err != nil {
			return err
		}
		if !more {
			break // end of stream; an empty (non-nil) page is skipped
		}
		for _, rs := range rss {
			if !first {
				if _, err := io.WriteString(w, ","); err != nil {
					return err
				}
			}
			first = false
			if err := enc.Encode(rs); err != nil {
				return err
			}
		}
	}
	_, err := io.WriteString(w, `]}`)
	return err
}

// ToOTLP builds an OTLP/HTTP JSON envelope from bare spans (grouped by run,
// no root span).
func ToOTLP(spans []*model.Span) map[string]any {
	byRun := map[string][]*model.Span{}
	var order []string
	for _, sp := range spans {
		if _, ok := byRun[sp.RunID]; !ok {
			order = append(order, sp.RunID)
		}
		byRun[sp.RunID] = append(byRun[sp.RunID], sp)
	}
	var runs []RunTrace
	for _, id := range order {
		runs = append(runs, RunTrace{Spans: byRun[id]})
	}
	return ToOTLPRuns(runs)
}

// ToOTLPRuns builds an OTLP/HTTP JSON envelope, one ResourceSpans per run.
func ToOTLPRuns(runs []RunTrace) map[string]any {
	rss := []any{}
	for _, rt := range runs {
		if rt.Run == nil && len(rt.Spans) == 0 {
			continue
		}
		rss = append(rss, resourceSpans(rt))
	}
	return map[string]any{"resourceSpans": rss}
}

func resourceSpans(rt RunTrace) map[string]any {
	var runID, agentID, fleetID string
	if rt.Run != nil {
		runID, agentID, fleetID = rt.Run.RunID, rt.Run.AgentID, rt.Run.FleetID
	} else {
		runID, agentID, fleetID = rt.Spans[0].RunID, rt.Spans[0].AgentID, rt.Spans[0].FleetID
	}
	resAttrs := []any{
		strAttr("service.name", nonEmpty(agentID, "warden-agent")),
		strAttr("gen_ai.agent.id", agentID),
		strAttr("warden.agent.id", agentID),
		strAttr("warden.fleet.id", fleetID),
		strAttr("warden.run.id", runID),
	}
	traceID := TraceID(runID)
	ospans := []any{}
	parent := ""
	if rt.Run != nil {
		root := rootSpan(rt.Run, traceID)
		parent = root["spanId"].(string)
		ospans = append(ospans, root)
	}
	for _, sp := range rt.Spans {
		ospans = append(ospans, otlpSpan(sp, traceID, parent, rt.Run))
	}
	return map[string]any{
		"resource": map[string]any{"attributes": resAttrs},
		"scopeSpans": []any{map[string]any{
			"scope": map[string]any{"name": ScopeName, "version": ScopeVersion},
			"spans": ospans,
		}},
	}
}

func rootSpan(r *model.Run, traceID string) map[string]any {
	end := r.StartedAt
	if r.EndedAt != nil {
		end = *r.EndedAt
	}
	attrs := []any{
		strAttr("gen_ai.operation.name", "invoke_agent"),
		strAttr("gen_ai.agent.id", r.AgentID),
		strAttr("gen_ai.agent.name", r.AgentID),
		strAttr("warden.run.status", string(r.Status)),
		intAttr("gen_ai.usage.input_tokens", r.TokensIn),
		intAttr("gen_ai.usage.output_tokens", r.TokensOut),
		dblAttr("warden.cost.usd", r.CostUSD),
		intAttr("warden.tool_calls", r.ToolCalls),
	}
	if r.Provider != "" {
		attrs = append(attrs, strAttr("gen_ai.provider.name", r.Provider))
	}
	if r.Model != "" {
		attrs = append(attrs, strAttr("gen_ai.request.model", r.Model))
	}
	if r.ReceiptRef != "" {
		attrs = append(attrs, strAttr("warden.receipt.body_hash", r.ReceiptRef))
	}
	if r.KillReason != nil {
		attrs = append(attrs, strAttr("warden.kill.reason", *r.KillReason))
	}
	status := map[string]any{"code": 1}
	switch r.Status {
	case model.RunFailed, model.RunKilledOperator, model.RunKilledGuard, model.RunTimedOut, model.RunReceiptMissing:
		status = map[string]any{"code": 2, "message": string(r.Status)}
		attrs = append(attrs, strAttr("error.type", string(r.Status)))
	case model.RunRunning, model.RunAwaitingApproval:
		status = map[string]any{"code": 0} // UNSET: still in flight
	}
	return map[string]any{
		"traceId":           traceID,
		"spanId":            hashHex("root:"+r.RunID, 16),
		"name":              "invoke_agent " + nonEmpty(r.AgentID, "agent"),
		"kind":              kindInternal,
		"startTimeUnixNano": nanos(r.StartedAt),
		"endTimeUnixNano":   nanos(end),
		"attributes":        attrs,
		"status":            status,
	}
}

func otlpSpan(sp *model.Span, traceID, parent string, run *model.Run) map[string]any {
	end := sp.StartedAt
	if sp.EndedAt != nil {
		end = *sp.EndedAt
	}
	attrs := []any{
		strAttr("warden.span.kind", string(sp.Kind)),
		strAttr("warden.policy.decision", sp.PolicyDecision),
		boolAttr("warden.redacted", sp.Redacted),
	}
	if sp.PolicyReason != "" {
		attrs = append(attrs, strAttr("warden.policy.reason", sp.PolicyReason))
	}
	if sp.LateAfterSeal {
		attrs = append(attrs, boolAttr("warden.late_after_seal", true))
	}
	name := sp.Name
	kind := kindInternal
	switch sp.Kind {
	case model.SpanLLMCall:
		kind = kindClient
		provider := ""
		if run != nil {
			provider = run.Provider
		}
		if provider == "" {
			provider = InferProvider(sp.Model)
		}
		attrs = append(attrs,
			strAttr("gen_ai.operation.name", "chat"),
			strAttr("gen_ai.request.model", sp.Model),
			intAttr("gen_ai.usage.input_tokens", sp.TokensIn),
			intAttr("gen_ai.usage.output_tokens", sp.TokensOut),
			dblAttr("warden.cost.usd", sp.CostUSD),
		)
		if provider != "" {
			attrs = append(attrs, strAttr("gen_ai.provider.name", provider))
		}
		if sp.TokensCached > 0 {
			attrs = append(attrs, intAttr("gen_ai.usage.cache_read.input_tokens", sp.TokensCached))
		}
		name = strings.TrimSpace("chat " + sp.Model)
	case model.SpanToolCall:
		attrs = append(attrs,
			strAttr("gen_ai.operation.name", "execute_tool"),
			strAttr("gen_ai.tool.name", sp.Tool),
			strAttr("warden.tool.name", sp.Tool),
			strAttr("warden.tool.server", sp.ToolServer),
			strAttr("warden.tool.args_summary", sp.ArgsSummary),
			intAttr("warden.tool.exit_status", int64(sp.ExitStatus)),
		)
		name = strings.TrimSpace("execute_tool " + sp.Tool)
	case model.SpanFileOp:
		attrs = append(attrs,
			strAttr("warden.file.path", sp.Path),
			strAttr("warden.file.op", sp.Op),
		)
	case model.SpanNetEgress:
		attrs = append(attrs, strAttr("server.address", sp.Host))
		if sp.Port > 0 {
			attrs = append(attrs, intAttr("server.port", int64(sp.Port)))
		}
	case model.SpanSubagentSpawn:
		attrs = append(attrs, strAttr("warden.spawn.child_run_id", sp.ChildRunID))
	case model.SpanHumanApproval:
		attrs = append(attrs,
			strAttr("warden.approval.gate", sp.Gate),
			strAttr("warden.approval.decision", sp.Decision),
		)
	}
	if name == "" {
		name = string(sp.Kind)
	}
	status := map[string]any{"code": otlpStatus(sp.Status)}
	if sp.Status == "denied" {
		attrs = append(attrs, strAttr("error.type", "policy_denied"))
		status["message"] = sp.PolicyReason
	} else if sp.Status == "error" {
		attrs = append(attrs, strAttr("error.type", "error"))
	}
	out := map[string]any{
		"traceId":           traceID,
		"spanId":            SpanID(sp.SpanID),
		"name":              name,
		"kind":              kind,
		"startTimeUnixNano": nanos(sp.StartedAt),
		"endTimeUnixNano":   nanos(end),
		"attributes":        attrs,
		"status":            status,
	}
	if parent != "" {
		out["parentSpanId"] = parent
	}
	return out
}

// InferProvider maps well-known model-name prefixes to the GenAI
// gen_ai.provider.name well-known values; "" when unknown.
func InferProvider(m string) string {
	m = strings.ToLower(m)
	switch {
	case strings.HasPrefix(m, "claude"):
		return "anthropic"
	case strings.HasPrefix(m, "gpt"), strings.HasPrefix(m, "o1"), strings.HasPrefix(m, "o3"),
		strings.HasPrefix(m, "o4"), strings.HasPrefix(m, "codex"):
		return "openai"
	case strings.HasPrefix(m, "gemini"):
		return "gcp.gemini"
	case strings.HasPrefix(m, "mistral"), strings.HasPrefix(m, "codestral"):
		return "mistral_ai"
	case strings.HasPrefix(m, "grok"):
		return "x_ai"
	case strings.HasPrefix(m, "deepseek"):
		return "deepseek"
	}
	return ""
}

// TraceID returns a valid 32-hex OTLP trace id for a run id.
func TraceID(runID string) string {
	if isHex(runID, 32) {
		return runID
	}
	return hashHex("trace:"+runID, 32)
}

// SpanID returns a valid 16-hex OTLP span id for a warden span id.
func SpanID(id string) string {
	if len(id) >= 16 && isHex(id[:16], 16) && id[:16] != "0000000000000000" {
		return id[:16]
	}
	return hashHex("span:"+id, 16)
}

func isHex(s string, n int) bool {
	if len(s) != n || s == strings.Repeat("0", n) {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func hashHex(s string, n int) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:n]
}

func nanos(t time.Time) string { return strconv.FormatInt(t.UnixNano(), 10) }

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func otlpStatus(s string) int {
	if s == "error" || s == "denied" {
		return 2 // ERROR
	}
	return 1 // OK
}

func strAttr(k, v string) map[string]any {
	return map[string]any{"key": k, "value": map[string]any{"stringValue": v}}
}

// intAttr encodes an int64 the way OTLP/JSON specifies: a decimal string.
func intAttr(k string, v int64) map[string]any {
	return map[string]any{"key": k, "value": map[string]any{"intValue": strconv.FormatInt(v, 10)}}
}

func dblAttr(k string, v float64) map[string]any {
	return map[string]any{"key": k, "value": map[string]any{"doubleValue": v}}
}

func boolAttr(k string, v bool) map[string]any {
	return map[string]any{"key": k, "value": map[string]any{"boolValue": v}}
}

// Pusher sends OTLP/HTTP JSON envelopes to a collector endpoint
// (e.g. http://localhost:4318/v1/traces). It uses only the standard library.
type Pusher struct {
	Endpoint string
	Headers  map[string]string
	Client   *http.Client
}

// Push POSTs one envelope and returns an error for any non-2xx response.
func (p *Pusher) Push(ctx context.Context, runs []RunTrace) error {
	if len(runs) == 0 {
		return nil
	}
	body, err := json.Marshal(ToOTLPRuns(runs))
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	c := p.Client
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("otlp push: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}
