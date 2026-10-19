// Package otel maps warden spans to OTLP/HTTP JSON so existing
// Datadog/Honeycomb/Grafana investments can ingest warden telemetry.
// Warden stays bilingual: its first-class concept is the run envelope (which
// OTel doesn't model); this export is the bridge, not the product.
//
// Mapping notes:
//   - OTLP trace_id = warden run_id (both 32 hex chars).
//   - OTLP span_id = first 16 hex chars of the warden span_id.
//   - Span kind-specific fields become attributes prefixed with "warden.".
//   - Policy decisions and redaction flags are attributes, so the OTel side
//     sees exactly what the dashboard sees (redacted form only).
package otel

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"

	"warden/internal/model"
)

// EncodeStream writes a single OTLP/HTTP JSON envelope to w, pulling span
// pages from next until it returns nil. Memory stays bounded by one page:
// a fleet with millions of spans must not be materialized to build the
// envelope. (Newlines emitted by the encoder are legal JSON whitespace.)
func EncodeStream(w io.Writer, next func() ([]*model.Span, error)) error {
	if _, err := io.WriteString(w, `{"resourceSpans":[`); err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	first := true
	for {
		spans, err := next()
		if err != nil {
			return err
		}
		if spans == nil {
			break // end of stream; an empty (non-nil) page is skipped
		}
		env := ToOTLP(spans)
		rss, _ := env["resourceSpans"].([]any)
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

// ResourceSpans is the OTLP/HTTP JSON envelope.
func ToOTLP(spans []*model.Span) map[string]any {
	// Group by run: one ResourceSpans entry per run.
	byRun := map[string][]*model.Span{}
	var order []string
	for _, sp := range spans {
		if _, ok := byRun[sp.RunID]; !ok {
			order = append(order, sp.RunID)
		}
		byRun[sp.RunID] = append(byRun[sp.RunID], sp)
	}
	var rss []any
	for _, runID := range order {
		rss = append(rss, resourceSpans(runID, byRun[runID]))
	}
	if rss == nil {
		rss = []any{}
	}
	return map[string]any{"resourceSpans": rss}
}

func resourceSpans(runID string, spans []*model.Span) map[string]any {
	resAttrs := []any{}
	if len(spans) > 0 {
		resAttrs = append(resAttrs,
			attr("warden.agent.id", spans[0].AgentID),
			attr("warden.fleet.id", spans[0].FleetID),
			attr("warden.run.id", runID),
		)
	}
	var ospans []any
	for _, sp := range spans {
		ospans = append(ospans, otlpSpan(sp))
	}
	if ospans == nil {
		ospans = []any{}
	}
	return map[string]any{
		"resource":   map[string]any{"attributes": resAttrs},
		"scopeSpans": []any{map[string]any{"spans": ospans}},
	}
}

func otlpSpan(sp *model.Span) map[string]any {
	spanID := sp.SpanID
	if len(spanID) > 16 {
		spanID = spanID[:16]
	}
	traceID := sp.RunID
	for len(traceID) < 32 {
		traceID += "0"
	}
	if len(traceID) > 32 {
		traceID = traceID[:32]
	}
	end := sp.StartedAt
	if sp.EndedAt != nil {
		end = *sp.EndedAt
	}
	attrs := []any{
		attr("warden.span.kind", string(sp.Kind)),
		attr("warden.policy.decision", sp.PolicyDecision),
		attr("warden.redacted", strconv.FormatBool(sp.Redacted)),
	}
	switch sp.Kind {
	case model.SpanLLMCall:
		attrs = append(attrs,
			attr("gen_ai.request.model", sp.Model),
			attr("gen_ai.usage.input_tokens", strconv.FormatInt(sp.TokensIn, 10)),
			attr("gen_ai.usage.output_tokens", strconv.FormatInt(sp.TokensOut, 10)),
			attr("warden.cost.usd", fmt.Sprintf("%.6f", sp.CostUSD)),
		)
	case model.SpanToolCall:
		attrs = append(attrs,
			attr("warden.tool.name", sp.Tool),
			attr("warden.tool.server", sp.ToolServer),
			attr("warden.tool.exit_status", strconv.Itoa(sp.ExitStatus)),
		)
	case model.SpanFileOp:
		attrs = append(attrs,
			attr("warden.file.path", sp.Path),
			attr("warden.file.op", sp.Op),
		)
	case model.SpanNetEgress:
		attrs = append(attrs,
			attr("server.address", sp.Host),
			attr("server.port", strconv.Itoa(sp.Port)),
		)
	case model.SpanSubagentSpawn:
		attrs = append(attrs, attr("warden.spawn.child_run_id", sp.ChildRunID))
	case model.SpanHumanApproval:
		attrs = append(attrs,
			attr("warden.approval.gate", sp.Gate),
			attr("warden.approval.decision", sp.Decision),
		)
	}
	name := sp.Name
	if name == "" {
		name = string(sp.Kind)
	}
	return map[string]any{
		"traceId":           traceID,
		"spanId":            spanID,
		"name":              name,
		"startTimeUnixNano": strconv.FormatInt(sp.StartedAt.UnixNano(), 10),
		"endTimeUnixNano":   strconv.FormatInt(end.UnixNano(), 10),
		"attributes":        attrs,
		"status":            map[string]any{"code": otlpStatus(sp.Status)},
	}
}

func otlpStatus(s string) int {
	if s == "error" || s == "denied" {
		return 2 // ERROR
	}
	return 1 // OK
}

func attr(k, v string) map[string]any {
	return map[string]any{
		"key":   k,
		"value": map[string]any{"stringValue": v},
	}
}
