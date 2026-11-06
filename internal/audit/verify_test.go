package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/calasdan-sketch/warden/internal/model"
	"github.com/calasdan-sketch/warden/internal/receipt"
)

// buildChain seals n receipts (each with two spans) and returns the items.
func buildChain(t *testing.T, s *receipt.Signer, n int) []Item {
	t.Helper()
	var items []Item
	prev := ""
	base := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		runID := strings.Repeat(string(rune('a'+i)), 32)
		reason := "stop <now> & audit" // HTML-sensitive characters must survive export
		r := &model.Run{RunID: runID, AgentID: "agent", FleetID: "f", Status: model.RunKilledOperator,
			StartedAt: base.Add(time.Duration(i) * time.Minute), KillReason: &reason}
		spans := []*model.Span{
			{SpanID: runID[:16] + "01", RunID: runID, Kind: model.SpanToolCall, Tool: "bash", ArgsSummary: "git status", StartedAt: base},
			{SpanID: runID[:16] + "02", RunID: runID, Kind: model.SpanLLMCall, Model: "claude-sonnet-4-5", TokensIn: 10, CostUSD: 0.01, StartedAt: base},
		}
		rec, body, err := s.Seal(receipt.SealInput{Run: r, PrevHash: prev, SealedAt: base.Add(time.Hour + time.Duration(i)*time.Second), Spans: spans})
		if err != nil {
			t.Fatal(err)
		}
		prev = rec.BodyHash
		items = append(items, Item{Receipt: rec, Body: body, Spans: spans})
	}
	return items
}

// writeBundle encodes items the way `warden export` does.
func writeBundle(t *testing.T, s *receipt.Signer, items []Item) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	hdr := BundleHeader{Type: "header", Format: BundleFormat, KeyID: s.KeyID(),
		ExportedAt: "2026-11-05T13:00:00Z", HeadHash: items[len(items)-1].Receipt.BodyHash, ReceiptCount: len(items)}
	hdr.Signature = s.SignStatement(HeaderDomain, HeaderStatement(&hdr))
	_ = enc.Encode(hdr)
	// Newest first, spans after receipts: verification must not depend on order.
	for i := len(items) - 1; i >= 0; i-- {
		it := items[i]
		_ = enc.Encode(map[string]any{"type": "receipt", "receipt": it.Receipt, "body": json.RawMessage(it.Body)})
		for _, sp := range it.Spans {
			_ = enc.Encode(map[string]any{"type": "span", "span": sp})
		}
	}
	return buf.Bytes()
}

func verifyBundle(t *testing.T, s *receipt.Signer, b []byte) *Report {
	t.Helper()
	items, hdr, err := ReadBundle(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	rep := Verify(items, s.PublicKey())
	if err := CheckHeader(hdr, items, s.PublicKey()); err != nil {
		rep.Problems = append(rep.Problems, err.Error())
	}
	return rep
}

func TestBundleRoundTripVerifies(t *testing.T) {
	s, _ := receipt.Generate()
	items := buildChain(t, s, 3)
	rep := verifyBundle(t, s, writeBundle(t, s, items))
	if !rep.OK() || rep.TraceSigned != 3 {
		t.Fatalf("clean bundle must verify: %+v", rep)
	}
}

func TestBundleDetectsTampering(t *testing.T) {
	s, _ := receipt.Generate()
	items := buildChain(t, s, 3)
	clean := string(writeBundle(t, s, items))
	lines := strings.Split(strings.TrimSpace(clean), "\n")

	drop := func(pred func(string) bool, nth int) string {
		var out []string
		seen := 0
		for _, l := range lines {
			if pred(l) {
				if seen == nth {
					seen++
					continue
				}
				seen++
			}
			out = append(out, l)
		}
		return strings.Join(out, "\n") + "\n"
	}
	isReceipt := func(l string) bool { return strings.Contains(l, `"type":"receipt"`) }
	isSpan := func(l string) bool { return strings.Contains(l, `"type":"span"`) }

	cases := map[string]string{
		"edited span":         strings.Replace(clean, "git status", "git statuz", 1),
		"deleted span":        drop(isSpan, 0),
		"deleted newest":      drop(isReceipt, 0), // tail truncation: caught by the signed header
		"deleted middle":      drop(isReceipt, 1),
		"edited receipt body": strings.Replace(clean, `"tool_calls":0`, `"tool_calls":9`, 1),
		"edited header count": strings.Replace(clean, `"receipt_count":3`, `"receipt_count":2`, 1),
		"injected extra span": clean + `{"type":"span","span":{"span_id":"x","run_id":"` + strings.Repeat("a", 32) + `","kind":"tool.call","started_at":"2026-11-05T12:00:00Z"}}` + "\n",
	}
	for name, b := range cases {
		if b == clean {
			t.Fatalf("%s: mutation did not apply", name)
		}
		if rep := verifyBundle(t, s, []byte(b)); rep.OK() {
			t.Errorf("%s: tampering not detected: %+v", name, rep)
		}
	}

	// A different key must not verify anything.
	other, _ := receipt.Generate()
	if rep := verifyBundle(t, other, []byte(clean)); rep.OK() {
		t.Error("bundle verified under the wrong key")
	}
}

func TestLateSpansReportedNotFatal(t *testing.T) {
	s, _ := receipt.Generate()
	items := buildChain(t, s, 1)
	items[0].Spans = append(items[0].Spans, &model.Span{SpanID: "late1", RunID: items[0].Receipt.RunID,
		Kind: model.SpanToolCall, Tool: "mcp", StartedAt: time.Now(), LateAfterSeal: true})
	rep := verifyBundle(t, s, writeBundle(t, s, items))
	if !rep.OK() || rep.LateSpans != 1 {
		t.Fatalf("late span must be reported but not fail: %+v", rep)
	}
}

func TestChainByLinkageForkAndGap(t *testing.T) {
	s, _ := receipt.Generate()
	items := buildChain(t, s, 3)
	recs := []*model.Receipt{items[0].Receipt, items[1].Receipt, items[2].Receipt}
	if err := ChainByLinkage(recs); err != nil {
		t.Fatal(err)
	}
	fork := *items[2].Receipt
	fork.RunID = "forged"
	if err := ChainByLinkage(append(recs, &fork)); err == nil {
		t.Error("fork not detected")
	}
	if err := ChainByLinkage([]*model.Receipt{recs[0], recs[2]}); err == nil {
		t.Error("gap not detected")
	}
}

func TestLegacyReceiptWithoutTraceStillVerifies(t *testing.T) {
	s, _ := receipt.Generate()
	r := &model.Run{RunID: strings.Repeat("c", 32), AgentID: "a", FleetID: "f", Status: model.RunCompleted, StartedAt: time.Now()}
	rec, body, err := s.Seal(receipt.SealInput{Run: r, SealedAt: time.Now()}) // Spans nil: legacy shape
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, "spans_digest") {
		t.Fatal("legacy receipt body must not change shape")
	}
	rep := Verify([]Item{{Receipt: rec, Body: body}}, s.PublicKey())
	if !rep.OK() || rep.LegacyNoTrc != 1 {
		t.Fatalf("legacy receipt: %+v", rep)
	}
}

func TestReadBundleRejectsGarbage(t *testing.T) {
	if _, _, err := ReadBundle(strings.NewReader("{not json\n")); err == nil {
		t.Error("garbage line accepted")
	}
	huge := `{"type":"span","span":{"name":"` + strings.Repeat("x", MaxBundleLine+10) + `"}}`
	if _, _, err := ReadBundle(strings.NewReader(huge)); err == nil {
		t.Error("oversized line accepted")
	}
}
