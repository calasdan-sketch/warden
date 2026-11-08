package audit

import (
	"bytes"
	"encoding/json"
	"os"
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
	bun, err := ReadBundle(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return VerifyBundle(bun, s.PublicKey())
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
	if !rep.OK() || rep.LateSpans != 1 || len(rep.Unsigned) != 1 || !strings.Contains(rep.Unsigned[0], "late1") {
		t.Fatalf("late span must be listed as unsigned (not fail the signatures): %+v", rep)
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
	if _, err := ReadBundle(strings.NewReader("{not json\n")); err == nil {
		t.Error("garbage line accepted")
	}
	huge := `{"type":"span","span":{"name":"` + strings.Repeat("x", MaxBundleLine+10) + `"}}`
	if _, err := ReadBundle(strings.NewReader(huge)); err == nil {
		t.Error("oversized line accepted")
	}
}

// Regression for the synapse-1 panel review: header fields beside the signed
// body, orphan spans and unparsed record types were passed over.
func TestBundleHeaderEditsAndUnsignedRecords(t *testing.T) {
	s, _ := receipt.Generate()
	items := buildChain(t, s, 2)
	clean := string(writeBundle(t, s, items))
	for name, mut := range map[string][2]string{
		"status":      {`"status":"killed_operator","started_at"`, `"status":"completed","started_at"`},
		"kill_reason": {`"kill_reason":"stop <now> & audit","body_hash"`, `"kill_reason":"routine","body_hash"`},
		"agent_id":    {`"run_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","agent_id":"agent"`, `"run_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","agent_id":"other"`},
		"cost":        {`"cost_usd":0,"tool_calls":0,"kill_reason"`, `"cost_usd":0.5,"tool_calls":0,"kill_reason"`},
	} {
		// Edit only the receipt HEADER (first occurrence on a receipt line), not the body.
		var out []string
		done := false
		for _, l := range strings.Split(clean, "\n") {
			if !done && strings.Contains(l, `"type":"receipt"`) && strings.Contains(l, mut[0]) {
				l = strings.Replace(l, mut[0], mut[1], 1)
				done = true
			}
			out = append(out, l)
		}
		if !done {
			t.Fatalf("%s: mutation did not apply", name)
		}
		if rep := verifyBundle(t, s, []byte(strings.Join(out, "\n"))); rep.OK() {
			t.Errorf("%s: edited receipt header not detected", name)
		}
	}
	orphan := clean + `{"type":"span","span":{"span_id":"fake","run_id":"nosuchrun","kind":"tool.call","tool":"bash","started_at":"2026-11-05T12:00:00Z"}}` + "\n" +
		`{"type":"run","run":{"run_id":"x"}}` + "\n" + `{"type":"kill_audit","kill":{"id":1}}` + "\n"
	rep := verifyBundle(t, s, []byte(orphan))
	joined := strings.Join(rep.Unsigned, "|")
	if !strings.Contains(joined, "fake") || !strings.Contains(joined, "run record") || !strings.Contains(joined, "kill_audit") {
		t.Errorf("orphan span / run / kill_audit must be listed as unsigned: %v", rep.Unsigned)
	}
	if _, err := ReadBundle(strings.NewReader(clean + `{"type":"mystery"}` + "\n")); err == nil {
		t.Error("unknown record type must be rejected")
	}
}

// The run row beside a receipt (what `runs`, `replay` and the dashboard
// show) is not signed. Editing it must not pass as a verified receipt.
func TestRunRowMustMatchSignedReceipt(t *testing.T) {
	s, _ := receipt.Generate()
	items := buildChain(t, s, 2)
	rowFor := func(it Item) *model.Run {
		r := &model.Run{RunID: it.Receipt.RunID, AgentID: it.Receipt.AgentID, FleetID: it.Receipt.FleetID,
			Status: it.Receipt.Status, StartedAt: it.Receipt.StartedAt, KillReason: it.Receipt.KillReason, KilledBy: it.Receipt.KilledBy}
		return r
	}
	for i := range items {
		items[i].Run = rowFor(items[i])
	}
	if rep := Verify(items, s.PublicKey()); !rep.OK() {
		t.Fatalf("matching rows must verify: %+v", rep.Problems)
	}
	// Hard fields: agent, fleet, operator, status, start time, kill reason/by.
	edits := map[string]func(r *model.Run){
		"agent":  func(r *model.Run) { r.AgentID = "someone-else" },
		"fleet":  func(r *model.Run) { r.FleetID = "other" },
		"status": func(r *model.Run) { r.Status = model.RunCompleted },
		"start":  func(r *model.Run) { r.StartedAt = r.StartedAt.Add(time.Hour) },
		"reason": func(r *model.Run) { x := "benign"; r.KillReason = &x },
		"by":     func(r *model.Run) { x := "nobody"; r.KilledBy = &x },
	}
	for name, edit := range edits {
		its := buildChain(t, s, 2)
		for i := range its {
			its[i].Run = rowFor(its[i])
		}
		edit(its[0].Run)
		rep := Verify(its, s.PublicKey())
		if rep.OK() || !strings.Contains(strings.Join(rep.Problems, "|"), "run record disagrees") {
			t.Errorf("%s edit not caught: %+v", name, rep.Problems)
		}
		if !rep.ChainOK {
			t.Errorf("%s edit: the receipts themselves are intact, the chain must still hold", name)
		}
	}
	// Running totals are reported, not failed: a joined emitter record may update them after the seal.
	its := buildChain(t, s, 1)
	its[0].Run = rowFor(its[0])
	its[0].Run.CostUSD = 9
	rep := Verify(its, s.PublicKey())
	if !rep.OK() || len(rep.Notes) != 1 {
		t.Errorf("a changed total should be a note, not a failure: ok=%v notes=%v", rep.OK(), rep.Notes)
	}
}

// TestBundleWrittenByWarden010StillVerifies is an upgrade test: a real export
// made by the 0.1.0 binary (testdata) left agent, fleet, operator, start time,
// call count and trace digest blank in each receipt header. Strict header
// checking used to report that as "header was edited". The signed body is
// intact, so it must verify, with a note.
func TestBundleWrittenByWarden010StillVerifies(t *testing.T) {
	f, err := os.Open("testdata/bundle-0.1.0.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, err := ReadBundle(f)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := LoadPublicKey("testdata/bundle-0.1.0.pub")
	if err != nil {
		t.Fatal(err)
	}
	rep := VerifyBundle(b, pub)
	if len(rep.Problems) != 0 || rep.Valid != rep.Receipts || rep.Receipts == 0 || !rep.ChainOK {
		t.Fatalf("0.1.0 bundle should verify: %+v", rep)
	}
	if len(rep.Notes) == 0 {
		t.Fatal("expected a note that the headers came from 0.1.0")
	}
	// A blank header must not let a real edit through: status is still compared.
	for _, it := range b.Items {
		if it.Receipt.Status == "completed" {
			it.Receipt.Status = "failed"
		}
	}
	if rep := VerifyBundle(b, pub); rep.OK() {
		t.Fatal("editing the status of a legacy header must still fail")
	}
}

func TestPartiallyBlankHeaderIsStillChecked(t *testing.T) {
	s, _ := receipt.Generate()
	items := buildChain(t, s, 1)
	r := items[0].Receipt
	r.AgentID, r.FleetID, r.Operator = "", "", ""
	r.ToolCalls, r.SpanCount, r.SpansDigest = 0, 0, ""
	// started_at left set: not the 0.1.0 shape, so the full comparison applies
	// (and it must fail because the agent id was blanked).
	if receipt.IsBlankLegacyHeader(r) {
		t.Fatal("a header with a start time is not the legacy shape")
	}
	if err := receipt.MatchesBody(r, items[0].Body); err == nil {
		t.Fatal("blanked fields with a start time must be reported")
	}
}

func TestHeaderStatusAndCallsAreComparedToSignedBody(t *testing.T) {
	s, _ := receipt.Generate()
	items := buildChain(t, s, 1)
	r := items[0].Receipt
	r.Status = ""
	if err := receipt.MatchesBody(r, items[0].Body); err == nil {
		t.Fatal("an emptied status in the header must be reported")
	}
	// Only the call count is non-blank: not the 0.1.0 shape, full comparison.
	items = buildChain(t, s, 1)
	r = items[0].Receipt
	r.AgentID, r.FleetID, r.Operator, r.SpansDigest = "", "", "", ""
	r.StartedAt, r.SpanCount, r.GuardsEvaluated = time.Time{}, 0, nil
	r.ToolCalls = 99
	if receipt.IsBlankLegacyHeader(r) {
		t.Fatal("a header that still shows a call count is not the 0.1.0 shape")
	}
	if err := receipt.MatchesBody(r, items[0].Body); err == nil {
		t.Fatal("wrong call count must be reported")
	}
}

// A signature re-encoded with different padding bits decodes to the same bytes
// but is not the text warden wrote; both the receipt and the header reject it.
func TestNonCanonicalSignatureEncodingIsRejected(t *testing.T) {
	s, _ := receipt.Generate()
	items := buildChain(t, s, 2)
	raw := writeBundle(t, s, items)
	if rep := verifyBundle(t, s, raw); !rep.OK() {
		t.Fatalf("baseline must verify: %v", rep.Problems)
	}
	// Ed25519 signatures are 64 bytes: base64 ends "==", whose last character
	// carries 2 data bits and 4 padding bits. Change a padding bit.
	flip := func(sig string) string {
		const abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
		i := strings.IndexByte(abc, sig[len(sig)-3])
		return sig[:len(sig)-3] + string(abc[i^1]) + sig[len(sig)-2:]
	}
	for _, field := range []string{`"signature":"`} {
		text := string(raw)
		n := 0
		for from := 0; ; {
			k := strings.Index(text[from:], field)
			if k < 0 {
				break
			}
			start := from + k + len(field)
			end := start + strings.IndexByte(text[start:], '"')
			sig := text[start:end]
			if strings.HasSuffix(sig, "==") {
				mut := text[:start] + flip(sig) + text[end:]
				bun, err := ReadBundle(strings.NewReader(mut))
				if err != nil {
					t.Fatal(err)
				}
				if rep := VerifyBundle(bun, s.PublicKey()); rep.OK() {
					t.Errorf("signature #%d with a changed padding bit verified", n)
				}
				n++
			}
			from = end
		}
		if n < 3 {
			t.Fatalf("expected the header and two receipts, found %d signatures", n)
		}
	}
}
