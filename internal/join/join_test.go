package join

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/calasdan-sketch/warden/internal/collect"
	"github.com/calasdan-sketch/warden/internal/model"
	"github.com/calasdan-sketch/warden/internal/policy"
	"github.com/calasdan-sketch/warden/internal/receipt"
	"github.com/calasdan-sketch/warden/internal/store"
)

func testImporter(t *testing.T) (*Importer, *store.Store, *collect.Collector) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "warden.db"))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Default()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := receipt.Generate()
	if err != nil {
		t.Fatal(err)
	}
	col := collect.New(st, pol, signer, dir)
	t.Cleanup(func() {
		col.Close()
		st.Close()
	})
	return New(st, col), st, col
}

func TestShortleashJoin(t *testing.T) {
	im, st, _ := testImporter(t)
	line := `{"run_id":"sl-1","agent_id":"jarvis:code","fleet":"prod",` +
		`"started_at":"2026-10-18T10:00:00Z","ended_at":"2026-10-18T10:30:00Z",` +
		`"outcome":"completed","tokens_in":1000,"tokens_out":500,"tokens_cached":200,` +
		`"cost_usd":4.17,"guards_evaluated":["budget"],"tool_calls":312,"files_touched":18}`
	if err := im.ImportLine(SourceShortleash, line); err != nil {
		t.Fatal(err)
	}
	run, err := st.GetRun("sl-1")
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != model.RunCompleted {
		t.Errorf("status = %s", run.Status)
	}
	// Cost joined, never recomputed: exactly the emitter's number.
	if run.CostUSD != 4.17 || run.TokensIn != 1000 || run.ToolCalls != 312 {
		t.Errorf("emitter numbers not joined: %+v", run)
	}
	if _, _, err := st.GetReceipt("sl-1"); err != nil {
		t.Errorf("joined run must seal a receipt: %v", err)
	}
	evs, _ := st.EventsForRun("sl-1", 10)
	foundGuard, foundJoin := false, false
	for _, e := range evs {
		if e.Kind == "guard_trip" {
			foundGuard = true
		}
		if e.Kind == "join" {
			foundJoin = true
		}
	}
	if !foundGuard || !foundJoin {
		t.Errorf("guard_trip/join events missing: %+v", evs)
	}
}

func TestShortleashKilledJoin(t *testing.T) {
	im, st, _ := testImporter(t)
	line := `{"run_id":"sl-2","agent_id":"a","fleet":"f","outcome":"killed",` +
		`"killed_by":"guard","kill_reason":"budget exceeded","cost_usd":9.99}`
	if err := im.ImportLine(SourceShortleash, line); err != nil {
		t.Fatal(err)
	}
	run, _ := st.GetRun("sl-2")
	if run.Status != model.RunKilledGuard {
		t.Errorf("status = %s, want killed_guard", run.Status)
	}
	if run.KillReason == nil || *run.KillReason != "budget exceeded" {
		t.Errorf("kill reason: %+v", run.KillReason)
	}
}

func TestShortleashMissingRunID(t *testing.T) {
	im, _, _ := testImporter(t)
	if err := im.ImportLine(SourceShortleash, `{"outcome":"completed"}`); err == nil {
		t.Error("record without run_id must fail")
	}
}

func TestPlanokJoin(t *testing.T) {
	im, st, _ := testImporter(t)
	line := `{"run_id":"pk-1","agent_id":"a","gate":"delete-bucket","decision":"denied",` +
		`"approver":"dan","requested_at":"2026-10-18T10:00:00Z","decided_at":"2026-10-18T10:12:04Z"}`
	if err := im.ImportLine(SourcePlanok, line); err != nil {
		t.Fatal(err)
	}
	spans, err := st.SpansForRun("pk-1")
	if err != nil || len(spans) != 1 {
		t.Fatalf("spans: %v %v", spans, err)
	}
	sp := spans[0]
	if sp.Kind != model.SpanHumanApproval || sp.Decision != "denied" || sp.Gate != "delete-bucket" {
		t.Errorf("approval span wrong: %+v", sp)
	}
	if sp.DecisionLatencyMs != 12*60*1000+4000 {
		t.Errorf("latency = %d, want 724000", sp.DecisionLatencyMs)
	}
	run, _ := st.GetRun("pk-1")
	if run.ApprovalsRequested != 1 || run.ApprovalsDenied != 1 {
		t.Errorf("approval counters: %+v", run)
	}
}

func TestMCPJailJoin(t *testing.T) {
	im, st, _ := testImporter(t)
	allowed := `{"run_id":"mj-1","agent_id":"a","fleet":"f","tool":"read_file","server":"fs-mcp",` +
		`"args":"/tmp/x.txt","allowed":true,"at":"2026-10-18T10:00:00Z"}`
	denied := `{"run_id":"mj-1","agent_id":"a","fleet":"f","tool":"web_fetch","server":"net-mcp",` +
		`"args":"https://evil.example.com","allowed":false,"at":"2026-10-18T10:01:00Z"}`
	// A secret in the args must be redacted by the collector even on the join path.
	secretLine := `{"run_id":"mj-1","agent_id":"a","fleet":"f","tool":"fetch","server":"net-mcp",` +
		`"args":"api_key=sk_live_abcdefghijklmnop1234","allowed":true,"at":"2026-10-18T10:02:00Z"}`
	for _, l := range []string{allowed, denied, secretLine} {
		if err := im.ImportLine(SourceMCPJail, l); err != nil {
			t.Fatal(err)
		}
	}
	spans, _ := st.SpansForRun("mj-1")
	if len(spans) != 3 {
		t.Fatalf("want 3 spans, got %d", len(spans))
	}
	byTool := map[string]*model.Span{}
	for _, s := range spans {
		byTool[s.Tool] = s
	}
	if byTool["read_file"].ToolServer != "fs-mcp" {
		t.Errorf("server not joined: %+v", byTool["read_file"])
	}
	if byTool["read_file"].PolicyVersion != "mcp-jail" || byTool["read_file"].PolicyDecision != "allow" {
		t.Errorf("external allow not honored: %+v", byTool["read_file"])
	}
	d := byTool["web_fetch"]
	if d.PolicyDecision != "deny" || d.Status != "denied" {
		t.Errorf("external deny not honored: %+v", d)
	}
	if d.PolicyReason != "denied by mcp-jail" {
		t.Errorf("deny reason lost: %+v", d)
	}
	s := byTool["fetch"]
	if !s.Redacted {
		t.Error("join path must redact before emission")
	}
	for _, sp := range spans {
		if containsStr(sp.ArgsSummary, "sk_live_abcdefghijklmnop1234") {
			t.Errorf("secret reached the store via join: %q", sp.ArgsSummary)
		}
	}
}

func TestMCPJailUnattached(t *testing.T) {
	im, st, _ := testImporter(t)
	line := `{"agent_id":"ghost","tool":"read_file","server":"fs","args":"x","allowed":true}`
	if err := im.ImportLine(SourceMCPJail, line); err != nil {
		t.Fatal(err)
	}
	run, err := st.GetRun("unattached:ghost")
	if err != nil {
		t.Fatalf("unattached bucket missing: %v", err)
	}
	if run.Status != model.RunRunning {
		t.Errorf("bucket should stay open: %s", run.Status)
	}
}

func TestGatewayJoin(t *testing.T) {
	im, st, _ := testImporter(t)
	// The run exists with emitter-authoritative gross cost.
	if err := im.ImportLine(SourceShortleash,
		`{"run_id":"gw-1","agent_id":"a","fleet":"f","outcome":"completed","cost_usd":4.17}`); err != nil {
		t.Fatal(err)
	}
	if err := im.ImportLine(SourceCalasGateway,
		`{"run_id":"gw-1","saved_usd":1.02,"cache_hit_tokens":5000,"strategy":"prompt-cache"}`); err != nil {
		t.Fatal(err)
	}
	run, _ := st.GetRun("gw-1")
	if run.CostUSD != 4.17 {
		t.Errorf("gross cost must never be touched by the join: %.2f", run.CostUSD)
	}
	if run.CostSavedUSD != 1.02 {
		t.Errorf("saved memo not joined: %.2f", run.CostSavedUSD)
	}
	if net := run.NetCost(); net < 3.14 || net > 3.16 {
		t.Errorf("net = %.2f, want 3.15", net)
	}
}

func TestImportFile(t *testing.T) {
	im, st, _ := testImporter(t)
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	content := "{\"run_id\":\"f-1\",\"agent_id\":\"a\",\"outcome\":\"completed\",\"cost_usd\":1}\n" +
		"\n" + // blank lines are skipped
		"{\"run_id\":\"f-2\",\"agent_id\":\"a\",\"outcome\":\"failed\",\"cost_usd\":2}\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	n, err := im.ImportFile(SourceShortleash, path)
	if err != nil || n != 2 {
		t.Fatalf("ImportFile = %d, %v", n, err)
	}
	if _, err := st.GetRun("f-1"); err != nil {
		t.Error(err)
	}
	if _, err := im.ImportFile(SourceShortleash, "/nonexistent.jsonl"); err == nil {
		t.Error("missing file should fail")
	}
}

func TestUnknownSource(t *testing.T) {
	im, _, _ := testImporter(t)
	if err := im.ImportLine("nope", `{}`); err == nil {
		t.Error("unknown source must fail")
	}
	if err := im.ImportLine(SourceShortleash, `not json`); err == nil {
		t.Error("bad JSON must fail")
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

var _ = time.Now
