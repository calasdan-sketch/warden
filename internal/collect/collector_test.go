package collect

import (
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"warden/internal/model"
	"warden/internal/policy"
	"warden/internal/receipt"
	"warden/internal/store"
)

func testCollector(t *testing.T, policyYAML string) (*Collector, *store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "warden.db"))
	if err != nil {
		t.Fatal(err)
	}
	var pol *policy.Policy
	if policyYAML == "" {
		pol, err = policy.Default()
	} else {
		pol, err = policy.Parse([]byte(policyYAML))
	}
	if err != nil {
		t.Fatal(err)
	}
	signer, err := receipt.Generate()
	if err != nil {
		t.Fatal(err)
	}
	c := New(st, pol, signer, dir)
	t.Cleanup(func() {
		c.Close()
		st.Close()
	})
	return c, st, dir
}

func startTestRun(t *testing.T, c *Collector) (*model.Run, string) {
	t.Helper()
	r, sock, err := c.StartRun(RunOptions{AgentID: "jarvis:code", FleetID: "prod", Operator: "dan"})
	if err != nil {
		t.Fatal(err)
	}
	return r, sock
}

func TestStartRunRefusals(t *testing.T) {
	c, st, _ := testCollector(t, "")
	if err := st.QuarantineAgent("evil:bot", time.Now().Add(time.Hour), "compromised"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.StartRun(RunOptions{AgentID: "evil:bot", FleetID: "prod"}); err == nil {
		t.Error("quarantined agent must be refused")
	}
	if err := st.FreezeFleet("prod", time.Now().Add(time.Hour), time.Now().Add(5*time.Minute), "incident"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.StartRun(RunOptions{AgentID: "jarvis:code", FleetID: "prod"}); err == nil {
		t.Error("frozen fleet must refuse new runs")
	}
	// Other fleets unaffected.
	if _, _, err := c.StartRun(RunOptions{AgentID: "jarvis:code", FleetID: "nightly"}); err != nil {
		t.Errorf("other fleet should start: %v", err)
	}
}

func TestEmitSpanRedactsBeforeStore(t *testing.T) {
	c, st, _ := testCollector(t, "")
	r, _ := startTestRun(t, c)
	secret := "sk_live_abcdefghijklmnop1234"
	err := c.EmitSpan(&model.Span{
		Kind: model.SpanToolCall, Tool: "web_fetch",
		ArgsSummary: "curl -H 'Authorization: Bearer " + secret + "' https://api.example.com",
		RunID:       r.RunID, AgentID: r.AgentID, FleetID: r.FleetID,
	})
	if err != nil {
		t.Fatal(err)
	}
	spans, err := st.SpansForRun(r.RunID)
	if err != nil || len(spans) == 0 {
		t.Fatalf("spans: %v %v", spans, err)
	}
	var found *model.Span
	for _, s := range spans {
		if s.Tool == "web_fetch" {
			found = s
		}
	}
	if found == nil {
		t.Fatal("span not stored")
	}
	if !found.Redacted {
		t.Error("span should be marked redacted")
	}
	if strings.Contains(found.ArgsSummary, secret) {
		t.Errorf("secret reached the store: %q", found.ArgsSummary)
	}
	if found.ArgHash == "" {
		t.Error("arg hash should be set")
	}
}

func TestEmitSpanPolicyDeny(t *testing.T) {
	c, st, _ := testCollector(t, "")
	r, _ := startTestRun(t, c)
	err := c.EmitSpan(&model.Span{
		Kind: model.SpanToolCall, Tool: "bash", Name: "bash",
		ArgsSummary: "terraform apply -auto-approve",
		RunID:       r.RunID, AgentID: r.AgentID, FleetID: r.FleetID,
	})
	if err != nil {
		t.Fatal(err)
	}
	spans, _ := st.SpansForRun(r.RunID)
	var denied *model.Span
	for _, s := range spans {
		if s.Status == "denied" {
			denied = s
		}
	}
	if denied == nil {
		t.Fatal("denied span not recorded")
	}
	if denied.PolicyDecision != "deny" || denied.PolicyReason == "" || denied.PolicyVersion == "" {
		t.Errorf("denied span missing policy fields: %+v", denied)
	}
	evs, _ := st.EventsForRun(r.RunID, 10)
	found := false
	for _, e := range evs {
		if e.Kind == "policy_deny" {
			found = true
		}
	}
	if !found {
		t.Error("policy_deny event not recorded")
	}
}

func TestEmitSpanApprovalRequired(t *testing.T) {
	c, st, _ := testCollector(t, "")
	r, _ := startTestRun(t, c)
	err := c.EmitSpan(&model.Span{
		Kind: model.SpanFileOp, Path: "/home/dan/.env", Op: "read",
		RunID: r.RunID, AgentID: r.AgentID, FleetID: r.FleetID,
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := st.PendingApprovals()
	if err != nil || len(pending) == 0 {
		t.Fatalf("expected pending approval: %v %v", pending, err)
	}
	spans, _ := st.SpansForRun(r.RunID)
	if len(spans) == 0 || spans[0].Status != "awaiting_approval" {
		t.Errorf("span should be awaiting_approval: %+v", spans)
	}
}

func TestInvalidSpanKindRejected(t *testing.T) {
	c, _, _ := testCollector(t, "")
	r, _ := startTestRun(t, c)
	if err := c.EmitSpan(&model.Span{Kind: "http.request", RunID: r.RunID}); err == nil {
		t.Error("invalid span kind must be rejected")
	}
}

func TestSocketIngestion(t *testing.T) {
	c, st, _ := testCollector(t, "")
	r, sock := startTestRun(t, c)

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	spanLine, _ := json.Marshal(map[string]any{
		"kind": "tool.call", "tool": "bash", "name": "bash",
		"args_summary": "git status",
	})
	lines := []string{
		string(spanLine),
		`{"heartbeat": true}`,
		`{"event": {"severity": "info", "kind": "note", "message": "hello"}}`,
		`this is not json {{{`,
		`{"kind": "bogus.kind"}`,
	}
	for _, l := range lines {
		if _, err := conn.Write([]byte(l + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	conn.Close()

	deadline := time.Now().Add(3 * time.Second)
	for {
		spans, _ := st.SpansForRun(r.RunID)
		if len(spans) >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket span never arrived")
		}
		time.Sleep(50 * time.Millisecond)
	}
	evs, _ := st.EventsForRun(r.RunID, 10)
	found := false
	for _, e := range evs {
		if e.Kind == "note" && e.Message == "hello" {
			found = true
		}
	}
	if !found {
		t.Error("socket event not recorded")
	}
}

func TestSealRunIdempotent(t *testing.T) {
	c, st, _ := testCollector(t, "")
	r, _ := startTestRun(t, c)
	_ = c.EmitSpan(&model.Span{Kind: model.SpanToolCall, Tool: "bash", ArgsSummary: "git status",
		RunID: r.RunID, AgentID: r.AgentID, FleetID: r.FleetID})
	rec1, err := c.SealRun(r.RunID, model.RunCompleted, nil, []string{"budget"})
	if err != nil {
		t.Fatal(err)
	}
	rec2, err := c.SealRun(r.RunID, model.RunCompleted, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec1.BodyHash != rec2.BodyHash {
		t.Error("double seal must return the same receipt")
	}
	got, err := st.GetRun(r.RunID)
	if err != nil || got.Status != model.RunCompleted || got.ToolCalls != 1 {
		t.Errorf("sealed run wrong: %+v %v", got, err)
	}
	stored, body, err := st.GetReceipt(r.RunID)
	if err != nil || stored.BodyHash != rec1.BodyHash || body == "" {
		t.Errorf("receipt not stored: %v %v", stored, err)
	}
}

func TestReconcileSealsDeadRuns(t *testing.T) {
	c, st, _ := testCollector(t, "")
	r, _ := startTestRun(t, c)
	// Simulate a crash: run stays 'running' with an ancient heartbeat.
	old := time.Now().UTC().Add(-2 * time.Hour)
	_, err := st.DB().Exec(`UPDATE runs SET last_heartbeat=? WHERE run_id=?`,
		old.Format(time.RFC3339Nano), r.RunID)
	if err != nil {
		t.Fatal(err)
	}
	n, err := c.Reconcile(time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("Reconcile = %d, %v; want 1", n, err)
	}
	got, _ := st.GetRun(r.RunID)
	if got.Status != model.RunReceiptMissing {
		t.Errorf("status = %s, want receipt_missing", got.Status)
	}
	if _, _, err := st.GetReceipt(r.RunID); err != nil {
		t.Errorf("dead run must still get a sealed receipt: %v", err)
	}
	// A fresh run is not reconciled.
	_, _ = startTestRun(t, c)
	n, err = c.Reconcile(time.Hour)
	if err != nil || n != 0 {
		t.Errorf("fresh run should not be reconciled: %d %v", n, err)
	}
}
