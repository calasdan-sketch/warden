package collect

import (
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/calasdan-sketch/warden/internal/model"
	"github.com/calasdan-sketch/warden/internal/policy"
	"github.com/calasdan-sketch/warden/internal/receipt"
	"github.com/calasdan-sketch/warden/internal/store"
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
	secret := "sk_l" + "ive_abcdefghijklmnop1234"
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
	// The event line is processed after the span line by the same
	// connection handler; poll for it too instead of racing it.
	for {
		evs, _ := st.EventsForRun(r.RunID, 10)
		found := false
		for _, e := range evs {
			if e.Kind == "note" && e.Message == "hello" {
				found = true
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket event not recorded")
		}
		time.Sleep(20 * time.Millisecond)
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

func TestReceiptCommitsToTraceAndLateSpansAreMarked(t *testing.T) {
	c, st, _ := testCollector(t, "")
	r, _ := startTestRun(t, c)
	for _, args := range []string{"git status", "git diff"} {
		if err := c.EmitSpan(&model.Span{Kind: model.SpanToolCall, Tool: "bash", ArgsSummary: args,
			RunID: r.RunID, AgentID: r.AgentID, FleetID: r.FleetID}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.SealRun(r.RunID, model.RunCompleted, nil, nil); err != nil {
		t.Fatal(err)
	}
	_, body, err := st.GetReceipt(r.RunID)
	if err != nil {
		t.Fatal(err)
	}
	spans, _ := st.SpansForRun(r.RunID)
	if late, covered, err := receipt.VerifyTrace(body, spans); err != nil || !covered || late != 0 {
		t.Fatalf("fresh trace should verify: late=%d covered=%v err=%v", late, covered, err)
	}

	// A span arriving after the seal is kept but marked late, and does not
	// break verification of the covered set.
	late := &model.Span{Kind: model.SpanToolCall, Tool: "bash", ArgsSummary: "git log",
		RunID: r.RunID, AgentID: r.AgentID, FleetID: r.FleetID}
	if err := c.EmitSpan(late); err != nil {
		t.Fatal(err)
	}
	if !late.LateAfterSeal {
		t.Fatal("span after seal must be marked late_after_seal")
	}
	spans, _ = st.SpansForRun(r.RunID)
	if n, covered, err := receipt.VerifyTrace(body, spans); err != nil || !covered || n != 1 {
		t.Fatalf("late span should be reported, not fail: late=%d err=%v", n, err)
	}

	// Tampering with a covered span is detected.
	if _, err := st.DB().Exec(`UPDATE spans SET args_summary='ls' WHERE run_id=? AND args_summary='git diff'`, r.RunID); err != nil {
		t.Fatal(err)
	}
	spans, _ = st.SpansForRun(r.RunID)
	if _, _, err := receipt.VerifyTrace(body, spans); err == nil {
		t.Fatal("modified span must fail trace verification")
	}
	// Hiding a covered span by flipping it to "late" is detected too.
	if _, err := st.DB().Exec(`UPDATE spans SET args_summary='git diff' WHERE run_id=? AND args_summary='ls'`, r.RunID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`UPDATE spans SET late=1 WHERE run_id=? AND args_summary='git status'`, r.RunID); err != nil {
		t.Fatal(err)
	}
	spans, _ = st.SpansForRun(r.RunID)
	if _, _, err := receipt.VerifyTrace(body, spans); err == nil {
		t.Fatal("covered span flipped to late must fail trace verification")
	}
	// Deleting a covered span is detected.
	if _, err := st.DB().Exec(`DELETE FROM spans WHERE run_id=? AND args_summary='git status'`, r.RunID); err != nil {
		t.Fatal(err)
	}
	spans, _ = st.SpansForRun(r.RunID)
	if _, _, err := receipt.VerifyTrace(body, spans); err == nil {
		t.Fatal("deleted span must fail trace verification")
	}
}

func TestSessionRunsKillSwitchAndContinuation(t *testing.T) {
	c, st, _ := testCollector(t, "")
	opts := RunOptions{AgentID: "claude-code", FleetID: "default"}
	s1, err := c.EnsureSessionRun("claude-code", "sess", opts)
	if err != nil || s1.Blocked {
		t.Fatalf("first: %+v %v", s1, err)
	}
	again, _ := c.EnsureSessionRun("claude-code", "sess", opts)
	if again.Run.RunID != s1.Run.RunID {
		t.Fatal("same session must resolve to the same live run")
	}
	// Normal end: the next call continues in a linked segment.
	if _, err := c.SealRun(s1.Run.RunID, model.RunCompleted, nil, nil); err != nil {
		t.Fatal(err)
	}
	s2, _ := c.EnsureSessionRun("claude-code", "sess", opts)
	if s2.Run.RunID == s1.Run.RunID || s2.Run.ParentRunID == nil || *s2.Run.ParentRunID != s1.Run.RunID {
		t.Fatalf("continuation should link to previous segment: %+v", s2.Run)
	}
	// Kill: the session stays blocked.
	kr := &model.KillRecord{Scope: model.KillScopeRun, Actor: "dan", Reason: "runaway", Target: s2.Run.RunID}
	if _, err := c.SealRun(s2.Run.RunID, model.RunKilledOperator, kr, nil); err != nil {
		t.Fatal(err)
	}
	s3, _ := c.EnsureSessionRun("claude-code", "sess", opts)
	if !s3.Blocked || !strings.Contains(s3.BlockReason, "runaway") {
		t.Fatalf("killed session must stay blocked: %+v", s3)
	}
	// Quarantine blocks every session of the agent.
	if err := st.QuarantineAgent("claude-code", time.Now().Add(time.Hour), "incident"); err != nil {
		t.Fatal(err)
	}
	s4, _ := c.EnsureSessionRun("claude-code", "other-session", opts)
	if !s4.Blocked {
		t.Fatal("quarantined agent must be blocked")
	}
}

func TestSessionRunManySegmentsAndConcurrency(t *testing.T) {
	c, _, _ := testCollector(t, "")
	opts := RunOptions{AgentID: "codex", FleetID: "default"}
	var prev string
	for i := 0; i < 40; i++ { // 40 Codex turns, each sealed by Stop
		s, err := c.EnsureSessionRun("codex", "long", opts)
		if err != nil || s.Blocked {
			t.Fatalf("turn %d: %+v %v", i, s, err)
		}
		if s.Run.RunID != SessionRunID("codex", "long", i) {
			t.Fatalf("turn %d resolved to the wrong segment", i)
		}
		if i > 0 && (s.Run.ParentRunID == nil || *s.Run.ParentRunID != prev) {
			t.Fatalf("turn %d not linked to %s", i, prev)
		}
		prev = s.Run.RunID
		if _, err := c.SealRun(s.Run.RunID, model.RunCompleted, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	// Parallel tool calls in one turn must land in one run.
	ids := make(chan string, 16)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := c.EnsureSessionRun("codex", "par", opts)
			if err != nil {
				t.Error(err)
				return
			}
			ids <- s.Run.RunID
		}()
	}
	wg.Wait()
	close(ids)
	seen := map[string]bool{}
	for id := range ids {
		seen[id] = true
	}
	if len(seen) != 1 {
		t.Fatalf("parallel hooks split across %d runs", len(seen))
	}
}
