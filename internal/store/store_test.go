package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/calasdan-sketch/warden/internal/model"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func testRun(id string) *model.Run {
	parent := "parent-1"
	return &model.Run{
		RunID:       id,
		ParentRunID: &parent,
		AgentID:     "jarvis:code",
		FleetID:     "prod",
		Operator:    "dan",
		StartedAt:   time.Now().UTC().Truncate(time.Millisecond),
		Status:      model.RunRunning,
		Model:       "claude-opus-4-6",
		Command:     "npm test",
		PID:         1234,
	}
}

func TestRunCRUD(t *testing.T) {
	s := openTest(t)
	r := testRun("run-1")
	if err := s.CreateRun(r); err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	got, err := s.GetRun("run-1")
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if got.AgentID != "jarvis:code" || got.FleetID != "prod" || got.Status != model.RunRunning {
		t.Errorf("roundtrip mismatch: %+v", got)
	}
	if got.ParentRunID == nil || *got.ParentRunID != "parent-1" {
		t.Errorf("parent not preserved: %+v", got.ParentRunID)
	}
	if !got.StartedAt.Equal(r.StartedAt) {
		t.Errorf("started_at not preserved: %v vs %v", got.StartedAt, r.StartedAt)
	}

	// Seal the run.
	ended := time.Now().UTC().Truncate(time.Millisecond)
	ks, kr, kb := "operator", "looping on npm install", "dan"
	got.Status = model.RunKilledOperator
	got.EndedAt = &ended
	got.KillSource, got.KillReason, got.KilledBy = &ks, &kr, &kb
	got.ToolCalls = 42
	if err := s.UpdateRun(got); err != nil {
		t.Fatalf("UpdateRun: %v", err)
	}
	got2, err := s.GetRun("run-1")
	if err != nil {
		t.Fatalf("GetRun after seal: %v", err)
	}
	if got2.Status != model.RunKilledOperator || got2.ToolCalls != 42 {
		t.Errorf("seal not persisted: %+v", got2)
	}
	if got2.KillReason == nil || *got2.KillReason != "looping on npm install" {
		t.Errorf("kill reason not persisted")
	}

	if err := s.UpdateRun(&model.Run{RunID: "nope"}); err == nil {
		t.Error("UpdateRun on missing run should fail")
	}
}

func TestListRunsFilter(t *testing.T) {
	s := openTest(t)
	for _, id := range []string{"a", "b", "c"} {
		r := testRun(id)
		if id == "c" {
			r.Status = model.RunCompleted
		}
		if id == "b" {
			r.FleetID = "nightly"
		}
		if err := s.CreateRun(r); err != nil {
			t.Fatal(err)
		}
	}
	live, err := s.ListRuns(RunFilter{LiveOnly: true})
	if err != nil || len(live) != 2 {
		t.Errorf("LiveOnly: got %d runs, err %v", len(live), err)
	}
	done, err := s.ListRuns(RunFilter{Status: model.RunCompleted})
	if err != nil || len(done) != 1 || done[0].RunID != "c" {
		t.Errorf("Status filter wrong: %v %v", done, err)
	}
	prod, err := s.ListRuns(RunFilter{FleetID: "prod"})
	if err != nil || len(prod) != 2 {
		t.Errorf("FleetID filter wrong: %v %v", prod, err)
	}
	n, err := s.CountLive()
	if err != nil || n != 2 {
		t.Errorf("CountLive = %d, %v; want 2", n, err)
	}
}

func TestSpanRoundtrip(t *testing.T) {
	s := openTest(t)
	if err := s.CreateRun(testRun("run-1")); err != nil {
		t.Fatal(err)
	}
	sp := &model.Span{
		SpanID: "span-1", RunID: "run-1", Kind: model.SpanToolCall, Name: "bash",
		AgentID: "jarvis:code", FleetID: "prod", StartedAt: time.Now().UTC().Truncate(time.Millisecond),
		Tool: "bash", ArgsSummary: "npm test", ArgHash: "abc123", ExitStatus: 0,
		PolicyDecision: "allow", PolicyVersion: "3", Redacted: true,
	}
	if err := s.InsertSpan(sp); err != nil {
		t.Fatalf("InsertSpan: %v", err)
	}
	got, err := s.SpansForRun("run-1")
	if err != nil {
		t.Fatalf("SpansForRun: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 span, got %d", len(got))
	}
	g := got[0]
	if g.Kind != model.SpanToolCall || g.Tool != "bash" || !g.Redacted || g.PolicyDecision != "allow" {
		t.Errorf("span mismatch: %+v", g)
	}
}

func TestEventsAlerts(t *testing.T) {
	s := openTest(t)
	if err := s.InsertEvent(&model.Event{RunID: "r1", At: time.Now(), Severity: "warning", Kind: "guard_trip", Message: "budget 80%"}); err != nil {
		t.Fatal(err)
	}
	evs, err := s.EventsForRun("r1", 10)
	if err != nil || len(evs) != 1 || evs[0].Kind != "guard_trip" {
		t.Errorf("events wrong: %v %v", evs, err)
	}

	a := &model.Alert{Rule: "loop_detection", Severity: "warning", AgentID: "jarvis:code",
		Message: "m", Threshold: ">=10", Observed: "14", At: time.Now(), Status: "active", Fingerprint: "fp1"}
	if err := s.InsertAlert(a); err != nil {
		t.Fatal(err)
	}
	fps, err := s.ActiveAlertFingerprints()
	if err != nil || !fps["fp1"] {
		t.Errorf("fingerprint missing: %v %v", fps, err)
	}
	if err := s.ResolveAlertsByFingerprint("fp1"); err != nil {
		t.Fatal(err)
	}
	fps, _ = s.ActiveAlertFingerprints()
	if fps["fp1"] {
		t.Error("fingerprint should be resolved")
	}
	rec, err := s.ListAlerts("recovered", 10)
	if err != nil || len(rec) != 1 {
		t.Errorf("recovered alerts wrong: %v %v", rec, err)
	}
}

func TestReceiptChain(t *testing.T) {
	s := openTest(t)
	h, err := s.LatestReceiptHash()
	if err != nil || h != "" {
		t.Errorf("empty chain head should be empty, got %q %v", h, err)
	}
	r := &model.Receipt{RunID: "r1", AgentID: "a", BodyHash: "h1", PrevHash: "", Signature: "sig", KeyID: "k1", SealedAt: time.Now()}
	if err := s.StoreReceipt(r, `{"run_id":"r1"}`); err != nil {
		t.Fatal(err)
	}
	h, err = s.LatestReceiptHash()
	if err != nil || h != "h1" {
		t.Errorf("chain head = %q, want h1 (%v)", h, err)
	}
	got, body, err := s.GetReceipt("r1")
	if err != nil || got.BodyHash != "h1" || body != `{"run_id":"r1"}` {
		t.Errorf("receipt mismatch: %+v %q %v", got, body, err)
	}
}

func TestKillAuditAndState(t *testing.T) {
	s := openTest(t)
	rec := &model.KillRecord{At: time.Now(), Actor: "dan", Scope: model.KillScopeRun,
		Target: "run-1", Reason: "looping", Result: "killed"}
	if err := s.InsertKill(rec); err != nil {
		t.Fatal(err)
	}
	if rec.ID == 0 {
		t.Error("kill record ID not set")
	}
	kills, err := s.ListKills(10)
	if err != nil || len(kills) != 1 || kills[0].Scope != model.KillScopeRun || kills[0].Reason != "looping" {
		t.Errorf("kills wrong: %v %v", kills, err)
	}

	// Agent quarantine with TTL.
	if err := s.QuarantineAgent("evil:bot", time.Now().Add(time.Hour), "compromised"); err != nil {
		t.Fatal(err)
	}
	q, reason, err := s.IsAgentQuarantined("evil:bot")
	if err != nil || !q || reason != "compromised" {
		t.Errorf("quarantine wrong: %v %q %v", q, reason, err)
	}
	q, _, _ = s.IsAgentQuarantined("good:bot")
	if q {
		t.Error("good:bot should not be quarantined")
	}
	// Expired quarantine auto-clears.
	if err := s.QuarantineAgent("old:bot", time.Now().Add(-time.Hour), "x"); err != nil {
		t.Fatal(err)
	}
	q, _, _ = s.IsAgentQuarantined("old:bot")
	if q {
		t.Error("expired quarantine should clear")
	}
	if err := s.ClearAgentQuarantine("evil:bot"); err != nil {
		t.Fatal(err)
	}

	// Fleet freeze.
	hd := time.Now().Add(5 * time.Minute)
	if err := s.FreezeFleet("prod", time.Now().Add(time.Hour), hd, "incident-42"); err != nil {
		t.Fatal(err)
	}
	frozen, reason, gotHD, err := s.FleetFreezeState("prod")
	if err != nil || !frozen || reason != "incident-42" {
		t.Errorf("freeze wrong: %v %q %v", frozen, reason, err)
	}
	if gotHD.Sub(hd).Abs() > time.Second {
		t.Errorf("hard deadline wrong: %v vs %v", gotHD, hd)
	}
	if err := s.UnfreezeFleet("prod"); err != nil {
		t.Fatal(err)
	}
	frozen, _, _, _ = s.FleetFreezeState("prod")
	if frozen {
		t.Error("fleet should be unfrozen")
	}

	// Tool deny-list.
	if err := s.DenyTool("web_fetch", "", "exfil risk"); err != nil {
		t.Fatal(err)
	}
	denied, reason, err := s.IsToolDenied("web_fetch", "prod")
	if err != nil || !denied || reason != "exfil risk" {
		t.Errorf("tool deny wrong: %v %q %v", denied, reason, err)
	}
	if err := s.DenyTool("bash", "nightly", "nightly lockdown"); err != nil {
		t.Fatal(err)
	}
	denied, _, _ = s.IsToolDenied("bash", "prod")
	if denied {
		t.Error("fleet-scoped deny should not apply to other fleets")
	}
	denied, _, _ = s.IsToolDenied("bash", "nightly")
	if !denied {
		t.Error("fleet-scoped deny should apply to nightly")
	}
	denies, err := s.ListToolDenies()
	if err != nil || len(denies) != 2 {
		t.Errorf("denies wrong: %v %v", denies, err)
	}
	if err := s.AllowTool("web_fetch", ""); err != nil {
		t.Fatal(err)
	}
	denied, _, _ = s.IsToolDenied("web_fetch", "prod")
	if denied {
		t.Error("tool should be allowed again")
	}
}

func TestApprovals(t *testing.T) {
	s := openTest(t)
	id, err := s.RequestApproval("run-1", "delete-s3-bucket", time.Now())
	if err != nil || id == 0 {
		t.Fatalf("RequestApproval: %v %v", id, err)
	}
	pending, err := s.PendingApprovals()
	if err != nil || len(pending) != 1 || pending[0].Gate != "delete-s3-bucket" {
		t.Errorf("pending wrong: %v %v", pending, err)
	}
	if err := s.DecideApproval(id, "denied", "dan", "too risky", time.Now()); err != nil {
		t.Fatalf("DecideApproval: %v", err)
	}
	pending, _ = s.PendingApprovals()
	if len(pending) != 0 {
		t.Error("approval should be decided")
	}
	if err := s.DecideApproval(id, "approved", "dan", "", time.Now()); err == nil {
		t.Error("double-decide should fail")
	}
}
