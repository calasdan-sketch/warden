package anomaly

import (
	"path/filepath"
	"testing"
	"time"

	"warden/internal/model"
	"warden/internal/store"
)

var fixedNow = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

func testEngine(t *testing.T) (*Engine, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "warden.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := New(st)
	e.now = func() time.Time { return fixedNow }
	return e, st
}

func mkRun(t *testing.T, st *store.Store, id, agent, fleet string, started time.Time, status model.RunStatus, cost float64) *model.Run {
	t.Helper()
	r := &model.Run{
		RunID: id, AgentID: agent, FleetID: fleet, Operator: "dan",
		StartedAt: started, Status: status, CostUSD: cost,
	}
	if status != model.RunRunning {
		ended := started.Add(time.Minute)
		r.EndedAt = &ended
	}
	if err := st.CreateRun(r); err != nil {
		t.Fatal(err)
	}
	return r
}

func mkSpan(t *testing.T, st *store.Store, run *model.Run, kind model.SpanKind, at time.Time, mut func(*model.Span)) {
	t.Helper()
	sp := &model.Span{
		SpanID: string(kind) + "-" + run.RunID + "-" + at.Format("150405.000000"),
		RunID:  run.RunID, Kind: kind, AgentID: run.AgentID, FleetID: run.FleetID,
		StartedAt: at,
	}
	if mut != nil {
		mut(sp)
	}
	if err := st.InsertSpan(sp); err != nil {
		t.Fatal(err)
	}
}

func activeRules(t *testing.T, st *store.Store) map[string]bool {
	t.Helper()
	fps, err := st.ActiveAlertFingerprints()
	if err != nil {
		t.Fatal(err)
	}
	return fps
}

func TestSpendVelocity(t *testing.T) {
	e, st := testEngine(t)
	agent := "spender"
	// 48 hours of $2/hr baseline.
	for i := 48; i >= 1; i-- {
		mkRun(t, st, "base-"+time.Now().Format("150405")+string(rune(i)), agent, "prod",
			fixedNow.Add(-time.Duration(i)*time.Hour), model.RunCompleted, 2.0)
	}
	// Current hour: $2 baseline run + $20 spike = $22/hr vs $2 median.
	mkRun(t, st, "spike-base", agent, "prod", fixedNow.Add(-30*time.Minute), model.RunCompleted, 2.0)
	target := mkRun(t, st, "spike", agent, "prod", fixedNow.Add(-10*time.Minute), model.RunRunning, 20.0)

	fired, err := e.EvaluateRun(target.RunID)
	if err != nil {
		t.Fatal(err)
	}
	var sv *model.Alert
	for _, a := range fired {
		if a.Rule == RuleSpendVelocity {
			sv = a
		}
	}
	if sv == nil {
		t.Fatalf("want a spend_velocity alert, got %+v", fired)
	}
	if sv.Severity != "warning" {
		t.Errorf("severity = %s, want warning", sv.Severity)
	}
	if sv.Threshold == "" || sv.Observed == "" {
		t.Error("alert must name threshold and observed value")
	}
	// Transition-only: second evaluation fires nothing new.
	fired, _ = e.EvaluateRun(target.RunID)
	if len(fired) != 0 {
		t.Errorf("re-evaluation should not re-fire, got %d", len(fired))
	}
}

func TestSpendVelocityBelowFloor(t *testing.T) {
	e, st := testEngine(t)
	agent := "quiet"
	for i := 10; i >= 1; i-- {
		mkRun(t, st, "qbase"+string(rune('a'+i)), agent, "prod",
			fixedNow.Add(-time.Duration(i)*time.Hour), model.RunCompleted, 0.01)
	}
	target := mkRun(t, st, "qrun", agent, "prod", fixedNow.Add(-time.Minute), model.RunRunning, 0.50)
	fired, err := e.EvaluateRun(target.RunID)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range fired {
		if a.Rule == RuleSpendVelocity {
			t.Errorf("spend velocity must not fire below the $%.0f/hr floor", spendVelocityFloor)
		}
	}
}

func TestRunCostOutlier(t *testing.T) {
	e, st := testEngine(t)
	agent := "steady"
	for i := 0; i < 6; i++ {
		mkRun(t, st, "hist"+string(rune('a'+i)), agent, "prod",
			fixedNow.Add(-time.Duration(6-i)*time.Hour), model.RunCompleted, 1.0)
	}
	target := mkRun(t, st, "outlier", agent, "prod", fixedNow.Add(-time.Minute), model.RunRunning, 50.0)
	fired, err := e.EvaluateRun(target.RunID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range fired {
		if a.Rule == RuleRunCostOutlier {
			found = true
			if a.Threshold == "" || a.Observed == "" {
				t.Error("alert must name threshold and observed value")
			}
		}
	}
	if !found {
		t.Errorf("run_cost_outlier should fire, got %+v", fired)
	}
	// A normal run does not fire.
	normal := mkRun(t, st, "normal", agent, "prod", fixedNow.Add(-time.Minute), model.RunRunning, 1.0)
	fired, _ = e.EvaluateRun(normal.RunID)
	for _, a := range fired {
		if a.Rule == RuleRunCostOutlier {
			t.Error("normal run should not be an outlier")
		}
	}
}

func TestLoopDetection(t *testing.T) {
	e, st := testEngine(t)
	r := mkRun(t, st, "loopy", "agent", "prod", fixedNow.Add(-time.Hour), model.RunRunning, 5)
	base := fixedNow.Add(-50 * time.Minute)
	for i := 0; i < 12; i++ {
		at := base.Add(time.Duration(i) * time.Minute)
		mkSpan(t, st, r, model.SpanToolCall, at, func(sp *model.Span) {
			sp.Tool = "bash"
			sp.ArgHash = "deadbeef"
			sp.ArgsSummary = "npm test"
		})
		// Thinking between calls must NOT break the streak.
		mkSpan(t, st, r, model.SpanLLMCall, at.Add(30*time.Second), nil)
	}
	fired, err := e.EvaluateRun(r.RunID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range fired {
		if a.Rule == RuleLoopDetection {
			found = true
		}
	}
	if !found {
		t.Errorf("loop_detection should fire, got %+v", fired)
	}
	// Below threshold: 9 identical calls, no fire.
	r2 := mkRun(t, st, "notloopy", "agent", "prod", fixedNow.Add(-time.Hour), model.RunRunning, 1)
	for i := 0; i < 9; i++ {
		mkSpan(t, st, r2, model.SpanToolCall, base.Add(time.Duration(i)*time.Minute), func(sp *model.Span) {
			sp.Tool = "bash"
			sp.ArgHash = "deadbeef"
		})
	}
	fired, _ = e.EvaluateRun(r2.RunID)
	for _, a := range fired {
		if a.Rule == RuleLoopDetection {
			t.Error("9 identical calls should not trip the loop rule")
		}
	}
	// A file.op between identical calls breaks the streak.
	r3 := mkRun(t, st, "broken", "agent", "prod", fixedNow.Add(-time.Hour), model.RunRunning, 1)
	for i := 0; i < 12; i++ {
		mkSpan(t, st, r3, model.SpanToolCall, base.Add(time.Duration(i)*time.Minute), func(sp *model.Span) {
			sp.Tool = "bash"
			sp.ArgHash = "deadbeef"
		})
		if i == 5 {
			mkSpan(t, st, r3, model.SpanFileOp, base.Add(time.Duration(i)*time.Minute).Add(time.Second), func(sp *model.Span) {
				sp.Path = "/x/out.txt"
				sp.Op = "write"
			})
		}
	}
	fired, _ = e.EvaluateRun(r3.RunID)
	for _, a := range fired {
		if a.Rule == RuleLoopDetection {
			t.Error("state change between calls should break the loop streak")
		}
	}
}

func TestFirstSeenTool(t *testing.T) {
	e, st := testEngine(t)
	old := mkRun(t, st, "oldrun", "agent", "prod", fixedNow.Add(-48*time.Hour), model.RunCompleted, 1)
	mkSpan(t, st, old, model.SpanToolCall, fixedNow.Add(-47*time.Hour), func(sp *model.Span) { sp.Tool = "bash" })

	r := mkRun(t, st, "newrun", "agent", "prod", fixedNow.Add(-time.Hour), model.RunRunning, 1)
	mkSpan(t, st, r, model.SpanToolCall, fixedNow.Add(-30*time.Minute), func(sp *model.Span) { sp.Tool = "bash" })
	mkSpan(t, st, r, model.SpanToolCall, fixedNow.Add(-20*time.Minute), func(sp *model.Span) { sp.Tool = "web_fetch" })

	fired, err := e.EvaluateRun(r.RunID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range fired {
		if a.Rule == RuleFirstSeenTool {
			found = true
			if a.Severity != "info" {
				t.Errorf("first_seen_tool severity = %s, want info", a.Severity)
			}
		}
	}
	if !found {
		t.Errorf("first_seen_tool should fire for web_fetch, got %+v", fired)
	}
	// Transition-only.
	fired, _ = e.EvaluateRun(r.RunID)
	for _, a := range fired {
		if a.Rule == RuleFirstSeenTool {
			t.Error("first_seen_tool re-fired")
		}
	}
}

func TestFirstSeenEgressHost(t *testing.T) {
	e, st := testEngine(t)
	old := mkRun(t, st, "oldrun", "agent", "fleet-a", fixedNow.Add(-48*time.Hour), model.RunCompleted, 1)
	mkSpan(t, st, old, model.SpanNetEgress, fixedNow.Add(-47*time.Hour), func(sp *model.Span) {
		sp.Host = "api.anthropic.com"
	})
	r := mkRun(t, st, "newrun", "agent", "fleet-a", fixedNow.Add(-time.Hour), model.RunRunning, 1)
	mkSpan(t, st, r, model.SpanNetEgress, fixedNow.Add(-30*time.Minute), func(sp *model.Span) {
		sp.Host = "api.anthropic.com"
	})
	mkSpan(t, st, r, model.SpanNetEgress, fixedNow.Add(-20*time.Minute), func(sp *model.Span) {
		sp.Host = "pastebin.example"
	})
	fired, err := e.EvaluateRun(r.RunID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range fired {
		if a.Rule == RuleFirstSeenEgressHost {
			found = true
		}
	}
	if !found {
		t.Errorf("first_seen_egress_host should fire, got %+v", fired)
	}
}

func TestEgressAfterIngest(t *testing.T) {
	e, st := testEngine(t)
	r := mkRun(t, st, "exfil", "agent", "prod", fixedNow.Add(-time.Hour), model.RunRunning, 1)
	mkSpan(t, st, r, model.SpanToolCall, fixedNow.Add(-30*time.Minute), func(sp *model.Span) {
		sp.Tool = "web_fetch"
		sp.OutputBytes = 50 * 1024
	})
	mkSpan(t, st, r, model.SpanNetEgress, fixedNow.Add(-28*time.Minute), func(sp *model.Span) {
		sp.Host = "evil.example.com"
	})
	fired, err := e.EvaluateRun(r.RunID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range fired {
		if a.Rule == RuleEgressAfterIngest {
			found = true
			if a.Severity != "critical" {
				t.Errorf("egress_after_ingest severity = %s, want critical", a.Severity)
			}
		}
	}
	if !found {
		t.Errorf("egress_after_ingest should fire, got %+v", fired)
	}
	// Small output: no fire.
	r2 := mkRun(t, st, "fine", "agent", "prod", fixedNow.Add(-time.Hour), model.RunRunning, 1)
	mkSpan(t, st, r2, model.SpanToolCall, fixedNow.Add(-30*time.Minute), func(sp *model.Span) {
		sp.Tool = "web_fetch"
		sp.OutputBytes = 100
	})
	mkSpan(t, st, r2, model.SpanNetEgress, fixedNow.Add(-28*time.Minute), func(sp *model.Span) {
		sp.Host = "other.example.com"
	})
	fired, _ = e.EvaluateRun(r2.RunID)
	for _, a := range fired {
		if a.Rule == RuleEgressAfterIngest {
			t.Error("small outputs should not trip egress_after_ingest")
		}
	}
}

func TestCredentialAdjacentFile(t *testing.T) {
	e, st := testEngine(t)
	r := mkRun(t, st, "creds", "agent", "prod", fixedNow.Add(-time.Hour), model.RunRunning, 1)
	mkSpan(t, st, r, model.SpanFileOp, fixedNow.Add(-30*time.Minute), func(sp *model.Span) {
		sp.Path = "/home/dan/.env"
		sp.Op = "read"
	})
	fired, err := e.EvaluateRun(r.RunID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range fired {
		if a.Rule == RuleCredentialFileAccess {
			found = true
		}
	}
	if !found {
		t.Errorf("credential_adjacent_file should fire, got %+v", fired)
	}
}

func TestSpawnStorm(t *testing.T) {
	e, st := testEngine(t)
	r := mkRun(t, st, "storm", "agent", "prod", fixedNow.Add(-time.Hour), model.RunRunning, 1)
	base := fixedNow.Add(-30 * time.Minute)
	for i := 0; i < 12; i++ {
		mkSpan(t, st, r, model.SpanSubagentSpawn, base.Add(time.Duration(i*4)*time.Second), func(sp *model.Span) {
			sp.ChildRunID = "child"
		})
	}
	fired, err := e.EvaluateRun(r.RunID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range fired {
		if a.Rule == RuleSpawnStorm {
			found = true
		}
	}
	if !found {
		t.Errorf("spawn_storm should fire, got %+v", fired)
	}
}

func TestApprovalDenialRetry(t *testing.T) {
	e, st := testEngine(t)
	r := mkRun(t, st, "fight", "agent", "prod", fixedNow.Add(-time.Hour), model.RunRunning, 1)
	mkSpan(t, st, r, model.SpanHumanApproval, fixedNow.Add(-30*time.Minute), func(sp *model.Span) {
		sp.Gate = "delete-bucket"
		sp.Decision = "denied"
	})
	mkSpan(t, st, r, model.SpanHumanApproval, fixedNow.Add(-25*time.Minute), func(sp *model.Span) {
		sp.Gate = "delete-bucket"
		sp.Decision = "denied"
	})
	fired, err := e.EvaluateRun(r.RunID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range fired {
		if a.Rule == RuleApprovalDenialRetry {
			found = true
		}
	}
	if !found {
		t.Errorf("approval_denial_retry should fire, got %+v", fired)
	}
	// Single denial without retry: no fire.
	r2 := mkRun(t, st, "calm", "agent", "prod", fixedNow.Add(-time.Hour), model.RunRunning, 1)
	mkSpan(t, st, r2, model.SpanHumanApproval, fixedNow.Add(-30*time.Minute), func(sp *model.Span) {
		sp.Gate = "delete-bucket"
		sp.Decision = "denied"
	})
	fired, _ = e.EvaluateRun(r2.RunID)
	for _, a := range fired {
		if a.Rule == RuleApprovalDenialRetry {
			t.Error("single denial without retry should not fire")
		}
	}
}

func TestSpinningRun(t *testing.T) {
	e, st := testEngine(t)
	agent := "spinner"
	for i := 0; i < 6; i++ {
		mkRun(t, st, "hist"+string(rune('a'+i)), agent, "prod",
			fixedNow.Add(-time.Duration(10-i)*time.Hour), model.RunCompleted, 1)
	}
	r := mkRun(t, st, "spinning", agent, "prod", fixedNow.Add(-2*time.Hour), model.RunRunning, 8)
	// 1 tool call + burning tokens in the last 15 min.
	mkSpan(t, st, r, model.SpanToolCall, fixedNow.Add(-5*time.Minute), func(sp *model.Span) { sp.Tool = "bash" })
	mkSpan(t, st, r, model.SpanLLMCall, fixedNow.Add(-5*time.Minute), func(sp *model.Span) {
		sp.TokensIn = 1000
		sp.TokensOut = 500
	})
	fired, err := e.EvaluateRun(r.RunID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range fired {
		if a.Rule == RuleSpinningRun {
			found = true
		}
	}
	if !found {
		t.Errorf("spinning_run should fire, got %+v", fired)
	}
}

func TestGuardTripCluster(t *testing.T) {
	e, st := testEngine(t)
	r := mkRun(t, st, "guarded", "agent", "fleet-b", fixedNow.Add(-time.Hour), model.RunRunning, 1)
	for i := 0; i < 3; i++ {
		if err := st.InsertEvent(&model.Event{
			RunID: r.RunID, At: fixedNow.Add(-time.Duration(i*5) * time.Minute),
			Severity: "warning", Kind: "guard_trip", Message: "budget 80%",
		}); err != nil {
			t.Fatal(err)
		}
	}
	fired, err := e.EvaluateFleet("fleet-b")
	if err != nil {
		t.Fatal(err)
	}
	if len(fired) != 1 || fired[0].Rule != RuleGuardTripCluster {
		t.Fatalf("want 1 guard_trip_cluster alert, got %+v", fired)
	}
	// Transition-only.
	fired, _ = e.EvaluateFleet("fleet-b")
	if len(fired) != 0 {
		t.Errorf("re-evaluation should not re-fire, got %d", len(fired))
	}
}

func TestSavingsCollapse(t *testing.T) {
	e, st := testEngine(t)
	fleet := "fleet-c"
	// 7 days of 50% cache-hit rate.
	for d := 7; d >= 1; d-- {
		r := mkRun(t, st, "day"+string(rune('a'+d)), "agent", fleet,
			fixedNow.Add(-time.Duration(d)*24*time.Hour), model.RunCompleted, 2)
		mkSpan(t, st, r, model.SpanLLMCall, fixedNow.Add(-time.Duration(d)*24*time.Hour), func(sp *model.Span) {
			sp.TokensIn = 1000
			sp.TokensOut = 1000
			sp.TokensCached = 1000 // 50%
		})
	}
	// Today: 10%.
	r := mkRun(t, st, "today", "agent", fleet, fixedNow.Add(-time.Hour), model.RunCompleted, 2)
	mkSpan(t, st, r, model.SpanLLMCall, fixedNow.Add(-30*time.Minute), func(sp *model.Span) {
		sp.TokensIn = 1000
		sp.TokensOut = 1000
		sp.TokensCached = 200 // 10%
	})
	fired, err := e.EvaluateFleet(fleet)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range fired {
		if a.Rule == RuleSavingsCollapse {
			found = true
		}
	}
	if !found {
		t.Errorf("savings_collapse should fire, got %+v", fired)
	}
}

func TestEvaluateMissingRun(t *testing.T) {
	e, _ := testEngine(t)
	if _, err := e.EvaluateRun("nope"); err == nil {
		t.Error("missing run should error")
	}
}

func TestRecovery(t *testing.T) {
	e, st := testEngine(t)
	agent := "rec"
	for i := 0; i < 6; i++ {
		mkRun(t, st, "hist"+string(rune('a'+i)), agent, "prod",
			fixedNow.Add(-time.Duration(6-i)*time.Hour), model.RunCompleted, 1.0)
	}
	// Fire the outlier rule (the $50 run also trips spend velocity)...
	target := mkRun(t, st, "outlier", agent, "prod", fixedNow.Add(-time.Minute), model.RunRunning, 50.0)
	fired, err := e.EvaluateRun(target.RunID)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, a := range fired {
		seen[a.Rule] = true
	}
	if !seen[RuleRunCostOutlier] || !seen[RuleSpendVelocity] {
		t.Fatalf("want outlier+velocity alerts, got %+v", fired)
	}
	// ...then the run's cost drops back under P95 (simulating the condition
	// clearing): both alerts must transition to recovered.
	target.CostUSD = 1.0
	if err := st.UpdateRun(target); err != nil {
		t.Fatal(err)
	}
	fired, err = e.EvaluateRun(target.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if len(fired) != 0 {
		t.Errorf("cleared condition should not fire, got %d", len(fired))
	}
	rec, err := st.ListAlerts("recovered", 10)
	if err != nil || len(rec) != 2 {
		t.Fatalf("both alerts should be recovered: %+v %v", rec, err)
	}
}

func TestAllTwelveRulesHaveFixedSeverity(t *testing.T) {
	// The severities are part of the alert contract: fixed per rule, never computed.
	rules := []string{
		RuleSpendVelocity, RuleRunCostOutlier, RuleLoopDetection, RuleFirstSeenTool,
		RuleFirstSeenEgressHost, RuleEgressAfterIngest, RuleCredentialFileAccess,
		RuleSpawnStorm, RuleApprovalDenialRetry, RuleSpinningRun,
		RuleGuardTripCluster, RuleSavingsCollapse,
	}
	if len(rules) != 12 {
		t.Fatalf("want 12 rules, got %d", len(rules))
	}
	seen := map[string]bool{}
	for _, r := range rules {
		if seen[r] {
			t.Errorf("duplicate rule %q", r)
		}
		seen[r] = true
	}
}
