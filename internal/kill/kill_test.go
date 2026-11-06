package kill

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/calasdan-sketch/warden/internal/collect"
	"github.com/calasdan-sketch/warden/internal/model"
	"github.com/calasdan-sketch/warden/internal/policy"
	"github.com/calasdan-sketch/warden/internal/receipt"
	"github.com/calasdan-sketch/warden/internal/store"
)

const testPolicyYAML = `
version: 1
shell:
  default: deny
  allow: [sleep, echo]
egress:
  default: deny
files:
  credential_adjacent: require_approval
`

func testManager(t *testing.T) (*Manager, *collect.Collector, *store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "warden.db"))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Parse([]byte(testPolicyYAML))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := receipt.Generate()
	if err != nil {
		t.Fatal(err)
	}
	col := collect.New(st, pol, signer, dir)
	mgr := New(st, col, dir)
	t.Cleanup(func() {
		col.Close()
		st.Close()
	})
	return mgr, col, st, dir
}

func startSleeper(t *testing.T, col *collect.Collector, agent, fleet string) *collect.Runner {
	t.Helper()
	r, err := col.NewRunner(collect.RunOptions{AgentID: agent, FleetID: fleet, Command: "sleep 30"})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	if err := r.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return r
}

func pgidAlive(pgid int) bool { return syscall.Kill(-pgid, 0) == nil }

func TestKillRunLive(t *testing.T) {
	mgr, col, st, dir := testManager(t)
	r := startSleeper(t, col, "jarvis:code", "prod")
	pf, err := collect.ReadPidFile(dir, r.RunID())
	if err != nil {
		t.Fatal(err)
	}

	if err := mgr.KillRun(r.RunID(), "looping on nothing", "dan"); err != nil {
		t.Fatalf("KillRun: %v", err)
	}
	r.Wait() // the wrap shim's exit path must stand down, not overwrite

	got, err := st.GetRun(r.RunID())
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.RunKilledOperator {
		t.Errorf("status = %s, want killed_operator", got.Status)
	}
	if got.KillReason == nil || *got.KillReason != "looping on nothing" {
		t.Errorf("kill reason lost: %+v", got.KillReason)
	}
	if src := got.KillSource; src == nil || *src != "run" {
		t.Errorf("kill source = %+v, want run", src)
	}
	time.Sleep(200 * time.Millisecond)
	if pgidAlive(pf.PGID) {
		t.Error("process group should be dead")
	}
	kills, _ := st.ListKills(10)
	if len(kills) != 1 || kills[0].Reason != "looping on nothing" || kills[0].Scope != model.KillScopeRun {
		t.Errorf("kill audit wrong: %+v", kills)
	}
	rec, body, err := st.GetReceipt(r.RunID())
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != model.RunKilledOperator {
		t.Errorf("receipt status = %s", rec.Status)
	}
	if err := receipt.Verify(rec, body, col.SignerPublicKey()); err != nil {
		t.Errorf("receipt verify: %v", err)
	}
}

func TestKillRunRequiresReason(t *testing.T) {
	mgr, col, _, _ := testManager(t)
	r := startSleeper(t, col, "a", "f")
	defer r.Shutdown("cleanup", "test")
	if err := mgr.KillRun(r.RunID(), "", "dan"); err == nil {
		t.Error("empty reason must be rejected")
	}
}

func TestKillRunIdempotentNoOp(t *testing.T) {
	mgr, col, st, _ := testManager(t)
	r := startSleeper(t, col, "a", "f")
	if err := mgr.KillRun(r.RunID(), "first", "dan"); err != nil {
		t.Fatal(err)
	}
	r.Wait()
	if err := mgr.KillRun(r.RunID(), "second", "dan"); err != nil {
		t.Fatalf("second kill should be a no-op, got: %v", err)
	}
	kills, _ := st.ListKills(10)
	if len(kills) != 2 {
		t.Fatalf("want 2 audit rows, got %d", len(kills))
	}
	if kills[0].Result == "" || !contains(kills[0].Result, "no-op") {
		t.Errorf("second kill should audit a no-op: %+v", kills[0])
	}
	got, _ := st.GetRun(r.RunID())
	if got.Status != model.RunKilledOperator || *got.KillReason != "first" {
		t.Errorf("first kill's record must stand: %+v", got)
	}
}

func TestKillRunMissing(t *testing.T) {
	mgr, _, _, _ := testManager(t)
	if err := mgr.KillRun("does-not-exist", "x", "dan"); err == nil {
		t.Error("killing a missing run must fail")
	}
}

func TestQuarantineAgent(t *testing.T) {
	mgr, col, st, _ := testManager(t)
	r := startSleeper(t, col, "evil:bot", "prod")

	if err := mgr.QuarantineAgent("evil:bot", time.Minute, "prompt injection suspected", "dan"); err != nil {
		t.Fatalf("QuarantineAgent: %v", err)
	}
	r.Wait()
	got, _ := st.GetRun(r.RunID())
	if got.Status != model.RunKilledOperator {
		t.Errorf("live run should be killed: %s", got.Status)
	}
	if src := got.KillSource; src == nil || *src != "agent" {
		t.Errorf("kill source = %+v, want agent", src)
	}
	// New runs refused during quarantine.
	if _, err := col.NewRunner(collect.RunOptions{AgentID: "evil:bot", FleetID: "prod", Command: "echo hi"}); err == nil {
		t.Error("quarantined agent must be refused")
	}
	// Other agents unaffected.
	r2 := startSleeper(t, col, "good:bot", "prod")
	defer r2.Shutdown("cleanup", "test")

	if err := mgr.ClearAgentQuarantine("evil:bot", "false alarm", "dan"); err != nil {
		t.Fatal(err)
	}
	r3, err := col.NewRunner(collect.RunOptions{AgentID: "evil:bot", FleetID: "prod", Command: "echo hi"})
	if err != nil {
		t.Errorf("cleared agent should run: %v", err)
	} else {
		r3.Shutdown("cleanup", "test")
	}
}

func TestFreezeFleet(t *testing.T) {
	mgr, col, st, _ := testManager(t)
	r := startSleeper(t, col, "a", "prod")

	if err := mgr.FreezeFleet("prod", time.Minute, "incident-42", "dan"); err != nil {
		t.Fatalf("FreezeFleet: %v", err)
	}
	// New runs refused while frozen.
	if _, err := col.NewRunner(collect.RunOptions{AgentID: "b", FleetID: "prod", Command: "echo hi"}); err == nil {
		t.Error("frozen fleet must refuse new runs")
	}
	// Other fleets unaffected.
	r2 := startSleeper(t, col, "b", "nightly")
	defer r2.Shutdown("cleanup", "test")

	// The live run got the soft-stop signal and sealed on exit.
	r.Wait()
	got, _ := st.GetRun(r.RunID())
	if got.Status == model.RunRunning {
		t.Error("soft-stopped run should have exited")
	}

	if err := mgr.UnfreezeFleet("prod", "incident resolved", "dan"); err != nil {
		t.Fatal(err)
	}
	r3, err := col.NewRunner(collect.RunOptions{AgentID: "b", FleetID: "prod", Command: "echo hi"})
	if err != nil {
		t.Errorf("unfrozen fleet should admit runs: %v", err)
	} else {
		r3.Shutdown("cleanup", "test")
	}

	kills, _ := st.ListKills(10)
	scopes := map[model.KillScope]bool{}
	for _, k := range kills {
		scopes[k.Scope] = true
	}
	if !scopes[model.KillScopeFleet] {
		t.Errorf("fleet kills not audited: %+v", kills)
	}
}

func TestDisableEnableTool(t *testing.T) {
	mgr, col, st, _ := testManager(t)
	if err := mgr.DisableTool("web_fetch", "", "exfil risk", "dan"); err != nil {
		t.Fatal(err)
	}
	denied, _, _ := st.IsToolDenied("web_fetch", "prod")
	if !denied {
		t.Error("tool should be denied")
	}
	// The policy gate picks up the deny-list through the collector's evaluator.
	r, _, err := col.StartRun(collect.RunOptions{AgentID: "a", FleetID: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	span := &model.Span{Kind: model.SpanToolCall, Tool: "web_fetch", RunID: r.RunID}
	if err := col.EmitSpan(span); err != nil {
		t.Fatal(err)
	}
	if span.PolicyDecision != "deny" {
		t.Errorf("deny-listed tool should be denied at the gate: %+v", span)
	}
	if err := mgr.EnableTool("web_fetch", "", "risk cleared", "dan"); err != nil {
		t.Fatal(err)
	}
	denied, _, _ = st.IsToolDenied("web_fetch", "prod")
	if denied {
		t.Error("tool should be re-allowed")
	}
	if err := mgr.DisableTool("", "", "x", "dan"); err == nil {
		t.Error("empty tool name must be rejected")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
