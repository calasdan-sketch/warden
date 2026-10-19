package collect

import (
	"syscall"
	"testing"
	"time"

	"warden/internal/model"
	"warden/internal/receipt"
	"warden/internal/store"
)

const testPolicyYAML = `
version: 1
shell:
  default: deny
  allow: [echo, sleep, sh]
egress:
  default: deny
files:
  credential_adjacent: require_approval
deny_tools: []
approval_tools: []
`

func TestWrapSuccess(t *testing.T) {
	c, st, _ := testCollector(t, testPolicyYAML)
	r, err := c.NewRunner(RunOptions{
		AgentID: "jarvis:code", FleetID: "prod", Operator: "dan", Command: "echo hello",
	})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	if err := r.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	r.Wait()
	if r.ExitCode() != 0 {
		t.Errorf("exit code = %d, want 0", r.ExitCode())
	}
	got, err := st.GetRun(r.RunID())
	if err != nil || got.Status != model.RunCompleted {
		t.Errorf("run status = %+v, %v; want completed", got, err)
	}
	if got.PID == 0 {
		t.Error("run should record child PID")
	}
	// Receipt sealed and verifiable.
	rec, body, err := st.GetReceipt(r.RunID())
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	signerPub := c.signer.PublicKey()
	if err := receipt.Verify(rec, body, signerPub); err != nil {
		t.Errorf("receipt verify: %v", err)
	}
	// pidfile cleaned up.
	if _, err := ReadPidFile(c.dataDir, r.RunID()); err == nil {
		t.Error("pidfile should be removed after seal")
	}
}

func TestWrapDeniedCommand(t *testing.T) {
	c, st, _ := testCollector(t, testPolicyYAML)
	_, err := c.NewRunner(RunOptions{
		AgentID: "jarvis:code", FleetID: "prod", Command: "terraform apply",
	})
	if err == nil {
		t.Fatal("expected policy refusal")
	}
	// The attempt is recorded: a failed run with a denied span.
	runs, err := st.ListRuns(store.RunFilter{Status: model.RunFailed})
	if err != nil || len(runs) != 1 {
		t.Fatalf("expected one failed run: %v %v", runs, err)
	}
	spans, _ := st.SpansForRun(runs[0].RunID)
	denied := false
	for _, s := range spans {
		if s.Status == "denied" {
			denied = true
		}
	}
	if !denied {
		t.Error("denied span not recorded")
	}
	if _, _, err := st.GetReceipt(runs[0].RunID); err != nil {
		t.Errorf("refused run must still seal a receipt: %v", err)
	}
}

func TestWrapKillLive(t *testing.T) {
	c, st, _ := testCollector(t, testPolicyYAML)
	r, err := c.NewRunner(RunOptions{
		AgentID: "jarvis:code", FleetID: "prod", Operator: "dan", Command: "sleep 30",
	})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	if err := r.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// The run is live: pidfile exists, status running.
	pf, err := ReadPidFile(c.dataDir, r.RunID())
	if err != nil {
		t.Fatalf("pidfile: %v", err)
	}
	if pf.PGID <= 0 {
		t.Fatalf("bad pgid in pidfile: %+v", pf)
	}

	if err := r.Shutdown("test kill: loop suspected", "tester"); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	got, err := st.GetRun(r.RunID())
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.RunKilledOperator {
		t.Errorf("status = %s, want killed_operator", got.Status)
	}
	if got.KillReason == nil || *got.KillReason != "test kill: loop suspected" {
		t.Errorf("kill reason not preserved: %+v", got.KillReason)
	}
	if got.KilledBy == nil || *got.KilledBy != "tester" {
		t.Errorf("killed_by not preserved: %+v", got.KilledBy)
	}
	// The process tree is actually dead.
	time.Sleep(200 * time.Millisecond)
	if err := syscall.Kill(-pf.PGID, 0); err == nil {
		t.Error("process group should be dead after kill")
	}
	// Receipt sealed even on kill, and verifiable.
	rec, body, err := st.GetReceipt(r.RunID())
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	if rec.Status != model.RunKilledOperator {
		t.Errorf("receipt status = %s, want killed_operator", rec.Status)
	}
	if err := receipt.Verify(rec, body, c.signer.PublicKey()); err != nil {
		t.Errorf("killed receipt must verify: %v", err)
	}
	// Kill is audited with the required reason.
	kills, err := st.ListKills(10)
	if err != nil || len(kills) != 1 {
		t.Fatalf("kill audit: %v %v", kills, err)
	}
	if kills[0].Scope != model.KillScopeRun || kills[0].Reason != "test kill: loop suspected" || kills[0].Actor != "tester" {
		t.Errorf("kill audit wrong: %+v", kills[0])
	}
}

func TestShutdownIdempotent(t *testing.T) {
	c, st, _ := testCollector(t, testPolicyYAML)
	r, err := c.NewRunner(RunOptions{AgentID: "a", FleetID: "f", Command: "sleep 30"})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	if err := r.Shutdown("first", "tester"); err != nil {
		t.Fatal(err)
	}
	if err := r.Shutdown("second", "tester"); err != nil {
		t.Errorf("second shutdown should be a no-op, got: %v", err)
	}
	kills, _ := st.ListKills(10)
	if len(kills) != 1 {
		t.Errorf("idempotent kill must audit exactly once, got %d", len(kills))
	}
}

func TestWrapFailedCommand(t *testing.T) {
	c, st, _ := testCollector(t, testPolicyYAML)
	r, err := c.NewRunner(RunOptions{AgentID: "a", FleetID: "f", Command: "echo hi; exit 3"})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	r.Wait()
	if r.ExitCode() != 3 {
		t.Errorf("exit code = %d, want 3", r.ExitCode())
	}
	got, _ := st.GetRun(r.RunID())
	if got.Status != model.RunFailed {
		t.Errorf("status = %s, want failed", got.Status)
	}
}
