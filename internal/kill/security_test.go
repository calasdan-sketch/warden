package kill

// Regression tests for the v1 scrutiny findings (2026-10-18).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/calasdan-sketch/warden/internal/collect"
	"github.com/calasdan-sketch/warden/internal/model"
)

// TestKillRefusesStalePidfile: a pidfile pointing at a dead PID must never
// be signaled — the kill is recorded as "not signaled" instead of risking
// a recycled PID owned by an innocent process.
func TestKillRefusesStalePidfile(t *testing.T) {
	mgr, col, st, dir := testManager(t)

	r := &model.Run{
		RunID: "run-stale", AgentID: "a", FleetID: "f",
		StartedAt: time.Now().UTC(), Status: model.RunRunning,
	}
	if err := st.CreateRun(r); err != nil {
		t.Fatal(err)
	}
	// Pidfile for a PID that cannot exist.
	if err := writeTestPidFile(dir, r.RunID, 1<<30); err != nil {
		t.Fatal(err)
	}
	if err := mgr.KillRun(r.RunID, "test", "tester"); err != nil {
		t.Fatalf("KillRun: %v", err)
	}
	kills, err := st.ListKills(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(kills) != 1 {
		t.Fatalf("want 1 kill audit record, got %d", len(kills))
	}
	if !strings.Contains(kills[0].Result, "not signaled") {
		t.Errorf("stale pidfile kill result = %q, want refusal note", kills[0].Result)
	}
	got, _ := st.GetRun(r.RunID)
	if got.Status != model.RunKilledOperator {
		t.Errorf("run status = %q, want killed_operator (seal-first)", got.Status)
	}
	_ = col
}

// writeTestPidFile writes a pidfile directly (the collect helper is
// unexported; the JSON shape is the contract).
func writeTestPidFile(dir, runID string, pid int) error {
	if err := os.MkdirAll(filepath.Join(dir, "pids"), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(&collect.PidFile{
		RunID: runID, PID: pid, PGID: pid, AgentID: "a", FleetID: "f",
	})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "pids", runID+".json"), b, 0o600)
}

// TestWaitPGIDExitNoSuchGroup: signaling a nonexistent process group must
// report promptly rather than sleeping out the grace period.
func TestWaitPGIDExitNoSuchGroup(t *testing.T) {
	start := time.Now()
	if !waitPGIDExit(1<<29, 5*time.Second) {
		t.Error("nonexistent process group should report dead immediately")
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("waitPGIDExit took %s for a dead group", time.Since(start))
	}
}
