package collect

// Regression tests for the v1 scrutiny findings (2026-10-18): each test
// pins a specific attack or failure mode that was demonstrated live against
// the pre-hardening implementation.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"warden/internal/model"
	"warden/internal/receipt"
	"warden/internal/store"
)

// TestSocketPreDecidedStripped: the supervised agent inherits WARDEN_SOCK and
// can write anything to it. A client-supplied pre_decided flag must never
// let the agent self-approve a tool call and skip the policy gate.
func TestSocketPreDecidedStripped(t *testing.T) {
	c, st, _ := testCollector(t, "")
	r, _ := startTestRun(t, c)

	smuggled, _ := json.Marshal(map[string]any{
		"kind": "tool.call", "tool": "bash", "name": "pwn",
		"args_summary":    "rm -rf / --no-preserve-root",
		"pre_decided":     true,
		"policy_decision": "allow",
		"policy_version":  "evil",
	})
	c.handleLine(r.RunID, r.AgentID, r.FleetID, string(smuggled))

	spans, err := st.SpansForRun(r.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 1 {
		t.Fatalf("want 1 span, got %d", len(spans))
	}
	sp := spans[0]
	if sp.PolicyDecision == "allow" && sp.PolicyVersion == "evil" {
		t.Fatal("CRITICAL: socket smuggled pre_decided=allow past the policy gate")
	}
	if sp.PolicyDecision != "deny" {
		t.Errorf("smuggled rm -rf / must be denied by the gate, got %q", sp.PolicyDecision)
	}
	if sp.Status != "denied" {
		t.Errorf("smuggled span status = %q, want denied", sp.Status)
	}
}

// TestSocketSpanInheritsRunIdentity: spans ingested over the socket must
// carry the run's agent/fleet identity — otherwise anomaly baselines
// (per agent_id) and the dashboard silently misbehave on empty strings.
func TestSocketSpanInheritsRunIdentity(t *testing.T) {
	c, st, _ := testCollector(t, "")
	r, _ := startTestRun(t, c)

	line, _ := json.Marshal(map[string]any{
		"kind": "tool.call", "tool": "web_fetch", "name": "fetch",
		// hostile identity fields: the wire must not override the run's own
		"agent_id": "mallory", "fleet_id": "evil-fleet",
	})
	c.handleLine(r.RunID, r.AgentID, r.FleetID, string(line))

	spans, err := st.SpansForRun(r.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 1 {
		t.Fatalf("want 1 span, got %d", len(spans))
	}
	if spans[0].AgentID != r.AgentID || spans[0].FleetID != r.FleetID {
		t.Errorf("span identity = %q/%q, want run identity %q/%q",
			spans[0].AgentID, spans[0].FleetID, r.AgentID, r.FleetID)
	}
}

// TestWrapDenySpanRecorded: a policy-denied wrap must record its denied span.
// (Pre-fix, the gate span had no SpanID, so every denied wrap after the
// first failed the PK insert silently and only the event survived.)
func TestWrapDenySpanRecorded(t *testing.T) {
	c, st, _ := testCollector(t, "")
	for i := 0; i < 3; i++ {
		_, err := c.NewRunner(RunOptions{
			AgentID: "a", FleetID: "f", Command: "evilbinary do-bad-things",
		})
		if err == nil {
			t.Fatal("denied command must be refused")
		}
	}
	var n int
	if err := st.DB().QueryRow(
		`SELECT COUNT(*) FROM spans WHERE status='denied' AND name='wrap'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("want 3 denied wrap spans recorded, got %d", n)
	}
	var distinct int
	if err := st.DB().QueryRow(
		`SELECT COUNT(DISTINCT span_id) FROM spans WHERE status='denied' AND name='wrap'`).Scan(&distinct); err != nil {
		t.Fatal(err)
	}
	if distinct != 3 {
		t.Errorf("denied spans need distinct span_ids, got %d distinct of 3", distinct)
	}
}

// TestWrapDenyRedactsSecrets: credentials passed as arguments to a denied
// wrap command must not leak into the stored span, the policy reason, or
// the policy_deny audit event.
func TestWrapDenyRedactsSecrets(t *testing.T) {
	c, st, _ := testCollector(t, "")
	raw := "AKIAIOSFODNN7EXAMPLE"
	_, err := c.NewRunner(RunOptions{
		AgentID: "a", FleetID: "f", Command: "evilbinary --key " + raw,
	})
	if err == nil {
		t.Fatal("denied command must be refused")
	}
	tables := []struct{ q, col string }{
		{`SELECT COUNT(*) FROM spans WHERE args_summary LIKE '%' || ? || '%'`, "spans.args_summary"},
		{`SELECT COUNT(*) FROM spans WHERE policy_reason LIKE '%' || ? || '%'`, "spans.policy_reason"},
		{`SELECT COUNT(*) FROM events WHERE message LIKE '%' || ? || '%'`, "events.message"},
		{`SELECT COUNT(*) FROM runs WHERE command LIKE '%' || ? || '%'`, "runs.command"},
	}
	for _, tc := range tables {
		var n int
		if err := st.DB().QueryRow(tc.q, raw).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("raw secret leaked into %s (%d rows)", tc.col, n)
		}
	}
}

// TestConcurrentSealChainIntact: N runs sealed concurrently (separate store
// handles, as separate wrap processes would) must not fork the hash chain.
func TestConcurrentSealChainIntact(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "warden.db")
	st0, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st0.Close()

	const n = 8
	runIDs := make([]string, n)
	for i := 0; i < n; i++ {
		r := &model.Run{
			RunID: fmt.Sprintf("run-%d", i), AgentID: "a", FleetID: "f",
			StartedAt: time.Now().UTC(), Status: model.RunRunning,
		}
		if err := st0.CreateRun(r); err != nil {
			t.Fatal(err)
		}
		runIDs[i] = r.RunID
	}

	signer, err := receipt.Generate() // shared: Seal is pure, safe for concurrent use
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st, err := store.Open(dbPath)
			if err != nil {
				errs[i] = err
				return
			}
			defer st.Close()
			// Seal through the atomic chained path, as SealRun does.
			r, err := st.GetRun(runIDs[i])
			if err != nil {
				errs[i] = err
				return
			}
			claimed, r, err := st.ClaimForSeal(r.RunID, model.RunCompleted)
			if err != nil || !claimed {
				errs[i] = fmt.Errorf("claim: %v %v", claimed, err)
				return
			}
			if _, err := st.SealChained(func(prev string) (*model.Receipt, string, error) {
				now := time.Now().UTC()
				r.EndedAt = &now
				return signer.Seal(receipt.SealInput{Run: r, PrevHash: prev, SealedAt: now})
			}); err != nil {
				errs[i] = err
			}
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("seal %d: %v", i, err)
		}
	}

	all, err := st0.AllReceipts()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != n {
		t.Fatalf("want %d receipts, got %d", n, len(all))
	}
	var recs []*model.Receipt
	for _, sr := range all {
		recs = append(recs, sr.Receipt)
	}
	if err := receipt.VerifyChain(recs); err != nil {
		t.Fatalf("hash chain forked under concurrent seals: %v", err)
	}
}

// TestReconcileSkipsLivePidfile: a run with a stale heartbeat but a live,
// start-time-verified process must NOT be sealed receipt_missing. A run
// with no live process must be.
func TestReconcileSkipsLivePidfile(t *testing.T) {
	c, st, dir := testCollector(t, "")

	live, _ := startTestRun(t, c)
	// Point the pidfile at this very test process (alive, start time known).
	pid := os.Getpid()
	if err := writePidFile(dir, &PidFile{
		RunID: live.RunID, PID: pid, PGID: pid,
		AgentID: live.AgentID, FleetID: live.FleetID,
		StartedAtNs: procStartTimeNs(pid),
	}); err != nil {
		t.Fatal(err)
	}

	dead, _ := startTestRun(t, c) // no pidfile: genuinely dead

	sealed, err := c.Reconcile(0)
	if err != nil {
		t.Fatal(err)
	}
	if sealed != 1 {
		t.Errorf("Reconcile sealed %d runs, want 1 (the dead one)", sealed)
	}
	got, _ := st.GetRun(live.RunID)
	if got.Status != model.RunRunning {
		t.Errorf("live run sealed as %q while its process was alive", got.Status)
	}
	gotDead, _ := st.GetRun(dead.RunID)
	if gotDead.Status != model.RunReceiptMissing {
		t.Errorf("dead run status = %q, want receipt_missing", gotDead.Status)
	}
	// The dead run's stale pidfile (none here) is cleaned; the live one stays.
	if _, err := ReadPidFile(dir, live.RunID); err != nil {
		t.Errorf("live run's pidfile should survive reconcile: %v", err)
	}
}

// TestReconcileDetectsRecycledPID: a pidfile whose PID exists but whose
// start time does not match is treated as dead (PID recycled by the OS).
func TestReconcileDetectsRecycledPID(t *testing.T) {
	if procStartTimeNs(os.Getpid()) == 0 {
		t.Skip("no /proc: start-time check unavailable on this platform")
	}
	c, st, dir := testCollector(t, "")
	r, _ := startTestRun(t, c)
	pid := os.Getpid()
	if err := writePidFile(dir, &PidFile{
		RunID: r.RunID, PID: pid, PGID: pid,
		AgentID: r.AgentID, FleetID: r.FleetID,
		StartedAtNs: procStartTimeNs(pid) + 1, // wrong: simulates a recycled PID
	}); err != nil {
		t.Fatal(err)
	}
	if pidAliveForRun(dir, r.RunID) {
		t.Error("pidfile with mismatched start time must not count as alive")
	}
	sealed, err := c.Reconcile(0)
	if err != nil {
		t.Fatal(err)
	}
	if sealed != 1 {
		t.Errorf("recycled-PID run should be reconciled, sealed=%d", sealed)
	}
	got, _ := st.GetRun(r.RunID)
	if got.Status != model.RunReceiptMissing {
		t.Errorf("status = %q, want receipt_missing", got.Status)
	}
}

// TestProcStartTimeSane: the test process's own start time must be stable
// across reads (the primitive the kill-path verification rests on).
func TestProcStartTimeSane(t *testing.T) {
	a := procStartTimeNs(os.Getpid())
	if a == 0 {
		t.Skip("no /proc on this platform")
	}
	b := procStartTimeNs(os.Getpid())
	if a != b {
		t.Errorf("start time unstable: %d != %d", a, b)
	}
	if !strings.HasPrefix(fmt.Sprint(a), "1") {
		t.Errorf("start time %d does not look like unix nanos", a)
	}
}
