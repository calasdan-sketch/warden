package collect

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"warden/internal/model"
	"warden/internal/policy"
)

// KillGrace is the SIGTERM grace period before SIGKILL (blueprint: 10s).
const KillGrace = 10 * time.Second

// Runner executes one wrapped command as a warden run, in its own process
// group so the whole subtree can be killed (SIGTERM -> grace -> SIGKILL).
// The receipt is sealed even when the run is killed.
type Runner struct {
	col  *Collector
	run  *model.Run
	cmd  *exec.Cmd
	pgid int

	mu       sync.Mutex
	sealed   bool
	killing  bool // Shutdown claimed the seal; the waiter must not seal
	sealErr  error
	waitDone chan struct{}
	sealDone chan struct{} // closed when the run is sealed (or sealing failed)
	sealOnce sync.Once
}

// PidFile is how the kill CLI finds a live run's process group.
// StartedAtNs is the child process start time in Unix nanoseconds (from
// /proc at spawn): kill paths verify it before signaling so a recycled PID
// can never make warden SIGTERM/SIGKILL an innocent process group.
type PidFile struct {
	RunID       string `json:"run_id"`
	PID         int    `json:"pid"`
	PGID        int    `json:"pgid"`
	AgentID     string `json:"agent_id"`
	FleetID     string `json:"fleet_id"`
	StartedAtNs int64  `json:"started_at_ns"`
}

// NewRunner creates the run, runs the pre-execution policy gate on the
// command, and prepares (but does not start) the child process.
//
// Deny: the attempt is recorded (denied span) and the run is sealed failed —
// the audit trail shows the blocked action with its human-readable reason.
// RequireApproval: the run waits for a human decision (see AwaitApproval).
func (c *Collector) NewRunner(opts RunOptions) (*Runner, error) {
	run, sockPath, err := c.StartRun(opts)
	if err != nil {
		return nil, err
	}
	r := &Runner{col: c, run: run, waitDone: make(chan struct{}), sealDone: make(chan struct{})}

	// Pre-execution gate: the wrapped command is itself a shell tool.call.
	gateSpan := &model.Span{
		SpanID: newID(),
		Kind:   model.SpanToolCall, Name: "wrap", Tool: "bash",
		ArgsSummary: opts.Command, RunID: run.RunID,
		AgentID: run.AgentID, FleetID: run.FleetID,
	}
	// Redact BEFORE evaluation (same order as EmitSpan): the policy reason
	// echoes the command, and an unredacted reason would leak credentials
	// passed as arguments into the stored span and the audit event.
	redactSpan(gateSpan)
	res := c.eval.Evaluate(gateSpan)
	if res.Decision == policy.Deny {
		gateSpan.Status = "denied"
		gateSpan.PolicyDecision = res.Decision.String()
		gateSpan.PolicyReason = res.Reason
		gateSpan.PolicyVersion = c.eval.Version()
		_ = c.store.InsertSpan(gateSpan)
		_ = c.EmitEvent(run.RunID, "warning", "policy_deny",
			fmt.Sprintf("wrap refused: %s", res.Reason))
		_, sealErr := c.SealRun(run.RunID, model.RunFailed, nil, nil)
		if sealErr != nil {
			return nil, sealErr
		}
		return nil, fmt.Errorf("refused by policy: %s", res.Reason)
	}

	cmd := exec.Command("sh", "-c", opts.Command)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		"WARDEN_RUN_ID="+run.RunID,
		"WARDEN_SOCK="+sockPath,
		"WARDEN_AGENT_ID="+run.AgentID,
		"WARDEN_FLEET_ID="+run.FleetID,
	)
	r.cmd = cmd

	// Record the launch as the run's first span (allowed or pending approval).
	// When the gate requires approval, EmitSpan registers the pending approval
	// and marks the span awaiting_approval; the caller waits via AwaitApproval.
	gateSpan.Status = "ok"
	if res.Decision == policy.RequireApproval {
		gateSpan.Status = "awaiting_approval"
		_, _, _ = c.store.ClaimForSeal(run.RunID, model.RunAwaitingApproval)
		run.Status = model.RunAwaitingApproval
	}
	if err := c.EmitSpan(gateSpan); err != nil {
		return nil, err
	}
	return r, nil
}

// AwaitApproval blocks until a human approves/denies the pending wrap gate,
// or the timeout elapses. Denied or timed out: the run is sealed failed.
func (r *Runner) AwaitApproval(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		pending, err := r.col.store.PendingApprovals()
		if err != nil {
			return err
		}
		stillWaiting := false
		for _, p := range pending {
			if p.RunID == r.run.RunID {
				stillWaiting = true
			}
		}
		if !stillWaiting {
			return nil // decided (or vanished); proceed — decision recorded
		}
		time.Sleep(time.Second)
	}
	_ = r.col.EmitEvent(r.run.RunID, "warning", "approval_timeout", "wrap approval timed out")
	r.sealFailed("approval timeout")
	return fmt.Errorf("approval timed out after %s", timeout)
}

// Start launches the child process and begins waiting on it.
func (r *Runner) Start() error {
	if err := r.cmd.Start(); err != nil {
		r.sealFailed(fmt.Sprintf("failed to start: %v", err))
		return err
	}
	r.pgid = r.cmd.Process.Pid
	r.run.PID = r.cmd.Process.Pid
	_ = r.col.store.UpdateRunPID(r.run.RunID, r.cmd.Process.Pid)
	if err := writePidFile(r.col.dataDir, &PidFile{
		RunID: r.run.RunID, PID: r.cmd.Process.Pid, PGID: r.pgid,
		AgentID: r.run.AgentID, FleetID: r.run.FleetID,
		StartedAtNs: procStartTimeNs(r.cmd.Process.Pid),
	}); err != nil {
		return err
	}
	go func() {
		_ = r.cmd.Wait()
		close(r.waitDone)
		r.sealCompleted()
	}()
	// Heartbeat while the child lives: without this, a long-running but
	// quiet run (no spans emitted) looks dead to the dashboard's stale-run
	// reconciler and would be sealed receipt_missing while still alive.
	go r.heartbeatLoop()
	return nil
}

// heartbeatLoop touches the run's heartbeat until the run is sealed.
func (r *Runner) heartbeatLoop() {
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-r.sealDone:
			return
		case <-t.C:
			_ = r.col.Heartbeat(r.run.RunID)
		}
	}
}

// Wait blocks until the child process exits AND the run is sealed.
func (r *Runner) Wait() {
	<-r.waitDone
	<-r.sealDone
}

func (r *Runner) markSealed(err error) {
	r.mu.Lock()
	r.sealErr = err
	r.mu.Unlock()
	r.sealOnce.Do(func() { close(r.sealDone) })
}

// Shutdown kills the run's process subtree (SIGTERM -> grace -> SIGKILL) and
// seals the receipt as killed. It is idempotent: killing a dead run is a
// no-op that still records the attempt.
func (r *Runner) Shutdown(reason, actor string) error {
	r.mu.Lock()
	if r.sealed {
		err := r.sealErr
		r.mu.Unlock()
		return err
	}
	r.killing = true // claim the seal before touching the process tree
	r.mu.Unlock()

	if r.cmd.Process != nil && r.pgid > 0 {
		_ = syscall.Kill(-r.pgid, syscall.SIGTERM)
		select {
		case <-r.waitDone:
		case <-time.After(KillGrace):
			_ = syscall.Kill(-r.pgid, syscall.SIGKILL)
			<-r.waitDone
		}
	}

	r.mu.Lock()
	r.sealed = true
	r.mu.Unlock()
	kill := &model.KillRecord{
		At: time.Now().UTC(), Actor: actor, Scope: model.KillScopeRun,
		Target: r.run.RunID, Reason: reason, Result: "killed",
	}
	if err := r.col.store.InsertKill(kill); err != nil {
		r.markSealed(err)
		return err
	}
	_, err := r.col.SealRun(r.run.RunID, model.RunKilledOperator, kill, nil)
	removePidFile(r.col.dataDir, r.run.RunID)
	r.markSealed(err)
	return err
}

func (r *Runner) sealCompleted() {
	r.mu.Lock()
	if r.sealed || r.killing {
		r.mu.Unlock()
		return
	}
	r.sealed = true
	r.mu.Unlock()
	status := model.RunCompleted
	if r.cmd.ProcessState != nil && !r.cmd.ProcessState.Success() {
		status = model.RunFailed
	}
	_, err := r.col.SealRun(r.run.RunID, status, nil, nil)
	removePidFile(r.col.dataDir, r.run.RunID)
	r.markSealed(err)
}

func (r *Runner) sealFailed(msg string) {
	r.mu.Lock()
	if r.sealed {
		r.mu.Unlock()
		return
	}
	r.sealed = true
	r.mu.Unlock()
	_ = r.col.EmitEvent(r.run.RunID, "warning", "run_failed", msg)
	_, err := r.col.SealRun(r.run.RunID, model.RunFailed, nil, nil)
	removePidFile(r.col.dataDir, r.run.RunID)
	r.markSealed(err)
}

// ExitCode returns the child's exit code once Wait has returned (-1 if unknown).
func (r *Runner) ExitCode() int {
	if r.cmd.ProcessState == nil {
		return -1
	}
	return r.cmd.ProcessState.ExitCode()
}

// RunID returns the run's ID.
func (r *Runner) RunID() string { return r.run.RunID }

func pidDir(dataDir string) string { return filepath.Join(dataDir, "pids") }

func writePidFile(dataDir string, pf *PidFile) error {
	if err := os.MkdirAll(pidDir(dataDir), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(pf)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(pidDir(dataDir), pf.RunID+".json"), b, 0o600)
}

func removePidFile(dataDir, runID string) {
	os.Remove(filepath.Join(pidDir(dataDir), runID+".json"))
}

// RemovePidFile deletes a run's pidfile. Exported for the kill manager.
func RemovePidFile(dataDir, runID string) { removePidFile(dataDir, runID) }

// ReadPidFile returns the pidfile for a run, or nil if the run isn't live here.
func ReadPidFile(dataDir, runID string) (*PidFile, error) {
	b, err := os.ReadFile(filepath.Join(pidDir(dataDir), runID+".json"))
	if err != nil {
		return nil, err
	}
	var pf PidFile
	if err := json.Unmarshal(b, &pf); err != nil {
		return nil, err
	}
	return &pf, nil
}
