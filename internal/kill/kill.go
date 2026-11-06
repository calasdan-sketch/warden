// Package kill implements the warden kill switch with the four exact scopes
// from the blueprint:
//
//	run:   SIGTERM -> grace -> SIGKILL on the run's process subtree. Idempotent.
//	agent: quarantine — kill live runs, refuse new runs for a TTL.
//	fleet: freeze — no new runs admitted; live runs get a soft-stop (SIGTERM)
//	        with a hard deadline, then stragglers are hard-killed on explicit
//	        enforce. Never automatic.
//	tool:  deny-list push — the tool is refused at every enforcement point;
//	        in-flight tool.call spans are allowed to complete.
//
// Every kill is audited with a required reason ("oops" is acceptable, empty
// is not). Kill permission is separate from view permission (enforced by the
// dashboard's RBAC; the CLI is the operator path).
package kill

import (
	"fmt"
	"syscall"
	"time"

	"github.com/calasdan-sketch/warden/internal/collect"
	"github.com/calasdan-sketch/warden/internal/model"
	"github.com/calasdan-sketch/warden/internal/store"
)

// Grace is the SIGTERM grace period before SIGKILL for run kills.
const Grace = 10 * time.Second

// DefaultFleetHardDeadline is the drain deadline for a fleet freeze.
const DefaultFleetHardDeadline = 5 * time.Minute

// Manager executes kills against live runs.
type Manager struct {
	st      *store.Store
	col     *collect.Collector
	dataDir string
}

// New builds a kill manager.
func New(st *store.Store, col *collect.Collector, dataDir string) *Manager {
	return &Manager{st: st, col: col, dataDir: dataDir}
}

func requireReason(reason string) error {
	if reason == "" {
		return fmt.Errorf("a reason is required (\"oops\" is acceptable, empty is not)")
	}
	return nil
}

// KillRun kills one run: seal-first (so the receipt is killed_operator even
// if the process tree fights back), then SIGTERM -> grace -> SIGKILL on the
// process subtree. Killing a finished run is a no-op that still audits.
func (m *Manager) KillRun(runID, reason, actor string) error {
	if err := requireReason(reason); err != nil {
		return err
	}
	r, err := m.st.GetRun(runID)
	if err != nil {
		return fmt.Errorf("kill: %w", err)
	}
	kill := &model.KillRecord{
		At: time.Now().UTC(), Actor: actor, Scope: model.KillScopeRun,
		Target: runID, Reason: reason,
	}
	if r.Status != model.RunRunning && r.Status != model.RunAwaitingApproval {
		kill.Result = fmt.Sprintf("no-op: run already %s", r.Status)
		return m.st.InsertKill(kill)
	}
	// Seal first: the receipt says killed_operator even if the tree is stubborn,
	// and the wrap shim's own exit path will see the sealed status and stand down.
	if _, err := m.col.SealRun(runID, model.RunKilledOperator, kill, nil); err != nil {
		return fmt.Errorf("kill: seal: %w", err)
	}
	result := "sealed; no live process group found (pidfile missing)"
	if pf, err := collect.ReadPidFile(m.dataDir, runID); err == nil && pf.PGID > 0 {
		result = m.killPGIDVerified(pf, Grace)
		collect.RemovePidFile(m.dataDir, runID)
	}
	kill.Result = result
	return m.st.InsertKill(kill)
}

// killPGIDVerified signals the run's process group only after verifying the
// pidfile still points at the supervised child (PID start-time check). A
// stale pidfile whose PID was recycled by the OS is never signaled —
// killing an innocent process group is worse than missing a dead one.
func (m *Manager) killPGIDVerified(pf *collect.PidFile, grace time.Duration) string {
	if pf.PID > 0 && !collect.PidAliveForRun(m.dataDir, pf.RunID) {
		return "not signaled: pidfile stale (process gone or PID recycled)"
	}
	return m.killPGID(pf.PGID, grace)
}

// killPGID sends SIGTERM, waits up to grace, then SIGKILL. It reports what happened.
func (m *Manager) killPGID(pgid int, grace time.Duration) string {
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	if waitPGIDExit(pgid, grace) {
		return "killed: SIGTERM sufficient"
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	if waitPGIDExit(pgid, 5*time.Second) {
		return "killed: SIGTERM timed out, SIGKILL delivered"
	}
	return "SIGKILL delivered; process group still present (possible zombie/D-state)"
}

func waitPGIDExit(pgid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		err := syscall.Kill(-pgid, 0)
		if err == syscall.ESRCH {
			return true // no such process group: dead
		}
		// EPERM (or nil) means the group exists — keep waiting.
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// QuarantineAgent kills the agent's live runs and refuses new runs for ttl
// (default 1h). This is the "this agent is compromised/misbehaving" button.
func (m *Manager) QuarantineAgent(agentID string, ttl time.Duration, reason, actor string) error {
	if err := requireReason(reason); err != nil {
		return err
	}
	if agentID == "" {
		return fmt.Errorf("agent id is required")
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	runs, err := m.st.ListRuns(store.RunFilter{AgentID: agentID, LiveOnly: true})
	if err != nil {
		return err
	}
	killed := 0
	for _, r := range runs {
		kr := &model.KillRecord{
			At: time.Now().UTC(), Actor: actor, Scope: model.KillScopeAgent,
			Target: agentID, Reason: reason,
		}
		if _, err := m.col.SealRun(r.RunID, model.RunKilledOperator, kr, nil); err != nil {
			return err
		}
		if pf, err := collect.ReadPidFile(m.dataDir, r.RunID); err == nil && pf.PGID > 0 {
			m.killPGIDVerified(pf, Grace)
			collect.RemovePidFile(m.dataDir, r.RunID)
		}
		killed++
	}
	if err := m.st.QuarantineAgent(agentID, time.Now().Add(ttl), reason); err != nil {
		return err
	}
	return m.st.InsertKill(&model.KillRecord{
		At: time.Now().UTC(), Actor: actor, Scope: model.KillScopeAgent,
		Target: agentID, Reason: reason,
		Result: fmt.Sprintf("quarantined for %s; %d live run(s) killed", ttl, killed),
	})
}

// ClearAgentQuarantine lifts a quarantine early.
func (m *Manager) ClearAgentQuarantine(agentID, reason, actor string) error {
	if err := requireReason(reason); err != nil {
		return err
	}
	if err := m.st.ClearAgentQuarantine(agentID); err != nil {
		return err
	}
	return m.st.InsertKill(&model.KillRecord{
		At: time.Now().UTC(), Actor: actor, Scope: model.KillScopeAgent,
		Target: agentID, Reason: reason, Result: "quarantine cleared",
	})
}

// FreezeFleet stops new runs from being admitted and soft-stops live runs
// (SIGTERM = drain signal). Stragglers are hard-killed only by an explicit
// EnforceFleetFreeze after the hard deadline — never automatically.
func (m *Manager) FreezeFleet(fleetID string, hardDeadline time.Duration, reason, actor string) error {
	if err := requireReason(reason); err != nil {
		return err
	}
	if fleetID == "" {
		return fmt.Errorf("fleet id is required")
	}
	if hardDeadline <= 0 {
		hardDeadline = DefaultFleetHardDeadline
	}
	hd := time.Now().Add(hardDeadline)
	// Freeze with no expiry: it lasts until an operator unfreezes it.
	if err := m.st.FreezeFleet(fleetID, time.Time{}, hd, reason); err != nil {
		return err
	}
	runs, err := m.st.ListRuns(store.RunFilter{FleetID: fleetID, LiveOnly: true})
	if err != nil {
		return err
	}
	signaled := 0
	for _, r := range runs {
		// Seal first (same discipline as KillRun): a soft-stopped run's
		// receipt must say killed_operator/fleet_freeze, not "completed".
		kr := &model.KillRecord{
			At: time.Now().UTC(), Actor: actor, Scope: model.KillScopeFleet,
			Target: fleetID, Reason: reason, Result: "fleet freeze soft-stop (SIGTERM)",
		}
		if _, err := m.col.SealRun(r.RunID, model.RunKilledOperator, kr, nil); err != nil {
			return err
		}
		if pf, err := collect.ReadPidFile(m.dataDir, r.RunID); err == nil && pf.PGID > 0 {
			if collect.PidAliveForRun(m.dataDir, r.RunID) {
				_ = syscall.Kill(-pf.PGID, syscall.SIGTERM)
			}
			collect.RemovePidFile(m.dataDir, r.RunID)
			signaled++
		}
	}
	return m.st.InsertKill(&model.KillRecord{
		At: time.Now().UTC(), Actor: actor, Scope: model.KillScopeFleet,
		Target: fleetID, Reason: reason,
		Result: fmt.Sprintf("fleet frozen; %d live run(s) soft-stopped (SIGTERM), hard deadline %s", signaled, hd.Format(time.RFC3339)),
	})
}

// EnforceFleetFreeze hard-kills runs still alive in a frozen fleet past the
// hard deadline. Explicit operator action only.
func (m *Manager) EnforceFleetFreeze(fleetID, reason, actor string) error {
	if err := requireReason(reason); err != nil {
		return err
	}
	frozen, _, hd, err := m.st.FleetFreezeState(fleetID)
	if err != nil {
		return err
	}
	if !frozen {
		return fmt.Errorf("fleet %q is not frozen", fleetID)
	}
	runs, err := m.st.ListRuns(store.RunFilter{FleetID: fleetID, LiveOnly: true})
	if err != nil {
		return err
	}
	killed := 0
	for _, r := range runs {
		kr := &model.KillRecord{
			At: time.Now().UTC(), Actor: actor, Scope: model.KillScopeFleet,
			Target: fleetID, Reason: reason,
		}
		if _, err := m.col.SealRun(r.RunID, model.RunKilledOperator, kr, nil); err != nil {
			return err
		}
		if pf, err := collect.ReadPidFile(m.dataDir, r.RunID); err == nil && pf.PGID > 0 {
			m.killPGIDVerified(pf, 0)
			collect.RemovePidFile(m.dataDir, r.RunID)
		}
		killed++
	}
	past := ""
	if time.Now().After(hd) {
		past = " (past hard deadline)"
	}
	return m.st.InsertKill(&model.KillRecord{
		At: time.Now().UTC(), Actor: actor, Scope: model.KillScopeFleet,
		Target: fleetID, Reason: reason,
		Result: fmt.Sprintf("freeze enforced: %d straggler(s) hard-killed%s", killed, past),
	})
}

// UnfreezeFleet re-admits new runs.
func (m *Manager) UnfreezeFleet(fleetID, reason, actor string) error {
	if err := requireReason(reason); err != nil {
		return err
	}
	if err := m.st.UnfreezeFleet(fleetID); err != nil {
		return err
	}
	return m.st.InsertKill(&model.KillRecord{
		At: time.Now().UTC(), Actor: actor, Scope: model.KillScopeFleet,
		Target: fleetID, Reason: reason, Result: "fleet unfrozen; new runs admitted",
	})
}

// DisableTool pushes a tool onto the deny-list (optionally fleet-scoped).
// In-flight tool.call spans are allowed to complete; new calls are refused.
func (m *Manager) DisableTool(tool, fleet, reason, actor string) error {
	if err := requireReason(reason); err != nil {
		return err
	}
	if tool == "" {
		return fmt.Errorf("tool name is required")
	}
	if err := m.st.DenyTool(tool, fleet, reason); err != nil {
		return err
	}
	target := tool
	if fleet != "" {
		target = fleet + ":" + tool
	}
	return m.st.InsertKill(&model.KillRecord{
		At: time.Now().UTC(), Actor: actor, Scope: model.KillScopeTool,
		Target: target, Reason: reason, Result: "tool denied at enforcement points; in-flight calls complete",
	})
}

// EnableTool removes a tool from the deny-list.
func (m *Manager) EnableTool(tool, fleet, reason, actor string) error {
	if err := requireReason(reason); err != nil {
		return err
	}
	if err := m.st.AllowTool(tool, fleet); err != nil {
		return err
	}
	target := tool
	if fleet != "" {
		target = fleet + ":" + tool
	}
	return m.st.InsertKill(&model.KillRecord{
		At: time.Now().UTC(), Actor: actor, Scope: model.KillScopeTool,
		Target: target, Reason: reason, Result: "tool re-allowed",
	})
}
