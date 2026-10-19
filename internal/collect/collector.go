// Package collect is the warden collector: the local ingestion point for
// agent telemetry.
//
// The collector is where the security floor is enforced: every span is
// redacted BEFORE emission (nothing secret-bearing reaches the store), and
// every tool.call / file.op / net.egress span passes the policy gate at the
// tool-call boundary before it is recorded.
//
// Ingestion paths:
//  1. Unix socket (JSONL): framework hooks and the wrap shim emit spans here.
//  2. Direct EmitSpan calls: the --report-to join layer and tests.
//  3. The Runner: `warden wrap -- <command>` — zero-code instrumentation for
//     agents that emit nothing.
//
// There is no daemon in v1: each `wrap` is self-contained, the dashboard and
// the kill CLI are separate processes sharing the SQLite store and pidfiles.
package collect

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"warden/internal/cost"
	"warden/internal/model"
	"warden/internal/policy"
	"warden/internal/receipt"
	"warden/internal/redact"
	"warden/internal/store"
)

type wireEvent struct {
	Severity string `json:"severity"`
	Kind     string `json:"kind"`
	Message  string `json:"message"`
	SpanID   string `json:"span_id"`
}

// Collector ingests spans, enforces policy, and manages run lifecycle.
type Collector struct {
	store   *store.Store
	eval    *policy.Evaluator
	signer  *receipt.Signer
	dataDir string

	mu        sync.Mutex
	socks     map[string]net.Listener // runID -> listener
	sockPaths map[string]string       // runID -> actual socket path (may be a fallback)
}

// RunOptions describes a new run.
type RunOptions struct {
	AgentID     string
	FleetID     string
	Operator    string
	Model       string
	Provider    string
	Command     string
	ParentRunID *string
}

// New builds a collector over an open store.
func New(st *store.Store, pol *policy.Policy, signer *receipt.Signer, dataDir string) *Collector {
	return &Collector{
		store:     st,
		eval:      policy.NewEvaluator(pol, st),
		signer:    signer,
		dataDir:   dataDir,
		socks:     map[string]net.Listener{},
		sockPaths: map[string]string{},
	}
}

// StartRun opens a new run envelope. It refuses quarantined agents and frozen
// fleets, and creates the per-run ingestion socket for framework hooks.
func (c *Collector) StartRun(opts RunOptions) (*model.Run, string, error) {
	if q, reason, err := c.store.IsAgentQuarantined(opts.AgentID); err != nil {
		return nil, "", err
	} else if q {
		return nil, "", fmt.Errorf("agent %q is quarantined: %s", opts.AgentID, reason)
	}
	if frozen, reason, _, err := c.store.FleetFreezeState(opts.FleetID); err != nil {
		return nil, "", err
	} else if frozen {
		return nil, "", fmt.Errorf("fleet %q is frozen: %s", opts.FleetID, reason)
	}

	runID := newID()
	cmd, _ := redact.RedactString(opts.Command)
	now := time.Now().UTC()
	r := &model.Run{
		RunID:     runID,
		AgentID:   opts.AgentID,
		FleetID:   opts.FleetID,
		Operator:  opts.Operator,
		Model:     opts.Model,
		Provider:  opts.Provider,
		Command:   truncate(cmd, 500),
		StartedAt: now,
		Status:    model.RunRunning,
	}
	if opts.ParentRunID != nil {
		r.ParentRunID = opts.ParentRunID
	}
	if err := c.store.CreateRun(r); err != nil {
		return nil, "", err
	}
	sockPath, err := c.serveSocket(runID)
	if err != nil {
		return nil, "", err
	}
	return r, sockPath, nil
}

// EmitSpan ingests one span: redaction -> policy gate -> store. This is the
// single choke point; the socket server and the join layer both funnel here.
func (c *Collector) EmitSpan(sp *model.Span) error {
	if !sp.Kind.Valid() {
		return fmt.Errorf("invalid span kind %q", sp.Kind)
	}
	if sp.SpanID == "" {
		sp.SpanID = newID()
	}
	if sp.StartedAt.IsZero() {
		sp.StartedAt = time.Now().UTC()
	}
	redactSpan(sp)

	// Fill in a rate-card cost estimate for hook-emitted llm.call spans that
	// lack one. Emitter-supplied cost is never touched.
	if sp.Kind == model.SpanLLMCall && sp.CostUSD == 0 && sp.Model != "" &&
		(sp.TokensIn+sp.TokensOut+sp.TokensCached) > 0 {
		sp.CostUSD = cost.Estimate(sp.Model, sp.TokensIn, sp.TokensOut, sp.TokensCached)
	}

	// Policy gate at the tool-call boundary — unless an external enforcement
	// point already decided (mcp-jail via the join layer).
	var res policy.Result
	if sp.PreDecided {
		switch sp.PolicyDecision {
		case "deny":
			res = policy.Result{Decision: policy.Deny, Reason: sp.PolicyReason, Version: sp.PolicyVersion}
		case "require_approval":
			res = policy.Result{Decision: policy.RequireApproval, Reason: sp.PolicyReason, Version: sp.PolicyVersion}
		default:
			res = policy.Result{Decision: policy.Allow, Version: sp.PolicyVersion}
		}
		if res.Version == "" {
			res.Version = "external"
			sp.PolicyVersion = "external"
		}
	} else {
		res = c.eval.Evaluate(sp)
		sp.PolicyDecision = res.Decision.String()
		sp.PolicyReason = res.Reason
		sp.PolicyVersion = c.eval.Version()
	}
	switch res.Decision {
	case policy.Deny:
		sp.Status = "denied"
	case policy.RequireApproval:
		sp.Status = "awaiting_approval"
	}

	if err := c.store.InsertSpan(sp); err != nil {
		return err
	}
	c.bumpCounters(sp)

	if res.Decision != policy.Allow {
		sev := "warning"
		kind := "policy_deny"
		if res.Decision == policy.RequireApproval {
			kind = "policy_approval_required"
			if _, err := c.store.RequestApproval(sp.RunID, approvalGateFor(sp), time.Now().UTC()); err != nil {
				return err
			}
		}
		return c.store.InsertEvent(&model.Event{
			RunID: sp.RunID, SpanID: sp.SpanID, At: time.Now().UTC(),
			Severity: sev, Kind: kind,
			Message: fmt.Sprintf("policy %s: %s %s — %s", res.Decision, sp.Kind, sp.Name, res.Reason),
		})
	}
	return nil
}

// EmitEvent appends a free-form event to a run.
func (c *Collector) EmitEvent(runID string, sev, kind, msg string) error {
	return c.store.InsertEvent(&model.Event{
		RunID: runID, At: time.Now().UTC(), Severity: sev, Kind: kind, Message: msg,
	})
}

// Heartbeat marks a run alive (used by Reconcile to find dead runs).
func (c *Collector) Heartbeat(runID string) error {
	return c.store.TouchHeartbeat(runID)
}

// SignerPublicKey exposes the receipt-signing public key (for verify paths).
func (c *Collector) SignerPublicKey() ed25519.PublicKey { return c.signer.PublicKey() }

// SealRun closes a run envelope and seals its signed receipt.
//
// It is safe to call concurrently and repeatedly: the seal is claimed
// atomically in the store, so exactly one sealer writes the receipt and
// every other caller gets the sealed receipt back (idempotent no-op).
func (c *Collector) SealRun(runID string, status model.RunStatus, kill *model.KillRecord, guards []string) (*model.Receipt, error) {
	if rec, _, err := c.store.GetReceipt(runID); err == nil && rec != nil {
		return rec, nil
	}
	claimed, r, err := c.store.ClaimForSeal(runID, status)
	if err != nil {
		return nil, err
	}
	if !claimed {
		if _, gerr := c.store.GetRun(runID); gerr != nil {
			return nil, fmt.Errorf("cannot seal run %s: %w", runID, gerr)
		}
		return c.awaitReceipt(runID, 5*time.Second)
	}
	r.Status = status
	if kill != nil {
		src := string(kill.Scope)
		r.KillSource = &src
		r.KillReason = &kill.Reason
		r.KilledBy = &kill.Actor
	}
	// Finalize counters from the store (source of truth, not memory).
	if err := c.finalizeCounters(r); err != nil {
		return nil, err
	}
	// The seal timestamp is captured INSIDE the chained transaction, while
	// the chain head is locked: this keeps sealed_at order consistent with
	// commit order, so concurrent seals can neither fork the chain nor
	// scramble its sealed_at ordering.
	rec, err := c.store.SealChained(func(prev string) (*model.Receipt, string, error) {
		now := time.Now().UTC()
		r.EndedAt = &now
		return c.signer.Seal(receipt.SealInput{
			Run: r, Guards: guards, PrevHash: prev, SealedAt: now,
		})
	})
	if err != nil {
		return nil, err
	}
	r.ReceiptRef = rec.BodyHash
	if err := c.store.UpdateRun(r); err != nil {
		return nil, err
	}
	c.closeSocket(runID)
	_ = c.store.InsertEvent(&model.Event{
		RunID: runID, At: rec.SealedAt, Severity: "info", Kind: "run_sealed",
		Message: fmt.Sprintf("run sealed: status=%s cost=$%.4f tool_calls=%d", status, r.CostUSD, r.ToolCalls),
	})
	return rec, nil
}

// awaitReceipt waits for another sealer's receipt to land.
func (c *Collector) awaitReceipt(runID string, timeout time.Duration) (*model.Receipt, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if rec, _, err := c.store.GetReceipt(runID); err == nil && rec != nil {
			return rec, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("timed out waiting for sealed receipt of run %s", runID)
}

// Reconcile seals runs that died without a receipt (host crash, SIGKILL of
// the shim): they become receipt_missing envelopes, flagged, cost estimated
// from spans — never silently dropped.
//
// A stale heartbeat alone is not proof of death: a quiet long-running run
// may simply emit nothing. Runs whose pidfile still points at a live,
// start-time-verified process are left alone.
func (c *Collector) Reconcile(staleAfter time.Duration) (int, error) {
	runs, err := c.store.StaleLiveRuns(staleAfter)
	if err != nil {
		return 0, err
	}
	sealed := 0
	for _, r := range runs {
		if pidAliveForRun(c.dataDir, r.RunID) {
			continue // heartbeat is stale but the child is alive; not dead
		}
		if _, err := c.SealRun(r.RunID, model.RunReceiptMissing, nil, []string{"reconcile"}); err != nil {
			return sealed, err
		}
		_ = c.store.InsertEvent(&model.Event{
			RunID: r.RunID, At: time.Now().UTC(), Severity: "warning", Kind: "receipt_missing",
			Message: "run died without a receipt (host crash or shim killed); envelope synthesized from spans",
		})
		sealed++
		RemovePidFile(c.dataDir, r.RunID) // dead run: drop the stale pidfile
	}
	return sealed, nil
}

// Close shuts down all ingestion sockets.
func (c *Collector) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, l := range c.socks {
		l.Close()
		delete(c.socks, id)
	}
}

// ---- internals ----

func (c *Collector) serveSocket(runID string) (string, error) {
	candidates := []string{filepath.Join(c.dataDir, "socks")}
	// Unix socket paths are capped (~108 bytes on Linux): a long WARDEN_DIR
	// makes the bind fail with EINVAL. Fall back to a short temp path so a
	// long data dir can never break span ingestion. The path is internal
	// (handed to the child via WARDEN_SOCK), so relocation is transparent.
	if len(filepath.Join(candidates[0], runID+".sock")) >= 100 {
		sum := sha256.Sum256([]byte(c.dataDir))
		candidates = append(candidates,
			filepath.Join(os.TempDir(), "warden-socks", hex.EncodeToString(sum[:])[:16]))
	}
	var lastErr error
	for _, dir := range candidates {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			lastErr = err
			continue
		}
		path := filepath.Join(dir, runID+".sock")
		os.Remove(path)
		l, err := net.Listen("unix", path)
		if err != nil {
			lastErr = err
			continue
		}
		c.mu.Lock()
		c.socks[runID] = l
		c.sockPaths[runID] = path
		c.mu.Unlock()
		go c.acceptLoop(runID, l)
		return path, nil
	}
	return "", fmt.Errorf("listen socket: %w", lastErr)
}

func (c *Collector) closeSocket(runID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if l, ok := c.socks[runID]; ok {
		l.Close()
		delete(c.socks, runID)
	}
	if p, ok := c.sockPaths[runID]; ok {
		os.Remove(p)
		delete(c.sockPaths, runID)
	} else {
		os.Remove(filepath.Join(c.dataDir, "socks", runID+".sock"))
	}
}

func (c *Collector) acceptLoop(runID string, l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return // listener closed
		}
		go c.handleConn(runID, conn)
	}
}

func (c *Collector) handleConn(runID string, conn net.Conn) {
	defer conn.Close()
	// The socket is per-run: resolve the run's identity once so every span
	// ingested here inherits it. The emitter must not be able to spoof
	// another agent's identity (or drop its own) on the wire.
	var agentID, fleetID string
	if r, err := c.store.GetRun(runID); err == nil {
		agentID, fleetID = r.AgentID, r.FleetID
	}
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		c.handleLine(runID, agentID, fleetID, line)
	}
}

func (c *Collector) handleLine(runID, agentID, fleetID, line string) {
	var probe struct {
		Kind      string     `json:"kind"`
		Heartbeat bool       `json:"heartbeat"`
		Event     *wireEvent `json:"event"`
	}
	if err := json.Unmarshal([]byte(line), &probe); err != nil {
		return // malformed line: drop, never crash the collector
	}
	switch {
	case probe.Heartbeat:
		_ = c.Heartbeat(runID)
	case probe.Event != nil:
		sev := probe.Event.Severity
		if sev == "" {
			sev = "info"
		}
		_ = c.store.InsertEvent(&model.Event{
			RunID: runID, SpanID: probe.Event.SpanID, At: time.Now().UTC(),
			Severity: sev, Kind: probe.Event.Kind, Message: probe.Event.Message,
		})
	case model.SpanKind(probe.Kind).Valid():
		var sp model.Span
		if err := json.Unmarshal([]byte(line), &sp); err != nil {
			return
		}
		sp.RunID = runID // the socket is per-run; the run owns the line
		sp.AgentID = agentID
		sp.FleetID = fleetID
		// SECURITY: the socket is untrusted input — the supervised agent
		// inherits WARDEN_SOCK and can write anything here. A client-supplied
		// pre_decided flag would let the agent self-approve its own tool
		// calls and skip the policy gate entirely. Only the in-process join
		// layer (sibling tools, same trust domain as the operator) may set
		// PreDecided; the wire can never do it.
		sp.PreDecided = false
		_ = c.EmitSpan(&sp)
	}
}

// redactSpan redacts secrets from a span BEFORE it is emitted anywhere.
// This is the security floor: the store, the dashboard, and the SIEM export
// only ever see the redacted form.
func redactSpan(sp *model.Span) {
	hit := false
	var h bool
	if sp.Name, h = redact.RedactString(sp.Name); h {
		hit = true
	}
	if sp.ArgsSummary, h = redact.RedactString(sp.ArgsSummary); h {
		hit = true
	}
	if sp.SpawnReason, h = redact.RedactString(sp.SpawnReason); h {
		hit = true
	}
	// ArgHash is computed over the REDACTED summary so equal redacted args
	// hash equal (loop detection still works; secrets never hashed raw).
	sum := sha256.Sum256([]byte(string(sp.Kind) + "\x00" + sp.Tool + "\x00" + sp.ArgsSummary))
	sp.ArgHash = hex.EncodeToString(sum[:])[:16]
	sp.Redacted = hit
}

// bumpCounters keeps the run row live for the dashboard's burn bar.
// It updates the store directly (the source of truth), so it works for runs
// created by the wrap shim, the join layer, or the socket alike.
func (c *Collector) bumpCounters(sp *model.Span) {
	switch sp.Kind {
	case model.SpanToolCall:
		_, _ = c.store.IncRunCounters(sp.RunID, 1, 0, 0, 0, 0)
	case model.SpanLLMCall:
		_, _ = c.store.IncRunCounters(sp.RunID, 0, sp.TokensIn, sp.TokensOut, sp.TokensCached, sp.CostUSD)
	case model.SpanSubagentSpawn:
		_ = c.store.IncRunSubagents(sp.RunID, 1)
	case model.SpanHumanApproval:
		denied := int64(0)
		if sp.Decision == "denied" {
			denied = 1
		}
		_ = c.store.IncRunApprovals(sp.RunID, 1, denied)
	}
}

// finalizeCounters reconciles the run row with ground truth from spans at seal.
func (c *Collector) finalizeCounters(r *model.Run) error {
	// Cost computed once, at the emitter: when a run's numbers were joined
	// from shortleash (cost_source=emitter), the sealer must not recompute
	// them from spans. That would resurrect the two-numbers-disagree problem.
	if r.CostSource == "emitter" {
		return nil
	}
	tc, ti, to, tcache, cost, err := c.store.SpanTotals(r.RunID)
	if err != nil {
		return err
	}
	r.ToolCalls, r.TokensIn, r.TokensOut, r.TokensCached, r.CostUSD = tc, ti, to, tcache, cost
	if n, err := c.store.DistinctCount(r.RunID, model.SpanFileOp, "path"); err == nil {
		r.FilesTouched = n
	}
	if n, err := c.store.DistinctCount(r.RunID, model.SpanNetEgress, "host"); err == nil {
		r.NetEgressHosts = n
	}
	if n, err := c.store.DistinctCount(r.RunID, model.SpanSubagentSpawn, "child_run_id"); err == nil {
		r.SubagentsSpawned = n
	}
	ar, ad, err := c.store.ApprovalTotals(r.RunID)
	if err == nil {
		r.ApprovalsRequested, r.ApprovalsDenied = ar, ad
	}
	return nil
}

func approvalGateFor(sp *model.Span) string {
	if sp.Kind == model.SpanFileOp {
		return "file:" + sp.Path
	}
	if sp.Tool != "" {
		return "tool:" + sp.Tool
	}
	return "span:" + sp.SpanID
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback: time-seeded xorshift. Collisions are unlikely but possible;
		// the store's primary key will reject a duplicate.
		seed := time.Now().UnixNano()
		for i := range b {
			seed = seed*6364136223846793005 + 1442695040888963407
			b[i] = byte(seed >> 56)
		}
	}
	return hex.EncodeToString(b[:])
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
