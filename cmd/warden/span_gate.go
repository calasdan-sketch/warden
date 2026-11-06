package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/calasdan-sketch/warden/internal/model"
	"github.com/calasdan-sketch/warden/internal/policy"
	"github.com/calasdan-sketch/warden/internal/redact"
)

// cmdSpan emits one span from a framework hook.
// It prefers the per-run unix socket (WARDEN_SOCK); without it, it writes
// directly to the store. WARDEN_RUN_ID is required in both cases.
func (a *app) cmdSpan(args []string) int {
	fs := newFlagSet("span")
	kind := fs.String("kind", "", "llm.call|tool.call|file.op|net.egress|subagent.spawn|human.approval")
	name := fs.String("name", "", "span name")
	tool := fs.String("tool", "", "tool.call: tool name")
	toolArgs := fs.String("args", "", "tool.call: argument summary (redacted at emission)")
	server := fs.String("server", "", "tool.call: MCP server name")
	modelName := fs.String("model", "", "llm.call: model")
	tIn := fs.Int64("tokens-in", 0, "llm.call: input tokens")
	tOut := fs.Int64("tokens-out", 0, "llm.call: output tokens")
	tCached := fs.Int64("tokens-cached", 0, "llm.call: cached tokens")
	cost := fs.Float64("cost", 0, "llm.call: cost USD (0 = rate-card estimate)")
	path := fs.String("path", "", "file.op: path")
	op := fs.String("op", "", "file.op: read|write|delete")
	host := fs.String("host", "", "net.egress: host")
	child := fs.String("child", "", "subagent.spawn: child run id")
	gate := fs.String("gate", "", "human.approval: gate name")
	decision := fs.String("decision", "", "human.approval: approved|denied|timeout")
	status := fs.String("status", "", "span status (default ok)")
	if !parseArgs(fs, args) {
		return 2
	}

	runID := os.Getenv("WARDEN_RUN_ID")
	if runID == "" {
		fmt.Fprintln(os.Stderr, "span: WARDEN_RUN_ID is not set (are you inside a warden run?)")
		return 2
	}
	k := model.SpanKind(*kind)
	if !k.Valid() {
		fmt.Fprintln(os.Stderr, "span: invalid --kind")
		return 2
	}
	sp := &model.Span{
		Kind: k, Name: *name, RunID: runID,
		StartedAt: time.Now().UTC(),
		Tool:      *tool, ToolServer: *server, ArgsSummary: *toolArgs,
		Model: *modelName, TokensIn: *tIn, TokensOut: *tOut, TokensCached: *tCached, CostUSD: *cost,
		Path: *path, Op: *op, Host: *host,
		ChildRunID: *child, Gate: *gate, Decision: *decision,
		Status: *status,
	}
	if sp.Status == "" {
		sp.Status = "ok"
	}

	// Prefer the socket: the collector applies redaction + policy + counters.
	if sock := os.Getenv("WARDEN_SOCK"); sock != "" {
		if err := sendSocketSpan(sock, sp); err == nil {
			return 0
		}
		// Socket gone (run sealed?) — fall through to direct store write.
	}
	// Direct path: look up agent/fleet from the run row.
	run, err := a.st.GetRun(runID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "span:", err)
		return 1
	}
	sp.AgentID, sp.FleetID = run.AgentID, run.FleetID
	if err := a.col.EmitSpan(sp); err != nil {
		fmt.Fprintln(os.Stderr, "span:", err)
		return 1
	}
	return 0
}

func sendSocketSpan(sock string, sp *model.Span) error {
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return err
	}
	defer conn.Close()
	b, err := json.Marshal(sp)
	if err != nil {
		return err
	}
	_, err = conn.Write(append(b, '\n'))
	return err
}

// cmdGate is the pre-execution policy check for framework hooks
// (e.g. a Claude Code PreToolUse hook). Exit codes: 0 allow, 3 deny,
// 4 require_approval (without --await). With --await it blocks until a human
// decides, then exits 0/3.
//
//	warden gate --tool bash --args "rm -rf /" [--await] [--timeout 10m]
func (a *app) cmdGate(args []string) int {
	fs := newFlagSet("gate")
	tool := fs.String("tool", "", "tool name")
	toolArgs := fs.String("args", "", "argument summary")
	host := fs.String("host", "", "net.egress host (for egress checks)")
	path := fs.String("path", "", "file.op path (for credential checks)")
	await := fs.Bool("await", false, "block until a human approves/denies")
	timeout := fs.Duration("timeout", 10*time.Minute, "max wait for approval")
	shell := fs.Bool("shell", false, "evaluate as a shell command even if --tool is not a known shell tool name")
	if !parseArgs(fs, args) {
		return 2
	}

	runID := os.Getenv("WARDEN_RUN_ID")
	agentID, fleetID := os.Getenv("WARDEN_AGENT_ID"), os.Getenv("WARDEN_FLEET_ID")
	if runID == "" {
		// Outside a run: still evaluate, with placeholder identity.
		runID, agentID, fleetID = "adhoc", "adhoc", "adhoc"
	}
	// Redact before evaluation: the policy reason echoes the arguments, and
	// an unredacted reason would leak credentials passed as arguments into
	// hook output and logs.
	redactedArgs, _ := redact.RedactString(*toolArgs)
	evalTool := *tool
	if *shell {
		evalTool = "bash" // force the shell policy branch
	}
	sp := &model.Span{
		Kind: model.SpanToolCall, Tool: evalTool, ArgsSummary: redactedArgs,
		RunID: runID, AgentID: agentID, FleetID: fleetID, StartedAt: time.Now().UTC(),
	}
	if *host != "" {
		sp.Kind = model.SpanNetEgress
		sp.Host = *host
	}
	if *path != "" {
		sp.Kind = model.SpanFileOp
		sp.Path = *path
		sp.Op = "read"
	}
	res := policy.NewEvaluator(a.pol, a.st).Evaluate(sp)
	out, _ := json.Marshal(map[string]string{
		"decision": res.Decision.String(), "reason": res.Reason, "version": res.Version,
	})
	fmt.Println(string(out))

	switch res.Decision {
	case policy.Allow:
		return 0
	case policy.Deny:
		return 3
	default:
		if !*await {
			return 4
		}
		// Register the approval and wait. The gate name carries the redacted
		// args — never the raw ones (credentials must not land in the
		// approvals queue).
		id, err := a.st.RequestApproval(runID, "gate:"+*tool+":"+truncateStr(redactedArgs, 80), time.Now().UTC())
		if err != nil {
			fmt.Fprintln(os.Stderr, "gate:", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "gate: waiting for human approval (#%d)…\n", id)
		deadline := time.Now().Add(*timeout)
		for time.Now().Before(deadline) {
			pending, _ := a.st.PendingApprovals()
			waiting := false
			for _, p := range pending {
				if p.ID == id {
					waiting = true
				}
			}
			if !waiting {
				decision, approver, _, err := a.st.ApprovalDecision(id)
				if err != nil {
					fmt.Fprintln(os.Stderr, "gate:", err)
					return 1
				}
				fmt.Fprintf(os.Stderr, "gate: %s by %s\n", decision, approver)
				if decision == "approved" {
					return 0
				}
				return 3
			}
			time.Sleep(2 * time.Second)
		}
		fmt.Fprintln(os.Stderr, "gate: approval timed out")
		return 3
	}
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
