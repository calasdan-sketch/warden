package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/calasdan-sketch/warden/internal/collect"
	"github.com/calasdan-sketch/warden/internal/hook"
	"github.com/calasdan-sketch/warden/internal/model"
	"github.com/calasdan-sketch/warden/internal/policy"
)

// runHookFailClosed opens the app and runs the hook, converting any
// startup error or panic into a deny (Claude Code JSON / Codex exit 2),
// unless the operator passed --fail-open.
func runHookFailClosed(dir, policyPath string, args []string) (code int) {
	harness := hook.ClaudeCode
	if len(args) > 0 && args[0] == hook.Codex {
		harness = hook.Codex
	}
	failOpen := false
	for _, a := range args {
		if a == "--fail-open" || a == "--fail-open=true" {
			failOpen = true
		}
	}
	block := func(why string) int {
		fmt.Fprintln(os.Stderr, "warden hook:", why)
		if failOpen {
			return 0
		}
		return hook.Blocked(harness, "warden could not evaluate this call ("+why+"); blocking (fail-closed)", os.Stdout, os.Stderr)
	}
	defer func() {
		if r := recover(); r != nil {
			code = block(fmt.Sprintf("internal error: %v", r))
		}
	}()
	if len(args) > 0 && (args[0] == hook.ClaudeCode || args[0] == hook.Codex) {
		for _, a := range args[1:] {
			if a == "--print-config" || a == "-print-config" {
				printHookConfig(args[0], nil)
				return 0
			}
		}
	}
	a, err := openApp(dir, policyPath, true)
	if err != nil {
		return block(err.Error())
	}
	defer a.close()
	return a.cmdHook(args)
}

// cmdHook is the harness hook entry point:
//
//	warden hook claude-code   (PreToolUse / SessionEnd hook in .claude/settings.json)
//	warden hook codex         (PreToolUse / SessionEnd hook in ~/.codex/hooks.json)
//	warden hook claude-code --print-config
func (a *app) cmdHook(args []string) int {
	if len(args) == 0 || (args[0] != hook.ClaudeCode && args[0] != hook.Codex) {
		fmt.Fprintln(os.Stderr, "hook: usage: warden hook claude-code|codex [--fleet F] [--strict] [--await] [--fail-open] [--print-config]")
		return 2
	}
	harness := args[0]
	fs := newFlagSet("hook " + harness)
	fleet := fs.String("fleet", "default", "fleet id for this harness's runs")
	strict := fs.Bool("strict", false, "enforce allowlist misses as hard denials instead of asking a human")
	await := fs.Bool("await", false, "on require_approval, block until decided in warden (warden approve / dashboard)")
	timeout := fs.Duration("timeout", 5*time.Minute, "--await: max wait for a decision (keep below the harness hook timeout)")
	failOpen := fs.Bool("fail-open", false, "if warden itself errors, let the tool call proceed (default: block)")
	printConfig := fs.Bool("print-config", false, "print the hook configuration snippet for this harness and exit")
	if !parseArgs(fs, args[1:]) {
		return 2
	}
	if *printConfig {
		printHookConfig(harness, fs.Args())
		return 0
	}

	fail := func(err error) int {
		fmt.Fprintln(os.Stderr, "warden hook:", err)
		if *failOpen {
			return 0
		}
		return hook.Blocked(harness, "warden could not evaluate this call ("+err.Error()+"); blocking (fail-closed)", os.Stdout, os.Stderr)
	}

	in, err := hook.ReadInput(os.Stdin)
	if err != nil {
		return fail(err)
	}
	opts := collect.RunOptions{
		AgentID: harness, FleetID: *fleet, Operator: actorName(), Model: in.Model,
		Command: harness + " session " + in.SessionID + " (cwd " + in.Cwd + ")",
	}

	switch in.HookEventName {
	case "PreToolUse":
	case "SessionEnd":
		return a.sealSession(harness, in.SessionID, opts)
	case "Stop":
		// Both harnesses fire Stop at the end of every turn; the session
		// (and its run) ends at SessionEnd. Sessions that never send it are
		// sealed by the idle reconciler and continue in a linked run.
		return 0
	default:
		// SessionStart, UserPromptSubmit, PostToolUse, …: keep the run alive.
		if _, err := a.col.EnsureSessionRun(harness, in.SessionID, opts); err != nil {
			fmt.Fprintln(os.Stderr, "warden hook:", err)
		}
		return 0
	}

	// A wrapped harness (`warden wrap -- claude`) reports into its wrap run.
	var st *collect.SessionState
	if rid := os.Getenv("WARDEN_RUN_ID"); rid != "" {
		if r, err := a.st.GetRun(rid); err == nil && (r.Status == model.RunRunning || r.Status == model.RunAwaitingApproval) {
			st = &collect.SessionState{Run: r}
		}
	}
	if st == nil {
		st, err = a.col.EnsureSessionRun(harness, in.SessionID, opts)
		if err != nil {
			return fail(err)
		}
	}
	if st.Blocked {
		if st.Run != nil && (st.Run.Status == model.RunRunning || st.Run.Status == model.RunAwaitingApproval) {
			_ = a.col.EmitEvent(st.Run.RunID, "warning", "hook_blocked", st.BlockReason)
		}
		return hook.Blocked(harness, st.BlockReason, os.Stdout, os.Stderr)
	}

	sp := hook.ToSpan(in)
	sp.RunID, sp.AgentID, sp.FleetID = st.Run.RunID, st.Run.AgentID, st.Run.FleetID
	res := a.col.Evaluate(sp)
	// apply_patch can touch several files: judge every one, keep the worst.
	for _, p := range hook.PatchPaths(hook.PatchInput(in)) {
		cand := *sp
		cand.Path = p
		if in.Cwd != "" && !filepath.IsAbs(p) {
			cand.Path = filepath.Join(in.Cwd, p)
		}
		if r := a.col.Evaluate(&cand); severity(r) > severity(res) {
			sp.Path, res = cand.Path, r
		}
	}
	v := hook.Decide(harness, res, *strict)
	// Policy saw the whole command; storage keeps a bounded summary.
	sp.ArgsSummary = hook.Summarize(sp.ArgsSummary)

	if *await && res.Decision == policy.RequireApproval {
		code, err := a.awaitHookApproval(harness, sp, res, *timeout)
		if err != nil {
			return fail(err)
		}
		return code
	}
	if err := a.col.RecordDecision(sp, v.Recorded, v.DeferredTo); err != nil {
		return fail(err)
	}
	return hook.Render(harness, v, os.Stdout, os.Stderr)
}

// awaitHookApproval records the call, opens a warden approval and waits.
func (a *app) awaitHookApproval(harness string, sp *model.Span, res policy.Result, timeout time.Duration) (int, error) {
	if err := a.col.RecordDecision(sp, res, ""); err != nil {
		return 0, err
	}
	gate := "hook:" + harness + ":" + sp.Name + ":" + truncateStr(sp.ArgsSummary+sp.Path+sp.Host, 80)
	id, err := a.st.RequestApproval(sp.RunID, gate, time.Now().UTC())
	if err != nil {
		return 0, err
	}
	fmt.Fprintf(os.Stderr, "warden: waiting for approval #%d (warden approve --id %d --decision approved)\n", id, id)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		decision, approver, reason, err := a.st.ApprovalDecision(id)
		if err == nil && decision != "" {
			if decision == "approved" {
				return 0, nil // still defers to the harness's own permission flow
			}
			msg := fmt.Sprintf("denied by %s via warden", approver)
			if reason != "" {
				msg += ": " + reason
			}
			return hook.Blocked(harness, msg, os.Stdout, os.Stderr), nil
		}
		time.Sleep(time.Second)
	}
	return hook.Blocked(harness, fmt.Sprintf("approval #%d timed out after %s", id, timeout), os.Stdout, os.Stderr), nil
}

func (a *app) sealSession(harness, sessionID string, opts collect.RunOptions) int {
	st, err := a.col.EnsureSessionRun(harness, sessionID, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warden hook:", err)
		return 0 // never block a session from ending
	}
	if st.Run != nil && (st.Run.Status == model.RunRunning || st.Run.Status == model.RunAwaitingApproval) {
		if _, err := a.col.SealRun(st.Run.RunID, model.RunCompleted, nil, []string{"hook:" + harness}); err != nil {
			fmt.Fprintln(os.Stderr, "warden hook: seal:", err)
		}
	}
	return 0
}

// transientInstall reports whether a binary path is in a place that does not
// last: an npx cache folder or the system temp directory.
func transientInstall(p string) bool {
	q := strings.ReplaceAll(filepath.ToSlash(p), `\`, "/")
	if strings.Contains(q, "/_npx/") {
		return true
	}
	tmp := filepath.ToSlash(filepath.Clean(os.TempDir()))
	return tmp != "" && tmp != "/" && strings.HasPrefix(q, tmp+"/")
}

// printHookConfig prints a ready-to-paste hook configuration.
func printHookConfig(harness string, extra []string) {
	bin := "warden"
	if p, err := exec.LookPath("warden"); err != nil || p == "" {
		if self, err := os.Executable(); err == nil {
			bin, _ = filepath.Abs(self)
		}
	}
	if transientInstall(bin) {
		fmt.Fprintf(os.Stderr, "WARNING: this warden lives in a temporary folder (%s), for example the cache npx uses.\n"+
			"A hook that points there stops working when the folder is cleaned, and Claude Code and Codex then let tool calls through.\n"+
			"Install warden permanently first (npm install -g @decnutz/warden, or go install github.com/calasdan-sketch/warden/cmd/warden@latest), then run this again.\n", bin)
	}
	cmd := hook.ShellQuote(bin) + " hook " + harness
	for _, e := range extra {
		cmd += " " + hook.ShellQuote(e)
	}
	entry := func(matcher string, timeout int) []any {
		h := map[string]any{"type": "command", "command": cmd, "timeout": timeout}
		g := map[string]any{"hooks": []any{h}}
		if matcher != "" {
			g["matcher"] = matcher
		}
		return []any{g}
	}
	var cfg map[string]any
	var where string
	if harness == hook.ClaudeCode {
		where = "Merge into .claude/settings.json (project) or ~/.claude/settings.json (user):"
		cfg = map[string]any{"hooks": map[string]any{
			"PreToolUse": entry("*", 600),
			"SessionEnd": entry("", 30),
		}}
	} else {
		where = "Merge into ~/.codex/hooks.json (user) or <project>/.codex/hooks.json:"
		cfg = map[string]any{"hooks": map[string]any{
			"PreToolUse": entry("", 600),
			"SessionEnd": entry("", 30),
		}}
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	fmt.Fprintln(os.Stderr, where)
	fmt.Println(string(b))
}

func severity(r policy.Result) int {
	switch r.Decision {
	case policy.Deny:
		if r.DefaultDeny {
			return 2
		}
		return 3
	case policy.RequireApproval:
		return 1
	}
	return 0
}
