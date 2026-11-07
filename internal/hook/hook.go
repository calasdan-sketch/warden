// Package hook adapts coding-agent harness hooks (Claude Code, Codex CLI)
// to warden: it maps a harness's PreToolUse payload to a warden span, and
// renders warden's policy decision in the harness's own protocol.
//
// Design rules:
//   - warden never grants: an "allow" decision produces no output, so the
//     harness's normal permission flow still applies. warden can only deny
//     or ask for a human.
//   - Explicit denials (deny patterns, deny_tools, operator kills,
//     quarantine, fleet freeze) always block.
//   - Default denials (a command/host simply not on an allowlist) are
//     escalated to the harness's human prompt where the harness has one
//     (Claude Code "ask"), unless strict mode is on. Codex hooks cannot ask,
//     so there the default denial is either enforced (strict) or deferred to
//     Codex's own approval/sandbox policy.
//   - Internal errors fail closed unless the operator opted into fail-open.
package hook

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/calasdan-sketch/warden/internal/model"
	"github.com/calasdan-sketch/warden/internal/policy"
	"github.com/calasdan-sketch/warden/internal/redact"
)

// Harness identifiers.
const (
	ClaudeCode = "claude-code"
	Codex      = "codex"
)

// MaxInput bounds the hook payload read from stdin (tool inputs can carry
// whole file contents for Write; warden only needs the head of them).
const MaxInput = 4 << 20

// Input is the subset of the harness hook payload warden reads. Claude Code
// and Codex share these field names.
type Input struct {
	SessionID     string          `json:"session_id"`
	HookEventName string          `json:"hook_event_name"`
	Cwd           string          `json:"cwd"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
	ToolUseID     string          `json:"tool_use_id"`
	Model         string          `json:"model"`
}

// ReadInput parses a hook payload, refusing oversized or malformed input.
func ReadInput(r io.Reader) (*Input, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxInput+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxInput {
		return nil, fmt.Errorf("hook payload exceeds %d bytes", MaxInput)
	}
	var in Input
	if err := json.Unmarshal(b, &in); err != nil {
		return nil, fmt.Errorf("hook payload is not JSON: %w", err)
	}
	return &in, nil
}

var shellToolNames = map[string]bool{
	"bash": true, "shell": true, "local_shell": true, "exec": true, "exec_command": true,
	"run_command": true, "terminal": true, "container.exec": true, "unified_exec": true,
}

var writeTools = map[string]bool{"write": true, "edit": true, "multiedit": true, "notebookedit": true, "apply_patch": true}

// ToSpan maps a PreToolUse payload to the warden span that policy judges.
func ToSpan(in *Input) *model.Span {
	sp := toSpan(in)
	id := in.ToolUseID
	if len(id) > 128 {
		id = id[:128]
	}
	sp.ToolCallID = id
	// Relative paths are judged where the harness will resolve them.
	if sp.Path != "" && in.Cwd != "" && !path.IsAbs(sp.Path) && !strings.HasPrefix(sp.Path, "~") &&
		!strings.HasPrefix(sp.Path, "$") && !strings.Contains(sp.Path, `\`) {
		sp.Path = path.Join(in.Cwd, sp.Path)
	}
	return sp
}

func toSpan(in *Input) *model.Span {
	var ti map[string]any
	_ = json.Unmarshal(in.ToolInput, &ti) // non-object input: treated as opaque args
	name := in.ToolName
	lname := strings.ToLower(name)
	sp := &model.Span{Kind: model.SpanToolCall, Name: name, Tool: name}

	if cmd, ok := commandOf(ti); ok && (shellToolNames[lname] || lname == "") {
		// Shell: policy judges the command text with the shell rules. The
		// tool is normalized to "bash" so the shell branch applies whatever
		// the harness calls its shell tool.
		sp.Tool = "bash"
		sp.ArgsSummary = cmd
		return sp
	}
	if strings.HasPrefix(name, "mcp__") {
		// mcp__<server>__<tool>
		parts := strings.SplitN(strings.TrimPrefix(name, "mcp__"), "__", 2)
		sp.ToolServer = parts[0]
		sp.ArgsSummary = compact(in.ToolInput)
		return sp
	}
	if lname == "apply_patch" {
		// Codex apply_patch carries the patch text in tool_input.command.
		patch, _ := ti["command"].(string)
		if patch == "" {
			patch, _ = ti["input"].(string)
		}
		if p := patchTarget(patch); p != "" {
			return &model.Span{Kind: model.SpanFileOp, Name: name, Path: p, Op: "write"}
		}
	}
	switch lname {
	case "read", "write", "edit", "multiedit", "notebookedit", "notebookread", "glob", "grep", "ls":
		p := firstString(ti, "file_path", "notebook_path", "path")
		// Glob's "pattern" and Grep's "glob" can name a credential store
		// directly ("/home/u/.aws/*", "**/.env") while "path" stays harmless.
		if lname == "glob" || lname == "grep" {
			for _, cand := range []string{firstString(ti, "pattern"), firstString(ti, "glob")} {
				if cand != "" && (lname == "glob" || cand == firstString(ti, "glob")) && redact.IsCredentialAdjacentPath(cand) && !redact.IsCredentialAdjacentPath(p) {
					p = dropBareWildcards(cand)
					break
				}
			}
		}
		if p != "" {
			op := "read"
			if writeTools[lname] {
				op = "write"
			}
			return &model.Span{Kind: model.SpanFileOp, Name: name, Path: p, Op: op}
		}
	case "webfetch", "web_fetch", "fetch":
		if h := hostOf(firstString(ti, "url")); h != "" {
			return &model.Span{Kind: model.SpanNetEgress, Name: name, Host: h}
		}
	case "task", "agent":
		return &model.Span{Kind: model.SpanSubagentSpawn, Name: name,
			SpawnReason: firstString(ti, "description", "subagent_type")}
	}
	sp.ArgsSummary = compact(in.ToolInput)
	return sp
}

// commandOf extracts tool_input.command as a string (Claude Code) or an
// argv array (Codex), shell-quoting argv elements so they re-parse intact.
func commandOf(ti map[string]any) (string, bool) {
	switch v := ti["command"].(type) {
	case string:
		return v, true
	case []any:
		parts := make([]string, 0, len(v))
		for _, p := range v {
			s, ok := p.(string)
			if !ok {
				return "", false
			}
			parts = append(parts, ShellQuote(s))
		}
		return strings.Join(parts, " "), len(parts) > 0
	}
	return "", false
}

// ShellQuote quotes s for a POSIX shell when it needs quoting.
func ShellQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n'\"\\$`;&|<>()*?[]{}~!#") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// dropBareWildcards removes path components made only of wildcards
// ("/home/u/.aws/*" -> "/home/u/.aws", "**/.env" -> ".env"), so a search
// pattern is judged by the names it spells out and not by every name a bare
// "*" could stand for.
func dropBareWildcards(p string) string {
	parts := strings.Split(p, "/")
	out := parts[:0]
	for i, c := range parts {
		if c != "" && strings.Trim(c, "*?") == "" {
			continue
		}
		if c == "" && i != 0 {
			continue
		}
		out = append(out, c)
	}
	return strings.Join(out, "/")
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	h := u.Hostname()
	if ip := net.ParseIP(h); ip != nil {
		return ip.String()
	}
	return strings.ToLower(h)
}

func compact(raw json.RawMessage) string {
	s := strings.Join(strings.Fields(string(raw)), " ")
	if len(s) > 500 {
		s = s[:500] + "…"
	}
	return s
}

// Verdict is what the hook tells the harness.
type Verdict struct {
	Action string // "none" (defer to harness), "deny", "ask"
	Reason string
	// Recorded is the decision stored on the span, and DeferredTo names the
	// harness prompt the decision was escalated to ("" when not deferred).
	Recorded   policy.Result
	DeferredTo string
}

// Decide maps a policy result to a harness verdict.
func Decide(harness string, res policy.Result, strict bool) Verdict {
	v := Verdict{Recorded: res}
	switch res.Decision {
	case policy.Allow:
		v.Action = "none"
	case policy.Deny:
		if res.DefaultDeny && !strict {
			// Not explicitly forbidden, just not allowlisted.
			if harness == ClaudeCode {
				v.Action, v.Reason, v.DeferredTo = "ask", "warden: "+res.Reason+" — approve only if you expected this", "claude-code"
				v.Recorded = policy.Result{Decision: policy.RequireApproval, Reason: res.Reason, Version: res.Version}
			} else {
				v.Action, v.DeferredTo = "none", harness
				v.Recorded = policy.Result{Decision: policy.RequireApproval, Reason: res.Reason, Version: res.Version}
			}
			return v
		}
		v.Action, v.Reason = "deny", "warden: "+res.Reason
	case policy.RequireApproval:
		if harness == ClaudeCode {
			v.Action, v.Reason, v.DeferredTo = "ask", "warden: "+res.Reason, "claude-code"
		} else {
			// Codex hooks cannot ask a human; fail closed.
			v.Action, v.Reason = "deny", "warden: "+res.Reason+" (Codex hooks cannot prompt; run with `warden hook codex --await` and approve via `warden approve`)"
		}
	}
	return v
}

// Render writes the verdict in the harness's protocol and returns the
// process exit code. Claude Code gets hookSpecificOutput JSON on stdout
// (exit 0). Codex gets exit code 2 with the reason on stderr, the blocking
// form its hooks document.
func Render(harness string, v Verdict, stdout, stderr io.Writer) int {
	if v.Action == "none" {
		return 0
	}
	if harness == ClaudeCode {
		out, _ := json.Marshal(map[string]any{
			"hookSpecificOutput": map[string]any{
				"hookEventName":            "PreToolUse",
				"permissionDecision":       v.Action,
				"permissionDecisionReason": v.Reason,
			},
		})
		fmt.Fprintln(stdout, string(out))
		return 0
	}
	// Codex: only deny is meaningful.
	fmt.Fprintln(stderr, v.Reason)
	return 2
}

// Blocked renders an unconditional block (kill switch, quarantine, freeze,
// or warden failing closed).
func Blocked(harness, reason string, stdout, stderr io.Writer) int {
	return Render(harness, Verdict{Action: "deny", Reason: "warden: " + reason}, stdout, stderr)
}

// MaxStoredArgs bounds the argument summary stored on a span. Policy always
// evaluates the full text first; only storage is truncated.
const MaxStoredArgs = 4096

// Summarize truncates an argument summary for storage, noting how much was cut.
func Summarize(s string) string {
	if len(s) <= MaxStoredArgs {
		return s
	}
	cut := s[:MaxStoredArgs]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return fmt.Sprintf("%s…[+%d bytes]", cut, len(s)-len(cut))
}

// PatchPaths lists the files an apply_patch envelope touches
// ("*** Add File: p", "*** Update File: p", "*** Delete File: p",
// "*** Move to: p").
func PatchPaths(patch string) []string {
	var out []string
	for _, line := range strings.Split(patch, "\n") {
		line = strings.TrimSpace(line)
		for _, pre := range []string{"*** Add File:", "*** Update File:", "*** Delete File:", "*** Move to:"} {
			if strings.HasPrefix(line, pre) {
				if p := strings.TrimSpace(strings.TrimPrefix(line, pre)); p != "" {
					out = append(out, p)
				}
			}
		}
	}
	return out
}

func patchTarget(patch string) string {
	if paths := PatchPaths(patch); len(paths) > 0 {
		return paths[0]
	}
	return ""
}

// PatchInput returns the patch text of an apply_patch call ("" otherwise).
func PatchInput(in *Input) string {
	if strings.ToLower(in.ToolName) != "apply_patch" {
		return ""
	}
	var ti map[string]any
	_ = json.Unmarshal(in.ToolInput, &ti)
	if s, ok := ti["command"].(string); ok {
		return s
	}
	s, _ := ti["input"].(string)
	return s
}
