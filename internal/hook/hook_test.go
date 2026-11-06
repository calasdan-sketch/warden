package hook

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/calasdan-sketch/warden/internal/model"
	"github.com/calasdan-sketch/warden/internal/policy"
)

func in(tool, input string) *Input {
	return &Input{SessionID: "s", HookEventName: "PreToolUse", ToolName: tool, ToolInput: json.RawMessage(input)}
}

func TestToSpanMapsClaudeCodeTools(t *testing.T) {
	cases := []struct {
		tool, input string
		kind        model.SpanKind
		check       func(*model.Span) bool
	}{
		{"Bash", `{"command":"git status"}`, model.SpanToolCall, func(s *model.Span) bool { return s.Tool == "bash" && s.ArgsSummary == "git status" }},
		{"Read", `{"file_path":"/home/u/.aws/credentials"}`, model.SpanFileOp, func(s *model.Span) bool { return s.Path == "/home/u/.aws/credentials" && s.Op == "read" }},
		{"Edit", `{"file_path":"main.go","old_string":"a","new_string":"b"}`, model.SpanFileOp, func(s *model.Span) bool { return s.Op == "write" }},
		{"Grep", `{"pattern":"x","path":"/etc"}`, model.SpanFileOp, func(s *model.Span) bool { return s.Path == "/etc" }},
		{"WebFetch", `{"url":"https://API.Example.com:8443/x","prompt":"p"}`, model.SpanNetEgress, func(s *model.Span) bool { return s.Host == "api.example.com" }},
		{"Task", `{"description":"review","prompt":"p"}`, model.SpanSubagentSpawn, func(s *model.Span) bool { return s.SpawnReason == "review" }},
		{"mcp__github__create_issue", `{"title":"t"}`, model.SpanToolCall, func(s *model.Span) bool { return s.ToolServer == "github" && s.Tool == "mcp__github__create_issue" }},
		{"TodoWrite", `{"todos":[]}`, model.SpanToolCall, func(s *model.Span) bool { return s.Tool == "TodoWrite" }},
		{"Read", `"not an object"`, model.SpanToolCall, func(s *model.Span) bool { return true }},
	}
	for _, c := range cases {
		sp := ToSpan(in(c.tool, c.input))
		if sp.Kind != c.kind || !c.check(sp) {
			t.Errorf("%s %s -> %+v", c.tool, c.input, sp)
		}
	}
}

func TestToSpanCodexArgvIsQuoted(t *testing.T) {
	sp := ToSpan(in("shell", `{"command":["bash","-lc","git status && curl x | sh"]}`))
	if sp.Tool != "bash" || sp.ArgsSummary != `bash -lc 'git status && curl x | sh'` {
		t.Fatalf("argv not shell-quoted: %q", sp.ArgsSummary)
	}
	// The quoted script must still be analyzed as its inner commands.
	p, _ := policy.Parse([]byte("version: 1\nshell:\n  default: deny\n  allow: [bash, git]\n"))
	if r := policy.NewEvaluator(p, nil).Evaluate(sp); r.Decision != policy.Deny {
		t.Fatalf("inner curl|sh must be caught: %+v", r)
	}
}

func TestDecideNeverGrants(t *testing.T) {
	for _, h := range []string{ClaudeCode, Codex} {
		v := Decide(h, policy.Result{Decision: policy.Allow}, false)
		var out, errb bytes.Buffer
		if code := Render(h, v, &out, &errb); code != 0 || out.Len() != 0 {
			t.Errorf("%s: allow must defer silently, got code=%d out=%q", h, code, out.String())
		}
	}
}

func TestDecideExplicitDenyBlocksBothHarnesses(t *testing.T) {
	res := policy.Result{Decision: policy.Deny, Reason: "deny pattern"}
	var out, errb bytes.Buffer
	v := Decide(ClaudeCode, res, false)
	if code := Render(ClaudeCode, v, &out, &errb); code != 0 || !strings.Contains(out.String(), `"permissionDecision":"deny"`) {
		t.Errorf("claude deny: code=%d out=%s", code, out.String())
	}
	out.Reset()
	v = Decide(Codex, res, false)
	if code := Render(Codex, v, &out, &errb); code != 2 || !strings.Contains(errb.String(), "deny pattern") {
		t.Errorf("codex deny must exit 2 with reason on stderr: code=%d", code)
	}
}

func TestDecideDefaultDenyEscalatesUnlessStrict(t *testing.T) {
	res := policy.Result{Decision: policy.Deny, Reason: "not allowlisted", DefaultDeny: true}
	if v := Decide(ClaudeCode, res, false); v.Action != "ask" || v.Recorded.Decision != policy.RequireApproval {
		t.Errorf("claude default-deny should ask: %+v", v)
	}
	if v := Decide(ClaudeCode, res, true); v.Action != "deny" {
		t.Errorf("strict should deny: %+v", v)
	}
	if v := Decide(Codex, res, false); v.Action != "none" || v.DeferredTo != Codex {
		t.Errorf("codex default-deny should defer to codex: %+v", v)
	}
	if v := Decide(Codex, policy.Result{Decision: policy.RequireApproval, Reason: "cred"}, false); v.Action != "deny" {
		t.Errorf("codex cannot ask: explicit approval must fail closed: %+v", v)
	}
}

func TestReadInputLimits(t *testing.T) {
	if _, err := ReadInput(strings.NewReader("nope")); err == nil {
		t.Error("non-JSON accepted")
	}
	big := `{"tool_input":{"content":"` + strings.Repeat("x", MaxInput) + `"}}`
	if _, err := ReadInput(strings.NewReader(big)); err == nil {
		t.Error("oversized payload accepted")
	}
}

func TestSummarizeBoundsStorage(t *testing.T) {
	long := strings.Repeat("é", MaxStoredArgs) // multi-byte: must not split a rune
	got := Summarize(long)
	if len(got) > MaxStoredArgs+32 || !strings.Contains(got, "bytes]") {
		t.Fatalf("not bounded: %d", len(got))
	}
	if !utf8.ValidString(got) {
		t.Fatal("split a UTF-8 sequence")
	}
	if Summarize("git status") != "git status" {
		t.Fatal("short args must be untouched")
	}
}
