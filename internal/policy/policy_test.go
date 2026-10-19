package policy

import (
	"strings"
	"testing"

	"warden/internal/model"
)

type stubDenyList struct {
	denied map[string]string // "tool" or "tool:fleet" -> reason
}

func (s stubDenyList) IsToolDenied(tool, fleet string) (bool, string, error) {
	if r, ok := s.denied[tool+":"+fleet]; ok {
		return true, r, nil
	}
	if r, ok := s.denied[tool]; ok {
		return true, r, nil
	}
	return false, "", nil
}

func toolSpan(tool, args string) *model.Span {
	return &model.Span{
		Kind:        model.SpanToolCall,
		Tool:        tool,
		ArgsSummary: args,
		FleetID:     "prod",
	}
}

func TestShellDenyByDefault(t *testing.T) {
	p, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	ev := NewEvaluator(p, nil)

	cases := []struct {
		name string
		args string
		want Decision
	}{
		{"allowlisted git", "git status", Allow},
		{"allowlisted npm", "npm test", Allow},
		{"allowlisted with path", "/usr/bin/go build ./...", Allow},
		{"not allowlisted", "terraform apply", Deny},
		{"unknown binary", "evilscript --pwn", Deny},
		{"rm-rf-root always denied", "rm -rf /", Deny},
		{"rm-rf-root via allowlisted sh", "sh -c 'rm -rf /'", Deny},
		{"fork bomb", ":(){ :|:& };:", Deny},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := ev.Evaluate(toolSpan("bash", tc.args))
			if r.Decision != tc.want {
				t.Errorf("Evaluate(%q) = %v, want %v (reason: %s)", tc.args, r.Decision, tc.want, r.Reason)
			}
			if r.Version == "" {
				t.Error("decision must carry policy version")
			}
			if tc.want != Allow && r.Reason == "" {
				t.Error("deny/approval must have a human-readable reason")
			}
		})
	}
}

func TestEgressDenyByDefault(t *testing.T) {
	p, _ := Default()
	ev := NewEvaluator(p, nil)
	cases := []struct {
		host string
		want Decision
	}{
		{"api.anthropic.com", Allow},
		{"evil.example.com", Deny},
		{"pastebin.com", Deny}, // exfil-shaped destinations are denied by default
		{"", Deny},
	}
	for _, tc := range cases {
		r := ev.Evaluate(&model.Span{Kind: model.SpanNetEgress, Host: tc.host})
		if r.Decision != tc.want {
			t.Errorf("egress %q = %v, want %v (%s)", tc.host, r.Decision, tc.want, r.Reason)
		}
	}
}

func TestCredentialAdjacentFileRequiresApproval(t *testing.T) {
	p, _ := Default()
	ev := NewEvaluator(p, nil)

	r := ev.Evaluate(&model.Span{Kind: model.SpanFileOp, Path: "/home/dan/.env", Op: "read"})
	if r.Decision != RequireApproval {
		t.Errorf(".env read = %v, want require_approval (%s)", r.Decision, r.Reason)
	}
	r = ev.Evaluate(&model.Span{Kind: model.SpanFileOp, Path: "/x/main.go", Op: "write"})
	if r.Decision != Allow {
		t.Errorf("main.go write = %v, want allow", r.Decision)
	}
}

func TestDenyListWins(t *testing.T) {
	p, _ := Default()
	dl := stubDenyList{denied: map[string]string{"web_fetch": "exfil risk"}}
	ev := NewEvaluator(p, dl)

	r := ev.Evaluate(toolSpan("web_fetch", "https://example.com"))
	if r.Decision != Deny || !strings.Contains(r.Reason, "exfil risk") {
		t.Errorf("deny-listed tool should be denied with operator reason: %+v", r)
	}
	// Fleet-scoped deny does not leak to other fleets.
	dl2 := stubDenyList{denied: map[string]string{"bash:nightly": "lockdown"}}
	ev2 := NewEvaluator(p, dl2)
	if r := ev2.Evaluate(toolSpan("bash", "npm test")); r.Decision != Allow {
		t.Errorf("fleet-scoped deny leaked: %+v", r)
	}
}

func TestStaticDenyAndApprovalTools(t *testing.T) {
	p, _ := Default()
	ev := NewEvaluator(p, nil)

	if r := ev.Evaluate(toolSpan("delete_bucket", "my-bucket")); r.Decision != RequireApproval {
		t.Errorf("delete_bucket = %v, want require_approval", r.Decision)
	}
	if r := ev.Evaluate(toolSpan("web_search", "golang sqlite")); r.Decision != Allow {
		t.Errorf("web_search = %v, want allow", r.Decision)
	}

	yaml := "version: 9\nshell:\n  default: allow\ndeny_tools: [nasty]\napproval_tools: []\n"
	p2, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	ev2 := NewEvaluator(p2, nil)
	if r := ev2.Evaluate(toolSpan("nasty", "")); r.Decision != Deny {
		t.Errorf("static deny_tools not enforced: %+v", r)
	}
	if r := ev2.Evaluate(toolSpan("bash", "anything")); r.Decision != Allow || r.Version != "9" {
		t.Errorf("default-allow shell wrong: %+v", r)
	}
}

func TestBadPolicyRejected(t *testing.T) {
	if _, err := Parse([]byte("version: [unclosed")); err == nil {
		t.Error("bad YAML should fail")
	}
	if _, err := Parse([]byte("version: 1\nshell:\n  deny_patterns: ['([bad']\n")); err == nil {
		t.Error("bad regex should fail")
	}
}

func TestLoadMissingFallsBackToDefault(t *testing.T) {
	p, err := Load("/nonexistent/warden-policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != 1 {
		t.Errorf("default policy version = %d, want 1", p.Version)
	}
}

func TestLLMSpansArePolicyNeutral(t *testing.T) {
	p, _ := Default()
	ev := NewEvaluator(p, nil)
	r := ev.Evaluate(&model.Span{Kind: model.SpanLLMCall, Model: "claude-opus-4-6", CostUSD: 99})
	if r.Decision != Allow {
		t.Errorf("llm.call should be policy-neutral: %+v", r)
	}
}

func TestShellBinaryExtraction(t *testing.T) {
	cases := map[string]string{
		"git status":           "git",
		"/usr/bin/go build":    "go",
		"sudo -u dan npm test": "npm",
		"FOO=1 BAR=2 node app": "node",
		"sh -c 'echo hi'":      "sh",
		"":                     "",
	}
	for in, want := range cases {
		if got := shellBinary(in); got != want {
			t.Errorf("shellBinary(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestApprovalBeatsShellAllowlist(t *testing.T) {
	p, _ := Parse([]byte("version: 1\nshell:\n  default: deny\n  allow: [bash]\napproval_tools: [bash]\n"))
	ev := NewEvaluator(p, nil)
	r := ev.Evaluate(toolSpan("bash", "echo hi"))
	if r.Decision != RequireApproval {
		t.Errorf("explicit approval_tools should beat shell allowlist: %+v", r)
	}
}

func TestDenyPatternBeatsApproval(t *testing.T) {
	p, _ := Parse([]byte("version: 1\nshell:\n  default: deny\n  allow: [bash]\n  deny_patterns: ['rm\\s+-rf']\napproval_tools: [bash]\n"))
	ev := NewEvaluator(p, nil)
	r := ev.Evaluate(toolSpan("bash", "rm -rf /tmp/x"))
	if r.Decision != Deny {
		t.Errorf("deny pattern must beat approval_tools: %+v", r)
	}
}

func TestCredentialPathInShellCommand(t *testing.T) {
	p, _ := Default()
	ev := NewEvaluator(p, nil)

	cases := []struct {
		name string
		args string
		want Decision
	}{
		{"cat .env needs approval", "cat .env", RequireApproval},
		{"read aws creds needs approval", "cat ~/.aws/credentials", RequireApproval},
		{"plain cat allowed", "cat README.md", Allow},
		{"ls ssh dir allowed", "ls ~/.ssh", Allow},
		{"deny pattern still wins", "cat .env; rm -rf /", Deny},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := ev.Evaluate(toolSpan("bash", tc.args))
			if r.Decision != tc.want {
				t.Errorf("Evaluate(%q) = %v, want %v (%s)", tc.args, r.Decision, tc.want, r.Reason)
			}
		})
	}
}

func TestCredentialAdjacentDenyMode(t *testing.T) {
	p, _ := Parse([]byte("version: 1\nshell:\n  default: deny\n  allow: [cat]\nfiles:\n  credential_adjacent: deny\n"))
	ev := NewEvaluator(p, nil)
	r := ev.Evaluate(toolSpan("bash", "cat .env"))
	if r.Decision != Deny {
		t.Errorf("credential_adjacent=deny should deny, got %v", r.Decision)
	}
}
