// Package policy implements deny-by-default policy gates at the tool-call
// boundary. It covers the "dangerous three" from the security brief:
// shell/exec, network egress, and credential use.
//
// Decisions are recorded on every span (policy_decision, policy_reason,
// policy_version) and in the audit trail. Policy files are versioned in git,
// diffable, reviewed like code.
package policy

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"warden/internal/model"
	"warden/internal/redact"
)

// Decision is the outcome of evaluating one span against policy.
type Decision int

const (
	// Allow lets the action proceed.
	Allow Decision = iota
	// Deny refuses the action with a human-readable reason.
	Deny
	// RequireApproval holds the action until a human decides (see store.Approvals).
	RequireApproval
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case Deny:
		return "deny"
	case RequireApproval:
		return "require_approval"
	}
	return "unknown"
}

// Result is a decided evaluation.
type Result struct {
	Decision Decision
	Reason   string // human-readable; always set on Deny/RequireApproval
	Version  string // policy version that decided
}

// Policy is the loaded policy.yaml.
type Policy struct {
	Version int `yaml:"version"`

	Shell struct {
		Default      string   `yaml:"default"` // "deny" (default) or "allow"
		Allow        []string `yaml:"allow"`   // allowlisted command binaries
		DenyPatterns []string `yaml:"deny_patterns"`
		denyRe       []*regexp.Regexp
	} `yaml:"shell"`

	Egress struct {
		Default    string   `yaml:"default"` // "deny" (default) or "allow"
		AllowHosts []string `yaml:"allow_hosts"`
	} `yaml:"egress"`

	Files struct {
		// CredentialAdjacent is what happens on credential-adjacent file access:
		// "require_approval" (default), "deny", or "allow".
		CredentialAdjacent string `yaml:"credential_adjacent"`
	} `yaml:"files"`

	// DenyTools are always refused, everywhere (static list; the dynamic
	// deny-list pushed by kill --scope tool lives in the store).
	DenyTools []string `yaml:"deny_tools"`
	// ApprovalTools require a human approval before each call.
	ApprovalTools []string `yaml:"approval_tools"`

	denyToolsSet     map[string]bool
	approvalToolsSet map[string]bool
}

// DenyList is the dynamic tool deny-list (kill --scope tool). Implemented by store.
type DenyList interface {
	IsToolDenied(tool, fleet string) (bool, string, error)
}

// DefaultYAML is the v1 default policy: deny-by-default on the dangerous three.
const DefaultYAML = `version: 1
shell:
  default: deny
  allow: [git, go, npm, node, python3, ls, cat, echo, mkdir, curl]
  deny_patterns:
    - 'rm\s+-rf\s+/(?:\s|$)'
    - ':\(\)\{\s*:\|\:&\s*\};:'   # fork bomb
    - 'mkfs\.'
    - 'dd\s+.*of=/dev/'
egress:
  default: deny
  allow_hosts:
    - proxy.golang.org
    - api.anthropic.com
files:
  credential_adjacent: require_approval
deny_tools: []
approval_tools: [delete_bucket, drop_database, send_email]
`

// Default returns the default v1 policy.
func Default() (*Policy, error) { return Parse([]byte(DefaultYAML)) }

// Load reads a policy file; missing file falls back to Default().
func Load(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Default()
		}
		return nil, err
	}
	return Parse(b)
}

// Parse parses policy YAML.
func Parse(b []byte) (*Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	for _, pat := range p.Shell.DenyPatterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("bad shell deny pattern %q: %w", pat, err)
		}
		p.Shell.denyRe = append(p.Shell.denyRe, re)
	}
	p.denyToolsSet = map[string]bool{}
	for _, t := range p.DenyTools {
		p.denyToolsSet[strings.ToLower(t)] = true
	}
	p.approvalToolsSet = map[string]bool{}
	for _, t := range p.ApprovalTools {
		p.approvalToolsSet[strings.ToLower(t)] = true
	}
	return &p, nil
}

// shellTools are the tool names treated as shell/exec.
var shellTools = map[string]bool{
	"bash": true, "sh": true, "shell": true, "exec": true, "run_command": true, "terminal": true,
}

// Evaluator applies policy to spans.
type Evaluator struct {
	policy   *Policy
	denyList DenyList
}

// NewEvaluator builds an evaluator. denyList may be nil.
func NewEvaluator(p *Policy, denyList DenyList) *Evaluator {
	return &Evaluator{policy: p, denyList: denyList}
}

// Version returns the policy version string stamped on every decision.
func (e *Evaluator) Version() string { return fmt.Sprintf("%d", e.policy.Version) }

// Evaluate decides the fate of one span. It is pure except for the dynamic
// deny-list lookup; it never touches the network.
func (e *Evaluator) Evaluate(sp *model.Span) Result {
	ver := fmt.Sprintf("%d", e.policy.Version)
	switch sp.Kind {
	case model.SpanToolCall:
		return e.evalTool(sp, ver)
	case model.SpanNetEgress:
		return e.evalEgress(sp, ver)
	case model.SpanFileOp:
		return e.evalFile(sp, ver)
	default:
		// llm.call, subagent.spawn, human.approval: policy-neutral in v1.
		return Result{Decision: Allow, Version: ver}
	}
}

func (e *Evaluator) evalTool(sp *model.Span, ver string) Result {
	tool := strings.ToLower(sp.Tool)

	// 1. Dynamic deny-list (kill --scope tool) wins over everything.
	if e.denyList != nil {
		if denied, reason, err := e.denyList.IsToolDenied(sp.Tool, sp.FleetID); err == nil && denied {
			return Result{Decision: Deny, Reason: fmt.Sprintf("tool %q disabled by operator: %s", sp.Tool, reason), Version: ver}
		}
	}
	// 2. Static policy deny list.
	if e.policy.denyToolsSet[tool] {
		return Result{Decision: Deny, Reason: fmt.Sprintf("tool %q denied by policy (deny_tools)", sp.Tool), Version: ver}
	}
	// 3. Shell deny patterns: deny always wins, even over explicit approvals.
	if shellTools[tool] {
		cmd := shellCommand(sp)
		if re := e.shellDenyMatch(cmd); re != nil {
			return Result{Decision: Deny,
				Reason:  fmt.Sprintf("shell command matches deny pattern %q", re.String()),
				Version: ver}
		}
		// Commands that touch credential-adjacent paths get the same
		// treatment as credential-adjacent file.op spans.
		if p := credentialPathInCommand(cmd); p != "" {
			switch e.policy.Files.CredentialAdjacent {
			case "deny":
				return Result{Decision: Deny,
					Reason:  fmt.Sprintf("command references credential-adjacent path %q: denied by policy", p),
					Version: ver}
			case "allow":
			default:
				return Result{Decision: RequireApproval,
					Reason:  fmt.Sprintf("command references credential-adjacent path %q: requires human approval", p),
					Version: ver}
			}
		}
	}
	// 4. Explicit approval gating beats the shell allowlist (explicit > default).
	if e.policy.approvalToolsSet[tool] {
		return Result{Decision: RequireApproval,
			Reason:  fmt.Sprintf("tool %q requires human approval (policy approval_tools)", sp.Tool),
			Version: ver}
	}
	// 5. Shell/exec: the dangerous one - deny by default against the allowlist.
	if shellTools[tool] {
		return e.evalShellAllow(sp, ver)
	}
	return Result{Decision: Allow, Version: ver}
}

// shellCommand returns the command text a shell span carries.
func shellCommand(sp *model.Span) string {
	if sp.ArgsSummary != "" {
		return sp.ArgsSummary
	}
	return sp.Name
}

// shellDenyMatch returns the first deny pattern matching the command, or nil.
func (e *Evaluator) shellDenyMatch(cmd string) *regexp.Regexp {
	for _, re := range e.policy.Shell.denyRe {
		if re.MatchString(cmd) {
			return re
		}
	}
	return nil
}

// evalShellAllow applies the shell allowlist / default after deny patterns
// and explicit approval gates have been checked.
func (e *Evaluator) evalShellAllow(sp *model.Span, ver string) Result {
	cmd := shellCommand(sp)
	if e.policy.Shell.Default == "allow" {
		return Result{Decision: Allow, Version: ver}
	}
	bin := shellBinary(cmd)
	for _, a := range e.policy.Shell.Allow {
		if bin == a {
			return Result{Decision: Allow, Version: ver}
		}
	}
	return Result{Decision: Deny,
		Reason:  fmt.Sprintf("shell command %q not allowlisted (binary %q; policy default is deny)", truncate(cmd, 80), bin),
		Version: ver}
}

// credentialPathInCommand scans a shell command for tokens that look like
// credential-adjacent paths. Returns the first hit, or "".
func credentialPathInCommand(cmd string) string {
	for _, tok := range strings.Fields(cmd) {
		tok = strings.Trim(tok, `"'`)
		if tok == "" {
			continue
		}
		if redact.IsCredentialAdjacentPath(tok) {
			return tok
		}
	}
	return ""
}

// shellBinary extracts the invoked binary from a command line: the first
// real token, with leading wrappers ("sudo -u dan", "env FOO=1") stripped.
func shellBinary(cmd string) string {
	toks := strings.Fields(cmd)
	skipNext := false
	for _, t := range toks {
		if skipNext {
			skipNext = false
			continue
		}
		lt := strings.ToLower(t)
		if lt == "sudo" || lt == "env" {
			continue
		}
		if strings.HasPrefix(t, "-") {
			// A flag may carry its value as the next token ("-u dan").
			if !strings.Contains(t, "=") {
				skipNext = true
			}
			continue
		}
		if strings.Contains(t, "=") { // VAR=value assignment
			continue
		}
		base := t
		if i := strings.LastIndex(base, "/"); i >= 0 {
			base = base[i+1:]
		}
		return strings.ToLower(base)
	}
	return ""
}

func (e *Evaluator) evalEgress(sp *model.Span, ver string) Result {
	if e.policy.Egress.Default == "allow" {
		return Result{Decision: Allow, Version: ver}
	}
	host := strings.ToLower(sp.Host)
	for _, h := range e.policy.Egress.AllowHosts {
		h = strings.ToLower(h)
		if host == h || strings.HasSuffix(host, "."+strings.TrimPrefix(h, "*.")) {
			return Result{Decision: Allow, Version: ver}
		}
	}
	return Result{Decision: Deny,
		Reason:  fmt.Sprintf("egress to %q denied: host not allowlisted (policy default is deny)", sp.Host),
		Version: ver}
}

func (e *Evaluator) evalFile(sp *model.Span, ver string) Result {
	if !redact.IsCredentialAdjacentPath(sp.Path) {
		return Result{Decision: Allow, Version: ver}
	}
	switch e.policy.Files.CredentialAdjacent {
	case "deny":
		return Result{Decision: Deny,
			Reason:  fmt.Sprintf("credential-adjacent file access denied: %s", sp.Path),
			Version: ver}
	case "allow":
		return Result{Decision: Allow, Version: ver}
	default: // require_approval
		return Result{Decision: RequireApproval,
			Reason:  fmt.Sprintf("credential-adjacent file %q requires human approval", sp.Path),
			Version: ver}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
