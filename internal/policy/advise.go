package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/calasdan-sketch/warden/internal/model"
)

// BinaryRisk says what allowlisting a program really grants.
type BinaryRisk int

const (
	// RiskReadOnly programs read or print and cannot run other code or reach
	// the network by themselves.
	RiskReadOnly BinaryRisk = iota
	// RiskWrites programs change files (still inside the write checks).
	RiskWrites
	// RiskNetwork programs move data off the machine, past the egress policy.
	RiskNetwork
	// RiskCode programs run whatever code or command they are handed:
	// allowlisting one allowlists everything.
	RiskCode
	// RiskUnknown programs are not in the table: judge them yourself.
	RiskUnknown
)

func (r BinaryRisk) String() string {
	return [...]string{"read-only", "writes files", "reaches the network", "runs arbitrary code", "unknown"}[r]
}

var binaryRisk = func() map[string]BinaryRisk {
	m := map[string]BinaryRisk{}
	set := func(r BinaryRisk, names ...string) {
		for _, n := range names {
			m[n] = r
		}
	}
	set(RiskReadOnly, "ls", "cat", "head", "tail", "wc", "grep", "egrep", "fgrep", "diff", "cmp", "sort", "uniq", "cut", "tr", "echo",
		"printf", "pwd", "which", "whoami", "id", "uname", "hostname", "date", "stat", "file", "du", "df", "tree", "basename", "dirname",
		"realpath", "readlink", "sleep", "true", "false", "test", "nl", "fold", "column", "comm", "paste", "rev", "tac", "seq", "yes", "md5sum",
		"sha1sum", "sha256sum", "git")
	set(RiskWrites, "mkdir", "touch", "cp", "mv", "rm", "rmdir", "ln", "chmod", "chown", "tee", "dd", "truncate", "install", "patch", "zip", "unzip", "gzip", "gunzip", "xxd", "split", "csplit")
	set(RiskNetwork, "curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "sftp", "rsync", "ftp", "telnet", "socat", "nmap", "dig", "nslookup", "ping", "gh", "aws", "gcloud", "az", "kubectl", "helm", "terraform")
	set(RiskCode, "sh", "bash", "zsh", "dash", "fish", "ksh", "csh", "python", "python2", "python3", "node", "nodejs", "deno", "bun", "ruby", "perl", "php", "lua",
		"awk", "gawk", "mawk", "sed", "tar", "cpio", "7z", "7za", "npm", "npx", "pnpm", "yarn", "pip", "pip3", "pipx", "uv", "go", "cargo", "rustc", "make", "cmake", "gcc", "cc", "g++", "clang",
		"java", "javac", "mvn", "gradle", "dotnet", "docker", "podman", "find", "xargs", "env", "sudo", "su", "doas", "eval", "exec", "source", ".", "nohup",
		"timeout", "watch", "time", "script", "screen", "tmux", "vi", "vim", "nvim", "emacs", "nano", "less", "more", "man", "ed", "ex", "busybox", "chroot", "nsenter", "strace", "gdb", "expect")
	return m
}()

// ClassifyBinary returns what allowlisting name would allow. git is
// read-only here because the default checks block its code-running forms.
func ClassifyBinary(name string) BinaryRisk {
	if r, ok := binaryRisk[strings.ToLower(name)]; ok {
		return r
	}
	return RiskUnknown
}

// Lint is one finding about a policy file.
type Lint struct {
	Level   string // "warn" or "info"
	Message string
}

// Lint reviews a parsed policy for settings that quietly remove protection.
func (p *Policy) Lint() []Lint {
	var out []Lint
	warn := func(f string, a ...any) { out = append(out, Lint{"warn", fmt.Sprintf(f, a...)}) }
	if p.Shell.Default == "allow" {
		warn("shell.default is allow: the allowlist is ignored and only deny_patterns, protected paths and the write/credential checks apply")
	}
	if p.Egress.Default == "allow" {
		warn("egress.default is allow: any host may be contacted (git remotes included)")
	}
	switch p.Files.CredentialAdjacent {
	case "allow":
		warn("files.credential_adjacent is allow: reading ~/.ssh, ~/.aws, .env and similar no longer needs approval")
	}
	for _, a := range p.Shell.Allow {
		name := a
		if i := strings.LastIndexAny(name, `/\`); i >= 0 {
			name = name[i+1:]
		}
		switch ClassifyBinary(name) {
		case RiskCode:
			warn("shell.allow has %q, which runs arbitrary code: allowlisting it allowlists everything it can launch", a)
		case RiskNetwork:
			warn("shell.allow has %q, which reaches the network and is not covered by egress.allow_hosts", a)
		case RiskUnknown:
			out = append(out, Lint{"info", fmt.Sprintf("shell.allow has %q, which warden does not know; make sure it cannot run other programs or reach the network", a)})
		}
	}
	for _, h := range p.Egress.AllowHosts {
		if strings.Trim(h, "*.?") == "" {
			warn("egress.allow_hosts has %q, which matches no host (wildcards work only as a leading \"*.\" before a real domain); use egress.default: allow if you truly mean every host", h)
		}
	}
	for _, d := range p.Shell.DenyPatterns {
		if d == "" || d == ".*" {
			warn("shell.deny_patterns has a pattern (%q) that matches everything: every shell command will be denied", d)
		}
	}
	if len(p.Shell.Allow) == 0 && p.Shell.Default != "allow" {
		out = append(out, Lint{"info", "shell.allow is empty: every shell command is denied (git and ls included)"})
	}
	for _, t := range p.ApprovalTools {
		if p.denyToolsSet[strings.ToLower(t)] {
			out = append(out, Lint{"info", fmt.Sprintf("%q is in both deny_tools and approval_tools; deny wins", t)})
		}
	}
	return out
}

// Segment is one simple command of a shell line, as warden sees it.
type Segment struct {
	Command string
	Binary  string
	Risk    BinaryRisk
	Allowed bool   // on the shell allowlist
	Problem string // why it is refused or needs review, if it is
}

// Explanation is the policy's verdict on one shell line, step by step.
type Explanation struct {
	Result   Result
	Segments []Segment
	// Hint says what to change to allow it, when that is a sensible thing to do.
	Hint string
}

// ExplainShell judges a shell command and shows which part decided it.
func (e *Evaluator) ExplainShell(cmd string) Explanation {
	sp := &model.Span{Kind: model.SpanToolCall, Tool: "Bash", ArgsSummary: cmd}
	ex := Explanation{Result: e.Evaluate(sp)}
	if len(cmd) > MaxAnalyzedCommand {
		return ex
	}
	var unlisted []string
	for _, seg := range ShellSegments(cmd) {
		ci := ParseCommand(seg)
		s := Segment{Command: seg, Binary: ci.Bin}
		if ci.Bin != "" {
			s.Risk = ClassifyBinary(ci.Bin)
			s.Allowed = safeBuiltins[ci.Bin] || e.binaryAllowed(ci)
			switch {
			case ci.Reject != "":
				s.Problem = ci.Reject
			case ci.EnvDump:
				s.Problem = "dumps the whole environment"
			case !s.Allowed:
				s.Problem = "not on shell.allow"
				unlisted = append(unlisted, ci.Bin)
			default:
				if why := riskyInvocation(ci); why != "" {
					s.Problem = why
				} else if why := e.riskyExtra(ci); why != "" {
					s.Problem = why
				}
			}
		}
		ex.Segments = append(ex.Segments, s)
	}
	if ex.Result.Decision != Allow && len(unlisted) > 0 {
		sort.Strings(unlisted)
		var names []string
		for i, n := range unlisted {
			if i > 0 && n == unlisted[i-1] {
				continue
			}
			names = append(names, n)
		}
		var bad []string
		for _, n := range names {
			if r := ClassifyBinary(n); r == RiskCode || r == RiskNetwork {
				bad = append(bad, fmt.Sprintf("%s (%s)", n, r))
			}
		}
		if len(bad) > 0 {
			ex.Hint = "allowlisting " + strings.Join(bad, ", ") + " would also allow far more than this one command; consider a sandbox or approving it case by case instead"
		} else {
			ex.Hint = "to allow it, add to shell.allow: " + strings.Join(names, ", ")
		}
	}
	return ex
}
