package policy

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// This file holds checks added after hands-on evasion testing (see
// internal/policy/evasion_test.go): writes to persistence and system paths
// through redirections and output options, git commands that move data off
// the machine, and environment dumps.

// writerBins are programs whose path arguments are write targets.
var writerBins = map[string]bool{
	"cp": true, "mv": true, "install": true, "ln": true, "tee": true, "touch": true,
	"truncate": true, "rm": true, "rsync": true, "scp": true, "dd": true, "sed": true,
	"curl": true, "wget": true, "sort": true, "gcc": true, "cc": true, "go": true,
	"chmod": true, "chown": true, "mkdir": true, "rmdir": true, "shred": true,
}

var rcFiles = map[string]bool{
	".bashrc": true, ".bash_profile": true, ".bash_login": true, ".bash_logout": true, ".profile": true,
	".zshrc": true, ".zprofile": true, ".zshenv": true, ".zlogin": true, ".zlogout": true,
	".inputrc": true, ".gitconfig": true, ".gitattributes": true, "authorized_keys": true,
	"known_hosts": true, "sudoers": true, "crontab": true, "config.fish": true, ".xinitrc": true, ".xprofile": true,
}

var deviceRe = regexp.MustCompile(`^/dev/(?:sd|hd|vd|xvd|nvme|mmcblk|disk|rdisk|mem$|kmem$|port$|kmsg$)`)

// sensitiveWrite reports whether writing to path would persist code, alter
// the system or destroy a disk. hard is true for raw devices, which no
// approval should unlock by default.
func sensitiveWrite(path string) (reason string, hard bool, ok bool) {
	p := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(path), `\`, "/"))
	p = strings.Trim(p, `"'`)
	if p == "" {
		return "", false, false
	}
	if deviceRe.MatchString(p) {
		return "writes to a raw device", true, true
	}
	if i := strings.LastIndex(p, "/"); i >= 0 {
		if rcFiles[p[i+1:]] {
			return "writes a shell or login startup file", false, true
		}
	} else if rcFiles[p] {
		return "writes a shell or login startup file", false, true
	}
	for _, pre := range []string{"/etc/", "/boot/", "/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/sys/", "/proc/",
		"/var/spool/cron", "/library/launchagents", "/library/launchdaemons", "c:/windows", "c:/program files"} {
		if strings.HasPrefix(p, pre) {
			return "writes a system path", false, true
		}
	}
	for _, sub := range []string{"/.git/hooks/", "/.config/autostart/", "/.config/systemd/", "/library/launchagents/",
		"/start menu/programs/startup/", "/.vscode/tasks.json", "/.git/config"} {
		if strings.Contains(p, sub) || strings.HasPrefix(p, sub[1:]) {
			return "writes a path that runs code later (hooks, autostart, tasks)", false, true
		}
	}
	return "", false, false
}

// redirectTargets returns the file targets of output redirections (>, >>,
// >|, &>, N>) in one command segment, quote-aware. fd duplications such as
// 2>&1 are ignored.
func redirectTargets(seg string) []string {
	var out []string
	rs := []rune(seg)
	var sq, dq bool
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case c == '\'' && !dq:
			sq = !sq
		case c == '"' && !sq:
			dq = !dq
		case c == '>' && !sq && !dq:
			j := i + 1
			if j < len(rs) && rs[j] == '(' { // >( ) process substitution
				continue
			}
			for j < len(rs) && (rs[j] == '>' || rs[j] == '|') {
				j++
			}
			if j < len(rs) && rs[j] == '&' { // 2>&1, >&2
				i = j
				continue
			}
			for j < len(rs) && (rs[j] == ' ' || rs[j] == '\t') {
				j++
			}
			start := j
			var tsq, tdq bool
			var b strings.Builder
			for ; j < len(rs); j++ {
				d := rs[j]
				if d == '\'' && !tdq {
					tsq = !tsq
					continue
				}
				if d == '"' && !tsq {
					tdq = !tdq
					continue
				}
				if !tsq && !tdq && (d == ' ' || d == '\t' || d == ';' || d == '|' || d == '&' || d == '<' || d == '>' || d == ')') {
					break
				}
				b.WriteRune(d)
			}
			if j > start && b.Len() > 0 {
				out = append(out, b.String())
			}
			i = j - 1
		}
	}
	return out
}

// outputOptionTargets returns values given to -o / --output style options.
func outputOptionTargets(ci CommandInfo) []string {
	var out []string
	for i, a := range ci.Args {
		switch {
		case a == "-o" || a == "--output" || a == "-O" || a == "--out" || a == "--output-file":
			if i+1 < len(ci.Args) {
				out = append(out, ci.Args[i+1])
			}
		case strings.HasPrefix(a, "--output=") || strings.HasPrefix(a, "--out="):
			out = append(out, a[strings.IndexByte(a, '=')+1:])
		case len(a) > 2 && (strings.HasPrefix(a, "-o") || strings.HasPrefix(a, "-O")) && !strings.HasPrefix(a, "--"):
			out = append(out, a[2:])
		case strings.HasPrefix(a, "of="):
			out = append(out, a[3:])
		}
	}
	return out
}

// sensitiveWriteInCommand scans a shell command (every nested segment) for a
// write to a sensitive path and returns what it found.
func sensitiveWriteInCommand(cmd string) (target, reason string, hard, found bool) {
	check := func(t string) bool {
		if r, h, ok := sensitiveWrite(t); ok {
			target, reason, hard, found = t, r, h, true
			return true
		}
		return false
	}
	for _, seg := range ShellSegments(cmd) {
		for _, t := range redirectTargets(seg) {
			if check(t) {
				return
			}
		}
		ci := ParseCommand(seg)
		for _, t := range outputOptionTargets(ci) {
			if check(t) {
				return
			}
		}
		if writerBins[ci.Bin] {
			for _, a := range ci.Args {
				if !strings.HasPrefix(a, "-") && check(a) {
					return
				}
			}
		}
	}
	return
}

var urlHostRe = regexp.MustCompile(`^(?:[a-zA-Z][a-zA-Z0-9+.-]*://|[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:)`)

// remoteHost extracts the host of a URL-like or scp-like (user@host:path)
// git remote argument.
func remoteHost(a string) (string, bool) {
	if !urlHostRe.MatchString(a) {
		return "", false
	}
	if strings.Contains(a, "://") {
		u, err := url.Parse(a)
		if err != nil || u.Hostname() == "" {
			return a, true // unparseable URL: treat as unknown host
		}
		return strings.ToLower(u.Hostname()), true
	}
	at := strings.IndexByte(a, '@')
	colon := strings.IndexByte(a[at:], ':')
	return strings.ToLower(a[at+1 : at+colon]), true
}

func (e *Evaluator) hostAllowed(host string) bool {
	if e.policy.Egress.Default == "allow" {
		return true
	}
	host = strings.ToLower(host)
	for _, h := range e.policy.Egress.AllowHosts {
		h = strings.ToLower(h)
		if host == h || strings.HasSuffix(host, "."+strings.TrimPrefix(h, "*.")) {
			return true
		}
	}
	return false
}

// riskyExtra holds the context-dependent checks that need the egress policy.
func (e *Evaluator) riskyExtra(ci CommandInfo) string {
	switch ci.Bin {
	case "git":
		sub := ""
		for i, a := range ci.Args {
			if !strings.HasPrefix(a, "-") && sub == "" {
				if i > 0 && (ci.Args[i-1] == "-C" || ci.Args[i-1] == "--git-dir" || ci.Args[i-1] == "--work-tree" || ci.Args[i-1] == "--namespace") {
					continue
				}
				sub = strings.ToLower(a)
			}
		}
		switch sub {
		case "push", "fetch", "pull", "clone", "ls-remote", "remote", "archive", "fetch-pack", "send-pack", "request-pull", "submodule":
			for _, a := range ci.Args {
				if host, ok := remoteHost(a); ok && !e.hostAllowed(host) {
					return fmt.Sprintf("git %s reaches host %q, which is not in egress allow_hosts", sub, host)
				}
			}
		}
	case "env", "printenv":
		if len(ci.Args) == 0 {
			return "dumps the whole environment (it can hold secrets)"
		}
	case "set", "declare", "typeset", "export", "compgen", "readonly":
		for _, a := range ci.Args {
			if a == "-p" || a == "-x" || a == "-v" || a == "-xp" || a == "-px" {
				return "dumps shell variables (they can hold secrets)"
			}
		}
		if (ci.Bin == "set" || ci.Bin == "export" || ci.Bin == "readonly") && len(ci.Args) == 0 {
			return "dumps shell variables (they can hold secrets)"
		}
	}
	return ""
}
