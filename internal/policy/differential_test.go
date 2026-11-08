package policy

import (
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/calasdan-sketch/warden/internal/model"
)

// TestDifferentialAgainstRealShell is a differential test: the policy's
// reading of a command line is compared with what a real shell does with it.
//
// Every program name lives in a private directory as a stub that only appends
// its own name to a log file (no real program ever runs: PATH is that
// directory alone). Random command lines are built from shell fragments that
// try to smuggle in a program ("evil") that is not on the allowlist. If the
// policy says Allow, the shell (dash and bash) must not have run any stub
// outside the allowlist. A failure here is a real bypass, and the failing
// line is printed.
func TestDifferentialAgainstRealShell(t *testing.T) {
	if runtime.GOOS == "windows" || testing.Short() {
		t.Skip("needs a POSIX shell; skipped with -short")
	}
	shells := []string{}
	for _, s := range []string{"sh", "bash"} {
		if p, err := exec.LookPath(s); err == nil {
			shells = append(shells, p)
		}
	}
	if len(shells) == 0 {
		t.Skip("no POSIX shell")
	}
	pol, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	ev := NewEvaluator(pol, nil)
	allowed := map[string]bool{}
	for _, a := range pol.Shell.Allow {
		allowed[a] = true
	}

	dir := t.TempDir()
	stubs := filepath.Join(dir, "bin")
	logf := filepath.Join(dir, "ran.log")
	work := filepath.Join(dir, "work")
	for _, d := range []string{stubs, work} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	names := []string{"evil", "curl", "sh", "bash", "env", "xargs", "sudo", "python3", "node", "find", "tee", "sed", "awk", "nc", "ssh"}
	names = append(names, pol.Shell.Allow...)
	for _, n := range names {
		body := "#!/bin/sh\nprintf '%s\\n' \"${0##*/}\" >> \"$WARDEN_TEST_LOG\"\n"
		if n == "env" {
			// env is a transparent wrapper: it runs what follows, so the
			// stub does too and only the wrapped program is judged.
			body = "#!/bin/sh\nexec \"$@\"\n"
		}
		if err := os.WriteFile(filepath.Join(stubs, n), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	frags := []string{
		"git status", "git log", "ls", "ls -la", "cat f", "echo hi", "pwd", "head f", "wc -l f", "grep x f", "sort f", "which ls",
		" ; ", " && ", " || ", " | ", " & ", "\n", " ", " ", " ",
		"evil", "evil x", "$(evil)", "`evil`", "(evil)", "{ evil; }", "<(evil)", ">(evil)", "$(echo evil)", "\"$(evil)\"", "'$(evil)'",
		"\\", "'", "\"", "$'ev\\x69l'", "e\\vil", "ev''il", "\"ev\"il", "${x:-$(evil)}", "$((1))", "$IFS", "${IFS}",
		"VAR=1 ", "PATH=. ", "FOO=$(evil) ", "eval ", "exec ", "time ", "! ", "command ", "builtin ", "nohup ", "nice ",
		"if true; then evil; fi", "for i in 1; do evil; done", "while false; do :; done", "case x in x) evil;; esac",
		"echo a > f", "echo a >> f", "< f", "2>&1", "<<EOF\nevil\nEOF\n", "<<<evil", "{evil,}", "~", "*", "?", "#", "\t",
		"git -c core.pager=evil log", "git status --porcelain", "alias ls=evil; ls", "xargs", "env", "sh -c evil", "bash -c 'evil'",
		"echo $(< f)", "cat <(echo x)", "ls /", "cd /", "cd ..", ".", "source", "trap evil EXIT; ",
	}

	r := rand.New(rand.NewSource(20261108))
	const cases = 20000
	checked, bypass := 0, 0
	seen := map[string]bool{}
	for i := 0; i < cases; i++ {
		n := 1 + r.Intn(6)
		var sb strings.Builder
		for j := 0; j < n; j++ {
			sb.WriteString(frags[r.Intn(len(frags))])
		}
		cmd := sb.String()
		if seen[cmd] {
			continue
		}
		seen[cmd] = true
		res := ev.Evaluate(&model.Span{Kind: model.SpanToolCall, Tool: "Bash", ArgsSummary: cmd})
		if res.Decision != Allow {
			continue
		}
		checked++
		for _, sh := range shells {
			_ = os.Remove(logf)
			c := exec.Command(sh, "-c", cmd)
			c.Dir = work
			c.Env = []string{"PATH=" + stubs, "WARDEN_TEST_LOG=" + logf, "HOME=" + work, "LC_ALL=C"}
			c.Stdin = strings.NewReader("")
			done := make(chan struct{})
			if err := c.Start(); err != nil {
				continue
			}
			go func() { _ = c.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				_ = c.Process.Kill()
				<-done
			}
			b, _ := os.ReadFile(logf)
			for _, ran := range strings.Fields(string(b)) {
				if !allowed[ran] {
					bypass++
					t.Errorf("BYPASS: policy allowed %q but %s ran %q", cmd, filepath.Base(sh), ran)
					break
				}
			}
		}
	}
	t.Logf("differential: %d random lines, %d allowed by policy and replayed in %d shell(s), %d bypasses", len(seen), checked, len(shells), bypass)
	if checked < 200 {
		t.Errorf("generator produced only %d allowed lines; the test is not exercising the policy", checked)
	}
}
