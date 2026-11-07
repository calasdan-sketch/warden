package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// capture runs f with stdout redirected and returns its exit code and output.
func capture(t *testing.T, f func() int) (int, string) {
	t.Helper()
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	code := f()
	w.Close()
	os.Stdout = old
	return code, <-done
}

func demoDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "demo")
	if _, _ = capture(t, func() int { return cmdDemo([]string{"--dir", dir}) }); false {
		t.Fatal()
	}
	return dir
}

// A typo in policy.yaml must stop the commands that gate, but never the
// kill switch or the audit trail: those are what you reach for in an incident.
func TestBrokenPolicyStopsGatingNotKillOrVerify(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(bad, []byte("version: 1\nshell:\n  deny_pattern: ['rm']\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openApp(dir, "", true); err == nil || !strings.Contains(err.Error(), "warden policy check") || !strings.Contains(err.Error(), "deny_pattern") {
		t.Fatalf("gating commands must refuse, naming the typo and the fix: %v", err)
	}
	a, err := openApp(dir, "", false)
	if err != nil {
		t.Fatalf("non-gating commands must still open: %v", err)
	}
	defer a.close()
	if code, _ := capture(t, func() int { return a.cmdVerify(nil) }); code != 0 {
		t.Errorf("verify on an empty store: exit %d", code)
	}
	for _, c := range []string{"wrap", "gate", "dashboard", "report", "span"} {
		if !gatingCommands[c] {
			t.Errorf("%s enforces policy and must be a gating command", c)
		}
	}
	for _, c := range []string{"kill", "verify", "replay", "runs", "export", "anchor", "approve"} {
		if gatingCommands[c] {
			t.Errorf("%s must work while the policy file is broken", c)
		}
	}
}

func TestPolicyCheckAndExplainCommands(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yaml")
	warny := filepath.Join(dir, "warny.yaml")
	typo := filepath.Join(dir, "typo.yaml")
	_ = os.WriteFile(good, []byte("version: 1\nshell:\n  allow: [git, ls]\n"), 0o600)
	_ = os.WriteFile(warny, []byte("version: 1\nshell:\n  allow: [git, python3]\n"), 0o600)
	_ = os.WriteFile(typo, []byte("version: 1\nshel:\n  allow: [git]\n"), 0o600)
	run := func(args ...string) (int, string) {
		return capture(t, func() int { return cmdPolicyOffline("", dir, args) })
	}
	if code, out := run("check", good); code != 0 || !strings.Contains(out, "valid") {
		t.Errorf("good: %d %q", code, out)
	}
	if code, out := run("check", warny); code != 0 || !strings.Contains(out, "python3") {
		t.Errorf("warnings are not failures: %d %q", code, out)
	}
	if code, _ := run("check", "--strict", warny); code != 3 {
		t.Errorf("--strict must exit 3 on warnings, got %d", code)
	}
	if code, _ := run("check", typo); code != 1 {
		t.Errorf("a typo'd file must be invalid, got %d", code)
	}
	if code, out := run("explain", "--policy", good, "git status"); code != 0 || !strings.Contains(out, "ALLOW") {
		t.Errorf("explain allow: %d %q", code, out)
	}
	if code, out := run("explain", "--policy", good, "git status; python3 -c 1"); code != 3 || !strings.Contains(out, "python3") || !strings.Contains(out, "arbitrary code") {
		t.Errorf("explain deny: %d %q", code, out)
	}
	if code, _ := run(); code != 2 {
		t.Errorf("no subcommand: %d", code)
	}
}

func TestDoctorChangesNothingAndFindsTampering(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	if code, _ := capture(t, func() int { return cmdDoctor("", missing, nil) }); code != 1 {
		t.Errorf("missing data dir should fail, got %d", code)
	}
	if _, err := os.Stat(missing); err == nil {
		t.Error("doctor must not create the data dir")
	}
	dir := demoDir(t) // the demo ends by tampering with its own store
	code, out := capture(t, func() int { return cmdDoctor("", dir, nil) })
	if code != 1 || !strings.Contains(out, "FAILS verification") {
		t.Errorf("doctor must flag the tampered trail: %d\n%s", code, out)
	}
}

func TestSummaryAndSuggestOnDemo(t *testing.T) {
	dir := demoDir(t)
	a, err := openApp(dir, "", false)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	code, out := capture(t, func() int { return a.cmdSummary([]string{"--since", "7d", "--json"}) })
	var sm Summary
	if code != 0 || json.Unmarshal([]byte(out), &sm) != nil {
		t.Fatalf("summary --json: %d %q", code, out)
	}
	if sm.Runs < 2 || sm.Asked < 1 || sm.CredentialHits < 1 || len(sm.Kills) != 1 || len(sm.TopStopped) == 0 {
		t.Errorf("summary missed the demo's activity: %+v", sm)
	}
	if code, out := capture(t, func() int { return a.cmdSummary([]string{"--since", "bogus"}) }); code != 2 {
		t.Errorf("bad --since: %d %q", code, out)
	}
	code, out = capture(t, func() int { return a.cmdPolicySuggest([]string{"--since", "7d", "--min", "1"}) })
	if code != 0 || !strings.Contains(out, "curl") || !strings.Contains(out, "NOT recommended") {
		t.Errorf("suggest must name curl and refuse to recommend it: %d %q", code, out)
	}
	if strings.Contains(out, "to allow the safe ones") && strings.Contains(strings.SplitN(out, "to allow the safe ones", 2)[1], "curl") {
		t.Error("suggest must never put curl in the snippet it offers")
	}
}

func TestParseSince(t *testing.T) {
	for in, ok := range map[string]bool{"24h": true, "7d": true, "2w": true, "90m": true, "1.5d": true, "": false, "d": false, "-1h": false, "0d": false, "abc": false} {
		if _, err := parseSince(in); (err == nil) != ok {
			t.Errorf("parseSince(%q): err=%v want ok=%v", in, err, ok)
		}
	}
}
