package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDemoEndToEnd runs the one-command demo: it drives the hook path, the
// kill switch, wrap, verification, export and tamper detection for real.
func TestDemoEndToEnd(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "demo")
	if code := cmdDemo([]string{"--dir", dir}); code != 0 {
		t.Fatalf("demo exit %d", code)
	}
	bundle := filepath.Join(dir, "audit-bundle.jsonl")
	if code := cmdVerifyBundle(bundle, filepath.Join(dir, "receipt.pub"), false); code != 0 {
		t.Fatalf("exported demo bundle must verify, exit %d", code)
	}
	if code := cmdVerifyBundle(bundle, "", false); code != 2 {
		t.Fatalf("bundle verify without --pubkey must refuse, exit %d", code)
	}
	// The demo tampered with the live store: store verification must fail.
	a, err := openApp(dir, "", true)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	if code := a.cmdVerify(nil); code != 1 {
		t.Fatalf("tampered store must fail verify, exit %d", code)
	}
	if info, err := os.Stat(bundle); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("audit bundle should be written 0600: %v %v", info.Mode(), err)
	}
}

func TestDemoRefusesNonEmptyDir(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "x"), []byte("x"), 0o600)
	if code := cmdDemo([]string{"--dir", dir}); code != 2 {
		t.Fatalf("demo must refuse a non-empty dir, exit %d", code)
	}
}

// runHookIO runs the hook entry point with stdin/stdout redirected.
func runHookIO(t *testing.T, dir string, args []string, input string) (int, string) {
	t.Helper()
	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inR, outW
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut }()
	go func() { _, _ = inW.WriteString(input); inW.Close() }()
	code := runHookFailClosed(dir, "", args)
	outW.Close()
	b, _ := io.ReadAll(outR)
	return code, string(b)
}

// Regression for the synapse-1 panel review: a broken policy file (which the
// agent could write) made `warden hook` exit 1 with no JSON, which Claude
// Code treats as "proceed".
func TestHookFailsClosedOnStartupError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte("shell: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	payload := `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf ~"}}`
	code, out := runHookIO(t, dir, []string{"claude-code"}, payload)
	if code != 0 || !strings.Contains(out, `"permissionDecision":"deny"`) {
		t.Fatalf("claude-code must get a deny, got code=%d out=%q", code, out)
	}
	if code, _ := runHookIO(t, dir, []string{"codex"}, payload); code != 2 {
		t.Fatalf("codex must get exit 2, got %d", code)
	}
	if code, out := runHookIO(t, dir, []string{"codex", "--fail-open"}, payload); code != 0 || out != "" {
		t.Fatalf("--fail-open is an explicit opt-out: code=%d out=%q", code, out)
	}
}

func TestHookDeniesTamperingWithWarden(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{
		`{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"` + filepath.Join(dir, "policy.yaml") + `","content":"x"}}`,
		`{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{"file_path":".claude/settings.json","old_string":"a","new_string":"b"},"cwd":"/home/u/proj"}`,
		`{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"` + filepath.Join(dir, "receipt.key") + `"}}`,
		`{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cat ` + dir + `/warden.db"}}`,
		`{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"apply_patch","cwd":"/home/u/p","tool_input":{"command":"*** Begin Patch\n*** Update File: README.md\n*** Add File: .codex/hooks.json\n+{}\n*** End Patch"}}`,
	} {
		code, out := runHookIO(t, dir, []string{"claude-code", "--strict"}, p)
		if code != 0 || !strings.Contains(out, `"permissionDecision":"deny"`) {
			t.Errorf("must deny %s: code=%d out=%q", p, code, out)
		}
	}
}
