package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStdout runs f and returns what it printed to stdout.
func captureStdout(t *testing.T, f func() int) (int, string) {
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

func TestReplayDemoRunsAndDetectsTamper(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "demo")
	if code := cmdDemo([]string{"--dir", dir}); code != 0 {
		t.Fatalf("demo exit %d", code)
	}
	a, err := openApp(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()

	// The demo rewrote a span in the live store: replay must say so and exit 3.
	runs, _ := a.st.ListRuns(storeFilter(50))
	tampered := 0
	for _, r := range runs {
		code, out := captureStdout(t, func() int { return a.cmdReplay([]string{r.RunID}) })
		if code == 3 {
			tampered++
			if !strings.Contains(out, "TAMPERED") {
				t.Errorf("exit 3 without a TAMPERED banner:\n%s", out)
			}
		}
	}
	if tampered == 0 {
		t.Fatal("replay never flagged the tampered demo run")
	}

	// A prefix, "last", --json, --step and --html all work.
	if code, out := captureStdout(t, func() int { return a.cmdReplay([]string{"last", "--json"}) }); code == 1 || !strings.Contains(out, `"steps"`) {
		t.Errorf("json replay failed (%d): %.200s", code, out)
	}
	html := filepath.Join(t.TempDir(), "r.html")
	if code, _ := captureStdout(t, func() int { return a.cmdReplay([]string{"last", "--html", html}) }); code == 1 || code == 2 {
		t.Errorf("html replay exit %d", code)
	}
	b, err := os.ReadFile(html)
	if err != nil || !strings.Contains(string(b), "default-src 'none'") {
		t.Errorf("html replay missing or without CSP: %v", err)
	}
	if code, _ := captureStdout(t, func() int { return a.cmdReplay([]string{"last", "--step", "999"}) }); code != 1 {
		t.Errorf("out-of-range step must fail, got %d", code)
	}
	if code, _ := captureStdout(t, func() int { return a.cmdReplay([]string{"no-such-run"}) }); code != 1 {
		t.Errorf("unknown run must fail, got %d", code)
	}

	// The exported bundle replays with no data dir and verifies.
	bundle := filepath.Join(dir, "audit-bundle.jsonl")
	pub := filepath.Join(dir, "receipt.pub")
	ok := 0
	for _, r := range runs {
		code, out := captureStdout(t, func() int { return cmdReplayWith(nil, []string{r.RunID, "--bundle", bundle, "--pubkey", pub}) })
		if code == 0 && strings.Contains(out, "VERIFIED") {
			ok++
		}
	}
	if ok == 0 {
		t.Error("no run replayed as VERIFIED from the exported bundle")
	}
	if code, _ := captureStdout(t, func() int { return cmdReplayWith(nil, []string{"x", "--bundle", bundle}) }); code != 2 {
		t.Errorf("--bundle without --pubkey must refuse, got %d", code)
	}
}

func TestAnchorDetectsDeletedReceipts(t *testing.T) {
	dir := t.TempDir()
	a, err := openApp(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	for i := 0; i < 3; i++ {
		if code, _ := captureStdout(t, func() int { return a.cmdWrap([]string{"--agent", "t", "--", "true"}) }); code != 0 {
			t.Fatalf("wrap %d exit %d", i, code)
		}
	}
	anchors := filepath.Join(t.TempDir(), "anchors.jsonl")
	if code, _ := captureStdout(t, func() int { return a.cmdAnchor([]string{"--out", anchors}) }); code != 0 {
		t.Fatal("anchor failed")
	}
	if info, _ := os.Stat(anchors); info == nil || info.Mode().Perm() != 0o600 {
		t.Error("anchor file must be 0600")
	}
	if code, out := captureStdout(t, func() int { return a.cmdVerify([]string{"--anchors", anchors}) }); code != 0 || !strings.Contains(out, "anchors: 1 checked") {
		t.Fatalf("honest store vs anchor: %d\n%s", code, out)
	}
	// New runs after the anchor are fine.
	captureStdout(t, func() int { return a.cmdWrap([]string{"--agent", "t", "--", "true"}) })
	if code, out := captureStdout(t, func() int { return a.cmdVerify([]string{"--anchors", anchors}) }); code != 0 {
		t.Fatalf("grown chain vs old anchor: %d\n%s", code, out)
	}
	// Delete the newest receipt(s) from the store: chain linkage still holds,
	// but the anchor catches it.
	if _, err := a.st.DB().Exec(`DELETE FROM receipts WHERE rowid IN (SELECT rowid FROM receipts ORDER BY rowid DESC LIMIT 2)`); err != nil {
		t.Fatal(err)
	}
	code, out := captureStdout(t, func() int { return a.cmdVerify([]string{"--anchors", anchors}) })
	if code != 1 || !strings.Contains(out, "deleted") {
		t.Fatalf("truncation must be caught by the anchor: %d\n%s", code, out)
	}
	// A bad anchors file is an error, not a pass.
	bad := filepath.Join(t.TempDir(), "bad")
	_ = os.WriteFile(bad, []byte("nope\n"), 0o600)
	if code, _ := captureStdout(t, func() int { return a.cmdVerify([]string{"--anchors", bad}) }); code != 1 {
		t.Errorf("unreadable anchors must fail, got %d", code)
	}
}
