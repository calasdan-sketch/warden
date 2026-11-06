package main

import (
	"os"
	"path/filepath"
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
	if code := cmdVerifyBundle(bundle, filepath.Join(dir, "receipt.pub")); code != 0 {
		t.Fatalf("exported demo bundle must verify, exit %d", code)
	}
	if code := cmdVerifyBundle(bundle, ""); code != 2 {
		t.Fatalf("bundle verify without --pubkey must refuse, exit %d", code)
	}
	// The demo tampered with the live store: store verification must fail.
	a, err := openApp(dir, "")
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
