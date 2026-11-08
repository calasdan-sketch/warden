package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The npm launcher must pass arguments, output and the exit code through
// untouched, and say plainly what to do when no binary is installed.
func TestNpmLauncherPassesThrough(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil || runtime.GOOS == "windows" {
		t.Skip("needs node and a POSIX shell")
	}
	launcher, _ := filepath.Abs(filepath.Join("..", "..", "npm", "warden", "bin", "warden.js"))
	dir := t.TempDir()
	fake := filepath.Join(dir, "fake warden")
	script := "#!/bin/sh\nprintf 'args:%s|%s\\n' \"$1\" \"$2\"\nexit 7\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, launcher, "verify", "two words")
	cmd.Env = append(os.Environ(), "WARDEN_BINARY="+fake)
	out, err := cmd.Output()
	ee, ok := err.(*exec.ExitError)
	if !ok || ee.ExitCode() != 7 {
		t.Fatalf("exit code not passed through: %v", err)
	}
	if string(out) != "args:verify|two words\n" {
		t.Errorf("arguments changed on the way: %q", out)
	}

	// No override and no platform package next to the launcher: a plain message, exit 1.
	cmd = exec.Command(node, launcher, "version")
	env := []string{}
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "WARDEN_BINARY=") {
			env = append(env, e)
		}
	}
	cmd.Env = env
	cmd.Dir = dir
	out2, err := cmd.CombinedOutput()
	ee, ok = err.(*exec.ExitError)
	if !ok || ee.ExitCode() != 1 || !strings.Contains(string(out2), "WARDEN_BINARY") {
		t.Errorf("missing-binary message: %v %q", err, out2)
	}
}
