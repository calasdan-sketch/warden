package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func buildTestBinary(t *testing.T) string {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "warden-test")
	if out, err := exec.Command("go", "build", "-o", exe, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return exe
}

func TestDashboardRefusesNetworkAddressWithoutLogin(t *testing.T) {
	exe := buildTestBinary(t)
	for _, addr := range []string{"0.0.0.0:0", ":0", "192.168.1.5:0"} {
		cmd := exec.Command(exe, "dashboard", "--listen", addr)
		cmd.Env = append(os.Environ(), "WARDEN_DIR="+t.TempDir(), "WARDEN_TOKENS=")
		out, err := cmd.CombinedOutput()
		ee, ok := err.(*exec.ExitError)
		if !ok || ee.ExitCode() != 2 {
			t.Fatalf("%s: want exit 2, got %v\n%s", addr, err, out)
		}
		if !strings.Contains(string(out), "refusing to listen") || !strings.Contains(string(out), "WARDEN_TOKENS") {
			t.Errorf("%s: message should say what to do instead:\n%s", addr, out)
		}
	}
}

func TestTransientInstallIsRecognised(t *testing.T) {
	for p, want := range map[string]bool{
		"/home/u/.npm/_npx/ab12/node_modules/@decnutz/warden-linux-x64/bin/warden": true,
		`C:\Users\u\AppData\Local\npm-cache\_npx\ab12\node_modules\warden.exe`:     true,
		filepath.Join(os.TempDir(), "x", "warden"):                                 true,
		"/usr/local/bin/warden": false,
		"/home/u/go/bin/warden": false,
	} {
		if got := transientInstall(p); got != want {
			t.Errorf("transientInstall(%q) = %v, want %v", p, got, want)
		}
	}
}
