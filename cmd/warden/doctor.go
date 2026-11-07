package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/calasdan-sketch/warden/internal/audit"
	"github.com/calasdan-sketch/warden/internal/policy"
	"github.com/calasdan-sketch/warden/internal/receipt"
	"github.com/calasdan-sketch/warden/internal/store"
)

// cmdDoctor checks an installation and says what to fix. It changes nothing:
// no data dir, key or database is created.
func cmdDoctor(policyPath, dir string, args []string) int {
	fs := newFlagSet("doctor")
	if !parseArgs(fs, args) {
		return 2
	}
	fails, warns := 0, 0
	say := func(level, format string, a ...any) {
		switch level {
		case "FAIL":
			fails++
		case "warn":
			warns++
		}
		fmt.Printf("%-5s %s\n", level, fmt.Sprintf(format, a...))
	}

	// Data dir.
	fi, err := os.Stat(dir)
	switch {
	case err != nil:
		say("FAIL", "data dir %s does not exist: run `warden init`", dir)
		fmt.Printf("\n%d problem(s)\n", fails)
		return 1
	case !fi.IsDir():
		say("FAIL", "%s is not a directory", dir)
		return 1
	default:
		say("ok", "data dir %s", dir)
		if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
			say("warn", "data dir is accessible to other users (mode %o): run `chmod 700 %s`", fi.Mode().Perm(), dir)
		}
	}

	// Signing key.
	var pub ed25519.PublicKey
	keyPath := filepath.Join(dir, "receipt.key")
	if kfi, err := os.Stat(keyPath); err != nil {
		say("FAIL", "no signing key at %s: run `warden init`", keyPath)
	} else {
		if runtime.GOOS != "windows" && kfi.Mode().Perm()&0o077 != 0 {
			say("FAIL", "signing key is readable by other users (mode %o): run `chmod 600 %s` and treat past receipts as exposed", kfi.Mode().Perm(), keyPath)
		}
		if s, err := receipt.LoadOrCreate(dir); err != nil {
			say("FAIL", "signing key unreadable: %v", err)
		} else {
			pub = s.PublicKey()
			say("ok", "signing key %s", s.KeyID())
			if onDisk, err := os.ReadFile(filepath.Join(dir, "receipt.pub")); err != nil || !bytes.Equal(onDisk, pub) {
				say("warn", "receipt.pub does not match receipt.key: auditors who hold it cannot verify new receipts")
			}
		}
	}

	// Policy.
	pp := policyPath
	if pp == "" {
		pp = filepath.Join(dir, "policy.yaml")
	}
	if _, err := os.Stat(pp); os.IsNotExist(err) {
		say("warn", "no policy file at %s: the built-in default applies (run `warden init` to write an editable copy)", pp)
	} else if p, err := policy.Load(pp); err != nil {
		say("FAIL", "policy %s is invalid, so every gating command and hook refuses to run: %v", pp, err)
	} else {
		say("ok", "policy %s (%d allowlisted commands, %d allowed hosts)", pp, len(p.Shell.Allow), len(p.Egress.AllowHosts))
		for _, l := range p.Lint() {
			if l.Level == "warn" {
				say("warn", "policy: %s", l.Message)
			}
		}
	}

	// Database and the audit trail.
	dbPath := filepath.Join(dir, "warden.db")
	if _, err := os.Stat(dbPath); err != nil {
		say("warn", "no database yet (%s): nothing has been recorded", dbPath)
	} else if st, err := store.Open(dbPath); err != nil {
		say("FAIL", "database %s will not open: %v", dbPath, err)
	} else {
		defer st.Close()
		all, err := st.AllReceipts()
		switch {
		case err != nil:
			say("FAIL", "cannot read receipts: %v", err)
		case len(all) == 0:
			say("ok", "database opens; no sealed runs yet")
		case pub == nil:
			say("warn", "%d sealed runs, but there is no key to verify them with", len(all))
		default:
			var items []audit.Item
			for _, sr := range all {
				spans, err := st.SpansForRun(sr.Receipt.RunID)
				if err != nil {
					say("FAIL", "cannot read spans: %v", err)
					break
				}
				run, _ := st.GetRun(sr.Receipt.RunID)
				items = append(items, audit.Item{Receipt: sr.Receipt, Body: sr.Body, Spans: spans, Run: run})
			}
			rep := audit.Verify(items, pub)
			if rep.OK() {
				say("ok", "audit trail verifies: %d sealed runs, chain intact", rep.Receipts)
			} else {
				say("FAIL", "audit trail FAILS verification (%d problem(s)); run `warden verify` and treat the record as untrustworthy", len(rep.Problems))
			}
		}
		if n, _ := st.CountLive(); n > 0 {
			say("ok", "%d run(s) live right now", n)
		}
	}

	// Harness hooks.
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	found := 0
	for _, c := range []struct{ harness, path string }{
		{"claude-code", filepath.Join(cwd, ".claude", "settings.json")},
		{"claude-code", filepath.Join(cwd, ".claude", "settings.local.json")},
		{"claude-code", filepath.Join(home, ".claude", "settings.json")},
		{"codex", filepath.Join(home, ".codex", "hooks.json")},
		{"codex", filepath.Join(cwd, ".codex", "hooks.json")},
	} {
		if home == "" && strings.HasPrefix(c.path, ".claude") {
			continue
		}
		b, err := os.ReadFile(c.path)
		if err != nil {
			continue
		}
		cmds := hookCommands(b)
		if len(cmds) == 0 {
			continue
		}
		found++
		for _, cmd := range cmds {
			bin := firstWord(cmd)
			if _, err := exec.LookPath(bin); err != nil {
				say("FAIL", "%s hook in %s runs %q, which does not exist: the harness will fail to run it (Codex treats that as allow)", c.harness, c.path, bin)
				continue
			}
			say("ok", "%s hook installed in %s", c.harness, c.path)
			if strings.Contains(cmd, "--fail-open") {
				say("warn", "that hook uses --fail-open: if warden errors, tool calls go through")
			}
		}
	}
	if found == 0 {
		say("warn", "no warden hook found in .claude/settings*.json or .codex/hooks.json here or in your home: run `warden hook claude-code --print-config` to see what to add")
	}

	fmt.Printf("\n%d problem(s), %d warning(s)\n", fails, warns)
	if fails > 0 {
		return 1
	}
	return 0
}

// hookCommands returns the commands of PreToolUse hooks that run `warden hook`.
func hookCommands(settings []byte) []string {
	var doc struct {
		Hooks map[string][]struct {
			Hooks []struct {
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if json.Unmarshal(settings, &doc) != nil {
		return nil
	}
	var out []string
	for _, g := range doc.Hooks["PreToolUse"] {
		for _, h := range g.Hooks {
			if strings.Contains(h.Command, " hook ") && strings.Contains(strings.ToLower(h.Command), "warden") {
				out = append(out, h.Command)
			}
		}
	}
	return out
}

// firstWord returns the program of a hook command, undoing simple quoting.
func firstWord(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	if q := cmd[0]; q == '\'' || q == '"' {
		if i := strings.IndexByte(cmd[1:], q); i >= 0 {
			return cmd[1 : 1+i]
		}
	}
	if i := strings.IndexAny(cmd, " \t"); i >= 0 {
		return cmd[:i]
	}
	return cmd
}
