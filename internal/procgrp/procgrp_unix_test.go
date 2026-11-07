//go:build !windows

package procgrp

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestGroupKillTakesDownChildren(t *testing.T) {
	cmd := exec.Command("sh", "-c", "sleep 30 & sleep 30 & wait")
	Configure(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pgid := cmd.Process.Pid
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	time.Sleep(150 * time.Millisecond)
	if GroupGone(pgid) {
		t.Fatal("group should be alive")
	}
	if !PidAlive(pgid) {
		t.Fatal("leader should be alive")
	}
	Term(pgid)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		Kill(pgid)
		t.Fatal("SIGTERM did not end the group leader")
	}
	for i := 0; i < 50 && !GroupGone(pgid); i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if !GroupGone(pgid) {
		// Reparented children that died stay as zombies until init reaps
		// them (containers often have no reaping init). Only a live member
		// is a failure.
		out, _ := exec.Command("ps", "-o", "stat=", "-g", strconv.Itoa(pgid)).Output()
		for _, st := range strings.Fields(string(out)) {
			if !strings.HasPrefix(st, "Z") {
				t.Errorf("a live process (state %s) survived the group kill", st)
			}
		}
	}
}

func TestShellIsPosix(t *testing.T) {
	if p, f := Shell(); p != "sh" || f != "-c" {
		t.Errorf("%s %s", p, f)
	}
}
