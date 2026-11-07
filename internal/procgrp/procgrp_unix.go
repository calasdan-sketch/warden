//go:build !windows

// Package procgrp isolates the operating-system specific parts of
// supervising a process tree: starting a child in its own group, signalling
// the whole group, and checking whether it is gone. Unix uses POSIX process
// groups; Windows (see procgrp_windows.go) uses a new process group plus
// taskkill /T for the tree.
package procgrp

import (
	"os/exec"
	"syscall"
)

// Configure makes cmd start in its own process group (group id == child pid).
func Configure(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

// Shell returns the program and flag used to run a command line.
func Shell() (string, string) { return "sh", "-c" }

// Term asks every process in the group to stop (SIGTERM).
func Term(pgid int) { _ = syscall.Kill(-pgid, syscall.SIGTERM) }

// Kill forcibly stops every process in the group (SIGKILL).
func Kill(pgid int) { _ = syscall.Kill(-pgid, syscall.SIGKILL) }

// GroupGone reports whether no process remains in the group. EPERM (the group
// exists but is not ours) counts as still present.
func GroupGone(pgid int) bool { return syscall.Kill(-pgid, 0) == syscall.ESRCH }

// PidAlive reports whether pid currently exists.
func PidAlive(pid int) bool { return syscall.Kill(pid, 0) == nil }
