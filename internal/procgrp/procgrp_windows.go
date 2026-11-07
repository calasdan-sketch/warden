//go:build windows

package procgrp

import (
	"os/exec"
	"strconv"
	"syscall"
)

const (
	createNewProcessGroup   = 0x00000200
	processQueryLimitedInfo = 0x00001000
	stillActive             = 259
	createNoWindow          = 0x08000000
)

// Configure starts the child in a new process group. On Windows the group id
// is the child's pid; the tree is stopped with taskkill /T.
func Configure(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNewProcessGroup}
}

// Shell returns the program and flag used to run a command line.
func Shell() (string, string) { return "cmd", "/C" }

func taskkill(pid int, force bool) {
	args := []string{"/T", "/PID", strconv.Itoa(pid)}
	if force {
		args = append([]string{"/F"}, args...)
	}
	c := exec.Command("taskkill", args...)
	c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	_ = c.Run()
}

// Term asks the process tree rooted at pgid to close.
func Term(pgid int) { taskkill(pgid, false) }

// Kill forcibly ends the process tree rooted at pgid.
func Kill(pgid int) { taskkill(pgid, true) }

// GroupGone reports whether the group leader has exited. (Windows has no
// group-membership query without job objects; a surviving grandchild is
// removed by taskkill /T.)
func GroupGone(pgid int) bool { return !PidAlive(pgid) }

// PidAlive reports whether pid is a running process.
func PidAlive(pid int) bool {
	h, err := syscall.OpenProcess(processQueryLimitedInfo, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	var code uint32
	if err := syscall.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == stillActive
}
