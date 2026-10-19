package collect

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// procStartTimeNs returns the process start time as Unix nanoseconds, or 0
// when it cannot be determined (non-Linux, /proc unavailable, zombie).
// It is recorded in the pidfile at spawn and re-checked before any kill
// signal, so a recycled PID can never be mistaken for the supervised child.
func procStartTimeNs(pid int) int64 {
	if runtime.GOOS != "linux" || pid <= 0 {
		return 0
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	// comm may contain spaces/parens: starttime is field 22 after the last ')'.
	s := string(b)
	i := strings.LastIndex(s, ")")
	if i < 0 {
		return 0
	}
	fields := strings.Fields(s[i+1:])
	if len(fields) < 21 { // field 22 overall, minus comm+state offset
		return 0
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0
	}
	boot := bootTimeNs()
	if boot == 0 {
		return 0
	}
	// The tick rate only needs to be consistent between the two reads being
	// compared (record at spawn vs. check at kill); 100 Hz is the Linux
	// default and any constant preserves equality.
	return boot + int64(ticks)*1e9/100
}

func bootTimeNs() int64 {
	// /proc/stat btime: seconds since epoch at boot.
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "btime ") {
			sec, err := strconv.ParseInt(strings.TrimSpace(line[6:]), 10, 64)
			if err != nil {
				return 0
			}
			return sec * 1e9
		}
	}
	return 0
}

// pidAliveForRun reports whether the process recorded in runID's pidfile is
// plausibly still the supervised child: the PID exists AND (on Linux) its
// start time matches the pidfile. A recycled PID fails the start-time check.
func pidAliveForRun(dataDir, runID string) bool {
	pf, err := ReadPidFile(dataDir, runID)
	if err != nil || pf.PID <= 0 {
		return false
	}
	if err := syscall.Kill(pf.PID, 0); err != nil {
		return false
	}
	if pf.StartedAtNs != 0 {
		if now := procStartTimeNs(pf.PID); now != 0 && now != pf.StartedAtNs {
			return false // PID recycled: not our child
		}
	}
	return true
}

// PidAliveForRun is the exported liveness check used by the reconciler and
// kill paths.
func PidAliveForRun(dataDir, runID string) bool { return pidAliveForRun(dataDir, runID) }
