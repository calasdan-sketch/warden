package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/calasdan-sketch/warden/internal/model"
	"github.com/calasdan-sketch/warden/internal/policy"
	"github.com/calasdan-sketch/warden/internal/redact"
)

// cmdBench measures what warden costs the agent: the latency a harness sees
// on every tool call (a fresh `warden hook` process), and the in-process cost
// of the policy and redaction steps. Anyone can re-run it:
//
//	warden bench [--n 200]
func cmdBench(args []string) int {
	fs := newFlagSet("bench")
	n := fs.Int("n", 200, "hook invocations to time")
	if !parseArgs(fs, args) {
		return 2
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "bench:", err)
		return 1
	}
	dir, err := os.MkdirTemp("", "warden-bench-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "bench:", err)
		return 1
	}
	defer os.RemoveAll(dir)
	if out, err := exec.Command(exe, "--dir", dir, "init").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "bench: init: %v\n%s", err, out)
		return 1
	}
	payload := func(i int, cmd string) []byte {
		b, _ := json.Marshal(map[string]any{"session_id": "bench", "hook_event_name": "PreToolUse", "cwd": dir,
			"tool_name": "Bash", "tool_input": map[string]string{"command": cmd}, "tool_use_id": fmt.Sprintf("t%d", i)})
		return b
	}
	var lat []float64
	for i := 0; i < *n; i++ {
		c := exec.Command(exe, "--dir", dir, "hook", "claude-code")
		c.Stdin = bytes.NewReader(payload(i, "git status && ls -la | grep foo"))
		t0 := time.Now()
		if err := c.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "bench: hook:", err)
			return 1
		}
		lat = append(lat, float64(time.Since(t0).Microseconds())/1000)
	}
	sort.Float64s(lat)
	pct := func(p float64) float64 { return lat[int(float64(len(lat)-1)*p)] }

	pol, _ := policy.Default()
	ev := policy.NewEvaluator(pol, nil)
	sp := &model.Span{Kind: model.SpanToolCall, Tool: "bash", ArgsSummary: "git status && ls -la | grep foo > out.txt"}
	const iters = 20000
	t0 := time.Now()
	for i := 0; i < iters; i++ {
		ev.Evaluate(sp)
	}
	evalUs := float64(time.Since(t0).Nanoseconds()) / iters / 1000

	text := strings.Repeat("git log --oneline -n 5 && echo hello world; ", 24)
	t0 = time.Now()
	const rIters = 2000
	for i := 0; i < rIters; i++ {
		redact.RedactString(text)
	}
	redUs := float64(time.Since(t0).Nanoseconds()) / rIters / 1000

	st, _ := os.Stat(exe)
	fmt.Printf("warden bench  (%s/%s, %s, %d CPU)\n", runtime.GOOS, runtime.GOARCH, runtime.Version(), runtime.NumCPU())
	fmt.Printf("hook round trip, fresh process per tool call (n=%d): p50 %.1f ms  p95 %.1f ms  p99 %.1f ms  max %.1f ms\n",
		len(lat), pct(.5), pct(.95), pct(.99), lat[len(lat)-1])
	fmt.Printf("policy decision, compound shell line: %.1f us each\n", evalUs)
	fmt.Printf("redaction, %d-byte input: %.1f us each (%.0f MB/s)\n", len(text), redUs, float64(len(text))/redUs)
	if st != nil {
		fmt.Printf("binary size: %.1f MB\n", float64(st.Size())/1e6)
	}
	return 0
}
