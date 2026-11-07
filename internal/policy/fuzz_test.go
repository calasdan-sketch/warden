package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/calasdan-sketch/warden/internal/model"
)

// FuzzEvaluateShell: the evaluator must never panic and must stay fast on
// hostile input, whatever the bytes.
func FuzzEvaluateShell(f *testing.F) {
	for _, s := range append(append([]string{}, evasionCorpus...), benignCorpus...) {
		f.Add(s)
	}
	f.Add("echo " + strings.Repeat(">", 200))
	f.Add(strings.Repeat("$(", 50) + "ls" + strings.Repeat(")", 50))
	p, _ := Default()
	e := NewEvaluator(p, nil)
	f.Fuzz(func(t *testing.T, cmd string) {
		start := time.Now()
		_ = e.Evaluate(&model.Span{Kind: model.SpanToolCall, Tool: "Bash", ArgsSummary: cmd})
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("evaluation took %v for %d bytes", d, len(cmd))
		}
	})
}

func TestHugeCommandsStayBounded(t *testing.T) {
	p, _ := Default()
	e := NewEvaluator(p, nil)
	for name, cmd := range map[string]string{
		"many segments":  strings.Repeat("git status ; ", 40000),
		"many redirects": "echo " + strings.Repeat("> a ", 100000),
		"deep nesting":   strings.Repeat("$(", 5000) + "ls" + strings.Repeat(")", 5000),
		"long quote":     "echo '" + strings.Repeat("a", 3<<20),
		"many quotes":    strings.Repeat("\"'", 200000),
	} {
		start := time.Now()
		d := e.Evaluate(&model.Span{Kind: model.SpanToolCall, Tool: "Bash", ArgsSummary: cmd}).Decision
		el := time.Since(start)
		t.Logf("%-14s %8d bytes: %v in %v", name, len(cmd), d, el)
		if len(cmd) > MaxAnalyzedCommand && d != Deny {
			t.Errorf("%s: oversized command must be refused, got %v", name, d)
		}
		if el > 2*time.Second {
			t.Errorf("%s: too slow (%v)", name, el)
		}
	}
}
