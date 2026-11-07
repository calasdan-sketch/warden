package replay

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/calasdan-sketch/warden/internal/model"
	"github.com/calasdan-sketch/warden/internal/policy"
)

func fixture() (*model.Run, []*model.Span) {
	t0 := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	run := &model.Run{RunID: "run1", AgentID: "a", FleetID: "f", StartedAt: t0, Status: model.RunCompleted}
	mk := func(i int, k model.SpanKind, f func(*model.Span)) *model.Span {
		s := &model.Span{SpanID: string(rune('a' + i)), RunID: "run1", Kind: k, StartedAt: t0.Add(time.Duration(i) * time.Second)}
		f(s)
		return s
	}
	return run, []*model.Span{
		mk(0, model.SpanLLMCall, func(s *model.Span) { s.Model = "m"; s.TokensIn = 10; s.TokensOut = 5; s.CostUSD = 0.01 }),
		mk(1, model.SpanToolCall, func(s *model.Span) { s.Tool = "bash"; s.ArgsSummary = "git status"; s.PolicyDecision = "allow" }),
		mk(2, model.SpanToolCall, func(s *model.Span) {
			s.Tool = "bash"
			s.ArgsSummary = "rm -rf /"
			s.PolicyDecision = "deny"
			s.PolicyReason = "denied by pattern"
		}),
		mk(3, model.SpanFileOp, func(s *model.Span) { s.Path = "/tmp/x"; s.Op = "write" }),
		mk(4, model.SpanNetEgress, func(s *model.Span) { s.Host = "example.com"; s.Port = 443 }),
	}
}

func TestBuildStateAccumulates(t *testing.T) {
	run, spans := fixture()
	// Out-of-order input must come out ordered.
	spans[0], spans[4] = spans[4], spans[0]
	s := Build(run, spans, Integrity{Status: "verified"})
	if len(s.Steps) != 5 {
		t.Fatalf("steps %d", len(s.Steps))
	}
	last := s.Steps[4].State
	if last.ToolCalls != 2 || last.Denied != 1 || last.TokensIn != 10 || len(last.Files) != 1 || len(last.Hosts) != 1 {
		t.Errorf("bad final state: %+v", last)
	}
	if s.Steps[2].State.Denied != 1 || s.Steps[1].State.Denied != 0 {
		t.Error("state must be as of each step, not final")
	}
	if s.Steps[2].Verdict != "deny" {
		t.Errorf("verdict %q", s.Steps[2].Verdict)
	}
}

func TestWhatIfCounterfactual(t *testing.T) {
	run, spans := fixture()
	s := Build(run, spans, Integrity{Status: "verified"})
	// A candidate policy that forbids git: the recorded "allow" must flip.
	p, err := policy.Parse([]byte("version: 1\nshell:\n  default: deny\n  allow: [ls]\n"))
	if err != nil {
		t.Fatal(err)
	}
	s.ApplyWhatIf(policy.NewEvaluator(p, nil), "cand.yaml")
	if s.WhatIf.NewlyBlocked < 1 {
		t.Errorf("git status should become blocked: %+v", s.WhatIf)
	}
	if !s.Steps[1].WhatIf.Changed || s.Steps[1].WhatIf.Decision == "allow" {
		t.Errorf("step 2 should change: %+v", s.Steps[1].WhatIf)
	}
	var out bytes.Buffer
	s.Text(&out, true)
	if !strings.Contains(out.String(), "CHANGES") || strings.Contains(out.String(), "tokens") {
		t.Errorf("gated listing wrong:\n%s", out.String())
	}
}

func TestWhatIfSkipsOperatorDecisions(t *testing.T) {
	run, spans := fixture()
	spans[2].PolicyReason = "session killed by operator"
	s := Build(run, spans, Integrity{Status: "verified"})
	p, _ := policy.Default()
	s.ApplyWhatIf(policy.NewEvaluator(p, nil), "d")
	if s.WhatIf.SkippedNonPure != 1 || s.Steps[2].WhatIf.Skipped == "" {
		t.Errorf("operator-decided call must be skipped: %+v", s.WhatIf)
	}
}

func TestUntrustedTextIsNeutralised(t *testing.T) {
	run, spans := fixture()
	evil := "echo \x1b[2J\x1b]0;pwned\x07 ‮gnirts​ </script><img src=x onerror=alert(1)>"
	spans[1].ArgsSummary = evil
	run.AgentID = "a\x1b[31m"
	s := Build(run, spans, Integrity{Status: "verified", Detail: "ok\x1b[0m"})
	var txt, h bytes.Buffer
	s.Text(&txt, false)
	if err := s.HTML(&h); err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{txt.String(), h.String()} {
		for _, bad := range []string{"\x1b", "‮", "​", "\x07"} {
			if strings.Contains(out, bad) {
				t.Errorf("control/bidi %q survived in output", bad)
			}
		}
	}
	// The only literal </script> allowed is the one closing our own tags.
	if n := strings.Count(h.String(), "</script>"); n != 2 {
		t.Errorf("payload must not be able to close the data script tag: %d </script>", n)
	}
	if strings.Contains(h.String(), "<img src=x") {
		t.Error("raw HTML from the trail reached the page")
	}
}

func TestStepRange(t *testing.T) {
	run, spans := fixture()
	s := Build(run, spans, Integrity{Status: "verified"})
	var b bytes.Buffer
	if err := s.Step(&b, 3); err != nil || !strings.Contains(b.String(), "rm -rf /") || !strings.Contains(b.String(), "denied 1") {
		t.Errorf("step 3: %v\n%s", err, b.String())
	}
	if s.Step(&b, 0) == nil || s.Step(&b, 6) == nil {
		t.Error("out of range must error")
	}
}

// Build used to re-sort the whole set of touched files on every step, so a
// 20,000-step run took minutes. It must stay close to linear.
func TestBuildLongRunIsFast(t *testing.T) {
	t0 := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	run := &model.Run{RunID: "r", StartedAt: t0}
	var spans []*model.Span
	for i := 0; i < 60000; i++ {
		spans = append(spans, &model.Span{SpanID: strings.Repeat("x", 1) + string(rune(i%90+33)), RunID: "r", Kind: model.SpanFileOp,
			Path: "/tmp/f" + strings.Repeat("z", i%7) + string(rune('a'+i%26)) + time.Duration(i).String(), Op: "read", StartedAt: t0.Add(time.Duration(i) * time.Millisecond)})
	}
	start := time.Now()
	s := Build(run, spans, Integrity{Status: "verified"})
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("Build of 60000 steps took %v; it must be near-linear", d)
	}
	last := s.Steps[len(s.Steps)-1].State
	if last.FilesN < 50000 || len(last.Files) != topN+1 || !strings.HasPrefix(last.Files[topN], "… +") {
		t.Errorf("last step state wrong: n=%d len=%d", last.FilesN, len(last.Files))
	}
	if s.Steps[100].State.Files != nil {
		t.Error("long runs must not carry per-step lists")
	}
	// ... but any step's lists are still available on demand, and sorted.
	st := s.StateAt(500)
	if st.FilesN != s.Steps[499].State.FilesN || len(st.Files) != topN+1 {
		t.Errorf("StateAt(500): n=%d len=%d", st.FilesN, len(st.Files))
	}
	for i := 1; i < topN; i++ {
		if st.Files[i-1] > st.Files[i] {
			t.Fatal("StateAt list not sorted")
		}
	}
	var b bytes.Buffer
	if err := s.Step(&b, 500); err != nil || !strings.Contains(b.String(), "files touched (") {
		t.Errorf("Step output: %v %q", err, b.String()[:80])
	}
}

func TestShortRunKeepsPerStepLists(t *testing.T) {
	run, spans := fixture()
	s := Build(run, spans, Integrity{Status: "verified"})
	st := s.Steps[3].State
	if len(st.Files) != 1 || st.FilesN != 1 || s.StateAt(4).Files[0] != "/tmp/x" {
		t.Errorf("short run state: %+v", st)
	}
}
