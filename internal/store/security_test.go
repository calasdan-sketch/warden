package store

// Regression tests for the v1 scrutiny findings (2026-10-18).

import (
	"testing"
	"time"

	"warden/internal/model"
)

// TestToolDenyCaseInsensitive: the dynamic deny-list must be case-insensitive
// like the rest of the policy engine. Pre-fix, `kill --scope tool --target
// Bash` did not stop a span reporting tool `bash`.
func TestToolDenyCaseInsensitive(t *testing.T) {
	s := openTest(t)
	if err := s.DenyTool("Bash", "", "test"); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"bash", "Bash", "BASH", "bAsH"} {
		denied, _, err := s.IsToolDenied(tool, "prod")
		if err != nil {
			t.Fatal(err)
		}
		if !denied {
			t.Errorf("tool %q should be denied after DenyTool(%q)", tool, "Bash")
		}
	}
	// Fleet-scoped entries are case-insensitive on the tool too.
	if err := s.DenyTool("Curl", "prod", "test"); err != nil {
		t.Fatal(err)
	}
	if denied, _, _ := s.IsToolDenied("curl", "prod"); !denied {
		t.Error("fleet-scoped deny should match case-insensitively")
	}
	if denied, _, _ := s.IsToolDenied("curl", "other"); denied {
		t.Error("deny must not leak across fleets")
	}
	// Clearing with a different case must work.
	if err := s.AllowTool("BASH", ""); err != nil {
		t.Fatal(err)
	}
	if denied, _, _ := s.IsToolDenied("bash", ""); denied {
		t.Error("AllowTool should clear the entry regardless of case")
	}
}

// TestListRunsPage: paged export must walk the whole table without gaps.
func TestListRunsPage(t *testing.T) {
	s := openTest(t)
	const total = 25
	for i := 0; i < total; i++ {
		r := testRun("run-pg")
		r.RunID = "run-pg-" + string(rune('a'+i/10)) + string(rune('0'+i%10))
		r.StartedAt = time.Now().UTC().Add(time.Duration(i) * time.Second)
		if err := s.CreateRun(r); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	for offset := 0; ; offset += 7 {
		page, err := s.ListRunsPage(7, offset)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		for _, r := range page {
			if seen[r.RunID] {
				t.Fatalf("duplicate run %s across pages", r.RunID)
			}
			seen[r.RunID] = true
		}
		if len(page) < 7 {
			break
		}
	}
	if len(seen) != total {
		t.Errorf("paged walk saw %d runs, want %d", len(seen), total)
	}
}

// TestSpansForRunOrderStable: spans with identical timestamps must come back
// in insertion order (loop detection depends on it).
func TestSpansForRunOrderStable(t *testing.T) {
	s := openTest(t)
	r := testRun("run-order")
	if err := s.CreateRun(r); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	for i, name := range []string{"first", "second", "third"} {
		sp := &model.Span{
			SpanID: "sp-" + name, RunID: r.RunID, Kind: model.SpanToolCall,
			Tool: "t", Name: name, StartedAt: at,
		}
		_ = i
		if err := s.InsertSpan(sp); err != nil {
			t.Fatal(err)
		}
	}
	spans, err := s.SpansForRun(r.RunID)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"first", "second", "third"} {
		if spans[i].Name != want {
			t.Errorf("span %d = %q, want %q (insertion order)", i, spans[i].Name, want)
		}
	}
}
