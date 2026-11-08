package otel

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/calasdan-sketch/warden/internal/model"
)

// TestGoldenOTLP pins the exact OTLP JSON for a fixed run (UPDATE_GOLDEN=1 to
// regenerate after a reviewed change).
func TestGoldenOTLP(t *testing.T) {
	old := ScopeVersion
	ScopeVersion = "test"
	defer func() { ScopeVersion = old }()
	t0 := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	run := &model.Run{RunID: "0123456789abcdef0123456789abcdef", AgentID: "a1", FleetID: "f1", Operator: "cli",
		StartedAt: t0, Status: model.RunCompleted}
	end := t0.Add(3 * time.Second)
	run.EndedAt = &end
	sp := spans()
	sp[0].RunID, sp[1].RunID = run.RunID, run.RunID
	sp[1].ArgsSummary = "rm -rf /"
	sp[1].PolicyReason = "denied by pattern"
	out := ToOTLPRuns([]RunTrace{{Run: run, Spans: sp}})
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	path := filepath.Join("testdata", "otlp.golden.json")
	if os.Getenv("UPDATE_GOLDEN") != "" {
		_ = os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden %s: %v", path, err)
	}
	if !bytes.Equal(want, b) {
		t.Errorf("OTLP output changed.\n--- want\n%s\n--- got\n%s", want, b)
	}
}
