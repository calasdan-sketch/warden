package replay

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Golden-file tests pin the exact bytes of every replay output format on a
// fixed run, so a format change is a deliberate, reviewed diff and never an
// accident. Regenerate with: UPDATE_GOLDEN=1 go test ./internal/replay
func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden file %s (UPDATE_GOLDEN=1 creates it): %v", path, err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("%s differs from the golden file.\n--- want\n%s\n--- got\n%s", name, want, got)
	}
}

func TestGoldenReplayFormats(t *testing.T) {
	run, spans := fixture()
	s := Build(run, spans, Integrity{Status: "verified", Detail: "receipt signature and signed trace digest match", Covered: 5})

	var text bytes.Buffer
	s.Text(&text, false)
	golden(t, "replay.txt.golden", text.Bytes())

	var gated bytes.Buffer
	s.Text(&gated, true)
	golden(t, "replay-gated.txt.golden", gated.Bytes())

	var js bytes.Buffer
	if err := s.JSON(&js); err != nil {
		t.Fatal(err)
	}
	golden(t, "replay.json.golden", js.Bytes())

	var step bytes.Buffer
	if err := s.Step(&step, 3); err != nil {
		t.Fatal(err)
	}
	golden(t, "replay-step3.txt.golden", step.Bytes())

	var page bytes.Buffer
	if err := s.HTML(&page); err != nil {
		t.Fatal(err)
	}
	h := page.String()
	// The page is large; pin its skeleton and that it is self-contained.
	for _, must := range []string{"<!doctype html>", "<title>", "rm -rf /"} {
		if !strings.Contains(strings.ToLower(h), strings.ToLower(must)) {
			t.Errorf("HTML replay missing %q", must)
		}
	}
	for _, mustNot := range []string{"http://", "https://", "<script src", "<link "} {
		if strings.Contains(h, mustNot) {
			t.Errorf("HTML replay must be self-contained, found %q", mustNot)
		}
	}
}
