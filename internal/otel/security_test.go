package otel

// Regression test for the v1 scrutiny findings (2026-10-18): the OTLP
// export must stream in bounded memory and still produce one valid envelope.

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/calasdan-sketch/warden/internal/model"
)

func testSpan(runID, name string) *model.Span {
	return &model.Span{
		SpanID: "sp-" + name, RunID: runID, Kind: model.SpanToolCall,
		Tool: "t", Name: name, StartedAt: time.Now().UTC(),
	}
}

func TestEncodeStreamSingleEnvelope(t *testing.T) {
	pages := [][]*model.Span{
		{testSpan("run-a", "one"), testSpan("run-a", "two")},
		{testSpan("run-b", "three")},
		{}, // empty page mid-stream is fine
		{testSpan("run-c", "four")},
	}
	i := 0
	var buf bytes.Buffer
	if err := EncodeStream(&buf, func() ([]*model.Span, error) {
		if i >= len(pages) {
			return nil, nil
		}
		p := pages[i]
		i++
		return p, nil
	}); err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatalf("streamed OTLP is not one valid JSON document: %v", err)
	}
	rss, ok := env["resourceSpans"].([]any)
	if !ok {
		t.Fatalf("no resourceSpans array: %v", env)
	}
	if len(rss) != 3 {
		t.Errorf("want 3 resourceSpans (one per run), got %d", len(rss))
	}
	// All four spans present across the envelope.
	n := 0
	for _, rs := range rss {
		m := rs.(map[string]any)
		scopes := m["scopeSpans"].([]any)
		spans := scopes[0].(map[string]any)["spans"].([]any)
		n += len(spans)
	}
	if n != 4 {
		t.Errorf("want 4 spans in envelope, got %d", n)
	}
}

func TestEncodeStreamPropagatesError(t *testing.T) {
	var buf bytes.Buffer
	errBoom := errTestBoom{}
	err := EncodeStream(&buf, func() ([]*model.Span, error) {
		return nil, errBoom
	})
	if err != errBoom {
		t.Errorf("want page error propagated, got %v", err)
	}
}

type errTestBoom struct{}

func (errTestBoom) Error() string { return "boom" }
