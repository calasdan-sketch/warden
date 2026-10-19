package cost

import "testing"

func TestEstimate(t *testing.T) {
	// 1M in / 1M out on opus-4 @ 15/75 = $90.
	if got := Estimate("claude-opus-4-6", 1_000_000, 1_000_000, 0); got != 90.0 {
		t.Errorf("opus estimate = %v, want 90", got)
	}
	// Cached tokens at 10% of input rate.
	if got := Estimate("claude-sonnet-4-5", 0, 0, 1_000_000); got < 0.299 || got > 0.301 {
		t.Errorf("cached estimate = %v, want ~0.3", got)
	}
	if got := Estimate("unknown-model-xyz", 1000, 1000, 0); got != 0 {
		t.Errorf("unknown model should estimate 0, got %v", got)
	}
	if got := Estimate("CLAUDE-OPUS-4-6", 1_000_000, 0, 0); got != 15.0 {
		t.Errorf("matching should be case-insensitive, got %v", got)
	}
}
