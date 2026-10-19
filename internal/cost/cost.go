// Package cost is warden's token rate card. It exists for one narrow purpose:
// when a framework hook emits an llm.call span without a cost, the collector
// fills in a rate-card estimate so the burn bar isn't blind. Emitter-supplied
// cost is never touched (cost computed once, at the emitter).
//
// The default card is approximate; treat it as an estimate, not an invoice.
// v1.1: configurable rate card via the policy file.
package cost

import "strings"

// Rate is USD per million tokens.
type Rate struct {
	InUSD  float64 // per 1M input tokens
	OutUSD float64 // per 1M output tokens
}

// cardEntry is one prefix->rate mapping.
type cardEntry struct {
	Prefix string
	Rate   Rate
}

// DefaultCard maps model name prefixes to rates.
var DefaultCard = []cardEntry{
	{"claude-opus-4", Rate{15.0, 75.0}},
	{"claude-sonnet-4", Rate{3.0, 15.0}},
	{"claude-haiku", Rate{1.0, 5.0}},
	{"gpt-5", Rate{5.0, 15.0}},
	{"gpt-4o", Rate{2.5, 10.0}},
	{"gemini-2", Rate{1.0, 4.0}},
}

// Estimate returns the USD estimate for a model invocation, or 0 when the
// model isn't on the card. Cached tokens are billed at 10% of input (the
// common provider convention for prompt-cache reads).
func Estimate(model string, in, out, cached int64) float64 {
	m := strings.ToLower(model)
	for _, e := range DefaultCard {
		if strings.HasPrefix(m, e.Prefix) {
			return float64(in)*e.Rate.InUSD/1e6 +
				float64(out)*e.Rate.OutUSD/1e6 +
				float64(cached)*e.Rate.InUSD/1e6*0.1
		}
	}
	return 0
}
