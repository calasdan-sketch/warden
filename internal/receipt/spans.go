package receipt

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"github.com/calasdan-sketch/warden/internal/model"
)

// SpansDigestAlg names the trace-digest algorithm committed to by receipts.
// Changing the canonical span encoding requires a new algorithm name.
const SpansDigestAlg = "warden-spanset-sha256-v1"

// canonicalSpanV1 is the exact, ordered field set hashed for each span.
// It deliberately excludes LateAfterSeal (bookkeeping, not content) and
// PreDecided (never stored). Field order and encoding must never change.
type canonicalSpanV1 struct {
	SpanID            string  `json:"span_id"`
	RunID             string  `json:"run_id"`
	Kind              string  `json:"kind"`
	Name              string  `json:"name"`
	AgentID           string  `json:"agent_id"`
	FleetID           string  `json:"fleet_id"`
	StartedAt         string  `json:"started_at"`
	EndedAt           string  `json:"ended_at"`
	Status            string  `json:"status"`
	Model             string  `json:"model"`
	TokensIn          int64   `json:"tokens_in"`
	TokensOut         int64   `json:"tokens_out"`
	TokensCached      int64   `json:"tokens_cached"`
	CostUSD           float64 `json:"cost_usd"`
	CacheHit          bool    `json:"cache_hit"`
	Tool              string  `json:"tool"`
	ToolServer        string  `json:"tool_server"`
	ArgsSummary       string  `json:"args_summary"`
	ArgHash           string  `json:"arg_hash"`
	ExitStatus        int     `json:"exit_status"`
	OutputBytes       int64   `json:"output_bytes"`
	Path              string  `json:"path"`
	Op                string  `json:"op"`
	Count             int64   `json:"count"`
	Bytes             int64   `json:"bytes"`
	Host              string  `json:"host"`
	Port              int     `json:"port"`
	NetBytes          int64   `json:"net_bytes"`
	ChildRunID        string  `json:"child_run_id"`
	SpawnReason       string  `json:"spawn_reason"`
	Gate              string  `json:"gate"`
	Decision          string  `json:"decision"`
	Approver          string  `json:"approver"`
	DecisionLatencyMs int64   `json:"decision_latency_ms"`
	PolicyDecision    string  `json:"policy_decision"`
	PolicyReason      string  `json:"policy_reason"`
	PolicyVersion     string  `json:"policy_version"`
	Redacted          bool    `json:"redacted"`
}

func tsCanon(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// SpanHash returns the hex SHA-256 of a span's canonical v1 encoding.
func SpanHash(sp *model.Span) string {
	c := canonicalSpanV1{
		SpanID: sp.SpanID, RunID: sp.RunID, Kind: string(sp.Kind), Name: sp.Name,
		AgentID: sp.AgentID, FleetID: sp.FleetID,
		StartedAt: tsCanon(sp.StartedAt), Status: sp.Status,
		Model: sp.Model, TokensIn: sp.TokensIn, TokensOut: sp.TokensOut, TokensCached: sp.TokensCached,
		CostUSD: sp.CostUSD, CacheHit: sp.CacheHit,
		Tool: sp.Tool, ToolServer: sp.ToolServer, ArgsSummary: sp.ArgsSummary, ArgHash: sp.ArgHash,
		ExitStatus: sp.ExitStatus, OutputBytes: sp.OutputBytes,
		Path: sp.Path, Op: sp.Op, Count: sp.Count, Bytes: sp.Bytes,
		Host: sp.Host, Port: sp.Port, NetBytes: sp.NetBytes,
		ChildRunID: sp.ChildRunID, SpawnReason: sp.SpawnReason,
		Gate: sp.Gate, Decision: sp.Decision, Approver: sp.Approver, DecisionLatencyMs: sp.DecisionLatencyMs,
		PolicyDecision: sp.PolicyDecision, PolicyReason: sp.PolicyReason, PolicyVersion: sp.PolicyVersion,
		Redacted: sp.Redacted,
	}
	if sp.EndedAt != nil {
		c.EndedAt = tsCanon(*sp.EndedAt)
	}
	b, _ := json.Marshal(c) // fixed struct of scalars: cannot fail
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// SpansDigest commits to the set of spans a receipt covers: every span of
// the run that was recorded before the seal (LateAfterSeal == false).
//
// The digest is order-independent (sorted per-span hashes), so it can be
// recomputed from any export regardless of row order, yet it detects any
// edit, deletion, insertion, or late/covered flag flip of a covered span.
// It returns the number of covered spans and the hex digest.
func SpansDigest(spans []*model.Span) (int64, string) {
	hs := make([]string, 0, len(spans))
	for _, sp := range spans {
		if sp.LateAfterSeal {
			continue
		}
		hs = append(hs, SpanHash(sp))
	}
	sort.Strings(hs)
	h := sha256.New()
	h.Write([]byte(SpansDigestAlg + "\n"))
	for _, x := range hs {
		h.Write([]byte(x))
		h.Write([]byte("\n"))
	}
	return int64(len(hs)), hex.EncodeToString(h.Sum(nil))
}

// SignedTrace is the trace commitment inside a signed receipt body.
type SignedTrace struct {
	SpanCount   int64
	SpansDigest string
	Alg         string
}

// TraceCommitment extracts the trace commitment from a canonical receipt
// body. ok is false for receipts sealed before trace digests existed.
func TraceCommitment(body string) (SignedTrace, bool, error) {
	var b receiptBody
	if err := json.Unmarshal([]byte(body), &b); err != nil {
		return SignedTrace{}, false, err
	}
	if b.SpansDigest == "" {
		return SignedTrace{}, false, nil
	}
	return SignedTrace{SpanCount: b.SpanCount, SpansDigest: b.SpansDigest, Alg: b.SpansDigestAlg}, true, nil
}

// VerifyTrace checks a run's spans against the signed trace commitment in
// its receipt body. It returns how many spans arrived after the seal (and
// are therefore not covered by the signature) alongside any mismatch.
func VerifyTrace(body string, spans []*model.Span) (late int, covered bool, err error) {
	tc, ok, err := TraceCommitment(body)
	if err != nil {
		return 0, false, err
	}
	for _, sp := range spans {
		if sp.LateAfterSeal {
			late++
		}
	}
	if !ok {
		return late, false, nil
	}
	if tc.Alg != "" && tc.Alg != SpansDigestAlg {
		return late, true, errUnknownAlg(tc.Alg)
	}
	n, d := SpansDigest(spans)
	if n != tc.SpanCount {
		return late, true, errTrace("span count %d != %d signed at seal: spans were deleted or inserted", n, tc.SpanCount)
	}
	if d != tc.SpansDigest {
		return late, true, errTrace("span digest mismatch: a covered span was modified after sealing")
	}
	return late, true, nil
}
