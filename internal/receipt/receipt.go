// Package receipt implements signed, hash-chained per-run receipts.
// A receipt is sealed even on kill: a killed run is not a missing run.
//
// Tamper evidence comes in two layers:
//  1. Ed25519 signature over the receipt body hash (proves who sealed it).
//  2. Hash chain: each receipt commits to the previous receipt's body hash
//     (proves nothing was inserted, deleted, or reordered).
//
// The external SIEM sink is the second copy: an attacker would have to
// compromise both this store and the SIEM to rewrite history undetected.
package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/calasdan-sketch/warden/internal/model"
)

// receiptBody is the canonical signed content. Field order is fixed and must
// never change: it is what the signature covers.
type receiptBody struct {
	RunID        string   `json:"run_id"`
	AgentID      string   `json:"agent_id"`
	FleetID      string   `json:"fleet_id"`
	Operator     string   `json:"operator"`
	Status       string   `json:"status"`
	StartedAt    string   `json:"started_at"`
	SealedAt     string   `json:"sealed_at"`
	TokensIn     int64    `json:"tokens_in"`
	TokensOut    int64    `json:"tokens_out"`
	TokensCached int64    `json:"tokens_cached"`
	CostUSD      float64  `json:"cost_usd"`
	ToolCalls    int64    `json:"tool_calls"`
	Guards       []string `json:"guards_evaluated"`
	KillReason   string   `json:"kill_reason"`
	KilledBy     string   `json:"killed_by"`
	PrevHash     string   `json:"prev_hash"`
	// Trace commitment (added in 0.1.0; omitted from older receipts so their
	// canonical bodies — and signatures — are unchanged).
	SpanCount      int64  `json:"span_count,omitempty"`
	SpansDigest    string `json:"spans_digest,omitempty"`
	SpansDigestAlg string `json:"spans_digest_alg,omitempty"`
}

// Signer holds the Ed25519 receipt-signing key.
type Signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// KeyID is the stable fingerprint of the signing key.
func (s *Signer) KeyID() string { return KeyIDOf(s.pub) }

// KeyIDOf is the fingerprint of any Ed25519 public key (first 16 hex chars
// of its SHA-256), matching the key_id stamped on receipts.
func KeyIDOf(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:16]
}

// PublicKey returns the raw public key (for verification config).
func (s *Signer) PublicKey() ed25519.PublicKey { return s.pub }

// Generate creates a fresh signing key.
func Generate() (*Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Signer{priv: priv, pub: pub}, nil
}

// Key paths inside the data dir.
const (
	privName = "receipt.key"
	pubName  = "receipt.pub"
)

// LoadOrCreate loads the receipt-signing key from dir, creating it (0600) if absent.
func LoadOrCreate(dir string) (*Signer, error) {
	privPath := filepath.Join(dir, privName)
	pubPath := filepath.Join(dir, pubName)
	if b, err := os.ReadFile(privPath); err == nil {
		priv := ed25519.PrivateKey(b)
		if len(priv) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("bad private key length in %s", privPath)
		}
		return &Signer{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	s, err := Generate()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(privPath, []byte(s.priv), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(pubPath, []byte(s.pub), 0o644); err != nil {
		return nil, err
	}
	return s, nil
}

// SealInput is everything needed to seal one receipt.
type SealInput struct {
	Run      *model.Run
	Guards   []string
	PrevHash string // head of the chain ("" for genesis)
	SealedAt time.Time
	// Spans are the run's spans at seal time; the receipt commits to their
	// digest so the full trace, not just its totals, is tamper-evident.
	// nil means "no trace commitment" (legacy behaviour).
	Spans []*model.Span
}

// Seal builds, hashes, and signs a receipt for a run.
func (s *Signer) Seal(in SealInput) (*model.Receipt, string, error) {
	r := in.Run
	killReason, killedBy := "", ""
	if r.KillReason != nil {
		killReason = *r.KillReason
	}
	if r.KilledBy != nil {
		killedBy = *r.KilledBy
	}
	body := receiptBody{
		RunID:        r.RunID,
		AgentID:      r.AgentID,
		FleetID:      r.FleetID,
		Operator:     r.Operator,
		Status:       string(r.Status),
		StartedAt:    r.StartedAt.UTC().Format(time.RFC3339Nano),
		SealedAt:     in.SealedAt.UTC().Format(time.RFC3339Nano),
		TokensIn:     r.TokensIn,
		TokensOut:    r.TokensOut,
		TokensCached: r.TokensCached,
		CostUSD:      r.CostUSD,
		ToolCalls:    r.ToolCalls,
		Guards:       in.Guards,
		KillReason:   killReason,
		KilledBy:     killedBy,
		PrevHash:     in.PrevHash,
	}
	if in.Spans != nil {
		body.SpanCount, body.SpansDigest = SpansDigest(in.Spans)
		body.SpansDigestAlg = SpansDigestAlg
	}
	canonical, err := json.Marshal(body)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(canonical)
	bodyHash := hex.EncodeToString(sum[:])
	sig := ed25519.Sign(s.priv, sum[:])

	rec := &model.Receipt{
		RunID:        r.RunID,
		AgentID:      r.AgentID,
		FleetID:      r.FleetID,
		Operator:     r.Operator,
		Status:       r.Status,
		StartedAt:    r.StartedAt,
		SealedAt:     in.SealedAt,
		TokensIn:     r.TokensIn,
		TokensOut:    r.TokensOut,
		TokensCached: r.TokensCached,
		CostUSD:      r.CostUSD,
		ToolCalls:    r.ToolCalls,
		BodyHash:     bodyHash,
		PrevHash:     in.PrevHash,
		Signature:    base64.StdEncoding.EncodeToString(sig),
		KeyID:        s.KeyID(),
		SpanCount:    body.SpanCount,
		SpansDigest:  body.SpansDigest,
	}
	if killReason != "" {
		rec.KillReason = &killReason
	}
	if killedBy != "" {
		rec.KilledBy = &killedBy
	}
	rec.GuardsEvaluated = in.Guards
	return rec, string(canonical), nil
}

// Verify checks one receipt's signature and body hash against pub.
func Verify(rec *model.Receipt, body string, pub ed25519.PublicKey) error {
	var b receiptBody
	if err := json.Unmarshal([]byte(body), &b); err != nil {
		return fmt.Errorf("receipt body not canonical JSON: %w", err)
	}
	// The stored fields must match the canonical body — otherwise the body
	// was swapped under the signature.
	if b.RunID != rec.RunID || b.PrevHash != rec.PrevHash {
		return fmt.Errorf("receipt header does not match signed body")
	}
	// Fields the store keeps beside the body must agree with it too.
	if rec.Status != "" && string(rec.Status) != b.Status {
		return fmt.Errorf("receipt status %q does not match signed body %q", rec.Status, b.Status)
	}
	sum := sha256.Sum256([]byte(body))
	if hex.EncodeToString(sum[:]) != rec.BodyHash {
		return fmt.Errorf("body hash mismatch: receipt was modified after sealing")
	}
	sig, err := base64.StdEncoding.DecodeString(rec.Signature)
	if err != nil {
		return fmt.Errorf("bad signature encoding: %w", err)
	}
	if !ed25519.Verify(pub, sum[:], sig) {
		return fmt.Errorf("signature invalid: not sealed by this key")
	}
	return nil
}

// VerifyChain checks that receipts link head-to-tail: each PrevHash equals the
// previous receipt's BodyHash. Receipts must be in seal order.
func VerifyChain(recs []*model.Receipt) error {
	prev := ""
	for i, r := range recs {
		if r.PrevHash != prev {
			return fmt.Errorf("chain broken at receipt %d (%s): prev_hash %q != %q",
				i, r.RunID, r.PrevHash, prev)
		}
		prev = r.BodyHash
	}
	return nil
}

func errTrace(format string, a ...any) error { return fmt.Errorf("trace: "+format, a...) }

func errUnknownAlg(alg string) error {
	return fmt.Errorf("trace: unknown digest algorithm %q (newer warden?)", alg)
}

// SignStatement signs an arbitrary domain-separated statement (e.g. an
// export header) and returns the base64 signature. The domain string keeps
// a statement signature from ever being replayable as a receipt signature.
func (s *Signer) SignStatement(domain string, msg []byte) string {
	sum := sha256.Sum256(append([]byte(domain+"\n"), msg...))
	return base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, sum[:]))
}

// VerifyStatement checks a SignStatement signature.
func VerifyStatement(pub ed25519.PublicKey, domain string, msg []byte, sigB64 string) bool {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(append([]byte(domain+"\n"), msg...))
	return ed25519.Verify(pub, sum[:], sig)
}

// MatchesBody checks that every field shown on a receipt header equals the
// signed canonical body. Verify only needs the body (it is what the
// signature covers), but an export also carries a human-readable header:
// without this check an edited header ("status": "completed" on a killed
// run) would sit next to a valid signature and mislead a reader.
func MatchesBody(rec *model.Receipt, body string) error {
	var b receiptBody
	if err := json.Unmarshal([]byte(body), &b); err != nil {
		return fmt.Errorf("receipt body not canonical JSON: %w", err)
	}
	var bad []string
	cmp := func(field string, ok bool) {
		if !ok {
			bad = append(bad, field)
		}
	}
	timeEq := func(s string, t time.Time) bool {
		if s == "" {
			return t.IsZero()
		}
		bt, err := time.Parse(time.RFC3339Nano, s)
		return err == nil && bt.Equal(t)
	}
	deref := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	cmp("run_id", rec.RunID == b.RunID)
	cmp("agent_id", rec.AgentID == b.AgentID)
	cmp("fleet_id", rec.FleetID == b.FleetID)
	cmp("operator", rec.Operator == b.Operator)
	cmp("status", string(rec.Status) == b.Status)
	cmp("started_at", timeEq(b.StartedAt, rec.StartedAt))
	cmp("sealed_at", timeEq(b.SealedAt, rec.SealedAt))
	cmp("tokens_in", rec.TokensIn == b.TokensIn)
	cmp("tokens_out", rec.TokensOut == b.TokensOut)
	cmp("tokens_cached", rec.TokensCached == b.TokensCached)
	cmp("cost_usd", rec.CostUSD == b.CostUSD)
	cmp("tool_calls", rec.ToolCalls == b.ToolCalls)
	cmp("kill_reason", deref(rec.KillReason) == b.KillReason)
	cmp("killed_by", deref(rec.KilledBy) == b.KilledBy)
	cmp("prev_hash", rec.PrevHash == b.PrevHash)
	cmp("span_count", rec.SpanCount == b.SpanCount)
	cmp("spans_digest", rec.SpansDigest == b.SpansDigest)
	guardsEq := len(rec.GuardsEvaluated) == len(b.Guards)
	for i := 0; guardsEq && i < len(b.Guards); i++ {
		guardsEq = rec.GuardsEvaluated[i] == b.Guards[i]
	}
	cmp("guards_evaluated", guardsEq)
	if len(bad) > 0 {
		return fmt.Errorf("receipt header field(s) %s differ from the signed body: header was edited", strings.Join(bad, ", "))
	}
	return nil
}

// FillFromBody populates a receipt header's display fields from its signed
// canonical body (the store keeps only the body plus index columns).
func FillFromBody(rec *model.Receipt, body string) error {
	var b receiptBody
	if err := json.Unmarshal([]byte(body), &b); err != nil {
		return err
	}
	rec.AgentID, rec.FleetID, rec.Operator = b.AgentID, b.FleetID, b.Operator
	rec.Status = model.RunStatus(b.Status)
	if t, err := time.Parse(time.RFC3339Nano, b.StartedAt); err == nil {
		rec.StartedAt = t
	}
	if t, err := time.Parse(time.RFC3339Nano, b.SealedAt); err == nil {
		rec.SealedAt = t
	}
	rec.TokensIn, rec.TokensOut, rec.TokensCached = b.TokensIn, b.TokensOut, b.TokensCached
	rec.CostUSD, rec.ToolCalls = b.CostUSD, b.ToolCalls
	rec.GuardsEvaluated = b.Guards
	rec.KillReason, rec.KilledBy = nil, nil
	if b.KillReason != "" {
		kr := b.KillReason
		rec.KillReason = &kr
	}
	if b.KilledBy != "" {
		kb := b.KilledBy
		rec.KilledBy = &kb
	}
	rec.SpanCount, rec.SpansDigest = b.SpanCount, b.SpansDigest
	return nil
}
