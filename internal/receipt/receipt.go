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
