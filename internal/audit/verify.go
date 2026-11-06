// Package audit verifies warden's tamper-evidence end to end: receipt
// signatures, the receipt hash chain, and each receipt's signed trace
// digest over the run's spans. It works on the live store and on an
// exported JSONL bundle alike, so a SIEM copy can be checked by a third
// party who holds only the public key — no warden database required.
package audit

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/calasdan-sketch/warden/internal/model"
	"github.com/calasdan-sketch/warden/internal/receipt"
)

// Item is one sealed receipt with its canonical body and the run's spans.
type Item struct {
	Receipt *model.Receipt
	Body    string
	Spans   []*model.Span
}

// Report is the outcome of a verification pass.
type Report struct {
	Receipts    int      // receipts examined
	Valid       int      // receipts whose signature, body and trace all verified
	TraceSigned int      // receipts that carry a trace commitment
	LegacyNoTrc int      // receipts sealed before trace digests (totals-only)
	LateSpans   int      // spans recorded after their seal (kept, not covered)
	ChainOK     bool     // hash chain intact (genesis → head, no forks/gaps)
	Problems    []string // human-readable failures
}

// OK reports whether everything verified.
func (r *Report) OK() bool { return r.ChainOK && r.Valid == r.Receipts && len(r.Problems) == 0 }

// Verify checks every item against pub, then the chain they form.
func Verify(items []Item, pub ed25519.PublicKey) *Report {
	rep := &Report{Receipts: len(items)}
	var recs []*model.Receipt
	for _, it := range items {
		if err := receipt.Verify(it.Receipt, it.Body, pub); err != nil {
			rep.Problems = append(rep.Problems, fmt.Sprintf("%s: %v", it.Receipt.RunID, err))
			continue
		}
		recs = append(recs, it.Receipt)
		late, covered, err := receipt.VerifyTrace(it.Body, it.Spans)
		rep.LateSpans += late
		if covered {
			rep.TraceSigned++
		} else {
			rep.LegacyNoTrc++
		}
		if err != nil {
			rep.Problems = append(rep.Problems, fmt.Sprintf("%s: %v", it.Receipt.RunID, err))
			continue
		}
		rep.Valid++
	}
	if err := ChainByLinkage(recs); err != nil {
		rep.Problems = append(rep.Problems, "chain: "+err.Error())
	} else {
		rep.ChainOK = true
	}
	return rep
}

// ChainByLinkage checks that receipts form exactly one unbroken chain from
// genesis (prev_hash "") to a single head, following prev_hash links. It is
// independent of row or file order, and detects deletion (gap), insertion
// of a forged link (fork), and reordering.
func ChainByLinkage(recs []*model.Receipt) error {
	if len(recs) == 0 {
		return nil
	}
	next := make(map[string]*model.Receipt, len(recs))
	for _, r := range recs {
		if other, dup := next[r.PrevHash]; dup {
			return fmt.Errorf("fork: %s and %s both extend %q", other.RunID, r.RunID, short(r.PrevHash))
		}
		next[r.PrevHash] = r
	}
	seen := 0
	cur := ""
	for {
		r, ok := next[cur]
		if !ok {
			break
		}
		seen++
		cur = r.BodyHash
		if seen > len(recs) {
			return fmt.Errorf("cycle in receipt chain")
		}
	}
	if seen != len(recs) {
		return fmt.Errorf("broken: only %d of %d receipts are reachable from genesis (a receipt was deleted or its prev_hash altered)", seen, len(recs))
	}
	return nil
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12] + "…"
	}
	return h
}

// BundleHeader is the first line of a JSONL export.
type BundleHeader struct {
	Type      string `json:"type"` // "header"
	Format    string `json:"format"`
	Version   string `json:"warden_version"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key_b64"`
	// Signed export statement: the chain head and receipt count at export
	// time. Without it, deleting the newest receipts from a bundle (tail
	// truncation) would be undetectable — the remaining chain still links.
	ExportedAt   string `json:"exported_at,omitempty"`
	HeadHash     string `json:"head_hash"`
	ReceiptCount int    `json:"receipt_count"`
	Signature    string `json:"signature,omitempty"`
}

// HeaderDomain separates export-statement signatures from receipt ones.
const HeaderDomain = "warden-export-header-v1"

// HeaderStatement is the exact byte string a bundle header signature covers.
func HeaderStatement(h *BundleHeader) []byte {
	return []byte(fmt.Sprintf("%s\n%s\n%s\n%d", h.Format, h.ExportedAt, h.HeadHash, h.ReceiptCount))
}

// CheckHeader verifies the signed header against the bundle's receipts:
// the signature must be valid, the head it names must be present, and at
// least as many receipts as it counted must be present.
func CheckHeader(h *BundleHeader, items []Item, pub ed25519.PublicKey) error {
	if h == nil || h.Signature == "" {
		return fmt.Errorf("bundle has no signed header: truncation of the newest receipts cannot be ruled out")
	}
	if !receipt.VerifyStatement(pub, HeaderDomain, HeaderStatement(h), h.Signature) {
		return fmt.Errorf("bundle header signature invalid (header edited, or a different key)")
	}
	if len(items) < h.ReceiptCount {
		return fmt.Errorf("bundle holds %d receipts but its signed header counted %d: receipts were removed", len(items), h.ReceiptCount)
	}
	if h.HeadHash == "" {
		return nil
	}
	for _, it := range items {
		if it.Receipt.BodyHash == h.HeadHash {
			return nil
		}
	}
	return fmt.Errorf("chain head %s named in the signed header is missing: receipts were removed", short(h.HeadHash))
}

// BundleFormat identifies the JSONL audit-bundle layout.
const BundleFormat = "warden-audit-jsonl-v1"

// MaxBundleLine bounds one JSONL record (a receipt or span is a few KiB).
const MaxBundleLine = 8 << 20

// ReadBundle parses a JSONL export into verification items. Spans and
// receipts are matched by run_id regardless of their order in the file.
func ReadBundle(r io.Reader) ([]Item, *BundleHeader, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), MaxBundleLine)
	type rec struct {
		rec  *model.Receipt
		body string
	}
	var order []string
	recs := map[string]rec{}
	spans := map[string][]*model.Span{}
	var hdr *BundleHeader
	line := 0
	for sc.Scan() {
		line++
		b := sc.Bytes()
		if len(strings.TrimSpace(string(b))) == 0 {
			continue
		}
		var env struct {
			Type    string          `json:"type"`
			Span    *model.Span     `json:"span"`
			Receipt *model.Receipt  `json:"receipt"`
			Body    json.RawMessage `json:"body"`
		}
		if err := json.Unmarshal(b, &env); err != nil {
			return nil, nil, fmt.Errorf("line %d: %w", line, err)
		}
		switch env.Type {
		case "header":
			var h BundleHeader
			if err := json.Unmarshal(b, &h); err != nil {
				return nil, nil, fmt.Errorf("line %d: %w", line, err)
			}
			hdr = &h
		case "span":
			if env.Span != nil {
				spans[env.Span.RunID] = append(spans[env.Span.RunID], env.Span)
			}
		case "receipt":
			if env.Receipt == nil || len(env.Body) == 0 {
				return nil, nil, fmt.Errorf("line %d: receipt record without body", line)
			}
			if _, dup := recs[env.Receipt.RunID]; dup {
				return nil, nil, fmt.Errorf("line %d: duplicate receipt for run %s", line, env.Receipt.RunID)
			}
			// The body is embedded as raw JSON: its exact bytes are what the
			// signature covers, so it must not be re-encoded.
			recs[env.Receipt.RunID] = rec{env.Receipt, string(env.Body)}
			order = append(order, env.Receipt.RunID)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("line %d: %w", line+1, err)
	}
	items := make([]Item, 0, len(order))
	for _, id := range order {
		r := recs[id]
		items = append(items, Item{Receipt: r.rec, Body: r.body, Spans: spans[id]})
	}
	return items, hdr, nil
}

// LoadPublicKey reads an Ed25519 public key: raw 32 bytes (warden's
// receipt.pub), or a text file holding it as base64 or hex.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}
	s := strings.TrimSpace(string(b))
	if k, err := base64.StdEncoding.DecodeString(s); err == nil && len(k) == ed25519.PublicKeySize {
		return ed25519.PublicKey(k), nil
	}
	if k, err := hex.DecodeString(s); err == nil && len(k) == ed25519.PublicKeySize {
		return ed25519.PublicKey(k), nil
	}
	return nil, fmt.Errorf("%s: not an Ed25519 public key (want 32 raw bytes, base64 or hex)", path)
}
