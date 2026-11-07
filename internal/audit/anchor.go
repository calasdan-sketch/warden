package audit

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/calasdan-sketch/warden/internal/model"
	"github.com/calasdan-sketch/warden/internal/receipt"
)

// An anchor is a small signed statement of "the chain had N receipts and its
// head was H at time T". It is meant to be shipped, as a line of JSON, to a
// place the supervised agent cannot write (a SIEM, an object store with
// retention lock, another machine). It closes the gap the threat model
// admits: whoever holds the signing key can re-sign a whole chain, but cannot
// reach back and change an anchor that already left the machine.
const (
	AnchorFormat = "warden-anchor-v1"
	AnchorDomain = "warden-anchor-v1"
)

// Anchor is one anchor line.
type Anchor struct {
	Type         string `json:"type"` // "anchor"
	Format       string `json:"format"`
	At           string `json:"at"`
	HeadHash     string `json:"head_hash"`
	ReceiptCount int    `json:"receipt_count"`
	KeyID        string `json:"key_id"`
	Signature    string `json:"signature"`
}

func anchorStatement(a *Anchor) []byte {
	return []byte(fmt.Sprintf("%s\n%s\n%s\n%d", a.Format, a.At, a.HeadHash, a.ReceiptCount))
}

// MakeAnchor signs the current chain head and count.
func MakeAnchor(s *receipt.Signer, head string, count int, now time.Time) *Anchor {
	a := &Anchor{Type: "anchor", Format: AnchorFormat, At: now.UTC().Format(time.RFC3339), HeadHash: head, ReceiptCount: count, KeyID: s.KeyID()}
	a.Signature = s.SignStatement(AnchorDomain, anchorStatement(a))
	return a
}

// ReadAnchors parses a JSONL file of anchors. Unknown record types are an
// error, and so is a line that is not valid JSON.
func ReadAnchors(r io.Reader) ([]Anchor, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	var out []Anchor
	n := 0
	for sc.Scan() {
		n++
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var a Anchor
		if err := json.Unmarshal(line, &a); err != nil {
			return nil, fmt.Errorf("anchors line %d: %w", n, err)
		}
		if a.Type != "anchor" || a.Format != AnchorFormat {
			return nil, fmt.Errorf("anchors line %d: not a %s record", n, AnchorFormat)
		}
		out = append(out, a)
	}
	return out, sc.Err()
}

// orderChain returns the receipts in chain order (genesis first), following
// prev_hash links; receipts not reachable from genesis are dropped.
func orderChain(recs []*model.Receipt) []*model.Receipt {
	next := make(map[string]*model.Receipt, len(recs))
	for _, r := range recs {
		next[r.PrevHash] = r
	}
	var out []*model.Receipt
	cur := ""
	for i := 0; i <= len(recs); i++ {
		r, ok := next[cur]
		if !ok {
			break
		}
		out = append(out, r)
		cur = r.BodyHash
	}
	return out
}

// VerifyAnchors checks every anchor against pub and against the chain. It
// returns one problem string per failure; no problems means every anchored
// head still sits at its anchored position in this chain.
func VerifyAnchors(anchors []Anchor, recs []*model.Receipt, pub ed25519.PublicKey) []string {
	var problems []string
	chain := orderChain(recs)
	var lastAt time.Time
	lastCount := -1
	for i, a := range anchors {
		label := fmt.Sprintf("anchor %d (%s, %d receipts)", i+1, a.At, a.ReceiptCount)
		if !receipt.VerifyStatement(pub, AnchorDomain, anchorStatement(&a), a.Signature) {
			problems = append(problems, label+": signature does not verify with the supplied key (forged, edited, or another key)")
			continue
		}
		if a.KeyID != "" && a.KeyID != receipt.KeyIDOf(pub) {
			problems = append(problems, label+": key_id is not the supplied key")
			continue
		}
		if t, err := time.Parse(time.RFC3339, a.At); err == nil {
			if !lastAt.IsZero() && t.Before(lastAt) && a.ReceiptCount > lastCount {
				problems = append(problems, label+": timestamp goes backwards while the count grows")
			}
			lastAt = t
		}
		lastCount = a.ReceiptCount
		switch {
		case a.ReceiptCount < 0:
			problems = append(problems, label+": negative count")
		case a.ReceiptCount == 0:
			if a.HeadHash != "" {
				problems = append(problems, label+": empty chain with a head hash")
			}
		case a.ReceiptCount > len(chain):
			problems = append(problems, fmt.Sprintf("%s: chain now has only %d receipts: receipts were deleted after this anchor", label, len(chain)))
		case chain[a.ReceiptCount-1].BodyHash != a.HeadHash:
			problems = append(problems, fmt.Sprintf("%s: receipt #%d is not the anchored one: history was rewritten (re-signed?) after this anchor", label, a.ReceiptCount))
		}
	}
	return problems
}
