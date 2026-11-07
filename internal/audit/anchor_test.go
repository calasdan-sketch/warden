package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/calasdan-sketch/warden/internal/model"
	"github.com/calasdan-sketch/warden/internal/receipt"
)

func sealN(t *testing.T, s *receipt.Signer, n int) []*model.Receipt {
	t.Helper()
	var recs []*model.Receipt
	prev := ""
	for i := 0; i < n; i++ {
		rec, _, err := s.Seal(receipt.SealInput{Run: &model.Run{RunID: "r" + string(rune('a'+i)), AgentID: "a", FleetID: "f", Status: model.RunCompleted,
			StartedAt: time.Now().Add(-time.Minute)}, PrevHash: prev, SealedAt: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, rec)
		prev = rec.BodyHash
	}
	return recs
}

func TestAnchorDetectsRewriteEvenWithStolenKey(t *testing.T) {
	s, _ := receipt.Generate()
	honest := sealN(t, s, 3)
	a := MakeAnchor(s, honest[2].BodyHash, 3, time.Now())
	if p := VerifyAnchors([]Anchor{*a}, honest, s.PublicKey()); len(p) != 0 {
		t.Fatalf("honest chain must satisfy its anchor: %v", p)
	}
	// An attacker with the key rewrites history: same runs, one changed
	// status, whole chain re-signed. Every signature in it verifies...
	forged := func() []*model.Receipt {
		var recs []*model.Receipt
		prev := ""
		for i := 0; i < 3; i++ {
			st := model.RunCompleted
			if i == 1 {
				st = model.RunFailed
			}
			rec, _, _ := s.Seal(receipt.SealInput{Run: &model.Run{RunID: "r" + string(rune('a'+i)), AgentID: "a", FleetID: "f", Status: st,
				StartedAt: time.Now().Add(-time.Hour)}, PrevHash: prev, SealedAt: time.Now()})
			recs = append(recs, rec)
			prev = rec.BodyHash
		}
		return recs
	}()
	if err := ChainByLinkage(forged); err != nil {
		t.Fatalf("the forged chain is internally consistent: %v", err)
	}
	// ...but the anchor that already left the machine does not match.
	p := VerifyAnchors([]Anchor{*a}, forged, s.PublicKey())
	if len(p) != 1 || !strings.Contains(p[0], "rewritten") {
		t.Errorf("rewrite must be detected: %v", p)
	}
}

func TestAnchorDetectsTruncationAndForgery(t *testing.T) {
	s, _ := receipt.Generate()
	recs := sealN(t, s, 4)
	a := MakeAnchor(s, recs[3].BodyHash, 4, time.Now())
	if p := VerifyAnchors([]Anchor{*a}, recs[:2], s.PublicKey()); len(p) != 1 || !strings.Contains(p[0], "deleted") {
		t.Errorf("truncation: %v", p)
	}
	edited := *a
	edited.ReceiptCount = 2
	if p := VerifyAnchors([]Anchor{edited}, recs, s.PublicKey()); len(p) != 1 || !strings.Contains(p[0], "signature") {
		t.Errorf("edited anchor: %v", p)
	}
	other, _ := receipt.Generate()
	if p := VerifyAnchors([]Anchor{*a}, recs, other.PublicKey()); len(p) != 1 {
		t.Errorf("wrong key: %v", p)
	}
	// Older anchors stay valid as the chain grows.
	old := MakeAnchor(s, recs[1].BodyHash, 2, time.Now().Add(-time.Hour))
	if p := VerifyAnchors([]Anchor{*old, *a}, recs, s.PublicKey()); len(p) != 0 {
		t.Errorf("growing chain: %v", p)
	}
}

func TestReadAnchorsStrict(t *testing.T) {
	s, _ := receipt.Generate()
	a := MakeAnchor(s, "h", 1, time.Now())
	b, _ := json.Marshal(a)
	got, err := ReadAnchors(bytes.NewReader(append(b, '\n')))
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := ReadAnchors(strings.NewReader(`{"type":"span"}` + "\n")); err == nil {
		t.Error("non-anchor record must be rejected")
	}
	if _, err := ReadAnchors(strings.NewReader("not json\n")); err == nil {
		t.Error("garbage must be rejected")
	}
}
