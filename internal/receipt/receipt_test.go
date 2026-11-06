package receipt

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/calasdan-sketch/warden/internal/model"
)

func testRun(id string) *model.Run {
	return &model.Run{
		RunID:     id,
		AgentID:   "jarvis:code",
		FleetID:   "prod",
		Operator:  "dan",
		Status:    model.RunCompleted,
		StartedAt: time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond),
		TokensIn:  1000, TokensOut: 500, TokensCached: 200,
		CostUSD:   1.23,
		ToolCalls: 42,
	}
}

func TestSealAndVerify(t *testing.T) {
	s, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	rec, body, err := s.Seal(SealInput{Run: testRun("r1"), Guards: []string{"budget"}, SealedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if rec.BodyHash == "" || rec.Signature == "" || rec.KeyID == "" {
		t.Error("seal must produce hash, signature, and key id")
	}
	if rec.PrevHash != "" {
		t.Error("genesis receipt must have empty prev_hash")
	}
	if err := Verify(rec, body, s.PublicKey()); err != nil {
		t.Errorf("verify failed: %v", err)
	}
}

func TestTamperDetected(t *testing.T) {
	s, _ := Generate()
	rec, body, _ := s.Seal(SealInput{Run: testRun("r1"), SealedAt: time.Now().UTC()})

	// Tamper with the body: cost changed after sealing.
	tampered := strings.Replace(body, `"cost_usd":1.23`, `"cost_usd":0.01`, 1)
	if err := Verify(rec, tampered, s.PublicKey()); err == nil {
		t.Error("modified body must fail verification")
	}
	// Tamper with the stored hash.
	rec2 := *rec
	rec2.BodyHash = strings.Repeat("0", 64)
	if err := Verify(&rec2, body, s.PublicKey()); err == nil {
		t.Error("modified hash must fail verification")
	}
	// Wrong key.
	other, _ := Generate()
	if err := Verify(rec, body, other.PublicKey()); err == nil {
		t.Error("wrong key must fail verification")
	}
}

func TestHashChain(t *testing.T) {
	s, _ := Generate()
	var recs []*model.Receipt
	var bodies []string
	prev := ""
	for _, id := range []string{"r1", "r2", "r3"} {
		rec, body, err := s.Seal(SealInput{Run: testRun(id), PrevHash: prev, SealedAt: time.Now().UTC()})
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, rec)
		bodies = append(bodies, body)
		prev = rec.BodyHash
	}
	if err := VerifyChain(recs); err != nil {
		t.Errorf("valid chain rejected: %v", err)
	}
	for i, rec := range recs {
		if err := Verify(rec, bodies[i], s.PublicKey()); err != nil {
			t.Errorf("receipt %d failed: %v", i, err)
		}
	}
	// Delete the middle receipt: chain must break.
	if err := VerifyChain([]*model.Receipt{recs[0], recs[2]}); err == nil {
		t.Error("chain with deleted receipt must break")
	}
	// Reorder: chain must break.
	if err := VerifyChain([]*model.Receipt{recs[1], recs[0]}); err == nil {
		t.Error("reordered chain must break")
	}
}

func TestKilledRunSealsWithKillFields(t *testing.T) {
	s, _ := Generate()
	kr, kb := "looping", "dan"
	r := testRun("r9")
	r.Status = model.RunKilledOperator
	r.KillReason = &kr
	r.KilledBy = &kb
	rec, body, err := s.Seal(SealInput{Run: r, PrevHash: "abc", SealedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != model.RunKilledOperator || rec.KillReason == nil || *rec.KillReason != "looping" {
		t.Errorf("kill fields not sealed: %+v", rec)
	}
	if err := Verify(rec, body, s.PublicKey()); err != nil {
		t.Errorf("killed-run receipt must verify: %v", err)
	}
}

func TestLoadOrCreate(t *testing.T) {
	dir := t.TempDir()
	s1, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s1.KeyID() != s2.KeyID() {
		t.Error("key must be stable across loads")
	}
	// Private key file must be owner-only.
	if fi, err := os.Stat(dir + "/" + privName); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("private key mode = %v, want 600", fi.Mode())
	}
	// Garbage in the key file must fail loudly, not silently regenerate.
	if err := os.WriteFile(dir+"/"+privName, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(dir); err == nil {
		t.Error("corrupt key file should fail")
	}
}

func TestKeyIDStable(t *testing.T) {
	s, _ := Generate()
	if s.KeyID() != s.KeyID() {
		t.Error("KeyID not stable")
	}
	if len(s.KeyID()) != 16 {
		t.Errorf("KeyID length = %d, want 16", len(s.KeyID()))
	}
}
