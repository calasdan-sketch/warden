package audit

import (
	"bytes"
	"math/rand"
	"os"
	"reflect"
	"testing"
)

// TestAnyByteFlipInABundleIsCaughtOrHarmless flips random bytes of real
// exported bundles (written by warden 0.1.0, 0.1.x and 0.2.0, kept in
// testdata). A flip is "harmless" only if the verifier would read exactly the
// same header, receipts, bodies and spans as before (for example a flip that
// turns a key into another spelling Go's decoder treats the same, or one
// inside a run summary row, which is counted and listed as UNSIGNED but never
// trusted). Every other flip must make verification fail. A flip that changes
// what the verifier reads and still verifies clean is a hole in the tamper
// evidence.
func TestAnyByteFlipInABundleIsCaughtOrHarmless(t *testing.T) {
	for _, name := range []string{"bundle-0.1.0", "bundle-0.1.x", "bundle-0.2.0"} {
		raw, err := os.ReadFile("testdata/" + name + ".jsonl")
		if err != nil {
			t.Fatal(err)
		}
		pub, err := LoadPublicKey("testdata/" + name + ".pub")
		if err != nil {
			t.Fatal(err)
		}
		base, err := ReadBundle(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		if rep := VerifyBundle(base, pub); !rep.OK() {
			t.Fatalf("%s: fixture must verify before it is damaged: %v", name, rep.Problems)
		}
		r := rand.New(rand.NewSource(99))
		caught, harmless := 0, 0
		for i := 0; i < 2500; i++ {
			m := append([]byte(nil), raw...)
			pos := r.Intn(len(m))
			switch r.Intn(3) {
			case 0:
				m[pos] ^= 1 << uint(r.Intn(8))
			case 1:
				m[pos] = "0123456789abcdef\"{}, :"[r.Intn(22)]
			default: // delete a byte
				m = append(m[:pos], m[pos+1:]...)
			}
			b, err := ReadBundle(bytes.NewReader(m))
			if err != nil {
				caught++
				continue
			}
			if rep := VerifyBundle(b, pub); !rep.OK() {
				caught++
				continue
			}
			if sameReading(base, b) {
				harmless++
				continue
			}
			lo, hi := max(0, pos-40), min(len(raw), pos+40)
			t.Fatalf("%s: damage at byte %d changed what the verifier reads but it verified clean:\n  was: %q\n  now: %q", name, pos, raw[lo:hi], m[lo:min(len(m), hi)])
		}
		t.Logf("%s: %d damaged copies rejected, %d unchanged in meaning", name, caught, harmless)
	}
}

// sameReading: two parsed bundles hold the same trusted content. key_id is a
// label (the signature is checked against the key the caller supplies), and so
// are the header's key and version labels.
func sameReading(a, b *Bundle) bool {
	ha, hb := *a.Header, *b.Header
	ha.KeyID, hb.KeyID = "", ""
	ha.PublicKey, hb.PublicKey = "", ""
	ha.Version, hb.Version = "", ""
	if !reflect.DeepEqual(ha, hb) || len(a.Items) != len(b.Items) {
		return false
	}
	for i := range a.Items {
		ra, rb := *a.Items[i].Receipt, *b.Items[i].Receipt
		ra.KeyID, rb.KeyID = "", ""
		if !reflect.DeepEqual(ra, rb) || a.Items[i].Body != b.Items[i].Body || !reflect.DeepEqual(a.Items[i].Spans, b.Items[i].Spans) {
			return false
		}
	}
	return reflect.DeepEqual(a.Orphans, b.Orphans) && a.RunRecords == b.RunRecords && a.KillRecords == b.KillRecords
}
