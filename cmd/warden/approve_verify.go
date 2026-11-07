package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/calasdan-sketch/warden/internal/audit"
	"github.com/calasdan-sketch/warden/internal/model"
	"github.com/calasdan-sketch/warden/internal/receipt"
)

func (a *app) cmdApprove(args []string) int {
	fs := newFlagSet("approve")
	id := fs.Int64("id", 0, "approval id (see: warden approvals)")
	decision := fs.String("decision", "", "approved|denied")
	reason := fs.String("reason", "", "reason for the decision")
	approver := fs.String("approver", actorName(), "who decided")
	if !parseArgs(fs, args) {
		return 2
	}
	if *id == 0 || (*decision != "approved" && *decision != "denied") {
		fmt.Fprintln(os.Stderr, "approve: --id and --decision approved|denied are required")
		return 2
	}
	if err := a.st.DecideApproval(*id, *decision, *approver, *reason, time.Now().UTC()); err != nil {
		fmt.Fprintln(os.Stderr, "approve:", err)
		return 1
	}
	fmt.Printf("approval %d: %s by %s\n", *id, *decision, *approver)
	return 0
}

func (a *app) cmdApprovals(args []string) int {
	_ = newFlagSet("approvals")
	pending, err := a.st.PendingApprovals()
	if err != nil {
		fmt.Fprintln(os.Stderr, "approvals:", err)
		return 1
	}
	if len(pending) == 0 {
		fmt.Println("no pending approvals")
		return 0
	}
	for _, p := range pending {
		fmt.Printf("#%-4d run=%s gate=%s requested=%s\n",
			p.ID, p.RunID, p.Gate, p.RequestedAt.Format(time.RFC3339))
	}
	return 0
}

func (a *app) cmdVerify(args []string) int {
	fs := newFlagSet("verify")
	runID := fs.String("run", "", "verify one run's receipt and trace (default: all, plus the chain)")
	pubPath := fs.String("pubkey", "", "Ed25519 public key file (default: <data dir>/receipt.pub)")
	anchorsPath := fs.String("anchors", "", "also check this file of external anchors (see: warden anchor)")
	if !parseArgs(fs, args) {
		return 2
	}
	if *pubPath == "" {
		*pubPath = filepath.Join(a.dataDir, "receipt.pub")
	}
	pub, err := audit.LoadPublicKey(*pubPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify: public key:", err)
		return 1
	}
	var items []audit.Item
	if *runID != "" {
		rec, body, err := a.st.GetReceipt(*runID)
		if err != nil {
			fmt.Fprintln(os.Stderr, "verify:", err)
			return 1
		}
		spans, err := a.st.SpansForRun(*runID)
		if err != nil {
			fmt.Fprintln(os.Stderr, "verify:", err)
			return 1
		}
		items = append(items, audit.Item{Receipt: rec, Body: body, Spans: spans})
	} else {
		all, err := a.st.AllReceipts()
		if err != nil {
			fmt.Fprintln(os.Stderr, "verify:", err)
			return 1
		}
		for _, sr := range all {
			spans, err := a.st.SpansForRun(sr.Receipt.RunID)
			if err != nil {
				fmt.Fprintln(os.Stderr, "verify:", err)
				return 1
			}
			items = append(items, audit.Item{Receipt: sr.Receipt, Body: sr.Body, Spans: spans})
		}
	}
	rep := audit.Verify(items, pub)
	if *runID != "" {
		// A single receipt is not a chain; only judge the receipt itself.
		rep.ChainOK = true
		rep.Problems = filterChain(rep.Problems)
	}
	if *anchorsPath != "" {
		var recs []*model.Receipt
		for _, it := range items {
			recs = append(recs, it.Receipt)
		}
		if *runID != "" {
			fmt.Fprintln(os.Stderr, "verify: --anchors checks the whole chain; drop --run")
			return 2
		}
		n, err := checkAnchors(rep, *anchorsPath, recs, pub)
		if err != nil {
			fmt.Fprintln(os.Stderr, "verify:", err)
			return 1
		}
		defer fmt.Printf("anchors: %d checked against the chain\n", n)
	}
	return printReport(rep)
}

// cmdVerifyBundle verifies an exported JSONL audit bundle without touching
// any warden data dir: what a third-party auditor (or the SIEM side) runs.
//
// Records that no signature covers (late spans, spans of runs without a
// receipt, run/kill_audit summary rows) are listed one by one, and make the
// check fail unless allowUnsigned: an auditor must not read "verified" over
// content an attacker could have added.
func cmdVerifyBundle(path, pubPath string, allowUnsigned bool) int {
	return cmdVerifyBundleAnchors(path, pubPath, allowUnsigned, "")
}

// checkAnchors reads an anchors file and folds its problems into rep.
func checkAnchors(rep *audit.Report, path string, recs []*model.Receipt, pub ed25519.PublicKey) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	as, err := audit.ReadAnchors(f)
	if err != nil {
		return 0, err
	}
	if len(as) == 0 {
		return 0, fmt.Errorf("%s holds no anchors", path)
	}
	for _, p := range audit.VerifyAnchors(as, recs, pub) {
		rep.Problems = append(rep.Problems, "anchor: "+p)
	}
	return len(as), nil
}

func cmdVerifyBundleAnchors(path, pubPath string, allowUnsigned bool, anchorsPath string) int {
	if pubPath == "" {
		fmt.Fprintln(os.Stderr, "verify: --bundle requires --pubkey (the operator's receipt.pub, obtained out of band;"+
			" a key shipped inside the bundle proves nothing)")
		return 2
	}
	pub, err := audit.LoadPublicKey(pubPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify: public key:", err)
		return 1
	}
	var r io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "verify:", err)
			return 1
		}
		defer f.Close()
		r = f
	}
	b, err := audit.ReadBundle(r)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify: bundle:", err)
		return 1
	}
	if b.Header != nil && b.Header.KeyID != "" && b.Header.KeyID != receipt.KeyIDOf(pub) {
		fmt.Printf("note: bundle says it was sealed by key %s; you supplied key %s\n", b.Header.KeyID, receipt.KeyIDOf(pub))
	}
	rep := audit.VerifyBundle(b, pub)
	if anchorsPath != "" {
		var recs []*model.Receipt
		for _, it := range b.Items {
			recs = append(recs, it.Receipt)
		}
		n, err := checkAnchors(rep, anchorsPath, recs, pub)
		if err != nil {
			fmt.Fprintln(os.Stderr, "verify:", err)
			return 1
		}
		defer fmt.Printf("anchors: %d checked against the bundle's chain\n", n)
	}
	code := printReport(rep)
	if code == 0 && hasUnsignedContent(rep) && !allowUnsigned {
		fmt.Println("FAIL bundle contains content no signature covers (listed above); re-run with --allow-unsigned to accept it as unverified")
		return 1
	}
	return code
}

// hasUnsignedContent ignores the run/kill_audit summary rows every export
// carries; spans outside any signature are what matter.
func hasUnsignedContent(rep *audit.Report) bool {
	for _, u := range rep.Unsigned {
		if strings.HasPrefix(u, "span ") {
			return true
		}
	}
	return false
}

func filterChain(ps []string) []string {
	var out []string
	for _, p := range ps {
		if !strings.HasPrefix(p, "chain:") {
			out = append(out, p)
		}
	}
	return out
}

func printReport(rep *audit.Report) int {
	if rep.Receipts == 0 {
		fmt.Println("no sealed receipts")
		return 0
	}
	for _, p := range rep.Problems {
		fmt.Println("FAIL", p)
	}
	fmt.Printf("verified %d/%d receipts (signature + body", rep.Valid, rep.Receipts)
	if rep.TraceSigned > 0 {
		fmt.Printf(" + signed trace on %d", rep.TraceSigned)
	}
	fmt.Print(")")
	if rep.ChainOK {
		fmt.Print(", chain intact")
	}
	fmt.Println()
	if rep.LegacyNoTrc > 0 {
		fmt.Printf("note: %d receipt(s) predate trace digests: their totals are signed, their individual spans are not\n", rep.LegacyNoTrc)
	}
	for _, u := range rep.Unsigned {
		fmt.Println("UNSIGNED", u)
	}
	if len(rep.Unsigned) > 0 {
		fmt.Printf("note: %d UNSIGNED item(s) above are not covered by any signature; do not treat them as evidence\n", len(rep.Unsigned))
	}
	if !rep.OK() {
		return 1
	}
	return 0
}

// cmdAnchor writes one signed anchor of the current chain head. Run it on a
// schedule and ship the file somewhere the agent cannot write (a SIEM, a
// write-once bucket, another host): an anchor that left the machine can no
// longer be rewritten, even by someone who steals the signing key.
func (a *app) cmdAnchor(args []string) int {
	fs := newFlagSet("anchor")
	out := fs.String("out", "", "append the anchor line to this file (default: print it)")
	if !parseArgs(fs, args) {
		return 2
	}
	all, err := a.st.AllReceipts()
	if err != nil {
		fmt.Fprintln(os.Stderr, "anchor:", err)
		return 1
	}
	head, err := a.st.LatestReceiptHash()
	if err != nil {
		fmt.Fprintln(os.Stderr, "anchor:", err)
		return 1
	}
	an := audit.MakeAnchor(a.signer, head, len(all), time.Now())
	line, err := json.Marshal(an)
	if err != nil {
		fmt.Fprintln(os.Stderr, "anchor:", err)
		return 1
	}
	if *out == "" {
		fmt.Println(string(line))
		return 0
	}
	f, err := os.OpenFile(*out, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "anchor:", err)
		return 1
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		fmt.Fprintln(os.Stderr, "anchor:", err)
		return 1
	}
	fmt.Printf("anchored %d receipts (head %.12s) to %s\n", an.ReceiptCount, head, *out)
	return 0
}
