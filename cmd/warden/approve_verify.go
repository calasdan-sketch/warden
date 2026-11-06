package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/calasdan-sketch/warden/internal/audit"
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
	return printReport(rep)
}

// cmdVerifyBundle verifies an exported JSONL audit bundle without touching
// any warden data dir: what a third-party auditor (or the SIEM side) runs.
func cmdVerifyBundle(path, pubPath string) int {
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
	items, hdr, err := audit.ReadBundle(r)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify: bundle:", err)
		return 1
	}
	if hdr != nil && hdr.KeyID != "" && hdr.KeyID != receipt.KeyIDOf(pub) {
		fmt.Printf("note: bundle says it was sealed by key %s; you supplied key %s\n", hdr.KeyID, receipt.KeyIDOf(pub))
	}
	rep := audit.Verify(items, pub)
	if err := audit.CheckHeader(hdr, items, pub); err != nil {
		rep.Problems = append(rep.Problems, "header: "+err.Error())
	}
	return printReport(rep)
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
	if rep.LateSpans > 0 {
		fmt.Printf("note: %d span(s) arrived after their run was sealed: kept in the audit trail, not covered by a signature\n", rep.LateSpans)
	}
	if !rep.OK() {
		return 1
	}
	return 0
}
