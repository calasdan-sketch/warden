package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"time"

	"warden/internal/model"
	"warden/internal/receipt"
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
	runID := fs.String("run", "", "verify one run's receipt (default: all)")
	if !parseArgs(fs, args) {
		return 2
	}

	pub, err := os.ReadFile(a.dataDir + "/receipt.pub")
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify: no public key:", err)
		return 1
	}
	var recs []struct {
		rec  *model.Receipt
		body string
	}
	if *runID != "" {
		rec, body, err := a.st.GetReceipt(*runID)
		if err != nil {
			fmt.Fprintln(os.Stderr, "verify:", err)
			return 1
		}
		recs = append(recs, struct {
			rec  *model.Receipt
			body string
		}{rec, body})
	} else {
		all, err := a.st.AllReceipts()
		if err != nil {
			fmt.Fprintln(os.Stderr, "verify:", err)
			return 1
		}
		for _, sr := range all {
			recs = append(recs, struct {
				rec  *model.Receipt
				body string
			}{sr.Receipt, sr.Body})
		}
	}
	if len(recs) == 0 {
		fmt.Println("no sealed receipts")
		return 0
	}
	bad := 0
	var chain []*model.Receipt
	for _, r := range recs {
		if err := receipt.Verify(r.rec, r.body, ed25519.PublicKey(pub)); err != nil {
			fmt.Printf("FAIL %s: %v\n", r.rec.RunID, err)
			bad++
			continue
		}
		chain = append(chain, r.rec)
	}
	if err := receipt.VerifyChain(chain); err != nil {
		fmt.Println("CHAIN", err)
		bad++
	}
	fmt.Printf("verified %d/%d receipts", len(recs)-bad, len(recs))
	if bad == 0 {
		fmt.Println(", chain intact")
	} else {
		fmt.Println()
	}
	if bad > 0 {
		return 1
	}
	return 0
}
