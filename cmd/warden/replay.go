package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/calasdan-sketch/warden/internal/audit"
	"github.com/calasdan-sketch/warden/internal/model"
	"github.com/calasdan-sketch/warden/internal/policy"
	"github.com/calasdan-sketch/warden/internal/receipt"
	"github.com/calasdan-sketch/warden/internal/replay"
	"github.com/calasdan-sketch/warden/internal/store"
)

// cmdRuns lists recent runs so an operator can find the id to replay.
func (a *app) cmdRuns(args []string) int {
	fs := newFlagSet("runs")
	limit := fs.Int("limit", 20, "how many runs (newest first)")
	agent := fs.String("agent", "", "only this agent")
	status := fs.String("status", "", "only this status (completed, killed_operator, ...)")
	if !parseArgs(fs, args) {
		return 2
	}
	runs, err := a.st.ListRuns(store.RunFilter{Limit: *limit, AgentID: *agent, Status: model.RunStatus(*status)})
	if err != nil {
		fmt.Fprintln(os.Stderr, "runs:", err)
		return 1
	}
	if len(runs) == 0 {
		fmt.Println("no runs")
		return 0
	}
	for _, r := range runs {
		fmt.Printf("%s  %-17s %-10s calls=%-4d $%-8.4f %s\n", replay.Clean(r.RunID, 40), r.Status, replay.Clean(r.AgentID, 12),
			r.ToolCalls, r.CostUSD, r.StartedAt.UTC().Format("2006-01-02 15:04:05Z"))
	}
	return 0
}

// resolveRun accepts a full run id or a unique prefix; "last" is the newest.
func (a *app) resolveRun(id string) (*model.Run, error) {
	if id == "last" {
		rs, err := a.st.ListRuns(store.RunFilter{Limit: 1})
		if err != nil || len(rs) == 0 {
			return nil, fmt.Errorf("no runs recorded")
		}
		return rs[0], nil
	}
	if r, err := a.st.GetRun(id); err == nil && r != nil {
		return r, nil
	}
	rs, err := a.st.ListRuns(store.RunFilter{Limit: 5000})
	if err != nil {
		return nil, err
	}
	var hit []*model.Run
	for _, r := range rs {
		if strings.HasPrefix(r.RunID, id) {
			hit = append(hit, r)
		}
	}
	switch len(hit) {
	case 0:
		return nil, fmt.Errorf("no run %q (try: warden runs)", id)
	case 1:
		return hit[0], nil
	}
	return nil, fmt.Errorf("%q matches %d runs; give more characters", id, len(hit))
}

// integrityFor judges one run's trail against its receipt.
func integrityFor(rec *model.Receipt, body string, spans []*model.Span, pub ed25519.PublicKey, full bool) replay.Integrity {
	if rec == nil {
		return replay.Integrity{Status: "unsealed", Detail: "no signed receipt for this run: nothing here is tamper-evident"}
	}
	rep := audit.Verify([]audit.Item{{Receipt: rec, Body: body, Spans: spans, FullHeader: full}}, pub)
	in := replay.Integrity{Late: rep.LateSpans}
	for _, p := range rep.Problems {
		if !strings.HasPrefix(p, "chain:") {
			in.Problem = append(in.Problem, p)
		}
	}
	switch {
	case len(in.Problem) > 0:
		in.Status = "tampered"
		in.Detail = "FAILED: " + strings.Join(in.Problem, "; ")
	case rep.TraceSigned == 0:
		in.Status = "legacy"
		in.Detail = "receipt signature valid, but it predates trace digests: totals are signed, individual spans are not"
	default:
		in.Status = "verified"
		if tc, ok, _ := receipt.TraceCommitment(body); ok {
			in.Covered = tc.SpanCount
		}
		in.Detail = fmt.Sprintf("receipt signature and signed trace digest match (%d spans covered)", in.Covered)
		if rep.LateSpans > 0 {
			in.Detail += fmt.Sprintf("; %d span(s) arrived after the seal and are NOT covered", rep.LateSpans)
		}
	}
	return in
}

// cmdReplay steps through a recorded run.
//
//	warden replay <run|prefix|last> [--step N] [--only-gated] [--what-if policy.yaml] [--json] [--html FILE]
//	warden replay --bundle audit.jsonl --pubkey receipt.pub <run>   (no data dir)
func (a *app) cmdReplay(args []string) int {
	return cmdReplayWith(a, args)
}

func cmdReplayWith(a *app, args []string) int {
	fs := newFlagSet("replay")
	step := fs.Int("step", 0, "show full state at this step with context")
	only := fs.Bool("only-gated", false, "list only denied / asked / error steps (and changed ones with --what-if)")
	whatIf := fs.String("what-if", "", "re-judge every gated call under this candidate policy file")
	asJSON := fs.Bool("json", false, "machine-readable output")
	htmlOut := fs.String("html", "", "write a self-contained HTML replay (no network) to this file")
	bundle := fs.String("bundle", "", "replay from an exported JSONL bundle instead of the data dir")
	pubPath := fs.String("pubkey", "", "Ed25519 public key (required with --bundle; default <data dir>/receipt.pub)")
	// Allow the run id before or after flags.
	var rest []string
	var flags []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			flags = append(flags, args[i])
			if !strings.Contains(args[i], "=") && needsValue(args[i]) && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		} else {
			rest = append(rest, args[i])
		}
	}
	if !parseArgs(fs, flags) {
		return 2
	}
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "replay: give one run id (or a unique prefix, or \"last\"); see: warden runs")
		return 2
	}
	var sess *replay.Session
	if *bundle != "" {
		if *pubPath == "" {
			fmt.Fprintln(os.Stderr, "replay: --bundle requires --pubkey (obtained out of band)")
			return 2
		}
		pub, err := audit.LoadPublicKey(*pubPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "replay: public key:", err)
			return 1
		}
		f, err := os.Open(*bundle)
		if err != nil {
			fmt.Fprintln(os.Stderr, "replay:", err)
			return 1
		}
		defer f.Close()
		b, err := audit.ReadBundle(f)
		if err != nil {
			fmt.Fprintln(os.Stderr, "replay: bundle:", err)
			return 1
		}
		var item *audit.Item
		for i := range b.Items {
			if strings.HasPrefix(b.Items[i].Receipt.RunID, rest[0]) {
				if item != nil {
					fmt.Fprintf(os.Stderr, "replay: %q matches more than one run\n", rest[0])
					return 1
				}
				item = &b.Items[i]
			}
		}
		if item == nil {
			fmt.Fprintf(os.Stderr, "replay: no run %q in the bundle\n", rest[0])
			return 1
		}
		rc := item.Receipt
		run := &model.Run{RunID: rc.RunID, AgentID: rc.AgentID, FleetID: rc.FleetID, Status: rc.Status, StartedAt: rc.StartedAt,
			TokensIn: rc.TokensIn, TokensOut: rc.TokensOut, CostUSD: rc.CostUSD, ToolCalls: rc.ToolCalls, KillReason: rc.KillReason, KilledBy: rc.KilledBy}
		end := rc.SealedAt
		run.EndedAt = &end
		sess = replay.Build(run, item.Spans, integrityFor(rc, item.Body, item.Spans, pub, true))
	} else {
		run, err := a.resolveRun(rest[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, "replay:", err)
			return 1
		}
		spans, err := a.st.SpansForRun(run.RunID)
		if err != nil {
			fmt.Fprintln(os.Stderr, "replay:", err)
			return 1
		}
		if *pubPath == "" {
			*pubPath = filepath.Join(a.dataDir, "receipt.pub")
		}
		pub, perr := audit.LoadPublicKey(*pubPath)
		rec, body, rerr := a.st.GetReceipt(run.RunID)
		var in replay.Integrity
		switch {
		case perr != nil:
			in = replay.Integrity{Status: "tampered", Detail: "cannot load the public key, so nothing can be verified: " + perr.Error()}
		case rerr != nil:
			in = integrityFor(nil, "", spans, pub, false)
		default:
			in = integrityFor(rec, body, spans, pub, false)
		}
		sess = replay.Build(run, spans, in)
	}
	if *whatIf != "" {
		cand, err := policy.Load(*whatIf)
		if err != nil {
			fmt.Fprintln(os.Stderr, "replay: --what-if policy:", err)
			return 1
		}
		sess.ApplyWhatIf(policy.NewEvaluator(cand, nil), filepath.Base(*whatIf))
	}
	switch {
	case *htmlOut != "":
		var buf bytes.Buffer
		if err := sess.HTML(&buf); err != nil {
			fmt.Fprintln(os.Stderr, "replay:", err)
			return 1
		}
		if err := os.WriteFile(*htmlOut, buf.Bytes(), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "replay:", err)
			return 1
		}
		fmt.Printf("wrote %s (%d steps, integrity %s); open it in a browser, no network needed\n", *htmlOut, len(sess.Steps), sess.Integrity.Status)
	case *asJSON:
		if err := sess.JSON(os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "replay:", err)
			return 1
		}
	case *step > 0:
		if err := sess.Step(os.Stdout, *step); err != nil {
			fmt.Fprintln(os.Stderr, "replay:", err)
			return 1
		}
	default:
		sess.Text(os.Stdout, *only)
	}
	if sess.Integrity.Status == "tampered" {
		return 3
	}
	return 0
}

func needsValue(f string) bool {
	f = strings.TrimLeft(f, "-")
	switch f {
	case "step", "what-if", "html", "bundle", "pubkey":
		return true
	}
	return false
}

func storeFilter(limit int) store.RunFilter { return store.RunFilter{Limit: limit} }
