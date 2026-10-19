package main

import (
	"encoding/json"
	"fmt"
	"os"

	"warden/internal/model"
	"warden/internal/otel"
	"warden/internal/store"
)

func (a *app) cmdExport(args []string) int {
	fs := newFlagSet("export")
	out := fs.String("out", "", "write to file (default: stdout)")
	format := fs.String("format", "jsonl", "jsonl (audit envelope) or otlp")
	if !parseArgs(fs, args) {
		return 2
	}
	w := os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			fmt.Fprintln(os.Stderr, "export:", err)
			return 1
		}
		defer f.Close()
		w = f
	}
	// Stream in pages: a fleet with 100k runs must not be materialized in RAM.
	const pageSize = 1000
	if *format == "otlp" {
		offset := 0
		if err := otel.EncodeStream(w, func() ([]*model.Span, error) {
			runs, err := a.st.ListRunsPage(pageSize, offset)
			if err != nil {
				return nil, err
			}
			if len(runs) == 0 {
				return nil, nil
			}
			offset += pageSize
			var spans []*model.Span
			for _, rn := range runs {
				rs, err := a.st.SpansForRun(rn.RunID)
				if err != nil {
					return nil, err
				}
				spans = append(spans, rs...)
			}
			return spans, nil
		}); err != nil {
			fmt.Fprintln(os.Stderr, "export:", err)
			return 1
		}
		return 0
	}
	enc := json.NewEncoder(w)
	for offset := 0; ; offset += pageSize {
		runs, err := a.st.ListRunsPage(pageSize, offset)
		if err != nil {
			fmt.Fprintln(os.Stderr, "export:", err)
			return 1
		}
		if len(runs) == 0 {
			break
		}
		for _, run := range runs {
			_ = enc.Encode(map[string]any{"type": "run", "run": run})
			spans, _ := a.st.SpansForRun(run.RunID)
			for _, sp := range spans {
				_ = enc.Encode(map[string]any{"type": "span", "span": sp})
			}
			if rec, body, err := a.st.GetReceipt(run.RunID); err == nil {
				_ = enc.Encode(map[string]any{"type": "receipt", "receipt": rec, "body": json.RawMessage(body)})
			}
		}
		if len(runs) < pageSize {
			break
		}
	}
	kills, _ := a.st.ListKills(100000)
	for _, k := range kills {
		_ = enc.Encode(map[string]any{"type": "kill_audit", "kill": k})
	}
	return 0
}

func (a *app) cmdScan(args []string) int {
	_ = newFlagSet("scan")
	runs, err := a.st.ListRuns(store.RunFilter{LiveOnly: true, Limit: 500})
	if err != nil {
		fmt.Fprintln(os.Stderr, "scan:", err)
		return 1
	}
	fleets := map[string]bool{}
	total := 0
	for _, r := range runs {
		fleets[r.FleetID] = true
		fired, err := a.engine.EvaluateRun(r.RunID)
		if err != nil {
			fmt.Fprintln(os.Stderr, "scan:", err)
			return 1
		}
		for _, al := range fired {
			fmt.Printf("[%s] %s: %s\n", al.Severity, al.Rule, al.Message)
			total++
		}
	}
	for f := range fleets {
		fired, err := a.engine.EvaluateFleet(f)
		if err != nil {
			fmt.Fprintln(os.Stderr, "scan:", err)
			return 1
		}
		for _, al := range fired {
			fmt.Printf("[%s] %s: %s\n", al.Severity, al.Rule, al.Message)
			total++
		}
	}
	fmt.Printf("scan: %d live runs, %d new alerts\n", len(runs), total)
	return 0
}
