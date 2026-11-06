package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/calasdan-sketch/warden/internal/audit"
	"github.com/calasdan-sketch/warden/internal/otel"
	"github.com/calasdan-sketch/warden/internal/store"
)

// headerFlags collects repeated --header "Key: Value" flags.
type headerFlags map[string]string

func (h headerFlags) String() string { return "" }
func (h headerFlags) Set(v string) error {
	k, val, ok := strings.Cut(v, ":")
	if !ok {
		k, val, ok = strings.Cut(v, "=")
	}
	k, val = strings.TrimSpace(k), strings.TrimSpace(val)
	if !ok || k == "" {
		return fmt.Errorf("want \"Key: Value\", got %q", v)
	}
	h[k] = val
	return nil
}

func (a *app) cmdExport(args []string) int {
	fs := newFlagSet("export")
	out := fs.String("out", "", "write to file (default: stdout)")
	format := fs.String("format", "jsonl", "jsonl (verifiable audit bundle) or otlp (OTLP/HTTP JSON, GenAI semconv)")
	endpoint := fs.String("endpoint", "", "otlp: POST to this OTLP/HTTP traces endpoint instead of writing (e.g. http://localhost:4318/v1/traces)")
	headers := headerFlags{}
	fs.Var(headers, "header", "otlp --endpoint: extra request header \"Key: Value\" (repeatable)")
	if !parseArgs(fs, args) {
		return 2
	}
	if *endpoint != "" {
		if *format != "otlp" {
			fmt.Fprintln(os.Stderr, "export: --endpoint requires --format otlp")
			return 2
		}
		return a.pushOTLP(*endpoint, headers)
	}
	w := os.Stdout
	if *out != "" {
		f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
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
		if err := otel.EncodeRunsStream(w, func() ([]otel.RunTrace, error) {
			page, err := a.runTraces(pageSize, offset)
			offset += pageSize
			return page, err
		}); err != nil {
			fmt.Fprintln(os.Stderr, "export:", err)
			return 1
		}
		return 0
	}
	if *format != "jsonl" {
		fmt.Fprintf(os.Stderr, "export: unknown --format %q (jsonl|otlp)\n", *format)
		return 2
	}
	enc := json.NewEncoder(w)
	// Receipt bodies are embedded as raw JSON and must stay byte-identical
	// to what was signed: HTML-escaping would rewrite them.
	enc.SetEscapeHTML(false)
	head, err := a.st.LatestReceiptHash()
	if err != nil {
		fmt.Fprintln(os.Stderr, "export:", err)
		return 1
	}
	count, err := a.st.CountReceipts()
	if err != nil {
		fmt.Fprintln(os.Stderr, "export:", err)
		return 1
	}
	hdr := audit.BundleHeader{
		Type: "header", Format: audit.BundleFormat, Version: version,
		KeyID: a.signer.KeyID(), PublicKey: base64.StdEncoding.EncodeToString(a.signer.PublicKey()),
		ExportedAt: time.Now().UTC().Format(time.RFC3339Nano), HeadHash: head, ReceiptCount: count,
	}
	hdr.Signature = a.signer.SignStatement(audit.HeaderDomain, audit.HeaderStatement(&hdr))
	_ = enc.Encode(hdr)
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

// runTraces returns one page of runs with their spans; nil at the end.
func (a *app) runTraces(limit, offset int) ([]otel.RunTrace, error) {
	runs, err := a.st.ListRunsPage(limit, offset)
	if err != nil || len(runs) == 0 {
		return nil, err
	}
	out := make([]otel.RunTrace, 0, len(runs))
	for _, rn := range runs {
		spans, err := a.st.SpansForRun(rn.RunID)
		if err != nil {
			return nil, err
		}
		out = append(out, otel.RunTrace{Run: rn, Spans: spans})
	}
	return out, nil
}

// pushOTLP sends every run to an OTLP/HTTP collector, a few runs per request.
func (a *app) pushOTLP(endpoint string, headers map[string]string) int {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		fmt.Fprintf(os.Stderr, "export: --endpoint must be an http(s) URL, got %q\n", endpoint)
		return 2
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		fmt.Fprintln(os.Stderr, "export: warning: sending audit data over plain http to a non-local host")
	}
	p := &otel.Pusher{Endpoint: endpoint, Headers: headers}
	const batch = 50
	sent := 0
	for offset := 0; ; offset += batch {
		page, err := a.runTraces(batch, offset)
		if err != nil {
			fmt.Fprintln(os.Stderr, "export:", err)
			return 1
		}
		if page == nil {
			break
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		err = p.Push(ctx, page)
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "export: after %d runs: %v\n", sent, err)
			return 1
		}
		sent += len(page)
	}
	fmt.Printf("pushed %d runs to %s\n", sent, endpoint)
	return 0
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
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
