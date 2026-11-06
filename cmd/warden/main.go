// Command warden is the agent flight recorder: a harness-agnostic runtime
// supervisor for AI agents ("what did this agent do, with which credential,
// and why").
//
//	warden wrap -- <command>      run a command as a supervised run
//	warden dashboard              serve the Fleet Command view
//	warden kill --scope ...       kill switch (run|agent|fleet|tool)
//	warden report --from ...      ingest --report-to JSONL from sibling tools
//	warden verify                 verify receipt signatures + hash chain
//	warden span | gate            framework hook emission / pre-exec policy check
//	warden approve | approvals    human approval gates
//	warden export | scan          SIEM export / run anomaly evaluation now
//	warden hook claude-code|codex harness hook (PreToolUse gate + kill switch)
//	warden demo                   self-contained 60-second tour
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/calasdan-sketch/warden/internal/anomaly"
	"github.com/calasdan-sketch/warden/internal/collect"
	"github.com/calasdan-sketch/warden/internal/join"
	"github.com/calasdan-sketch/warden/internal/kill"
	"github.com/calasdan-sketch/warden/internal/otel"
	"github.com/calasdan-sketch/warden/internal/policy"
	"github.com/calasdan-sketch/warden/internal/receipt"
	"github.com/calasdan-sketch/warden/internal/store"
)

// version is overridden at release build time: -ldflags "-X main.version=..."
var version = "0.1.0"

// app holds the wired dependencies for CLI commands.
type app struct {
	dataDir string
	st      *store.Store
	col     *collect.Collector
	kills   *kill.Manager
	engine  *anomaly.Engine
	import_ *join.Importer
	signer  *receipt.Signer
	pol     *policy.Policy
}

func dataDir() string {
	if d := os.Getenv("WARDEN_DIR"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".warden"
	}
	return filepath.Join(home, ".warden")
}

// openApp wires everything. Commands that only read still get the full app;
// it's cheap and keeps behavior consistent.
func openApp(dir, policyPath string) (*app, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	st, err := store.Open(filepath.Join(dir, "warden.db"))
	if err != nil {
		return nil, err
	}
	var pol *policy.Policy
	if policyPath == "" {
		policyPath = filepath.Join(dir, "policy.yaml")
	}
	pol, err = policy.Load(policyPath)
	if err != nil {
		st.Close()
		return nil, err
	}
	signer, err := receipt.LoadOrCreate(dir)
	if err != nil {
		st.Close()
		return nil, err
	}
	col := collect.New(st, pol, signer, dir)
	return &app{
		dataDir: dir,
		st:      st,
		col:     col,
		kills:   kill.New(st, col, dir),
		engine:  anomaly.New(st),
		import_: join.New(st, col),
		signer:  signer,
		pol:     pol,
	}, nil
}

func (a *app) close() {
	a.col.Close()
	a.st.Close()
}

func actorName() string {
	if a := os.Getenv("WARDEN_ACTOR"); a != "" {
		return a
	}
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "cli"
}

func main() {
	// Global flags may precede the subcommand.
	var dir, policyPath string
	args := os.Args[1:]
	for len(args) >= 2 && (args[0] == "--dir" || args[0] == "--policy") {
		if args[0] == "--dir" {
			dir, args = args[1], args[2:]
		} else {
			policyPath, args = args[1], args[2:]
		}
	}
	if dir == "" {
		dir = dataDir()
	}
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	cmd, rest := args[0], args[1:]
	otel.ScopeVersion = version

	// Commands that don't need the store.
	switch cmd {
	case "version", "--version", "-v":
		fmt.Println("warden", version)
		return
	case "help", "--help", "-h":
		usage()
		return
	case "demo":
		os.Exit(cmdDemo(rest))
	case "verify":
		// Bundle verification is for auditors: it must not need (or create)
		// a warden data dir.
		if b, pk, ok := bundleFlags(rest); ok {
			os.Exit(cmdVerifyBundle(b, pk))
		}
	}

	a, err := openApp(dir, policyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warden:", err)
		os.Exit(1)
	}
	defer a.close()

	var code int
	switch cmd {
	case "init":
		code = a.cmdInit(rest)
	case "wrap":
		code = a.cmdWrap(rest)
	case "dashboard", "serve":
		code = a.cmdDashboard(rest)
	case "kill":
		code = a.cmdKill(rest)
	case "approve":
		code = a.cmdApprove(rest)
	case "approvals":
		code = a.cmdApprovals(rest)
	case "verify":
		code = a.cmdVerify(rest)
	case "report":
		code = a.cmdReport(rest)
	case "span":
		code = a.cmdSpan(rest)
	case "gate":
		code = a.cmdGate(rest)
	case "export":
		code = a.cmdExport(rest)
	case "scan":
		code = a.cmdScan(rest)
	case "hook":
		code = a.cmdHook(rest)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		usage()
		code = 2
	}
	os.Exit(code)
}

func usage() {
	fmt.Print(`warden — the agent flight recorder

Usage: warden [--dir DIR] [--policy FILE] <command> [flags]

  demo                    60-second self-contained tour (temp dir, no network, no keys)
  wrap -- <cmd...>        Run a command as a supervised run (policy-gated, receipt-sealed)
  hook claude-code|codex  Harness hook: gate each tool call, record it, honor the kill switch
                          (--print-config prints the settings snippet to paste)
  dashboard               Serve the Fleet Command view (burn bar, runs, kill, anomalies)
  kill                    Kill switch: --scope run|agent|fleet|tool --target X --reason R
  report                  Ingest --report-to JSONL: --from shortleash|planok|mcp-jail|calas-gateway
  verify                  Verify receipt signatures, the hash chain and each signed trace
                          (--bundle FILE --pubkey KEY verifies an export, no data dir needed)
  span                    Emit one span (framework hooks; uses WARDEN_RUN_ID/WARDEN_SOCK)
  gate                    Pre-execution policy check for hooks (use --await to block on approval)
  approve                 Decide a pending approval: --id N --decision approved|denied
  approvals               List pending approvals
  export                  Audit trail: --format jsonl (verifiable bundle) | otlp [--endpoint URL]
  scan                    Run anomaly evaluation over live runs now
  init                    Initialize the data dir (policy template + signing key)
  version                 Print version

Global flags: --dir DIR (default ~/.warden, or $WARDEN_DIR), --policy FILE
`)
}

// bundleFlags extracts --bundle/--pubkey for store-less verification.
func bundleFlags(args []string) (bundle, pubkey string, ok bool) {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	b := fs.String("bundle", "", "")
	p := fs.String("pubkey", "", "")
	_ = fs.String("run", "", "")
	if err := fs.Parse(args); err != nil || *b == "" {
		return "", "", false
	}
	return *b, *p, true
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

// parseArgs parses args into fs; on error it prints usage and returns false.
func parseArgs(fs *flag.FlagSet, args []string) bool {
	if err := fs.Parse(args); err != nil {
		return false
	}
	return true
}
