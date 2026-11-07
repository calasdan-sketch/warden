package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/calasdan-sketch/warden/internal/model"
	"github.com/calasdan-sketch/warden/internal/policy"
	"github.com/calasdan-sketch/warden/internal/replay"
)

// parseSince accepts 90m, 24h, 7d, 2w (and any time.ParseDuration string).
func parseSince(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if n := len(s); n > 1 {
		mult := map[byte]time.Duration{'d': 24 * time.Hour, 'w': 7 * 24 * time.Hour}[s[n-1]]
		if mult > 0 {
			v, err := strconv.ParseFloat(s[:n-1], 64)
			if err != nil || v <= 0 {
				return 0, fmt.Errorf("bad duration %q", s)
			}
			return time.Duration(v * float64(mult)), nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("bad duration %q (try 24h, 7d, 2w)", s)
	}
	return d, nil
}

// cmdPolicyOffline runs the policy subcommands that need no data dir:
// check and explain. They are for people editing policy.yaml.
func cmdPolicyOffline(policyPath, dir string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: warden policy check [FILE] [--strict] | explain \"<shell command>\" | suggest [--since 7d]")
		return 2
	}
	sub, rest := args[0], args[1:]
	resolve := func(explicit string) string {
		switch {
		case explicit != "":
			return explicit
		case policyPath != "":
			return policyPath
		default:
			return filepath.Join(dir, "policy.yaml")
		}
	}
	switch sub {
	case "check":
		fs := newFlagSet("policy check")
		strict := fs.Bool("strict", false, "exit 3 when there are warnings")
		if !parseArgs(fs, rest) {
			return 2
		}
		file := resolve(fs.Arg(0))
		if _, err := os.Stat(file); err != nil {
			if os.IsNotExist(err) && fs.Arg(0) == "" {
				fmt.Printf("%s does not exist: warden uses its built-in default policy (run: warden init)\n", file)
				return 0
			}
			fmt.Fprintln(os.Stderr, "policy check:", err)
			return 1
		}
		p, err := policy.Load(file)
		if err != nil {
			fmt.Fprintln(os.Stderr, "INVALID", file+":", err)
			return 1
		}
		lints := p.Lint()
		warns := 0
		for _, l := range lints {
			if l.Level == "warn" {
				warns++
			}
			fmt.Printf("%-5s %s\n", l.Level, l.Message)
		}
		fmt.Printf("%s: valid (version %d, %d allowlisted commands, %d allowed hosts, %d warnings)\n",
			file, p.Version, len(p.Shell.Allow), len(p.Egress.AllowHosts), warns)
		if *strict && warns > 0 {
			return 3
		}
		return 0
	case "explain":
		fs := newFlagSet("policy explain")
		file := fs.String("policy", "", "policy file (default: the active one)")
		if !parseArgs(fs, rest) {
			return 2
		}
		if fs.NArg() == 0 {
			fmt.Fprintln(os.Stderr, "usage: warden policy explain \"<shell command>\"")
			return 2
		}
		path := resolve(*file)
		p, err := policy.Load(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "policy explain:", err)
			return 1
		}
		p.Protect(dir, path)
		cmd := strings.Join(fs.Args(), " ")
		ex := policy.NewEvaluator(p, nil).ExplainShell(cmd)
		fmt.Printf("decision: %s\n", strings.ToUpper(ex.Result.Decision.String()))
		if ex.Result.Reason != "" {
			fmt.Printf("because:  %s\n", replay.Clean(ex.Result.Reason, 400))
		}
		for _, s := range ex.Segments {
			if s.Binary == "" {
				continue
			}
			state := "ok"
			if s.Problem != "" {
				state = s.Problem
			}
			fmt.Printf("  %-14s %-22s %s\n", replay.Clean(s.Binary, 14), s.Risk, replay.Clean(state, 160))
		}
		if ex.Hint != "" {
			fmt.Println("hint:    ", ex.Hint)
		}
		switch ex.Result.Decision {
		case policy.Allow:
			return 0
		case policy.Deny:
			return 3
		}
		return 4
	}
	fmt.Fprintf(os.Stderr, "policy: unknown subcommand %q (check, explain, suggest)\n", sub)
	return 2
}

// cmdPolicySuggest reads what the policy stopped in the recorded history and
// proposes allowlist additions, sorted by how safe they are to grant.
func (a *app) cmdPolicySuggest(args []string) int {
	fs := newFlagSet("policy suggest")
	since := fs.String("since", "7d", "look back this far (e.g. 24h, 7d, 4w)")
	minN := fs.Int("min", 2, "only suggest programs that were stopped at least this many times")
	if !parseArgs(fs, args) {
		return 2
	}
	d, err := parseSince(*since)
	if err != nil {
		fmt.Fprintln(os.Stderr, "policy suggest:", err)
		return 2
	}
	spans, err := a.st.SpansSince(time.Now().Add(-d), true, 200000)
	if err != nil {
		fmt.Fprintln(os.Stderr, "policy suggest:", err)
		return 1
	}
	ev := policy.NewEvaluator(a.pol, nil)
	type stat struct {
		n        int
		example  string
		onlyThis int // stopped with this program as the only unlisted one
	}
	bins := map[string]*stat{}
	hosts := map[string]int{}
	creds, other := 0, 0
	for _, sp := range spans {
		switch sp.Kind {
		case model.SpanToolCall:
			cmd := sp.ArgsSummary
			if cmd == "" {
				cmd = sp.Name
			}
			if !strings.Contains(strings.ToLower(sp.PolicyReason), "not allowlisted") {
				if strings.Contains(sp.PolicyReason, "credential-adjacent") {
					creds++
				} else {
					other++
				}
				continue
			}
			ex := ev.ExplainShell(cmd)
			var unl []string
			for _, s := range ex.Segments {
				if s.Binary != "" && !s.Allowed && s.Problem == "not on shell.allow" {
					unl = append(unl, s.Binary)
				}
			}
			seen := map[string]bool{}
			for _, b := range unl {
				if seen[b] {
					continue
				}
				seen[b] = true
				st := bins[b]
				if st == nil {
					st = &stat{example: replay.Clean(cmd, 90)}
					bins[b] = st
				}
				st.n++
				if len(unl) == 1 {
					st.onlyThis++
				}
			}
		case model.SpanNetEgress:
			if sp.Host != "" {
				hosts[replay.Clean(sp.Host, 80)]++
			}
		}
	}
	if len(bins) == 0 && len(hosts) == 0 {
		fmt.Printf("nothing to suggest: in the last %s the policy stopped no commands for being unlisted (%d stopped for credentials, %d for other reasons)\n", *since, creds, other)
		return 0
	}
	type row struct {
		bin  string
		st   *stat
		risk policy.BinaryRisk
	}
	var rows []row
	for b, st := range bins {
		if st.n >= *minN {
			rows = append(rows, row{b, st, policy.ClassifyBinary(b)})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].risk != rows[j].risk {
			return rows[i].risk < rows[j].risk
		}
		if rows[i].st.n != rows[j].st.n {
			return rows[i].st.n > rows[j].st.n
		}
		return rows[i].bin < rows[j].bin
	})
	fmt.Printf("what the policy stopped in the last %s, by program (a suggestion is never applied for you)\n\n", *since)
	var safe []string
	for _, r := range rows {
		verdict := ""
		switch r.risk {
		case policy.RiskReadOnly:
			verdict = "fine to allow"
			safe = append(safe, r.bin)
		case policy.RiskWrites:
			verdict = "changes or deletes files: allow it only if you want that without asking"
		case policy.RiskNetwork:
			verdict = "NOT recommended: reaches the network outside egress.allow_hosts"
		case policy.RiskCode:
			verdict = "NOT recommended: runs arbitrary code, so it allows everything it can launch"
		default:
			verdict = "unknown program: check it cannot run other programs or reach the network"
		}
		fmt.Printf("  %-12s stopped %-4d times  %-22s %s\n               e.g. %s\n", replay.Clean(r.bin, 12), r.st.n, r.risk, verdict, r.st.example)
	}
	if len(hosts) > 0 {
		fmt.Println("\nhosts contacted and refused:")
		var hs []string
		for h := range hosts {
			hs = append(hs, h)
		}
		sort.Slice(hs, func(i, j int) bool { return hosts[hs[i]] > hosts[hs[j]] })
		for i, h := range hs {
			if i == 10 {
				break
			}
			fmt.Printf("  %-40s %d times\n", h, hosts[h])
		}
		fmt.Println("  add a host to egress.allow_hosts only if you recognise it")
	}
	if len(safe) > 0 {
		sort.Strings(safe)
		fmt.Printf("\nto allow the read-only ones, add to shell.allow in policy.yaml:\n  %s\n", strings.Join(safe, ", "))
	}
	if creds+other > 0 {
		fmt.Printf("\n(also stopped: %d for credential-adjacent paths and %d for other rules; those are not allowlist problems)\n", creds, other)
	}
	return 0
}
