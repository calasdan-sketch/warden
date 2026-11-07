package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/calasdan-sketch/warden/internal/model"
	"github.com/calasdan-sketch/warden/internal/replay"
	"github.com/calasdan-sketch/warden/internal/store"
)

var quotedRe = regexp.MustCompile(`"[^"]*"`)

// normalizeReason drops the quoted command or path from a policy reason so
// the same rule firing on different commands counts as one line.
func normalizeReason(r string) string {
	return replay.Clean(quotedRe.ReplaceAllString(r, `"…"`), 110)
}

type countRow struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// Summary is what `warden summary` reports.
type Summary struct {
	Since          time.Time      `json:"since"`
	Runs           int            `json:"runs"`
	RunsByStatus   map[string]int `json:"runs_by_status"`
	Agents         []countRow     `json:"agents"`
	ToolCalls      int            `json:"tool_calls"`
	Allowed        int            `json:"allowed"`
	Denied         int            `json:"denied"`
	Asked          int            `json:"asked"`
	TopStopped     []countRow     `json:"top_stopped_reasons"`
	Hosts          []countRow     `json:"hosts_contacted"`
	CredentialHits int            `json:"credential_adjacent_stops"`
	FilesTouched   int            `json:"distinct_files"`
	CostUSD        float64        `json:"cost_usd"`
	Kills          []string       `json:"kills"`
	Truncated      bool           `json:"truncated,omitempty"`
}

func topN(m map[string]int, n int) []countRow {
	var rows []countRow
	for k, v := range m {
		rows = append(rows, countRow{k, v})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].Name < rows[j].Name
	})
	if len(rows) > n {
		rows = rows[:n]
	}
	return rows
}

// cmdSummary prints a plain digest of a time window: who ran, what was
// stopped and why, where it reached, what it cost. It reads the record; it
// does not verify it (use `warden verify` or `warden doctor` for that).
func (a *app) cmdSummary(args []string) int {
	fs := newFlagSet("summary")
	since := fs.String("since", "24h", "window, e.g. 24h, 7d, 4w")
	asJSON := fs.Bool("json", false, "machine-readable output")
	if !parseArgs(fs, args) {
		return 2
	}
	d, err := parseSince(*since)
	if err != nil {
		fmt.Fprintln(os.Stderr, "summary:", err)
		return 2
	}
	from := time.Now().UTC().Add(-d)
	runs, err := a.st.ListRuns(store.RunFilter{Limit: 100000, Since: from})
	if err != nil {
		fmt.Fprintln(os.Stderr, "summary:", err)
		return 1
	}
	const spanCap = 500000
	spans, err := a.st.SpansSince(from, false, spanCap)
	if err != nil {
		fmt.Fprintln(os.Stderr, "summary:", err)
		return 1
	}
	sm := Summary{Since: from, Runs: len(runs), RunsByStatus: map[string]int{}, Truncated: len(spans) >= spanCap}
	agents := map[string]int{}
	for _, r := range runs {
		sm.RunsByStatus[string(r.Status)]++
		agents[replay.Clean(r.AgentID, 40)]++
	}
	reasons, hosts := map[string]int{}, map[string]int{}
	files := map[string]bool{}
	for _, sp := range spans {
		sm.CostUSD += sp.CostUSD
		switch sp.Kind {
		case model.SpanToolCall:
			sm.ToolCalls++
			switch sp.PolicyDecision {
			case "deny":
				sm.Denied++
			case "require_approval":
				sm.Asked++
			default:
				sm.Allowed++
			}
		case model.SpanFileOp:
			if sp.Path != "" {
				files[sp.Path] = true
			}
			if sp.PolicyDecision == "deny" {
				sm.Denied++
			} else if sp.PolicyDecision == "require_approval" {
				sm.Asked++
			}
		case model.SpanNetEgress:
			if sp.Host != "" {
				hosts[replay.Clean(sp.Host, 80)]++
			}
		}
		if sp.PolicyDecision == "deny" || sp.PolicyDecision == "require_approval" {
			reasons[normalizeReason(sp.PolicyReason)]++
			if containsFold(sp.PolicyReason, "credential-adjacent") {
				sm.CredentialHits++
			}
		}
	}
	sm.FilesTouched = len(files)
	sm.Agents = topN(agents, 8)
	sm.TopStopped = topN(reasons, 6)
	sm.Hosts = topN(hosts, 8)
	if ks, err := a.st.ListKills(200); err == nil {
		for _, k := range ks {
			if k.At.After(from) {
				sm.Kills = append(sm.Kills, fmt.Sprintf("%s %s %s by %s: %s", k.At.UTC().Format("2006-01-02 15:04Z"), k.Scope, replay.Clean(k.Target, 40), replay.Clean(k.Actor, 30), replay.Clean(k.Reason, 100)))
			}
		}
	}
	if *asJSON {
		e := json.NewEncoder(os.Stdout)
		e.SetIndent("", "  ")
		_ = e.Encode(sm)
		return 0
	}
	fmt.Printf("warden summary: since %s (%s)\n\n", from.Format("2006-01-02 15:04Z"), *since)
	fmt.Printf("runs: %d", sm.Runs)
	for _, s := range topN(toCounts(sm.RunsByStatus), 10) {
		fmt.Printf("   %s %d", s.Name, s.Count)
	}
	fmt.Println()
	for _, r := range sm.Agents {
		fmt.Printf("  agent %-20s %d run(s)\n", r.Name, r.Count)
	}
	fmt.Printf("\ntool calls: %d (%d allowed)   stopped, all kinds of call: %d sent to a human, %d denied\n", sm.ToolCalls, sm.Allowed, sm.Asked, sm.Denied)
	if sm.CredentialHits > 0 {
		fmt.Printf("credential-adjacent stops: %d  <- look at these first (warden replay <run> --only-gated)\n", sm.CredentialHits)
	}
	if len(sm.TopStopped) > 0 {
		fmt.Println("\nmost common reasons a call was stopped:")
		for _, r := range sm.TopStopped {
			fmt.Printf("  %4d  %s\n", r.Count, r.Name)
		}
	}
	if len(sm.Hosts) > 0 {
		fmt.Println("\nhosts contacted (as reported by hooks and spans):")
		for _, r := range sm.Hosts {
			fmt.Printf("  %4d  %s\n", r.Count, r.Name)
		}
	}
	fmt.Printf("\nfiles touched (distinct, as reported): %d   cost recorded: $%.4f\n", sm.FilesTouched, sm.CostUSD)
	if len(sm.Kills) > 0 {
		fmt.Println("\nkill switch used:")
		for _, k := range sm.Kills {
			fmt.Println(" ", k)
		}
	}
	if sm.Truncated {
		fmt.Printf("\nnote: only the newest %d spans were read; narrow --since for exact numbers\n", spanCap)
	}
	fmt.Println("\nthis is a digest of the record, not a check of it: run `warden verify` to prove nothing was edited")
	return 0
}

func toCounts(m map[string]int) map[string]int { return m }

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}
