// Package anomaly implements warden's anomaly detection: 12 deterministic
// rules, no ML. Every rule is a named threshold with a fixed severity; every
// alert names the rule + threshold + observed value and links to the run.
//
// Alert discipline:
//   - Alert only on transitions (first-seen, threshold-crossing, recovery).
//     A continuing condition never re-alerts; recovery marks the alert
//     'recovered'.
//   - Dedupe key: (rule, scope, fingerprint) with the fingerprint stored on
//     the alert row.
//   - Baselines are per agent_id, never global.
//
// Rule severities are fixed per rule, never computed.
package anomaly

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"warden/internal/model"
	"warden/internal/redact"
	"warden/internal/store"
)

// Rule names (stable identifiers used in fingerprints and the API).
const (
	RuleSpendVelocity        = "spend_velocity"
	RuleRunCostOutlier       = "run_cost_outlier"
	RuleLoopDetection        = "loop_detection"
	RuleFirstSeenTool        = "first_seen_tool"
	RuleFirstSeenEgressHost  = "first_seen_egress_host"
	RuleEgressAfterIngest    = "egress_after_ingest"
	RuleCredentialFileAccess = "credential_adjacent_file"
	RuleSpawnStorm           = "spawn_storm"
	RuleApprovalDenialRetry  = "approval_denial_retry"
	RuleSpinningRun          = "spinning_run"
	RuleGuardTripCluster     = "guard_trip_cluster"
	RuleSavingsCollapse      = "savings_collapse"
)

// Tunables (conservative defaults: fewer alerts, higher thresholds).
const (
	loopThreshold       = 10               // rule 3: consecutive identical tool calls
	spendVelocityFactor = 3.0              // rule 1: >3x the 7-day median
	spendVelocityFloor  = 5.0              // rule 1: $/hr floor to avoid noise
	spawnStormPerMin    = 10               // rule 8: spawns per minute
	egressIngestWindow  = 5 * time.Minute  // rule 6
	approvalRetryWindow = 10 * time.Minute // rule 9
	denialsPerHour      = 3                // rule 9
	guardTripClusterN   = 3                // rule 11
	guardTripWindow     = 15 * time.Minute // rule 11
	savingsCollapsePP   = 20.0             // rule 12: percentage-point drop
	baselineDays        = 30               // first-seen baselines
	minBaselineRuns     = 5                // rules 2 and 10 need history
)

// Engine evaluates the 12 rules against the store.
type Engine struct {
	st  *store.Store
	now func() time.Time
}

// New builds an engine.
func New(st *store.Store) *Engine {
	return &Engine{st: st, now: time.Now}
}

// outcome is one rule's verdict for one evaluation.
type outcome struct {
	fp    string       // primary fingerprint; "" = rule not applicable
	owned []string     // every fingerprint this rule owns in this evaluation
	alert *model.Alert // nil = not firing
}

// fps returns all fingerprints the rule owns here.
func (o outcome) fps() []string {
	if len(o.owned) > 0 {
		return o.owned
	}
	if o.fp != "" {
		return []string{o.fp}
	}
	return nil
}

// EvaluateRun runs the run/agent-scoped rules (1-10) for one run and returns
// newly fired alerts. Transition-only: already-active conditions don't re-fire;
// cleared conditions are marked recovered.
func (e *Engine) EvaluateRun(runID string) ([]*model.Alert, error) {
	r, err := e.st.GetRun(runID)
	if err != nil {
		return nil, err
	}
	spans, err := e.st.SpansForRun(runID)
	if err != nil {
		return nil, err
	}
	active, err := e.st.ActiveAlertFingerprints()
	if err != nil {
		return nil, err
	}

	outs := []outcome{
		e.spendVelocity(r),
		e.runCostOutlier(r),
		e.loopDetection(r, spans),
		e.firstSeenTool(r, spans),
		e.firstSeenEgressHost(r, spans),
		e.egressAfterIngest(r, spans),
		e.credentialFileAccess(r, spans),
		e.spawnStorm(r, spans),
		e.approvalDenialRetry(r, spans),
		e.spinningRun(r, spans),
	}

	var fired []*model.Alert
	owned := map[string]bool{}
	for _, o := range outs {
		for _, fp := range o.fps() {
			owned[fp] = true
		}
		if o.alert != nil && o.fp != "" && !active[o.fp] {
			o.alert.Fingerprint = o.fp
			o.alert.At = e.now().UTC()
			o.alert.Status = "active"
			if err := e.st.InsertAlert(o.alert); err != nil {
				return nil, err
			}
			fired = append(fired, o.alert)
		}
	}
	// Recovery: owned fingerprints that are active but no longer firing.
	// First-seen rules (4-7) only own a fingerprint while firing, so their
	// alerts stay active until acknowledged — ack-to-clear by design.
	for fp := range active {
		if !owned[fp] || !isRunOwned(fp, runID, r.AgentID) {
			continue
		}
		stillFiring := false
		for _, o := range outs {
			if o.alert != nil && o.fp == fp {
				stillFiring = true
			}
		}
		if !stillFiring {
			_ = e.st.ResolveAlertsByFingerprint(fp)
		}
	}
	return fired, nil
}

// EvaluateFleet runs the fleet-scoped rules (11-12).
func (e *Engine) EvaluateFleet(fleetID string) ([]*model.Alert, error) {
	active, err := e.st.ActiveAlertFingerprints()
	if err != nil {
		return nil, err
	}
	outs := []outcome{
		e.guardTripCluster(fleetID),
		e.savingsCollapse(fleetID),
	}
	var fired []*model.Alert
	owned := map[string]bool{}
	for _, o := range outs {
		for _, fp := range o.fps() {
			owned[fp] = true
		}
		if o.alert != nil && o.fp != "" && !active[o.fp] {
			o.alert.Fingerprint = o.fp
			o.alert.At = e.now().UTC()
			o.alert.Status = "active"
			if err := e.st.InsertAlert(o.alert); err != nil {
				return nil, err
			}
			fired = append(fired, o.alert)
		}
	}
	for fp := range active {
		if !owned[fp] || !isFleetOwned(fp, fleetID) {
			continue
		}
		stillFiring := false
		for _, o := range outs {
			if o.alert != nil && o.fp == fp {
				stillFiring = true
			}
		}
		if !stillFiring {
			_ = e.st.ResolveAlertsByFingerprint(fp)
		}
	}
	return fired, nil
}

func isRunOwned(fp, runID, agentID string) bool {
	// fingerprint: rule:scope:id[:extra]
	parts := strings.SplitN(fp, ":", 3)
	if len(parts) < 3 {
		return false
	}
	scope, id := parts[1], parts[2]
	return (scope == "run" && (id == runID || strings.HasPrefix(id, runID+":"))) ||
		(scope == "agent" && (id == agentID || strings.HasPrefix(id, agentID+":")))
}

func isFleetOwned(fp, fleetID string) bool {
	parts := strings.SplitN(fp, ":", 3)
	if len(parts) < 3 {
		return false
	}
	scope, id := parts[1], parts[2]
	return scope == "fleet" && (id == fleetID || strings.HasPrefix(id, fleetID+":"))
}

func fpOf(rule, scope, id string) string { return rule + ":" + scope + ":" + id }

func mkAlert(rule, severity string, r *model.Run, msg, threshold, observed string) *model.Alert {
	return &model.Alert{
		Rule: rule, Severity: severity,
		AgentID: r.AgentID, FleetID: r.FleetID, RunID: r.RunID,
		Message: msg, Threshold: threshold, Observed: observed,
	}
}

// --- Rule 1: spend velocity -------------------------------------------------

func (e *Engine) spendVelocity(r *model.Run) outcome {
	fp := fpOf(RuleSpendVelocity, "agent", r.AgentID)
	now := e.now().UTC()
	hourly, err := e.st.AgentHourlyCost(r.AgentID, now.Add(-7*24*time.Hour))
	if err != nil || len(hourly) == 0 {
		return outcome{fp: fp}
	}
	// Current velocity: last 60 minutes of cost.
	var lastHour float64
	if len(hourly) > 0 {
		lastHour = hourly[len(hourly)-1]
	}
	median := medianFloat(hourly)
	if lastHour < spendVelocityFloor {
		return outcome{fp: fp} // below the noise floor
	}
	if median <= 0 || lastHour <= spendVelocityFactor*median {
		return outcome{fp: fp}
	}
	return outcome{fp: fp, alert: &model.Alert{
		Rule: RuleSpendVelocity, Severity: "warning",
		AgentID: r.AgentID, FleetID: r.FleetID, RunID: r.RunID,
		Message:   fmt.Sprintf("spend velocity: %s at $%.2f/hr vs $%.2f/hr 7-day median", r.AgentID, lastHour, median),
		Threshold: fmt.Sprintf(">%.0fx 7-day median ($%.2f/hr floor)", spendVelocityFactor, spendVelocityFloor),
		Observed:  fmt.Sprintf("$%.2f/hr", lastHour),
	}}
}

// --- Rule 2: run cost outlier ----------------------------------------------

func (e *Engine) runCostOutlier(r *model.Run) outcome {
	fp := fpOf(RuleRunCostOutlier, "run", r.RunID)
	hist, err := e.st.ListRuns(store.RunFilter{AgentID: r.AgentID, Status: model.RunCompleted, Limit: 30})
	if err != nil || len(hist) < minBaselineRuns {
		return outcome{fp: fp}
	}
	costs := make([]float64, len(hist))
	for i, h := range hist {
		costs[i] = h.CostUSD
	}
	p95 := percentile(costs, 95)
	if p95 <= 0 || r.CostUSD <= p95 {
		return outcome{fp: fp}
	}
	return outcome{fp: fp, alert: mkAlert(RuleRunCostOutlier, "warning", r,
		fmt.Sprintf("run cost outlier: run at $%.2f vs P95 $%.2f over last %d %s runs", r.CostUSD, p95, len(hist), r.AgentID),
		fmt.Sprintf(">P95 ($%.2f) of last %d completed runs", p95, len(hist)),
		fmt.Sprintf("$%.2f", r.CostUSD))}
}

// --- Rule 3: loop detection -------------------------------------------------

func (e *Engine) loopDetection(r *model.Run, spans []*model.Span) outcome {
	fp := fpOf(RuleLoopDetection, "run", r.RunID)
	best, bestN := "", 0
	cur, curN := "", 0
	for _, sp := range spans {
		switch sp.Kind {
		case model.SpanToolCall:
			key := sp.Tool + "\x00" + sp.ArgHash
			if key == cur {
				curN++
			} else {
				cur, curN = key, 1
			}
			if curN > bestN {
				best, bestN = key, curN
			}
		case model.SpanLLMCall:
			// Thinking between identical tool calls doesn't break a loop —
			// think/act/think/act is exactly the stuck pattern.
		default:
			// file.op, net.egress, subagent.spawn, human.approval: the world
			// changed, so the streak is over.
			cur, curN = "", 0
		}
	}
	if bestN < loopThreshold {
		return outcome{fp: fp}
	}
	tool := trimSuffixKey(best)
	return outcome{fp: fp, alert: mkAlert(RuleLoopDetection, "warning", r,
		fmt.Sprintf("loop detected: %s called %d times consecutively with identical arguments", tool, bestN),
		fmt.Sprintf(">=%d consecutive identical tool.call", loopThreshold),
		fmt.Sprintf("%d consecutive %s calls", bestN, tool))}
}

func trimSuffixKey(k string) string {
	if i := len(k); i > 0 {
		// key was tool + "\x00" + arghash; cut at the separator
		for j := 0; j < len(k); j++ {
			if k[j] == 0 {
				return k[:j]
			}
		}
	}
	return k
}

// --- Rule 4: first-seen tool ------------------------------------------------

func (e *Engine) firstSeenTool(r *model.Run, spans []*model.Span) outcome {
	// The baseline excludes this run's own spans: a tool is first-seen when
	// no OTHER run of this agent used it in 30 days.
	seen, err := e.st.DistinctSpanValues(model.SpanToolCall, "tool", "agent_id", r.AgentID,
		e.now().UTC().Add(-baselineDays*24*time.Hour), r.RunID)
	if err != nil {
		return outcome{}
	}
	known := map[string]bool{}
	for _, t := range seen {
		known[t] = true
	}
	for _, sp := range spans {
		if sp.Kind != model.SpanToolCall || sp.Tool == "" {
			continue
		}
		if known[sp.Tool] {
			continue
		}
		fp := fpOf(RuleFirstSeenTool, "agent", r.AgentID+":"+sp.Tool)
		return outcome{fp: fp, alert: mkAlert(RuleFirstSeenTool, "info", r,
			fmt.Sprintf("first-seen tool: %s invoked %q (never in %d days)", r.AgentID, sp.Tool, baselineDays),
			fmt.Sprintf("tool unseen for agent in %d days", baselineDays),
			sp.Tool)}
	}
	return outcome{}
}

// --- Rule 5: first-seen egress host -----------------------------------------

func (e *Engine) firstSeenEgressHost(r *model.Run, spans []*model.Span) outcome {
	seen, err := e.st.DistinctSpanValues(model.SpanNetEgress, "host", "fleet_id", r.FleetID,
		e.now().UTC().Add(-baselineDays*24*time.Hour), r.RunID)
	if err != nil {
		return outcome{}
	}
	known := map[string]bool{}
	for _, h := range seen {
		known[h] = true
	}
	for _, sp := range spans {
		if sp.Kind != model.SpanNetEgress || sp.Host == "" || known[sp.Host] {
			continue
		}
		fp := fpOf(RuleFirstSeenEgressHost, "fleet", r.FleetID+":"+sp.Host)
		return outcome{fp: fp, alert: mkAlert(RuleFirstSeenEgressHost, "warning", r,
			fmt.Sprintf("first-seen egress host: run contacted %q (never seen for fleet %s in %d days)", sp.Host, r.FleetID, baselineDays),
			fmt.Sprintf("host unseen for fleet in %d days", baselineDays),
			sp.Host)}
	}
	return outcome{}
}

// --- Rule 6: egress after ingest --------------------------------------------

func (e *Engine) egressAfterIngest(r *model.Run, spans []*model.Span) outcome {
	// A net.egress to a first-seen host within 5 min of a tool.call whose
	// output exceeded 10KB. (URL-in-output detection needs content we don't
	// store; the >10KB half of the panel's rule is implemented.)
	seen, err := e.st.DistinctSpanValues(model.SpanNetEgress, "host", "fleet_id", r.FleetID,
		e.now().UTC().Add(-baselineDays*24*time.Hour), r.RunID)
	if err != nil {
		return outcome{} // baseline unreadable: rule not applicable, never alert
	}
	known := map[string]bool{}
	for _, h := range seen {
		known[h] = true
	}
	var bigOut []time.Time
	for _, sp := range spans {
		if sp.Kind == model.SpanToolCall && sp.OutputBytes > 10*1024 {
			bigOut = append(bigOut, sp.StartedAt)
		}
	}
	if len(bigOut) == 0 {
		return outcome{}
	}
	for _, sp := range spans {
		if sp.Kind != model.SpanNetEgress || sp.Host == "" || known[sp.Host] {
			continue
		}
		for _, t := range bigOut {
			d := sp.StartedAt.Sub(t)
			if d >= 0 && d <= egressIngestWindow {
				fp := fpOf(RuleEgressAfterIngest, "run", r.RunID+":"+sp.Host)
				return outcome{fp: fp, alert: &model.Alert{
					Rule: RuleEgressAfterIngest, Severity: "critical",
					AgentID: r.AgentID, FleetID: r.FleetID, RunID: r.RunID,
					Message: fmt.Sprintf("possible exfiltration: egress to first-seen host %q within %s of a >10KB tool output",
						sp.Host, egressIngestWindow),
					Threshold: fmt.Sprintf("egress to first-seen host within %s of >10KB tool output", egressIngestWindow),
					Observed:  fmt.Sprintf("%s -> %s after large output", sp.Host, d.Round(time.Second)),
				}}
			}
		}
	}
	return outcome{}
}

// --- Rule 7: credential-adjacent file access ---------------------------------

func (e *Engine) credentialFileAccess(r *model.Run, spans []*model.Span) outcome {
	for _, sp := range spans {
		if sp.Kind != model.SpanFileOp || sp.Path == "" {
			continue
		}
		if !redact.IsCredentialAdjacentPath(sp.Path) {
			continue
		}
		seen, err := e.st.DistinctSpanValues(model.SpanFileOp, "path", "agent_id", r.AgentID,
			e.now().UTC().Add(-baselineDays*24*time.Hour), r.RunID)
		if err != nil {
			return outcome{}
		}
		known := map[string]bool{}
		for _, p := range seen {
			known[p] = true
		}
		if known[sp.Path] {
			continue
		}
		fp := fpOf(RuleCredentialFileAccess, "agent", r.AgentID+":"+sp.Path)
		return outcome{fp: fp, alert: mkAlert(RuleCredentialFileAccess, "warning", r,
			fmt.Sprintf("credential-adjacent file access: %s touched %q first time in %d days", r.AgentID, sp.Path, baselineDays),
			"first credential-adjacent access for agent",
			sp.Path)}
	}
	return outcome{}
}

// --- Rule 8: spawn storm ------------------------------------------------------

func (e *Engine) spawnStorm(r *model.Run, spans []*model.Span) outcome {
	fp := fpOf(RuleSpawnStorm, "run", r.RunID)
	var times []time.Time
	for _, sp := range spans {
		if sp.Kind == model.SpanSubagentSpawn {
			times = append(times, sp.StartedAt)
		}
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	for i := range times {
		j := i
		for j < len(times) && times[j].Sub(times[i]) <= time.Minute {
			j++
		}
		if j-i > spawnStormPerMin {
			return outcome{fp: fp, alert: mkAlert(RuleSpawnStorm, "warning", r,
				fmt.Sprintf("spawn storm: %d subagents spawned within one minute", j-i),
				fmt.Sprintf(">%d spawns/min for one parent run", spawnStormPerMin),
				fmt.Sprintf("%d spawns/min", j-i))}
		}
	}
	return outcome{fp: fp}
}

// --- Rule 9: approval denial -> retry ------------------------------------------

func (e *Engine) approvalDenialRetry(r *model.Run, spans []*model.Span) outcome {
	fp := fpOf(RuleApprovalDenialRetry, "run", r.RunID)
	type ap struct {
		gate     string
		decision string
		at       time.Time
	}
	var aps []ap
	for _, sp := range spans {
		if sp.Kind == model.SpanHumanApproval {
			aps = append(aps, ap{sp.Gate, sp.Decision, sp.StartedAt})
		}
	}
	denials := 0
	for _, a := range aps {
		if a.decision == "denied" {
			denials++
		}
	}
	if denials >= denialsPerHour {
		return outcome{fp: fp, alert: mkAlert(RuleApprovalDenialRetry, "warning", r,
			fmt.Sprintf("approval fight: %d denials in this run", denials),
			fmt.Sprintf(">=%d denials", denialsPerHour),
			fmt.Sprintf("%d denials", denials))}
	}
	// Denied, then the same gate requested again within 10 minutes.
	for i, a := range aps {
		if a.decision != "denied" {
			continue
		}
		for j, b := range aps {
			if i == j || b.gate != a.gate {
				continue
			}
			d := b.at.Sub(a.at)
			if d > 0 && d <= approvalRetryWindow {
				return outcome{fp: fp, alert: mkAlert(RuleApprovalDenialRetry, "warning", r,
					fmt.Sprintf("approval denial retried: gate %q denied then re-requested %s later", a.gate, d.Round(time.Second)),
					fmt.Sprintf("same gate re-requested within %s of denial", approvalRetryWindow),
					fmt.Sprintf("gate %q", a.gate))}
			}
		}
	}
	return outcome{fp: fp}
}

// --- Rule 10: spinning run ------------------------------------------------------

func (e *Engine) spinningRun(r *model.Run, spans []*model.Span) outcome {
	fp := fpOf(RuleSpinningRun, "run", r.RunID)
	if r.Status != model.RunRunning {
		return outcome{fp: fp}
	}
	hist, err := e.st.ListRuns(store.RunFilter{AgentID: r.AgentID, Status: model.RunCompleted, Limit: 100})
	if err != nil || len(hist) < minBaselineRuns {
		return outcome{fp: fp}
	}
	var durs []float64
	for _, h := range hist {
		if h.EndedAt != nil {
			durs = append(durs, h.EndedAt.Sub(h.StartedAt).Seconds())
		}
	}
	if len(durs) < minBaselineRuns {
		return outcome{fp: fp}
	}
	p99 := percentile(durs, 99)
	aliveFor := e.now().UTC().Sub(r.StartedAt).Seconds()
	if aliveFor <= p99 {
		return outcome{fp: fp}
	}
	cutoff := e.now().UTC().Add(-15 * time.Minute)
	var recentTools int
	var recentTokens int64
	for _, sp := range spans {
		if sp.StartedAt.Before(cutoff) {
			continue
		}
		if sp.Kind == model.SpanToolCall {
			recentTools++
		}
		if sp.Kind == model.SpanLLMCall {
			recentTokens += sp.TokensIn + sp.TokensOut
		}
	}
	if recentTools >= 5 || recentTokens == 0 {
		return outcome{fp: fp}
	}
	return outcome{fp: fp, alert: mkAlert(RuleSpinningRun, "warning", r,
		fmt.Sprintf("spinning run: alive %s (>P99 %s) with %d tool calls in 15 min while burning tokens",
			time.Duration(aliveFor)*time.Second, time.Duration(p99)*time.Second, recentTools),
		fmt.Sprintf(">P99 duration (%s) with <5 tool calls/15min and tokens burning", time.Duration(p99)*time.Second),
		fmt.Sprintf("alive %s, %d recent tool calls", time.Duration(aliveFor)*time.Second, recentTools))}
}

// --- Rule 11: guard-trip cluster --------------------------------------------------

func (e *Engine) guardTripCluster(fleetID string) outcome {
	fp := fpOf(RuleGuardTripCluster, "fleet", fleetID)
	n, err := e.st.CountGuardTrips(fleetID, e.now().UTC().Add(-guardTripWindow))
	if err != nil || n < guardTripClusterN {
		return outcome{fp: fp}
	}
	return outcome{fp: fp, alert: &model.Alert{
		Rule: RuleGuardTripCluster, Severity: "warning",
		FleetID:   fleetID,
		Message:   fmt.Sprintf("guard-trip cluster: %d guard trips in fleet %s in %s", n, fleetID, guardTripWindow),
		Threshold: fmt.Sprintf(">=%d guard trips in %s", guardTripClusterN, guardTripWindow),
		Observed:  fmt.Sprintf("%d trips", n),
	}}
}

// --- Rule 12: savings collapse -------------------------------------------------------

func (e *Engine) savingsCollapse(fleetID string) outcome {
	fp := fpOf(RuleSavingsCollapse, "fleet", fleetID)
	days, err := e.st.FleetDailyCache(fleetID, e.now().UTC().Add(-8*24*time.Hour))
	if err != nil || len(days) < 2 {
		return outcome{fp: fp}
	}
	rate := func(d store.DayCache) float64 {
		if d.Total == 0 {
			return 0
		}
		return 100 * float64(d.Cached) / float64(d.Total)
	}
	today := rate(days[len(days)-1])
	var baseline []float64
	for _, d := range days[:len(days)-1] {
		if d.Total > 0 {
			baseline = append(baseline, rate(d))
		}
	}
	if len(baseline) == 0 {
		return outcome{fp: fp}
	}
	med := medianFloat(baseline)
	if med-today <= savingsCollapsePP {
		return outcome{fp: fp}
	}
	return outcome{fp: fp, alert: &model.Alert{
		Rule: RuleSavingsCollapse, Severity: "warning",
		FleetID:   fleetID,
		Message:   fmt.Sprintf("savings collapse: fleet %s cache-hit rate %.1f%% vs 7-day median %.1f%%", fleetID, today, med),
		Threshold: fmt.Sprintf(">%.0fpp drop vs 7-day median", savingsCollapsePP),
		Observed:  fmt.Sprintf("%.1f%% (median %.1f%%)", today, med),
	}}
}

// --- stats helpers ---------------------------------------------------------------

func medianFloat(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	cp := append([]float64{}, v...)
	sort.Float64s(cp)
	mid := len(cp) / 2
	if len(cp)%2 == 1 {
		return cp[mid]
	}
	return (cp[mid-1] + cp[mid]) / 2
}

func percentile(v []float64, p float64) float64 {
	if len(v) == 0 {
		return 0
	}
	cp := append([]float64{}, v...)
	sort.Float64s(cp)
	idx := int((p / 100) * float64(len(cp)))
	if idx >= len(cp) {
		idx = len(cp) - 1
	}
	return cp[idx]
}
