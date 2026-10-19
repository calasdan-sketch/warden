// Package join is warden's join layer: it consumes the structured output of
// Dan's existing tools instead of re-emitting their data.
//
// The cross-tool contract (what emitters guarantee):
//  1. Stable IDs: run_id is assigned at run start and passed to every child/emitter.
//  2. Append-only, structured: JSONL, one record per line, never mutated after write.
//  3. Cost computed once: each emitter owns its numbers (shortleash: run cost;
//     calas-gateway: savings). Warden joins, never re-derives.
//
// Sources:
//   - shortleash receipts -> run envelopes (run close; cost/tokens authoritative)
//   - planok approval records -> human.approval spans
//   - mcp-jail audit log -> tool.call spans (with MCP server name)
//   - calas-gateway ledger -> cost_saved_usd memo on the run
//
// Records that arrive without a run_id land in a synthetic per-agent
// "unattached" run — flagged, never silently dropped.
package join

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"warden/internal/collect"
	"warden/internal/model"
	"warden/internal/store"
)

// Source identifies an emitter.
type Source string

const (
	SourceShortleash   Source = "shortleash"
	SourcePlanok       Source = "planok"
	SourceMCPJail      Source = "mcp-jail"
	SourceCalasGateway Source = "calas-gateway"
)

// shortleashReceipt is the documented shortleash receipt schema (subset used).
type shortleashReceipt struct {
	RunID        string   `json:"run_id"`
	ParentRunID  string   `json:"parent_run_id"`
	AgentID      string   `json:"agent_id"`
	Fleet        string   `json:"fleet"`
	StartedAt    string   `json:"started_at"`
	EndedAt      string   `json:"ended_at"`
	Outcome      string   `json:"outcome"` // completed|failed|killed|timeout
	KilledBy     string   `json:"killed_by"`
	KillReason   string   `json:"kill_reason"`
	TokensIn     int64    `json:"tokens_in"`
	TokensOut    int64    `json:"tokens_out"`
	TokensCached int64    `json:"tokens_cached"`
	CostUSD      float64  `json:"cost_usd"`
	Guards       []string `json:"guards_evaluated"`
	ToolCalls    int64    `json:"tool_calls"`
	FilesTouched int64    `json:"files_touched"`
}

// planokRecord is the documented planok approval schema.
type planokRecord struct {
	RunID       string `json:"run_id"`
	AgentID     string `json:"agent_id"`
	Gate        string `json:"gate"`
	Decision    string `json:"decision"` // approved|denied|timeout
	Approver    string `json:"approver"`
	RequestedAt string `json:"requested_at"`
	DecidedAt   string `json:"decided_at"`
}

// mcpJailRecord is the documented mcp-jail audit schema.
type mcpJailRecord struct {
	RunID   string `json:"run_id"`
	AgentID string `json:"agent_id"`
	Fleet   string `json:"fleet"`
	Tool    string `json:"tool"`
	Server  string `json:"server"`
	Args    string `json:"args"`
	Allowed bool   `json:"allowed"`
	At      string `json:"at"`
}

// gatewayRecord is the documented calas-gateway ledger schema.
type gatewayRecord struct {
	RunID          string  `json:"run_id"`
	SavedUSD       float64 `json:"saved_usd"`
	CacheHitTokens int64   `json:"cache_hit_tokens"`
	Strategy       string  `json:"strategy"`
	At             string  `json:"at"`
}

// Importer joins emitter records into warden runs/spans.
type Importer struct {
	st  *store.Store
	col *collect.Collector
}

// New builds an importer.
func New(st *store.Store, col *collect.Collector) *Importer {
	return &Importer{st: st, col: col}
}

// ImportLine ingests one JSONL record from source.
func (im *Importer) ImportLine(source Source, line string) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	switch source {
	case SourceShortleash:
		var r shortleashReceipt
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return fmt.Errorf("shortleash: %w", err)
		}
		return im.importShortleash(&r)
	case SourcePlanok:
		var r planokRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return fmt.Errorf("planok: %w", err)
		}
		return im.importPlanok(&r)
	case SourceMCPJail:
		var r mcpJailRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return fmt.Errorf("mcp-jail: %w", err)
		}
		return im.importMCPJail(&r)
	case SourceCalasGateway:
		var r gatewayRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return fmt.Errorf("calas-gateway: %w", err)
		}
		return im.importGateway(&r)
	}
	return fmt.Errorf("unknown source %q", source)
}

// ImportFile ingests a whole JSONL file.
func (im *Importer) ImportFile(source Source, path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		if err := im.ImportLine(source, sc.Text()); err != nil {
			return n, err
		}
		n++
	}
	return n, sc.Err()
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Now().UTC()
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Now().UTC()
}

// ensureRun returns the run, creating a minimal envelope when the emitter is
// the first to mention it (backfill path).
func (im *Importer) ensureRun(runID, agentID, fleetID string, started time.Time) (*model.Run, error) {
	if runID == "" {
		return im.unattachedRun(agentID, fleetID)
	}
	r, err := im.st.GetRun(runID)
	if err == nil {
		return r, nil
	}
	if agentID == "" {
		agentID = "unknown"
	}
	if fleetID == "" {
		fleetID = "default"
	}
	r = &model.Run{
		RunID: runID, AgentID: agentID, FleetID: fleetID,
		StartedAt: started, Status: model.RunRunning,
	}
	if err := im.st.CreateRun(r); err != nil {
		return nil, err
	}
	return r, nil
}

// unattachedRun is the synthetic bucket for spans that arrive without a run_id.
func (im *Importer) unattachedRun(agentID, fleetID string) (*model.Run, error) {
	if agentID == "" {
		agentID = "unknown"
	}
	id := "unattached:" + agentID
	r, err := im.st.GetRun(id)
	if err == nil {
		return r, nil
	}
	if fleetID == "" {
		fleetID = "default"
	}
	r = &model.Run{
		RunID: id, AgentID: agentID, FleetID: fleetID,
		StartedAt: time.Now().UTC(), Status: model.RunRunning,
		Command: "synthetic bucket for spans without run_id",
	}
	if err := im.st.CreateRun(r); err != nil {
		return nil, err
	}
	_ = im.st.InsertEvent(&model.Event{
		RunID: id, At: time.Now().UTC(), Severity: "warning", Kind: "unattached_spans",
		Message: "spans arrived without a run_id; bucketed here instead of dropped",
	})
	return r, nil
}

func shortleashStatus(outcome, killedBy string) model.RunStatus {
	switch outcome {
	case "completed":
		return model.RunCompleted
	case "failed":
		return model.RunFailed
	case "timeout":
		return model.RunTimedOut
	case "killed":
		if killedBy == "guard" {
			return model.RunKilledGuard
		}
		return model.RunKilledOperator
	}
	return model.RunFailed
}

func (im *Importer) importShortleash(r *shortleashReceipt) error {
	if r.RunID == "" {
		return fmt.Errorf("shortleash record missing run_id")
	}
	run, err := im.ensureRun(r.RunID, r.AgentID, r.Fleet, parseTime(r.StartedAt))
	if err != nil {
		return err
	}
	// Cost and tokens are authoritative from the emitter: joined, never recomputed.
	// The sealer honors this via cost_source=emitter (see finalizeCounters).
	run.TokensIn = r.TokensIn
	run.TokensOut = r.TokensOut
	run.TokensCached = r.TokensCached
	run.CostUSD = r.CostUSD
	run.ToolCalls = r.ToolCalls
	run.FilesTouched = r.FilesTouched
	run.CostSource = "emitter"
	if r.ParentRunID != "" {
		run.ParentRunID = &r.ParentRunID
	}
	if err := im.st.UpdateRun(run); err != nil {
		return err
	}
	// Guard trips become events (feeds the guard-trip-cluster rule).
	for _, g := range r.Guards {
		_ = im.st.InsertEvent(&model.Event{
			RunID: run.RunID, At: time.Now().UTC(), Severity: "warning", Kind: "guard_trip",
			Message: fmt.Sprintf("shortleash guard tripped: %s", g),
		})
	}
	status := shortleashStatus(r.Outcome, r.KilledBy)
	var kill *model.KillRecord
	if status == model.RunKilledOperator || status == model.RunKilledGuard {
		src := r.KilledBy
		if src == "" {
			src = "unknown"
		}
		kill = &model.KillRecord{
			At: time.Now().UTC(), Actor: "shortleash:" + src, Scope: model.KillScopeRun,
			Target: run.RunID, Reason: r.KillReason, Result: "joined from shortleash receipt",
		}
		if kill.Reason == "" {
			kill.Reason = "killed (" + src + ")"
		}
	}
	rec, err := im.col.SealRun(run.RunID, status, kill, r.Guards)
	if err != nil {
		return err
	}
	_ = rec
	_ = im.st.InsertEvent(&model.Event{
		RunID: run.RunID, At: time.Now().UTC(), Severity: "info", Kind: "join",
		Message: fmt.Sprintf("shortleash receipt joined: cost=$%.4f (authoritative)", r.CostUSD),
	})
	return nil
}

func (im *Importer) importPlanok(r *planokRecord) error {
	run, err := im.ensureRun(r.RunID, r.AgentID, "", parseTime(r.RequestedAt))
	if err != nil {
		return err
	}
	req := parseTime(r.RequestedAt)
	dec := parseTime(r.DecidedAt)
	sp := &model.Span{
		Kind: model.SpanHumanApproval, Name: r.Gate, Gate: r.Gate,
		Decision: r.Decision, Approver: r.Approver,
		DecisionLatencyMs: dec.Sub(req).Milliseconds(),
		RunID:             run.RunID, AgentID: run.AgentID, FleetID: run.FleetID,
		StartedAt: req,
	}
	ended := dec
	sp.EndedAt = &ended
	return im.col.EmitSpan(sp)
}

func (im *Importer) importMCPJail(r *mcpJailRecord) error {
	run, err := im.ensureRun(r.RunID, r.AgentID, r.Fleet, parseTime(r.At))
	if err != nil {
		return err
	}
	status := "ok"
	if !r.Allowed {
		status = "denied"
	}
	sp := &model.Span{
		Kind: model.SpanToolCall, Name: r.Tool, Tool: r.Tool, ToolServer: r.Server,
		ArgsSummary: r.Args, Status: status,
		PreDecided: true, // mcp-jail already enforced; the collector redacts but doesn't re-decide
		RunID:      run.RunID, AgentID: run.AgentID, FleetID: run.FleetID,
		StartedAt: parseTime(r.At),
	}
	if !r.Allowed {
		sp.PolicyDecision = "deny"
		sp.PolicyReason = "denied by mcp-jail"
		sp.PolicyVersion = "mcp-jail"
	} else {
		sp.PolicyDecision = "allow"
		sp.PolicyVersion = "mcp-jail"
	}
	return im.col.EmitSpan(sp)
}

func (im *Importer) importGateway(r *gatewayRecord) error {
	if r.RunID == "" {
		return fmt.Errorf("calas-gateway record missing run_id")
	}
	run, err := im.ensureRun(r.RunID, "", "", parseTime(r.At))
	if err != nil {
		return err
	}
	// Savings are a memo joined onto the run; gross cost is never touched.
	run.CostSavedUSD += r.SavedUSD
	if err := im.st.UpdateRun(run); err != nil {
		return err
	}
	return im.st.InsertEvent(&model.Event{
		RunID: run.RunID, At: time.Now().UTC(), Severity: "info", Kind: "join",
		Message: fmt.Sprintf("calas-gateway savings joined: $%.4f saved (%s)", r.SavedUSD, r.Strategy),
	})
}
