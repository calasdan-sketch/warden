// Package model defines the core telemetry primitives of warden:
// runs, spans (6 fixed kinds), events, alerts, receipts, and audit records.
//
// The unit of account is the run (long-lived, hierarchical), not the request.
package model

import "time"

// SpanKind is the fixed, opinionated taxonomy of span types.
// Users cannot invent new span kinds; everything an agent does maps to one of these.
type SpanKind string

const (
	SpanLLMCall       SpanKind = "llm.call"
	SpanToolCall      SpanKind = "tool.call"
	SpanFileOp        SpanKind = "file.op"
	SpanNetEgress     SpanKind = "net.egress"
	SpanSubagentSpawn SpanKind = "subagent.spawn"
	SpanHumanApproval SpanKind = "human.approval"
)

// Valid reports whether k is one of the six span kinds.
func (k SpanKind) Valid() bool {
	switch k {
	case SpanLLMCall, SpanToolCall, SpanFileOp, SpanNetEgress, SpanSubagentSpawn, SpanHumanApproval:
		return true
	}
	return false
}

// Span is one recorded action inside a run. Kind-specific fields are only
// meaningful for their kind; the rest stay zero. High-cardinality data
// (full prompts, full outputs, file contents) is never stored here —
// summaries, hashes, and counts only.
type Span struct {
	SpanID string `json:"span_id"`
	RunID  string `json:"run_id"`

	Kind SpanKind `json:"kind"`
	Name string   `json:"name,omitempty"`

	AgentID string `json:"agent_id"`
	FleetID string `json:"fleet_id"`

	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`

	// Outcome of the action itself.
	Status string `json:"status,omitempty"` // ok, error, denied, awaiting_approval

	// llm.call
	Model        string  `json:"model,omitempty"`
	TokensIn     int64   `json:"tokens_in,omitempty"`
	TokensOut    int64   `json:"tokens_out,omitempty"`
	TokensCached int64   `json:"tokens_cached,omitempty"`
	CostUSD      float64 `json:"cost_usd,omitempty"`
	CacheHit     bool    `json:"cache_hit,omitempty"`

	// tool.call
	Tool        string `json:"tool,omitempty"`
	ToolServer  string `json:"tool_server,omitempty"`  // MCP server name; joins to mcp-audit findings
	ArgsSummary string `json:"args_summary,omitempty"` // first N chars, secrets redacted
	ToolCallID  string `json:"tool_call_id,omitempty"` // harness tool-use id (gen_ai.tool.call.id)
	ArgHash     string `json:"arg_hash,omitempty"`     // hash of full args (redacted form)
	ExitStatus  int    `json:"exit_status,omitempty"`
	OutputBytes int64  `json:"output_bytes,omitempty"`

	// file.op (aggregated per path prefix per run — cardinality discipline)
	Path  string `json:"path,omitempty"`
	Op    string `json:"op,omitempty"` // read, write, delete
	Count int64  `json:"count,omitempty"`
	Bytes int64  `json:"bytes,omitempty"`

	// net.egress (aggregated by host)
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	NetBytes int64  `json:"net_bytes,omitempty"`

	// subagent.spawn
	ChildRunID  string `json:"child_run_id,omitempty"`
	SpawnReason string `json:"spawn_reason,omitempty"`

	// human.approval
	Gate              string `json:"gate,omitempty"`
	Decision          string `json:"decision,omitempty"` // approved, denied, timeout
	Approver          string `json:"approver,omitempty"`
	DecisionLatencyMs int64  `json:"decision_latency_ms,omitempty"`

	// Policy decision made at the tool-call boundary for this span.
	PolicyDecision string `json:"policy_decision,omitempty"` // allow, deny, require_approval
	PolicyReason   string `json:"policy_reason,omitempty"`
	PolicyVersion  string `json:"policy_version,omitempty"`

	// PreDecided marks spans whose policy decision was made by an external
	// enforcement point (e.g. mcp-jail). The collector still redacts but does
	// not re-evaluate. Ingestion-time only.
	PreDecided bool `json:"pre_decided,omitempty"`

	// Redacted reports whether any field was redacted by the collector before emission.
	Redacted bool `json:"redacted,omitempty"`

	// LateAfterSeal marks a span recorded after its run's receipt was
	// sealed (e.g. a sibling-tool feed ingested later). Such spans are kept
	// for the audit trail but are NOT covered by the receipt's signed trace
	// digest; verify reports them separately. Set by the store, atomically.
	LateAfterSeal bool `json:"late_after_seal,omitempty"`
}

// RunStatus is the lifecycle state of a run.
type RunStatus string

const (
	RunRunning          RunStatus = "running"
	RunCompleted        RunStatus = "completed"
	RunFailed           RunStatus = "failed"
	RunKilledOperator   RunStatus = "killed_operator"
	RunKilledGuard      RunStatus = "killed_guard"
	RunTimedOut         RunStatus = "timed_out"
	RunAwaitingApproval RunStatus = "awaiting_approval"
	RunReceiptMissing   RunStatus = "receipt_missing"
)

// Run is the sealed (or live) envelope for one agent run.
// Cost is computed once, at the emitter, and joined — never recomputed downstream.
type Run struct {
	RunID       string  `json:"run_id"`
	ParentRunID *string `json:"parent_run_id,omitempty"`

	AgentID  string `json:"agent_id"`
	FleetID  string `json:"fleet_id"`
	Operator string `json:"operator,omitempty"`

	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	Status    RunStatus  `json:"status"`

	Model    string `json:"model,omitempty"`
	Provider string `json:"provider,omitempty"`

	TokensIn     int64 `json:"tokens_in"`
	TokensOut    int64 `json:"tokens_out"`
	TokensCached int64 `json:"tokens_cached"`

	CostUSD      float64 `json:"cost_usd"`       // gross; authoritative from emitter
	CostSavedUSD float64 `json:"cost_saved_usd"` // memo from calas-gateway ledger; never subtracted from gross
	CostSource   string  `json:"cost_source"`    // "spans" (warden summed) or "emitter" (joined, authoritative)

	ToolCalls        int64 `json:"tool_calls"`
	FilesTouched     int64 `json:"files_touched"`
	NetEgressHosts   int64 `json:"net_egress_hosts"`
	SubagentsSpawned int64 `json:"subagents_spawned"`

	ApprovalsRequested int64 `json:"approvals_requested"`
	ApprovalsDenied    int64 `json:"approvals_denied"`

	KillSource *string `json:"kill_source,omitempty"` // operator, guard, fleet_freeze
	KillReason *string `json:"kill_reason,omitempty"`
	KilledBy   *string `json:"killed_by,omitempty"`

	ReceiptRef string `json:"receipt_ref,omitempty"` // pointer to sealed receipt

	Command string `json:"command,omitempty"` // wrapped command (redacted)
	PID     int    `json:"pid,omitempty"`
}

// NetCost is the joined net-cost story: gross minus saved. Displayed as a
// memo, never subtracted inside the authoritative cost field.
func (r *Run) NetCost() float64 { return r.CostUSD - r.CostSavedUSD }

// Event is a free-form record on the run/event stream (guard trips, warnings, etc.).
type Event struct {
	ID       int64     `json:"id"`
	RunID    string    `json:"run_id"`
	SpanID   string    `json:"span_id,omitempty"`
	At       time.Time `json:"at"`
	Severity string    `json:"severity"` // info, warning, critical
	Kind     string    `json:"kind"`     // e.g. guard_trip, policy_deny, telemetry_gap
	Message  string    `json:"message"`
	DataJSON string    `json:"data_json,omitempty"`
}

// Alert is emitted by the anomaly engine. Severity is fixed per rule.
// Every alert names the rule + threshold + observed value.
type Alert struct {
	ID          int64     `json:"id"`
	Rule        string    `json:"rule"`
	Severity    string    `json:"severity"` // info, warning, critical
	AgentID     string    `json:"agent_id"`
	FleetID     string    `json:"fleet_id"`
	RunID       string    `json:"run_id,omitempty"`
	Message     string    `json:"message"`
	Threshold   string    `json:"threshold"`
	Observed    string    `json:"observed"`
	At          time.Time `json:"at"`
	Status      string    `json:"status"` // active, recovered, acked
	Fingerprint string    `json:"fingerprint"`
}

// Receipt is the signed, hash-chained per-run close record. It is sealed even
// on kill — a killed run is not a missing run.
type Receipt struct {
	RunID     string    `json:"run_id"`
	AgentID   string    `json:"agent_id"`
	FleetID   string    `json:"fleet_id"`
	Operator  string    `json:"operator,omitempty"`
	Status    RunStatus `json:"status"`
	StartedAt time.Time `json:"started_at"`
	SealedAt  time.Time `json:"sealed_at"`

	TokensIn     int64   `json:"tokens_in"`
	TokensOut    int64   `json:"tokens_out"`
	TokensCached int64   `json:"tokens_cached"`
	CostUSD      float64 `json:"cost_usd"`
	ToolCalls    int64   `json:"tool_calls"`

	GuardsEvaluated []string `json:"guards_evaluated,omitempty"`
	KillReason      *string  `json:"kill_reason,omitempty"`
	KilledBy        *string  `json:"killed_by,omitempty"`

	// Tamper evidence: hash chain + Ed25519 signature.
	BodyHash  string `json:"body_hash"` // sha256 over canonical receipt body
	PrevHash  string `json:"prev_hash"` // body_hash of the previously sealed receipt (genesis: "")
	Signature string `json:"signature"` // Ed25519 over body_hash, base64
	KeyID     string `json:"key_id"`    // fingerprint of the signing key

	// Trace commitment: number of covered spans and their set digest.
	SpanCount   int64  `json:"span_count,omitempty"`
	SpansDigest string `json:"spans_digest,omitempty"`
}

// KillScope enumerates the four kill scopes with exact semantics.
type KillScope string

const (
	KillScopeRun   KillScope = "run"   // SIGTERM -> grace -> SIGKILL on the run's process subtree; idempotent
	KillScopeAgent KillScope = "agent" // quarantine: kill live runs, refuse new runs for a TTL
	KillScopeFleet KillScope = "fleet" // freeze: no new runs; soft-stop live runs, hard-kill stragglers after deadline
	KillScopeTool  KillScope = "tool"  // deny-list push: tool refused at enforcement points, in-flight calls complete
)

// Valid reports whether s is a known kill scope.
func (s KillScope) Valid() bool {
	switch s {
	case KillScopeRun, KillScopeAgent, KillScopeFleet, KillScopeTool:
		return true
	}
	return false
}

// KillRecord is the audited record of one kill action. Reason is required —
// "oops" is acceptable, empty is not.
type KillRecord struct {
	ID      int64     `json:"id"`
	At      time.Time `json:"at"`
	Actor   string    `json:"actor"`
	Scope   KillScope `json:"scope"`
	Target  string    `json:"target"`
	Reason  string    `json:"reason"`
	Result  string    `json:"result"`
	Details string    `json:"details,omitempty"`
}
