# Gap #12 — Observability Panel Brief
**Role:** Observability Engineer · **Author:** Odin · **Date:** 2026-10-18

> Working product name: **Runlight** — "turn on the lights for your agent runs."
> (Provisional. The other tools in Dan's line are compound-descriptive: ShortLeash, Flakebox, SafeEasyAPI. *Runlight* fits. Verify name availability on npm/PyPI before committing.)

## TL;DR

Enterprises aren't blocked on agents because they can't build them — they're blocked because **they can't see them**. "Monitoring agents at scale" concretely means: *every agent run in the org, live, with cost ticking, with a kill button attached.* The wedge is not a metrics platform. It's a **live fleet view + cost burn + kill switch** — the three things an eng manager reaches for at 2am when the invoice arrives or the agent goes sideways.

Opinionated core thesis: **Runlight does not re-instrument the world.** Dan's ecosystem already emits structured data (shortleash receipts, calas-gateway's savings ledger, planok approval records, mcp-jail audit logs). The product is the **correlation + visualization + alerting + kill layer** over those existing emitters, plus a zero-code collector shim for agents that emit nothing. One schema to join them. One view to watch them. One button to stop them.

---

## 1. Core telemetry primitives

### The unit of account is the **run**, not the request

Agents don't behave like HTTP services. A "request" model (Datadog APM, standard OTel) fails because an agent run is:

- **long-lived** (minutes to hours, survives compaction/restarts),
- **hierarchical** (spawns subagents that spawn subagents),
- **multi-resource** (LLM tokens, tools, files, network, human approvals),
- **stateful across interruptions** (paused for approval, resumed later).

So the primitive hierarchy is: **Run → Spans → Events**. Runs nest (parent run → child runs).

### 1.1 The Run envelope

Every run gets a sealed envelope at close (or a live envelope while running). Fields:

| Field | Type | Notes |
|---|---|---|
| `run_id` | uuid | globally unique |
| `parent_run_id` | uuid? | null for roots; forms the fleet tree |
| `agent_id` | string | stable identity of the agent *definition* (e.g. `jarvis:code`, `dispatch-crew-matcher`) — NOT the process. Kills and policies key off this. |
| `fleet_id` | string | which fleet/deployment this run belongs to (`prod`, `nightly-sweep`, …) |
| `operator` | string | human owner on call for this agent |
| `started_at` / `ended_at` | ts | wall clock |
| `status` | enum | `running` `completed` `failed` `killed_operator` `killed_guard` `timed_out` `awaiting_approval` |
| `model` | string | e.g. `claude-opus-4-6`, plus provider |
| `tokens_in` / `tokens_out` / `tokens_cached` | int | cached broken out — this is where the money story lives |
| `cost_usd` | decimal | gross, computed from a rate card |
| `cost_saved_usd` | decimal | from calas-gateway ledger (cache hits, prompt-cache optimization) |
| `tool_calls` | int | total |
| `files_touched` | int | distinct paths |
| `net_egress_hosts` | int | distinct external hosts |
| `subagents_spawned` | int | |
| `approvals_requested` / `approvals_denied` | int | from planok |
| `kill_source` | enum? | who/what stopped it, if killed |
| `receipt_ref` | string | pointer to the shortleash receipt (source of truth, not duplicated) |

**Rule: cost is computed once, at the emitter, and joined — never recomputed downstream.** shortleash owns run cost. calas-gateway owns savings. Runlight joins them into gross/net. This kills the #1 source of dashboard distrust: two numbers that disagree.

### 1.2 Span taxonomy (fixed, small, opinionated)

Don't let users invent span types. Six span kinds cover ~everything an agent does:

1. **`llm.call`** — one model invocation. Fields: model, tokens in/out/cached, latency, cost, stop reason, cache-hit flag. *This is the money span.*
2. **`tool.call`** — one tool invocation. Fields: tool name, arg hash + arg summary (first N chars, secrets redacted at the collector — see §3), latency, exit status, output size. For MCP tools, include server name (joins to mcp-audit findings).
3. **`file.op`** — file reads/writes/deletes, aggregated per directory per run (not per-byte — cardinality discipline). Fields: path prefix, op, count, bytes. First-touch of a path outside the run's observed baseline is an event (see §4).
4. **`net.egress`** — outbound connections, aggregated by host. Fields: host, port, bytes, count. First-seen host is an event.
5. **`subagent.spawn`** — child run creation. Fields: child `run_id`, agent_id, reason/prompt summary. This is how the tree is built.
6. **`human.approval`** — planok gate events. Fields: gate name, decision (approved/denied/timeout), approver, latency-to-decision. Denied-then-retried is an anomaly signal (§4).

Plus a free-form **`event`** stream for everything else (guard trips, cache saves, warnings), each with severity and a join key to the enclosing span/run.

### 1.3 What a run trace actually contains (concrete example)

A completed coding-agent run's trace, summarized:

- Envelope (above) — e.g. 47 min, 312 tool calls, $4.17 gross / $1.02 saved → $3.15 net
- Waterfall of spans: `llm.call` → `tool.call(bash)` → `file.op(src/)` → … with the approval gate as a visible pause block ("awaiting approval: 12m 04s — approved by dan")
- **File diff summary** (not full diffs — too heavy): per-file lines added/removed, generated from the run's write ops. Full diffs stay in git; the trace links to the commit. *Opinionated: traces store diff stats, never diff content.* Content is a privacy/exfiltration liability (§3).
- Tool-call argument redaction: the collector redacts values matching secret patterns before emission. The dashboard shows `api_key=[redacted]`, never the value.
- The sealed shortleash receipt attached as the authoritative close record: guards evaluated, budget consumed, kill reason if any.

### 1.4 Cardinality and retention discipline (decided up front, not later)

- High-cardinality fields (full prompts, full tool outputs, file contents) are **never stored** by default. Stored: hashes, summaries, counts, first-N-chars.
- Retention defaults: raw spans 30 days, run envelopes + daily aggregates 13 months, anomaly events 13 months. Enterprise tier: configurable, with legal-hold flag per fleet.
- Sampling: keep 100% of envelopes and anomaly events always; sample full span waterfalls (default: 100% under $1/run, 10% above — cost-proportional sampling, because expensive runs are exactly the ones you want to inspect).

---

## 2. The smallest shippable wedge

### One view: **Fleet Command**

A single screen. No tabs to get lost in. It answers the eng manager's three 2am questions: *what's running, what is it costing, how do I stop it.*

Layout (top to bottom):

1. **Burn bar** — org/fleet spend today vs. budget, live-ticking. Gross and net (savings-adjusted). One number, huge. Turns amber at 75% of daily budget, red at 100%. *This is the "I need this" moment — nobody has this number live right now; they find out from the invoice.*
2. **Live run table** — every running agent right now: agent name, fleet, elapsed, tool calls, cost-so-far (ticking), current activity ("tool.call: bash — npm test"), operator. Sorted by cost-so-far descending. Each row has a **kill button**.
3. **Anomaly feed** — the last N first-seen / threshold-crossing events (§4), one line each, severity-colored, click to expand to the run trace. *Not* a scrolling log — a curated feed. Empty state says "quiet" and means it.
4. **Run detail drawer** (click any row) — the trace waterfall, envelope stats, diff summary, approval history, the sealed receipt, and the kill switch with reason field.

That's the wedge. Everything else (fleet comparisons, per-agent history, budget policies, SSO, weekly reports) is phase 2.

**Why this wedge wins:** Datadog-for-agents pitches fail because they start with "instrument everything, build dashboards." This starts with the visceral demo: *"Here's your 14 agents running right now. That one has spent $38 in the last hour doing npm installs in a loop. [Kill]."* The kill button next to the live cost is the entire pitch. Monitoring without a kill switch is just anxiety as a service.

### Explicitly NOT in the wedge

- Custom dashboards / query language. (Phase 2. The fixed Fleet Command view is the product.)
- Log aggregation. (Agents' stdout is not the product; traces are.)
- APM-style service maps. (Agent fleets are trees, not meshes — the run tree *is* the map.)
- ML-based "AI insights." (§4 explains why.)

---

## 3. Architecture: one product, solo dev → 500-person org

### 3.1 The shape: collector → store → view

```
┌─────────────┐     ┌──────────────┐     ┌───────────────┐
│  agent-side │     │  local store │     │   dashboard   │
│  collector  │────▶│ (SQLite)     │────▶│ (localhost)   │
│  (shim/SDK) │     │  single file │     │  single binary│
└─────────────┘     └──────────────┘     └───────────────┘
        │                    │  ▲ optional relay
        │  zero-config       │  │ (TLS, batching)
        ▼  local-first       ▼  │
   ┌──────────────────────────────────────────┐
   │  team gateway (ingest + auth + retention) │
   │  central store (Postgres)                 │
   │  SaaS or self-hosted dashboard (SSO/RBAC) │
   └──────────────────────────────────────────┘
```

### 3.2 The collector: zero-code first, SDK second

**The solo-dev unlock is zero-code instrumentation.** Most agents Dan's users run (Claude Code, his own dev tools, ad-hoc scripts) won't be rewritten to emit spans. So:

- **`runlight wrap -- <any command>`**: a CLI shim that wraps an agent invocation, assigns `run_id`, captures exit status/wall time, and — via hooks into the agent framework where available (Claude Code hooks, tool-call interception in mcp-jail's stdio proxy, shortleash's receipt emission) — attaches tool/token/file telemetry. Where no hooks exist, it still records the envelope (duration, exit, cost estimated from any gateway traffic seen).
- **Framework hooks, not code changes**: Claude Code hooks (`PreToolUse`/`PostToolUse`) emitting JSONL to the collector; mcp-jail already proxies MCP stdio — it becomes a `tool.call` emitter for free; shortleash already emits receipts — the collector subscribes to them as run-close events.
- **Thin SDK** (Python/JS, <200 lines to integrate) for users building their own agents: `runlight.span("tool.call", ...)` — emits OTel-compatible spans to the local collector over a unix socket.

**Opinionated protocol decision:** emit **OTel-compatible spans** on the wire (so existing Datadog/Honeycomb/Grafana investments can ingest Runlight data — this defuses the "not another agent" objection in enterprise sales), but the product's first-class concept is the **Run envelope**, which OTel doesn't model. Runlight server reconstructs runs from spans + receipts. Don't force users into OTel religion; be bilingual.

### 3.3 Solo dev mode (default): local-first, $0, private

- One binary / one `pip install runlight`. `runlight dashboard` opens localhost. SQLite file in `~/.runlight/`. Nothing leaves the machine. Ever.
- This is the entire product for a solo dev: wrap your agents, watch the burn bar, kill the loop that's eating your API credits at 3am.
- Pricing implication: the solo tier is free forever — it's the top of the enterprise funnel, same playbook as the free tools feeding On File's audience.

### 3.4 Team/enterprise mode: the same binary, pointed at a gateway

- `runlight --gateway https://runlight.internal` — collectors batch and ship over TLS with an agent API key. Same schema, same dashboard, multi-fleet.
- **Team gateway** (self-hostable, single binary + Postgres): ingestion, API-key auth, retention enforcement, RBAC (who can see which fleet's traces; who can kill — kill is a separate permission from view, always).
- **SaaS option** for orgs that don't want to self-host: same gateway, Calas-operated, SSO (Google/Okta), audit log of every dashboard action (who killed what, when — this is a compliance feature, not a nice-to-have).
- **Data minimization as architecture**: secret redaction happens in the *collector*, before emission. The gateway never sees raw secrets even if TLS is terminated. File contents and prompts never leave the agent host unless the org explicitly enables "full capture" per fleet — and that toggle is itself audit-logged. This is the answer to the "52% blocked by security" finding: the security story isn't a whitepaper, it's that sensitive data is redacted at the edge by default.

### 3.5 Scaling notes (concrete, not hand-wavy)

- A 500-person org running agents aggressively: ~10k runs/day, ~50 spans/run → 500k spans/day. This is *small* for a columnar store; Postgres handles it, ClickHouse if they insist. The hard scaling problem is not volume — it's **live tail** (the Fleet Command view needs sub-second run-state updates). Solve with: collectors heartbeat run-state every 5s over the existing batch channel; gateway keeps a `live_runs` materialized view; dashboard polls or SSEs. No Kafka required at this scale. Say so explicitly — enterprise buyers are allergic to "you'll need to run Kafka."
- Multi-region: collectors are region-local; gateway is per-region with cross-region read replica for the dashboard. Don't build global ingestion on day one.

---

## 4. Anomaly detection without ML snake oil

No "AI-powered insights." Every detector below is a deterministic rule with a named threshold, a dedupe policy, and a plain-English explanation attached to the alert. If you can't write the rule on an index card, it doesn't ship.

### 4.1 The detectable set (concrete)

| # | Detector | Rule (index-card version) | Why it matters |
|---|---|---|---|
| 1 | **Spend velocity** | Agent's $/hr over trailing 60 min > 3× its trailing 7-day median (min $5/hr floor to avoid noise) | Catches the runaway loop before the invoice. The money detector. |
| 2 | **Run cost outlier** | Run's projected cost > P95 of that `agent_id`'s last 30 completed runs | "This run is nothing like its siblings." |
| 3 | **Loop detection** | Same `tool.call` with same arg-hash ≥ N times in a run (N=10 default) without a `file.op` or state change between | Catches ~most "agent stuck" cases deterministically. The highest-value single rule. |
| 4 | **First-seen tool** | `agent_id` invokes a tool it has never invoked in 30 days | New capability = new blast radius. |
| 5 | **First-seen egress host** | Run contacts a host never seen for this `fleet_id` | Exfiltration-shaped. Pairs with #6. |
| 6 | **Egress-after-ingest** | `net.egress` to a first-seen host within 5 min of a `tool.call` whose output contained a URL or >10KB payload | The closest thing to a deterministic exfiltration heuristic. High severity. |
| 7 | **Credential-adjacent file access** | `file.op` touching `*.pem`, `*.key`, `.env*`, `id_rsa*`, `*credentials*` for the first time for this agent | Secrets access is always worth one alert. |
| 8 | **Spawn storm** | `subagent.spawn` rate > 10/min for a single parent run | Fleet-amplified runaway. |
| 9 | **Approval denial → retry** | planok `denied` followed by same-gate request within 10 min, or ≥3 denials in an hour | Agent (or operator) fighting the human gate. |
| 10 | **Spinning run** | Run alive > P99 duration for its agent with <5 tool calls in last 15 min and tokens still burning | The "hung but spending" case. |
| 11 | **Guard-trip cluster** | ≥3 shortleash guard trips (budget/spawn/token/timeout) in one fleet in 15 min | Something systemic changed — new prompt, new model, new task shape. |
| 12 | **Savings collapse** | calas-gateway cache-hit rate for a fleet drops >20pp vs 7-day median | Silent cost increase — prompt change defeated the cache. Nobody else watches this. |

### 4.2 Alert discipline (this is where competitors die)

- **Alert only on transitions**: first-seen, threshold-crossing, recovery ("spend velocity back under threshold"). Never re-alert a continuing condition — the feed shows state, not a siren loop.
- **Dedupe key**: `(detector, agent_id, fingerprint)` with a 24h quiet period after acknowledge.
- **Severity is fixed per detector**, not computed: #6 is always critical; #4 is always info. No scoring model to mistrust.
- **Every alert links to the run trace** and names the exact rule + threshold + observed value. "Spend velocity: jarvis:code at $41/hr vs $9/hr median (rule: >3×)" — an eng manager can evaluate this in 5 seconds.
- **Baselines are per-`agent_id`, never global.** A code agent and a doc-chaser have nothing in common; global baselines are where false positives are born.

### 4.3 What we deliberately do NOT claim

- No "predicting failures." No sentiment on prompts. No LLM-judging-LLM "quality scores" — that's a demo feature that collapses under adversarial use and erodes trust in the real detectors.

---

## 5. Kill switch design

### 5.1 The four scopes, with exact semantics

| Scope | Target | Effect | Propagation |
|---|---|---|---|
| **Run** | one `run_id` | SIGTERM to the run's process tree → 10s grace → SIGKILL. Receipt sealed `killed_operator` with operator identity + reason. | Kills all descendant runs (the whole subtree). Idempotent — killing a dead run is a no-op that still logs. |
| **Agent** | one `agent_id` | Quarantine: all live runs killed (as above); **new runs for this `agent_id` are refused** at the collector/shim for a TTL (default 1h, configurable, or until manually cleared). | Applies fleet-wide in team mode. The "this agent is compromised/misbehaving" button. |
| **Fleet** | one `fleet_id` | **Freeze**: no new runs admitted; live runs get soft-stop (drain: finish current tool call, then seal) with a 5-min deadline, then hard-kill stragglers. | One action, whole fleet. The incident-response button. |
| **Tool** | one tool name (optionally per-fleet) | The tool becomes refused at every enforcement point (shim, mcp-jail proxy, framework hooks) with `tool_disabled_by_operator`. In-flight `tool.call` spans are allowed to complete (no mid-write kills — data corruption is worse than the extra 30 seconds). | Effective within seconds via gateway policy push; collectors cache the deny-list so it works if the gateway is unreachable. |

### 5.2 Non-negotiable semantics

1. **Kill is always audited.** Every kill records: who (dashboard user or API key), when, scope, target, reason (free text, required — "oops" is acceptable, empty is not), and the resulting receipt states. The audit log is append-only and visible to fleet admins. This is the compliance answer.
2. **Receipts are sealed even on kill.** A killed run is not a missing run — shortleash seals the receipt with `killed_operator`, partial cost, and the kill audit ref. The #1 observability failure mode is "the thing we killed left no trace." Never.
3. **Soft before hard, except when it isn't.** Default: drain (finish the current tool call, seal cleanly). Hard kill available per-action with a confirmation that names the blast radius ("kill 14 runs across 3 agents?"). Agent-scope quarantine and fleet freeze are always explicit operator actions — no automatic fleet-wide kills, ever. Automatic killing at fleet scope is how you turn an incident into an outage.
4. **Kill permission ≠ view permission.** RBAC: `viewer` sees traces; `operator` can kill runs; `admin` can quarantine agents / freeze fleets / disable tools. In solo mode all three are you.
5. **Kill must work when the dashboard is down.** The deny-list and quarantine state live in the gateway but are cached by collectors; `runlight kill` CLI works against the gateway API directly. Design for the incident where the pretty UI is the thing that's broken.
6. **Two-person rule (enterprise opt-in):** fleet freeze and tool-disable can require a second approver via planok. Default off for solo/small teams — friction kills adoption — available for the orgs whose compliance team demands it.

### 5.3 Relationship to existing guards (no turf war)

- **shortleash** = the *automatic* circuit breaker (budget/spawn/token/timeout guards trip without a human). Runlight *displays* guard trips as events and can *suggest* kills; it never overrides shortleash's automatic decisions.
- **planok** = the *human gate at start* (should this run begin?). Runlight = the *human gate during* (should this run continue?). One product story: "humans approve the start, humans can stop the middle, machines guard the edges."
- Kill signals flow *through* the existing enforcement points (shortleash's run supervisor, mcp-jail's proxy, the shim) — Runlight issues policy, it doesn't reimplement process control.

---

## 6. Consuming shortleash receipts and the calas-gateway ledger

**The single most important architectural decision: Runlight is a join layer, not another emitter.** Both systems already emit structured data. Duplicating their accounting would create the two-numbers-disagree problem that kills dashboard trust.

### 6.1 shortleash receipts → run envelopes

| shortleash receipt field | Runlight run field | Notes |
|---|---|---|
| `run_id`, `parent_run_id` | same | join key; tree reconstruction |
| `agent_id`, `fleet` | same | policy/scope keys |
| `started_at`, `ended_at`, `outcome` | envelope lifecycle | `outcome: killed` + `killed_by` → `status` |
| `tokens_in/out/cached` | same | never recomputed |
| `cost_usd` | `cost_usd` (gross) | authoritative; Runlight displays, doesn't derive |
| `guards_evaluated[]` | events + detector #11 input | each trip is an event on the run |
| `tool_calls`, `files_touched` | envelope counters | cross-checked against span counts; mismatch >5% raises a `telemetry_gap` event (the collector missed spans — worth knowing) |
| `kill_reason`, `killed_by` | `kill_source` + audit link | |

The collector **subscribes** to receipt emission (file watch on the receipts dir, or a socket in team mode). Receipt = run-close. Live runs are tracked via heartbeats + spans; the receipt seals them. If a run dies without a receipt (host crash), the gateway synthesizes a `receipt_missing` envelope after heartbeat timeout — flagged, cost estimated from spans, never silently dropped.

### 6.2 calas-gateway savings ledger → the net-cost story

The ledger emits per-request/per-run savings events: `run_id`, `cache_hit_tokens`, `estimated_cost_without_cache`, `actual_cost`, `saved_usd`, `strategy` (prompt-cache, response cache, model downgrade…).

Runlight joins on `run_id` and produces the number no one else shows: **net cost = gross − saved**, displayed as "$4.17 − $1.02 saved = **$3.15**". Fleet-level: "calas-gateway saved you $312 this week (38% of gross)." This turns the gateway from invisible plumbing into a visible ROI story — and detector #12 (savings collapse) watches for it silently breaking.

Opinionated: savings are displayed as a *memo*, never subtracted inside the authoritative cost field. Finance teams need gross; eng managers want net. Show both, label both, derive neither.

### 6.3 planok + mcp-jail as bonus emitters (same pattern)

- planok approval records → `human.approval` spans + detector #9 input. No new code — the collector tails planok's decision log.
- mcp-jail audit log → `tool.call` spans for MCP tools + the server name join to mcp-audit findings ("this run used `github-mcp`, last audited B+, 2 unresolved findings" — surfaced in the run drawer).

### 6.4 The schema contract (what Dan's other tools must guarantee)

For this to work, the emitters keep three promises — worth writing down as a cross-tool contract:

1. **Stable IDs**: `run_id` is a uuid assigned at run start and passed to every child/emitter. No ID, no join.
2. **Append-only, structured**: receipts/ledger/audit entries are JSONL, one record per line, never mutated after write. Corrections are new records.
3. **Cost computed once**: each emitter owns its numbers (shortleash: run cost; gateway: savings). Runlight never re-derives.

If a future tool wants to appear in Runlight, it implements these three and it's in. That's the ecosystem moat: each tool is useful alone; together they're the only suite where the agent's cost, safety, and approval story join up without integration work.

---

## 7. What could kill this product (honest risks)

1. **"Datadog will add an agents tab."** True and irrelevant if we win the wedge: Datadog's tab will be generic APM thinking applied to agents. Our moat is the run-envelope model + kill switch + the cost story joined to Dan's existing tools. Don't out-Datadog Datadog; own the agent-native layer.
2. **Instrumentation fatigue.** If `runlight wrap` isn't genuinely zero-config, nobody instruments and there's no product. The shim quality is the company.
3. **Alert fatigue.** One noisy detector poisons the whole feed. Ship with conservative defaults (fewer alerts, higher thresholds) and let users tighten. A quiet feed that catches the big one beats a chatty feed that's ignored.
4. **Enterprise security review.** The answer is architectural (§3.4): redaction at the collector, no prompts/file contents by default, self-hostable gateway, append-only audit log. Lead with this in every enterprise conversation — it's the 52%.
5. **Dan building all of it.** Scope discipline: the wedge (§2) is shippable by one person. Everything in "phase 2" stays unwritten until the wedge has 10 orgs watching their burn bar.

---

## 8. Open questions for Dan / the panel

1. **Name**: *Runlight* — check npm/PyPI/GitHub availability. Alternatives: Fleetwatch, Runlens.
2. **OTel stance**: bilingual (§3.2) is my recommendation — does the panel agree, or should we go all-in on our own protocol and offer OTel export only?
3. **Kill confirmation UX**: for fleet freeze, is a typed confirmation ("type FREEZE") right, or does it slow down incident response? I lean typed-confirmation for freeze, single-click for single-run kill.
4. **SaaS vs self-host first**: my read — ship self-hostable gateway first (the blocked-by-security buyers can't use SaaS anyway), add Calas-operated SaaS second. Agree?
5. **Pricing wedge**: free solo tier forever; team gateway priced per... what? Per run is the honest unit but punishes adoption; per seat undercounts value (agents aren't seats). Leaning: **per fleet + spend-based tiers** (e.g. free under $500/mo observed agent spend — aligns price with the value story: "we watch your $X/mo burn for $Y"). Panel input wanted.
6. **Does the wedge need the savings (net cost) story on day one**, or is gross-cost-only acceptable for v1 with net arriving when the gateway join lands? I lean: gross-only v1, net as the "and it gets better" — but the join is cheap since the ledger exists.

---

*End of brief. No implementation code written per instructions. The wedge in §2 is the build order: Fleet Command view → collector shim → receipt/ledger joins → detectors → kill switch hardening → team gateway.*
