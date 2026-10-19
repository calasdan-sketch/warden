# Gap #12 Blueprint: Agent Flight Recorder (name TBD — see §7)

Synthesized from 4 expert briefs (2026-10-18):
- `panel-security-architect.md` — CISO requirements, control plane, self-hosted-first
- `panel-observability.md` — telemetry primitives, Fleet Command, 12 deterministic anomaly rules
- `panel-saas-strategist.md` — packaging, land-and-expand, pricing tiers
- `panel-competitive.md` — reality check (Endor Labs, Runlayer $42M), the real hole, kill criteria

## The wedge (all four panels converged)

**The agent's black box / flight recorder.** A harness-agnostic runtime supervisor that records every shell command, file touched, API call, and dollar into a signed per-run receipt, enforces policy pre-execution, and answers: *"what did this agent do, with which credential, and why."*

The 60-second demo: any agent framework → live action ticker → one blocked `.env` read with a human-readable reason → one signed receipt at the end → kill button per run.

**Why this hole is real** (competitive panel): Endor Labs owns *coding-agent* governance on laptops. Runlayer owns MCP gateways. Nobody owns **production agents** with **harness-agnostic runtime enforcement** and **one fused console** (actions + policy + approvals + spend + anomaly) behind a buy button instead of a sales call.

## 1. Scope: v1 = the smallest shippable that unblocks a pilot

1. **Runtime collector** — captures 6 span kinds: `llm.call`, `tool.call`, `file.op`, `net.egress`, `subagent.spawn`, `human.approval`. Run is the unit (long-lived, hierarchical — not OTel's request model, but OTel-compatible on the wire).
2. **Signed per-run receipts** — hash-chained, sealed even on kill. The audit artifact the CISO inspects.
3. **Live fleet view** — burn bar (gross + net cost, ticking), run table sorted by cost with per-row kill, anomaly feed, run-detail drawer with trace waterfall.
4. **Policy gates pre-execution** — deny-by-default at tool-call boundary (shell, network egress, credential use). Human approval gates for destructive actions.
5. **Kill switch** — 4 scopes with exact semantics: run (SIGTERM→grace→SIGKILL, subtree, idempotent), agent (quarantine + TTL), fleet (freeze: drain then hard-kill), tool (deny-list push). Always audited with required reason. No automatic fleet-wide kills ever.
6. **SIEM/audit export** — one-click export; append-only JSONL.

**Explicit v1 non-goals:** ML anomaly detection (12 deterministic rules only), multi-region, SAML/SSO (Compliance tier feature, stub the hooks), log rotation UI.

## 2. Architecture

```
Agent process
  └─ wrap shim / framework hook (zero-code instrumentation)
       └─ Collector (redaction BEFORE emission — secrets never leave the box)
            ├─ SQLite (solo: single binary, localhost dashboard, free forever)
            └─ Postgres (team: self-hostable gateway, RBAC, append-only audit)
  Dashboard: embedded web UI (solo) → gateway UI (team)
  OTel-compatible wire: bilingual, ingest into Datadog — don't fight it
```

**Join layer, not another emitter.** Consumes existing tools via `--report-to`:
- shortleash receipts → run envelopes (automatic guard)
- planok logs → approval spans (human gate at start)
- mcp-jail logs → MCP tool spans (this product = human gate *during*)
- calas-gateway ledger → net-cost story ("$4.17 − $1.02 saved = $3.15")
- mcp-audit findings → joined to tool spans

Cross-tool contract: stable IDs, append-only JSONL, cost computed once.

## 3. Anomaly detection (v1): 12 deterministic rules, no ML

Spend velocity, run-cost outlier, loop detection (same tool+args ≥N — highest value), first-seen tool/egress host, egress-after-ingest (exfiltration heuristic), credential-adjacent file access, spawn storms, approval-denial→retry, spinning runs, guard-trip clusters, savings collapse. Fixed severity, alert-on-transition only, baselines per agent_id. Every alert names rule + threshold + observed value.

## 4. Security floor (immutable)

- Redaction in the collector before emission (secret patterns from mcp-audit's library + 12 new)
- Deny-by-default egress; coverage report proving no side channels
- Audit trail: append-only, hash-chained, signed; SIEM sink as second copy
- The product must never become the god-key: its own credential store is the #1 pentest target — minimal privilege, documented threat model

## 5. Language & delivery

**Go**, single static binary (consistent with ContextRouter; the panel's "one binary in their VPC" requirement). Embedded web dashboard. `install → wrap → dashboard` in 3 commands. SQLite default, Postgres via flag.

## 6. Pricing & packaging (SaaS strategist's model, adopted)

"The tools are free, the *proof* is paid." OSS CLIs stay fully functional.

| Tier | Price | What |
|------|-------|------|
| Open | $0 | Solo: single binary, SQLite, localhost dashboard, unlimited |
| Team | $99/mo | 25 managed agents ($3/agent after), fleet view, policy sync |
| Compliance | $549/mo | 100 agents ($2.50/agent after), SSO, retention, evidence export, SLA |
| Enterprise | Custom (floor $2k) | Self-hosted, custom retention, dedicated support |

Land-and-expand: dev (CLI/HN) → eng manager (Team) → CISO (Compliance). PLG-to-sales handoff at ~25 managed agents. Human seats free unlimited — price per managed agent, never per seat.

**Caveats:** self-hosted tier needs 3 signed LOIs before building; status page + runbook before first Compliance signature.

## 7. Name — 3 proposals for Dan (NOT locked)

1. **warden** — security architect's pick. Fits the one-word lowercase convention, CISO-invoice-safe, "the agent-safety company" flagship energy.
2. **runlight** — observability pick. "Turn on the lights for your agent runs." Friendly, demoable.
3. **paddock** — SaaS strategist's pick. Where you keep agents under control. Distinctive.

(Rejected: RunTape, Corral, Stable, Watchtower [overused], Kennel [too jokey], Harness [collides with Harness.io], Overwatch [Blizzard].)

## 8. Kill criteria (mechanical tripwires)

1. Langfuse/LangSmith adds tool-span policies → they own the installed base
2. Endor expands beyond coding harnesses to production agents
3. Cloudflare adds per-tool allow/deny in MCP portal
4. Any observability vendor adds a policy-decision field to spans

If tripwire 1 fires within 8 weeks of our launch: pivot to "the policy layer that plugs into Langfuse" instead of competing.

## 9. Build phases (v1)

- **P1 — Collector + spans:** wrap shim, 6 span kinds, SQLite store, redaction at emission
- **P2 — Receipts + policy:** signed per-run receipts, deny-by-default gates, approval hooks
- **P3 — Fleet view:** embedded dashboard, live burn bar, kill switch (4 scopes), anomaly feed (12 rules)
- **P4 — Joins:** `--report-to` ingestion from shortleash/planok/mcp-jail/calas-gateway
- **P5 — Harden:** scrutiny panel, fix criticals/highs, race/stress tests

Test criteria per phase in implementation plan. No network calls in the hot path. Everything local-first.
