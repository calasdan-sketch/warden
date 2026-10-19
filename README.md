# warden (working name)

**What did this agent do, with which credential, and why** — a harness-agnostic
runtime supervisor for AI agents. One static binary: wrap any agent command,
capture its behavior as spans, gate its tool calls against policy, seal a
signed per-run receipt even when the run is killed, and watch the fleet from an
embedded dashboard.

This is v1. The security floor is immutable: **redaction before emission,
deny-by-default egress, hash-chained audit, never a god-key.**

## 60-second demo

```bash
./warden init                                    # creates ~/.warden (db, keys, policy)
./warden wrap -- npm test                       # supervise any command; seals a receipt
./warden dashboard                              # http://127.0.0.1:8420 — burn bar, runs, alerts
```

## Commands

| Command | What it does |
|---|---|
| `init` | Self-heal setup: creates data dir, SQLite schema, signing key, default policy. Re-runnable. |
| `wrap [--agent X --fleet Y] -- <cmd>` | Run `<cmd>` under supervision. Gates the command against policy first (deny → refuse, approval → wait), records a span, seals a signed receipt on completion, failure, or kill. Handles SIGINT/SIGTERM: the run is sealed even when you Ctrl-C. |
| `span --kind …` | Emit a span from a framework hook or wrapper script (needs `WARDEN_RUN_ID` + `WARDEN_SOCK` in env — set automatically for wrapped children). Six span kinds: `llm.call`, `tool.call`, `file.op`, `net.egress`, `subagent.spawn`, `human.approval`. |
| `gate --tool T --args "…"` | Ask the policy engine directly. Exit 0 = allow, 3 = deny, 4 = require_approval. With `--await`, blocks until a human approves or denies. |
| `kill --scope run|agent|fleet|tool --target X --reason "…" [--actor Y]` | Kill switch. Run: SIGTERM → 10s grace → SIGKILL, seals `killed_operator` receipt. Agent: quarantine (+ optional `--ttl`). Fleet: freeze (runs soft-stop; nothing auto-killed fleet-wide, ever). Tool: deny-list (`--fleet` scope for the list). Reason is required; every action is audit-logged. |
| `approve --id N --decision approved|denied` / `approvals` | Decide pending human approvals; list them. |
| `dashboard [--listen 127.0.0.1:8420] [--budget 500]` | Embedded web UI: live burn bar, run table with per-row kill, anomaly feed, approvals queue, run-detail trace waterfall with the sealed receipt. Localhost by default (no auth); with `WARDEN_TOKENS=secret=role,...` it's bearer-token RBAC: viewer < operator < admin. |
| `verify [--run ID]` | Verify receipt signatures + the hash chain. |
| `scan` | Run the 12 anomaly rules over live runs and print new alerts. |
| `report --from shortleash|planok|mcp-jail|calas-gateway --file X [--watch]` | Ingest a sibling tool's JSONL feed (stable IDs, append-only). Costs from shortleash are treated as authoritative. |
| `export [--format jsonl|otlp] [--out FILE]` | Dump the audit trail: JSONL envelope (runs, spans, receipts, kill audit) or OTLP/HTTP JSON spans for Datadog/Honeycomb/Grafana. |
| `version` | Build info. |

## Architecture (one binary, local-first)

```
wrapped agent → socket JSONL → collector (redact → policy gate → store)
                                      ↓
                        SQLite (spans, runs, events, alerts, receipts,
                                kill audit, approvals)
                                      ↓
            dashboard (live SSE) · receipts (Ed25519 + hash chain)
            · anomaly engine (12 deterministic rules, no ML)
```

- **Collector** (`internal/collect`): the choke point. Every span is redacted
  *before* emission, evaluated against policy at the tool-call boundary, then
  stored. No network in the hot path.
- **Policy** (`internal/policy`): deny-by-default, in this eval order —
  dynamic deny-list → static deny_tools → shell deny patterns → approval_tools →
  shell allowlist → allow. Egress is deny-by-default with `allow_hosts`.
  Touching a credential-adjacent path (`.env`, `~/.ssh/*`, `~/.aws/*`, `*.pem`,
  `id_rsa*`, …) requires human approval — including when the path appears as an
  argument to an otherwise-allowed shell command.
- **Receipts** (`internal/receipt`): Ed25519-signed, hash-chained per-run
  envelopes. Sealed on completion, failure, and kill. If the warden process
  itself dies (SIGKILL, host crash), the next dashboard run reconciles the
  orphaned run as `receipt_missing` — a killed run is never a missing run,
  but the receipt says honestly what happened.
- **Anomalies** (`internal/anomaly`): 12 deterministic rules — spend_velocity,
  run_cost_outlier, loop_detection, first_seen_tool, first_seen_egress_host,
  egress_after_ingest, credential_adjacent_file, spawn_storm,
  approval_denial_retry, spinning_run, guard_trip_cluster, savings_collapse.
  Transition-only alerting: rules 1,2,3,8,9,10,11,12 auto-recover; rules 4–7
  (first_seen_tool, first_seen_egress_host, egress_after_ingest,
  credential_adjacent_file) are ack-to-clear by design.
- **Joins** (`internal/join`): shortleash → sealed runs, planok → approval
  spans, mcp-jail → tool.call spans, calas-gateway → cost-saved memos.
  Runs without a known run id land in an `unattached:<agent>` bucket.

## Policy file

`$WARDEN_DIR/policy.yaml` (or `--policy`). Example:

```yaml
version: 1
shell:
  default: deny
  allow: [git, go, python3, node]
  deny_patterns: ['rm\s+-rf\s+/(?:\s|$)']
  approval_tools: [kubectl]
egress:
  default: deny
  allow_hosts: [api.anthropic.com, api.openai.com]
files:
  credential_adjacent: require_approval   # or deny
```

## Data & durability

- Default data dir: `~/.warden` (`WARDEN_DIR` overrides). One SQLite file,
  one Ed25519 key (0600), one policy file.
- `init` is idempotent and runs migrations forward; schema is append-friendly
  (alerts/events are transition-only, export is append-only JSONL).
- The dashboard reconciles every 5 minutes: runs with no heartbeat for >15
  minutes **and** no live, start-time-verified process are sealed as
  `receipt_missing`. A quiet-but-alive run (e.g. a long `wrap` that emits no
  spans) is never sealed early — the shim heartbeats while its child lives.
  `scan` only runs the anomaly rules; it does not reconcile.

## What v1 deliberately leaves for v1.1

- **Postgres** — SQLite only in v1 (single-binary, zero-setup story).
- **SSO/SAML** — bearer-token RBAC is the v1 stand-in (Compliance tier).
- **Two-person rule** — approvals are single-decider in v1.
- **Cost-proportional sampling** — all spans are stored; no sampling yet.
- **Signing-key rotation** — one Ed25519 key per data dir, no rotation ceremony yet.

## Threat model (read this before trusting the audit trail)

Warden v1 is a **solo-operator** tool: the supervisor and the supervised agent
run as the **same OS user**. That sets hard limits, stated plainly:

- **The agent can read `~/.warden`.** The receipt-signing key (0600) and the
  SQLite store are readable by the same UID the wrapped agent runs as. A
  sufficiently motivated malicious agent could forge receipts or rewrite
  history. Mitigations, in order: run the agent as a **separate UID** (or in
  a container) with `WARDEN_DIR` owned by the operator; treat the
  **SIEM export as the second copy** — an attacker must compromise both the
  store and the SIEM to rewrite history undetected; `verify` detects
  tampering after the fact, it does not prevent it.
- **The socket is untrusted input.** The supervised process inherits
  `WARDEN_SOCK` and can emit arbitrary spans/events for its own run —
  including fake `guard_trip` events. The collector redacts and policy-gates
  everything, and the wire can never set `pre_decided` (only the in-process
  join layer may), but warden cannot distinguish a lying hook from a truthful
  one. Hooks are trusted code: keep them out of the agent's write path.
- **The join layer trusts the JSONL files.** `report --from` treats sibling
  tools' append-only logs as authoritative (shortleash receipts are even
  re-sealed under warden's key). Those files must be written by the trusted
  tool, not the agent.
- **Pattern-based shell policy is a speed bump, not a sandbox.** Deny
  patterns (`rm -rf /`, fork bombs) match command *text*; obfuscated
  equivalents evade them, and `wrap` cannot see syscalls — it gates the
  command string before execution. True network/process enforcement belongs
  in framework hooks (`warden gate`) or a real sandbox, not in v1.
- **Deny-by-default egress** applies to `net.egress` spans at the policy
  gate. `wrap` alone cannot observe or block the child's actual network
  calls; hooks reporting egress get the enforcement.
- **Kill is best-effort against a hostile child.** Process-group kill
  (SIGTERM → 10s → SIGKILL) with PID start-time verification, but a child
  that re-execs into a new session (`setsid`) escapes the group. The receipt
  still records what warden saw.
- **Deterministic anomaly rules can be ramped around.** Baselines are
  per-agent history; a compromised agent that increases spend slowly will
  not trip velocity rules. The rules catch accidents and crude attacks, not
  patient adversaries.
- **Dashboard tokens** travel in `Authorization: Bearer` headers; the SSE
  endpoint also accepts `?token=` (EventSource cannot set headers) — prefer
  header auth and rotate tokens; solo mode (no tokens) binds localhost only.

## Enforcement points, honestly

| Path | What is enforced |
|---|---|
| `wrap -- <cmd>` | Command text gated pre-execution (deny → refuse, approval → wait). No syscall/net visibility into the child. |
| `gate` (framework hook) | Pre-execution decision for one tool call; exit 0/3/4. Use `--shell` when the harness's tool name is not a known shell name. The hook is the real enforcement point for network and tool calls. |
| `span` (framework hook) | Telemetry only — always policy-gated at the collector, never self-approved. |
| Dashboard / CLI `kill` | Run/agent/fleet/tool, audited, reason required. |
