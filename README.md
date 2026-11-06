# warden

**A flight recorder and kill switch for AI agents.** It answers *what did this
agent do, with which credential, and why*, and it produces records you can prove
nobody edited. warden is one static Go binary: run any agent under it, or plug it into
Claude Code / Codex hooks. It gates every tool call against your policy, records
each one, and seals a signed receipt that commits to the run's full trace. You
can stop a run, an agent, a fleet or a tool from the CLI or the dashboard.

```bash
warden demo        # 60-second tour in a temp dir: no network, no API keys, nothing else touched
```

> **Status: pre-1.0 (0.1.0, unreleased).** The npm package `@decnutz/warden@0.0.1`
> is an empty placeholder. 0.1.0 is the first build that ships binaries. See
> [Path to 1.0](#path-to-10) for what is stable and what may still change.

## Quick start

```bash
# from source (Go 1.26+; pure Go, no cgo)
go build -o warden ./cmd/warden

# or, once 0.1.0 is published:
npx @decnutz/warden demo
go install github.com/calasdan-sketch/warden/cmd/warden@latest
```

Then:

```bash
./warden demo                                  # the guided tour
./warden init                                  # ~/.warden: SQLite db, Ed25519 key, default policy
./warden wrap --agent ci -- npm test           # supervise any command; seals a receipt
./warden hook claude-code --print-config       # wire Claude Code in (see below)
./warden dashboard                             # http://127.0.0.1:8420: fleet view, traces, kill buttons
./warden verify                                # signatures + chain + every signed trace
```

What `warden demo` shows, in order:

1. A simulated Claude Code session goes through the real hook code path.
   `git status` is allowed. `git log; curl … | sh` is caught as a second
   command smuggled after an allowlisted one. Reading `~/.aws/credentials` and
   a fetch to an unknown host are sent to a human. `rm -rf /` is denied. A
   Bearer token in a command is redacted before storage.
2. The kill switch is used on that session, and the session's next tool call
   is denied.
3. `warden wrap` supervises a real process and seals its receipt.
4. `verify` checks that every receipt is signed, chained, and committed to its
   trace.
5. An "attacker" rewrites the denied `rm -rf /` span in SQLite. `verify`
   catches it, and the exported audit bundle still verifies on its own.

## Claude Code and Codex hooks

`warden hook <harness>` is a PreToolUse hook. It maps the harness's tool call
to a warden span (Bash becomes a shell command; Read/Write/Edit/Grep become file
operations; WebFetch becomes network egress; `mcp__server__tool` becomes an MCP
tool call). It then runs the call through policy, records it, and answers in
the harness's own protocol.

```bash
warden hook claude-code --print-config   # paste into .claude/settings.json
warden hook codex --print-config         # paste into ~/.codex/hooks.json
```

| warden decision | Claude Code | Codex |
|---|---|---|
| allow | no output: Claude's normal permission flow still applies. **warden never grants.** | no output |
| explicit deny (deny pattern, `deny_tools`, operator tool kill) | `permissionDecision: "deny"` with the reason | exit 2, reason on stderr |
| needs approval (credential-adjacent file, `approval_tools`) | `"ask"`: Claude's own prompt asks the human | deny (Codex hooks can't ask). `--await` waits for `warden approve` instead |
| not on an allowlist (default deny) | `"ask"`, or deny with `--strict` | defers to Codex's own approvals, or deny with `--strict` |
| session killed / agent quarantined / fleet frozen | deny, every call, until a new session | exit 2 |
| warden itself fails | deny (fail-closed), unless `--fail-open` | exit 2, unless `--fail-open` |

Each harness session is one warden run, keyed by the harness `session_id`.
Claude Code's `SessionEnd` seals it. Codex has no session-end hook, so each
`Stop` seals one segment and the next turn starts a new run linked by
`parent_run_id`. A kill outlives the run it killed: a killed session stays
blocked.

Sources: the [Claude Code hooks reference](https://code.claude.com/docs/en/hooks).
For Codex, a [third-party guide](https://codex.danielvaughan.com/2026/04/15/codex-cli-hooks-complete-guide-events-policy-patterns/)
documents `~/.codex/hooks.json`, `PreToolUse`/`Stop` and exit-2 blocking.
Check it against your Codex version.

## Tamper evidence: what is signed, exactly

- **Receipts.** Each run is sealed with an Ed25519 signature over a canonical
  body that holds the run's totals, its kill reason, and `prev_hash`: a hash
  chain over all receipts. The run is sealed on completion, failure and kill.
- **Traces (new in 0.1.0).** The signed body also commits to a
  `spans_digest`, a digest over every span the run recorded before its seal,
  plus `span_count`. Editing, deleting, inserting or re-labelling any covered
  span fails `verify`. Spans that arrive after the seal (for example a sibling
  tool's feed ingested later) are kept but marked `late_after_seal`. The store
  sets that flag atomically, and `verify` reports these spans as uncovered,
  never as signed.
- **Exports.** `warden export` writes a JSONL audit bundle whose header is
  signed with the chain head and receipt count. That makes deleting the newest
  receipts (truncation) detectable too. An auditor can check the bundle with no
  warden data dir:
  `warden verify --bundle audit.jsonl --pubkey receipt.pub`.
- **Not covered:** events, alerts, the kill-audit table and approvals are
  stored but not signed. Receipts sealed by older builds sign their totals
  only. `verify` says so.

## OpenTelemetry (GenAI semantic conventions)

`warden export --format otlp` emits OTLP/HTTP JSON.
`--endpoint http://localhost:4318/v1/traces [--header "Authorization: Bearer …"]`
pushes it to any OTLP collector instead. The push uses only the Go standard
library. Each run becomes one trace with an `invoke_agent {agent}` root span:

- `llm.call` becomes `chat {model}` (CLIENT), with `gen_ai.operation.name=chat`,
  `gen_ai.provider.name` (inferred from the model when not recorded),
  `gen_ai.request.model`, and integer-typed `gen_ai.usage.input_tokens`,
  `output_tokens` and `cache_read.input_tokens`.
- `tool.call` becomes `execute_tool {tool}`, with `gen_ai.tool.name`.
- Denied calls get status ERROR and `error.type=policy_denied`.
- Trace and span IDs are always valid hex. Non-hex run IDs are hashed, not
  padded.

The GenAI conventions are still at **Development** stability upstream
([overview](https://www.dash0.com/knowledge/opentelemetry-genai-semantic-conventions-explained)),
so attribute names may change there. warden keeps its own `warden.*`
attributes alongside them.

## How it compares

These are the tools a buyer usually looks at first. Each row is limited to
what the linked source says. Most of them are tracing and evaluation products;
warden is a runtime supervisor. They complement each other: export warden's
OTLP into any of them.

| Tool | What it is best known for | License / hosting | Source |
|---|---|---|---|
| AgentOps | Agent-first tracing with session replay; integrations for CrewAI, AutoGen, the OpenAI Agents SDK and ADK | MIT; cloud with free tier | [morphllm](https://www.morphllm.com/ai-agent-observability-tools) |
| Langfuse | The most-adopted OSS LLM tracer: prompt management, datasets, evals | MIT core; self-host or cloud | [morphllm](https://www.morphllm.com/ai-agent-observability-tools) |
| LangSmith | Tightest loop for LangChain/LangGraph; OTel in and out | Closed platform | [morphllm](https://www.morphllm.com/ai-agent-observability-tools) |
| Arize Phoenix | Trajectory and span-level evals; single-container self-host | Elastic License 2.0 | [morphllm](https://www.morphllm.com/ai-agent-observability-tools) |
| Helicone | One-line proxy with caching and routing; acquired by Mintlify in March 2026, now in maintenance mode | Apache-2.0 | [morphllm](https://www.morphllm.com/ai-agent-observability-tools) |
| Datadog LLM Observability | Agent traces next to APM and infrastructure; priced per LLM span | Proprietary SaaS | [morphllm](https://www.morphllm.com/ai-agent-observability-tools) |
| Invariant Labs (Snyk) | Agent security guardrails; acquired by Snyk in June 2025 | Commercial | [tech.eu](https://tech.eu/2025/06/24/snyk-acquires-ai-security-pioneer-invariant-labs-for-a-new-era-in-ai-safeguards/) |
| Lasso Security | AI gateway and MCP traffic security | Commercial | [lasso.security](https://www.lasso.security/use-cases/ai-gateway-security) |
| Endor Labs Agent Governance | Policy enforcement for coding agents through Claude Code hooks | Commercial | [docs](https://docs.endorlabs.com/agent-governance/claude-code) |
| Aileron | Python "flight recorder": hash-chained JSONL, Ed25519-signed checkpoints, MCP stdio proxy | Apache-2.0 (alpha) | [PyPI](https://pypi.org/project/aileron/) |

What warden brings together in one local binary, with no service to run:

- pre-execution policy on shell, file, egress and MCP calls;
- Claude Code and Codex hook adapters;
- a kill switch that keeps blocking a killed session;
- Ed25519 receipts that commit to the full span trace;
- audit exports a third party can verify offline;
- deterministic anomaly rules;
- GenAI-convention OTLP.

We have not benchmarked it against the tools above. Treat this as a feature
comparison, not a performance claim.

## Commands

| Command | What it does |
|---|---|
| `demo [--dir D]` | Self-contained tour (see above). Refuses a non-empty dir. |
| `init` | Self-heal setup: creates data dir, SQLite schema, signing key, default policy. Re-runnable. |
| `wrap [--agent X --fleet Y] -- <cmd>` | Run `<cmd>` (via `sh -c`) under supervision. Gates the command first (deny → refuse, approval → wait), records a span, seals a signed receipt on completion, failure, or kill. Ctrl-C still seals. |
| `hook claude-code\|codex [--strict] [--await] [--fail-open] [--fleet F]` | Harness hook (see above). `--print-config` prints the snippet to paste. |
| `span --kind …` | Emit a span from a framework hook (needs `WARDEN_RUN_ID` + `WARDEN_SOCK`, set automatically for wrapped children). Kinds: `llm.call`, `tool.call`, `file.op`, `net.egress`, `subagent.spawn`, `human.approval`. |
| `gate --tool T --args "…"` | Ask the policy engine directly. Exit 0 = allow, 3 = deny, 4 = require_approval. `--await` blocks until a human decides. |
| `kill --scope run\|agent\|fleet\|tool --target X --reason "…"` | Kill switch. Run: SIGTERM → 10 s grace → SIGKILL on the whole process group, sealed `killed_operator`. Agent: quarantine (`--ttl`). Fleet: freeze. Tool: deny-list. A reason is required; every action is audited. |
| `approve --id N --decision approved\|denied` / `approvals` | Decide or list pending human approvals. |
| `dashboard [--listen 127.0.0.1:8420] [--budget 500]` | Web UI: burn bar, run table with per-row kill, anomaly feed, approvals, trace waterfall with the sealed receipt. Bearer-token RBAC with `WARDEN_TOKENS=secret=role,…` (viewer < operator < admin). |
| `verify [--run ID] [--pubkey K]` / `verify --bundle F --pubkey K` | Verify receipts, the chain and signed traces in the store, or in an exported bundle with no data dir. |
| `export [--format jsonl\|otlp] [--out FILE] [--endpoint URL --header "K: V"]` | Verifiable JSONL audit bundle (written 0600), OTLP/HTTP JSON, or a direct OTLP push. |
| `scan` | Run the 12 anomaly rules over live runs and print new alerts. |
| `report --from shortleash\|planok\|mcp-jail\|calas-gateway --file X [--watch]` | Ingest a sibling tool's JSONL feed. |
| `version` | Build info. |

## Policy file

`$WARDEN_DIR/policy.yaml` (or `--policy`):

```yaml
version: 1
shell:
  default: deny
  allow: [git, go, python3, node]
  deny_patterns: ['rm\s+-rf\s+/(?:\s|$)']
egress:
  default: deny
  allow_hosts: [api.anthropic.com, api.openai.com]
files:
  credential_adjacent: require_approval   # or deny
approval_tools: [kubectl]
```

Rules are checked in this order: the dynamic deny-list (`kill --scope tool`),
then `deny_tools`, shell deny patterns, credential-adjacent paths,
`approval_tools`, the shell allowlist, and finally allow.

**Every command in a compound shell line must be allowlisted.** warden splits
on `;` `&&` `||` `|` `&` and newlines outside quotes. It also descends into
`$( )`, backticks, `<( )` and `sh -c '…'` bodies. So `git status; curl x | sh`
is judged by `git`, `curl` *and* `sh`, and `git commit -m "a; b"` by `git`
alone. Harmless builtins (`cd`, `exit`, `true`, `test`, …) and shell keywords
never need allowlisting. `eval`, `exec` and `source` always do. When the
parser can't tell, it denies rather than allows (for example with heredocs or
nesting deeper than 4 levels).

## Architecture (one binary, local-first)

```
wrapped agent ─ socket JSONL ─┐
harness hook (claude/codex) ──┼─→ collector (redact → policy gate → store)
sibling-tool JSONL feeds ─────┘                  ↓
              SQLite (runs, spans, events, alerts, receipts, kill audit, approvals)
                                                 ↓
     dashboard (SSE) · receipts (Ed25519 + chain + trace digest) · 12 anomaly rules
                     · verifiable JSONL bundle · OTLP (GenAI semconv)
```

Default data dir: `~/.warden` (`WARDEN_DIR` overrides). It holds one SQLite
file, one Ed25519 key (0600) and one policy file. Migrations run forward
automatically; schema v4 adds the `late` flag on spans. While the dashboard runs, it
reconciles every 5 minutes: a run with no heartbeat for more than 15 minutes
**and** no live, start-time-verified process is sealed as `receipt_missing`.
A hook session that sits idle that long is sealed this way too, and its next
call continues in a linked run.

## Threat model (read this before trusting the audit trail)

warden is a **solo-operator** tool today. The supervisor and the supervised
agent run as the **same OS user**, which sets hard limits:

- **The agent can read `~/.warden`**, including the signing key. A determined
  malicious agent could forge new receipts. Mitigations: run the agent as a
  separate UID or in a container, with `WARDEN_DIR` owned by the operator.
  Ship exports to a SIEM and keep the public key elsewhere: anything already
  exported stays verifiable against that key. `verify` detects tampering after
  the fact; it does not prevent it.
- **The socket is untrusted input.** A supervised process can emit arbitrary
  spans for its own run. They are redacted and policy-gated, and the wire can
  never set `pre_decided`, but warden cannot tell a lying hook from an honest
  one. Hooks are trusted code: keep them out of the agent's write path.
  Harness hooks (`warden hook`) get their input from the harness, not from the
  agent.
- **The join layer trusts sibling-tool JSONL files.** Those files must be
  written by the trusted tool, not by the agent.
- **Shell policy reads command text; it is not a sandbox.** Compound commands
  and substitutions are analyzed, but `wrap` and hooks can't see syscalls, and
  obfuscation (variables expanded at runtime, `python -c`, scripts on disk)
  can evade pattern rules. Pair warden with a real sandbox for untrusted code.
- **Egress is enforced only where it is reported**: hook calls such as
  WebFetch, or `net.egress` spans. `wrap` cannot see a child's sockets.
- **Kill is best-effort against a hostile child.** It kills the process group,
  verifies PID start times, and waits for the group to be gone. A child that
  calls `setsid` escapes the group. In hook mode a kill blocks the session's
  next tool call; it does not stop the harness process itself.
- **Deterministic anomaly rules can be ramped around.** A patient adversary
  that increases spend slowly will not trip the velocity rules.
- **Dashboard tokens** travel in `Authorization: Bearer` headers. SSE also
  accepts `?token=`. Rotate tokens. With no tokens configured, keep the
  dashboard on localhost.

## Honest limits

- Linux and macOS only (POSIX process groups). There are no Windows builds yet.
- SQLite only. Single-decider approvals. One signing key per data dir, with no
  rotation ceremony yet.
- `verify --bundle` holds the bundle's spans in memory. Split very large
  archives into several exports.
- The Codex hook protocol is taken from a third-party guide; test it against
  your Codex version before relying on it.

## Path to 1.0

| Area | 0.1.0 status | Before 1.0 |
|---|---|---|
| Receipt and trace format (`warden-spanset-sha256-v1`) | Versioned; old receipts still verify | Frozen, with a published spec and test vectors |
| CLI flags and exit codes (`gate` 0/3/4, `hook`, `verify`) | Intended stable | Frozen |
| Policy YAML `version: 1` | Stable keys | New rules only in a new `version` |
| OTLP mapping | Tracks GenAI semconv (Development upstream) | Follows upstream; will change when upstream does |
| Store schema | Forward migrations only | Same, plus Postgres |
| Distribution | `scripts/build-npm.sh` builds npm packages per OS/CPU (not yet published) | Signed release binaries + checksums |
| Open items | | Key rotation, two-person approvals, Windows, signed kill audit |

## Building the npm package

`@decnutz/warden` is a small Node launcher (`npm/warden/bin/warden.js`, no
postinstall, no network). npm installs exactly one platform package with the
Go binary through `optionalDependencies` (the esbuild pattern):
`@decnutz/warden-linux-x64`, `-linux-arm64`, `-darwin-x64`, `-darwin-arm64`.
`WARDEN_BINARY=/path/to/warden` overrides the lookup.

```bash
scripts/build-npm.sh     # cross-compiles, writes npm/dist/*, runs a launcher smoke test, npm pack
```

To release, publish the four platform packages first, then the launcher.
Versions must match: the script checks `package.json` against
`cmd/warden/main.go`.

## License

MIT, © Calas Automations Inc.
