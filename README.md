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

> **Status: pre-1.0 (0.2.0, unreleased).** The npm package `@decnutz/warden@0.0.1`
> is an empty placeholder. 0.2.0 is the first build intended to ship binaries. See
> [Path to 1.0](#path-to-10) for what is stable and what may still change.

## Quick start

```bash
# from source (Go 1.26+; pure Go, no cgo; builds for Linux, macOS and Windows)
go build -o warden ./cmd/warden

# or, once 0.2.0 is published:
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
./warden runs                                  # recent runs: find the id of the one that went wrong
./warden replay last                           # step through it: timeline, verdicts, tamper check
./warden bench                                 # what warden costs per tool call, on YOUR machine
```

What `warden demo` shows, in order:

1. A simulated Claude Code session goes through the real hook code path.
   `git status` is allowed. `git log; curl … | sh` is caught as a second
   command smuggled after an allowlisted one, and `PATH=/tmp:$PATH git status` as
   an attempt to swap in another `git`. Reading `~/.aws/credentials` and
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
| explicit deny (deny pattern, `deny_tools`, operator tool kill, touching warden's own files or the harness hook config) | `permissionDecision: "deny"` with the reason | exit 2, reason on stderr |
| needs approval (credential-adjacent file, `approval_tools`) | `"ask"`: Claude's own prompt asks the human | deny (Codex hooks can't ask). `--await` waits for `warden approve` instead |
| not on an allowlist, or a risky form of an allowlisted command (default deny) | `"ask"`, or deny with `--strict` | defers to Codex's own approvals, or deny with `--strict` |
| session killed / agent quarantined / fleet frozen | deny, every call, until a new session | exit 2 |
| warden itself fails (unreadable data dir, broken policy, locked DB, crash) | deny (fail-closed), unless `--fail-open` | exit 2, unless `--fail-open` |

Each harness session is one warden run, keyed by the harness `session_id`.
`SessionEnd` (both harnesses) seals it. A session that never sends it is sealed
by the idle reconciler, and its next call continues in a new run linked by
`parent_run_id`. A kill outlives the run it killed: a killed session stays
blocked. Codex `apply_patch` calls are judged per file the patch touches, and
the worst result wins.

Sources: the [Claude Code hooks reference](https://code.claude.com/docs/en/hooks)
and the [official Codex hooks docs](https://learn.chatgpt.com/docs/hooks)
(`developers.openai.com/codex/hooks` redirects there). Both were checked on
2026-11-06. Codex points worth knowing:

- Codex runs non-managed hooks only after you trust them with `/hooks`.
- Codex can't ask a human from a hook (`"ask"` is unsupported there), so warden
  denies with exit 2.
- Codex documents a failed, timed-out or malformed `PreToolUse` hook as *not*
  blocking the tool. That is fail-open on Codex's side, which warden cannot
  override, so keep the hook timeout generous.

## Tamper evidence: what is signed, exactly

- **Receipts.** Each run is sealed with an Ed25519 signature over a canonical
  body that holds the run's totals, its kill reason, and `prev_hash`: a hash
  chain over all receipts. The run is sealed on completion, failure and kill.
- **Traces.** The signed body also commits to a
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
- **Bundle checks are strict.** `verify --bundle` checks every field of each
  receipt's readable header against the signed body, and rejects unknown record
  types. It lists every record no signature covers, prefixed `UNSIGNED`: late
  spans, spans of runs with no receipt, and run and kill-audit rows. It fails
  when unsigned spans are present, unless you pass `--allow-unsigned`.
- **Not covered:** events, alerts, the kill-audit table and approvals are
  stored but not signed. Receipts sealed by older builds sign their totals
  only. `verify` says so.

## Replay an incident (`warden replay`)

When something went wrong, `warden replay <run|prefix|last>` shows what the agent
did, step by step, and whether you can trust the record:

```bash
warden replay last                          # timeline: +time, kind, what, verdict (allow / DENY / ASK)
warden replay last --only-gated             # just the denied, asked and failed steps
warden replay last --step 7                 # state after step 7: calls, denies, tokens, cost,
                                            #   files touched, hosts contacted, plus the steps around it
warden replay last --what-if new-policy.yaml   # re-judge every recorded call under a candidate policy
warden replay last --html incident.html     # one self-contained page (no network), j/k to step
warden replay --bundle audit.jsonl --pubkey receipt.pub <run>   # an auditor's copy, no data dir
```

- **Integrity comes first.** The header says `VERIFIED` (receipt signature and signed
  trace digest match), `TAMPERED` (and the command exits 3), `LEGACY` (receipt predates
  trace digests) or `UNSEALED` (no receipt). Spans recorded after the seal are marked
  as not covered.
- **What-if is a counterfactual, not a prediction.** It re-runs the policy over the
  *recorded* (already redacted) calls. It shows which would now be blocked
  ("would the new policy have stopped this?") or newly allowed ("will the new policy
  break our workflow?"). Calls that were stopped by operator state (kill, quarantine,
  freeze) are listed as not replayable. It does not re-run anything.
- Everything in the trail is untrusted text. Terminal escapes, bidi and zero-width
  characters are stripped; the HTML page is rendered with `textContent` under a
  `default-src 'none'` content-security policy.

## Anchor the chain off the machine (`warden anchor`)

The threat model below is blunt: whoever holds the signing key can re-sign the whole
chain. `warden anchor` closes that gap in the one way software can. It emits a small
signed statement (chain head, receipt count, time). Ship it somewhere the agent
cannot write: a SIEM, an object store with a retention lock, another host.

```bash
warden anchor --out /mnt/worm/warden-anchors.jsonl     # run from cron, hourly for example
warden verify --anchors /mnt/worm/warden-anchors.jsonl # every anchored head must still sit at its place in the chain
warden verify --bundle audit.jsonl --pubkey receipt.pub --anchors anchors.jsonl
```

If the chain is later rewritten (even completely re-signed with a stolen key) or the
newest receipts are deleted, the anchors that already left the machine no longer match,
and `verify` fails. Older anchors stay valid as the chain grows. An anchor only protects
history up to its timestamp, and only as well as the place you put it.

## OpenTelemetry (GenAI semantic conventions)

`warden export --format otlp` emits OTLP/HTTP JSON.
`--endpoint http://localhost:4318/v1/traces [--header "Authorization: Bearer …"]`
pushes it to any OTLP collector instead. The push uses only the Go standard
library. Each run becomes one trace with an `invoke_agent {agent}` root span:

- `llm.call` becomes `chat {model}` (CLIENT), with `gen_ai.operation.name=chat`,
  `gen_ai.provider.name` (inferred from the model when not recorded),
  `gen_ai.request.model`, and integer-typed `gen_ai.usage.input_tokens`,
  `output_tokens` and `cache_read.input_tokens`.
- `tool.call` becomes `execute_tool {tool}`, with `gen_ai.tool.name` and,
  from hooks, `gen_ai.tool.call.id` (the harness `tool_use_id`).
- Denied calls get status ERROR and `error.type=policy_denied`.
- Trace and span IDs are always valid hex. Non-hex run IDs are hashed, not
  padded.

The GenAI conventions are still at **Development** stability upstream
([overview](https://www.dash0.com/knowledge/opentelemetry-genai-semantic-conventions-explained)),
so attribute names may change there. warden keeps its own `warden.*`
attributes alongside them.

## What gets redacted, and what does not

Redaction runs in the collector, before anything is stored, exported or hashed.
It masks (replacing the value, keeping the key name where there is one):
vendor tokens (AWS, GitHub, GitLab, Slack and Discord webhooks, Stripe, Google, OpenAI
`sk-`/`sk-proj-`, Anthropic, npm, Hugging Face, SendGrid, Shopify and others), private-key
blocks (also when cut off), JWTs, `user:password@` in **any** URL scheme (postgres, mongodb,
redis, ...), `Authorization` and API-key headers, Azure/SAS secrets, `--password x` style
flags, `mysql -pSECRET`, and `KEY = value` assignments with spaces or quotes (including
names like `AWS_SECRET_ACCESS_KEY`, `DB_PASSWORD`). Base64 text that decodes to a vendor
token is masked too. Counters such as `max_tokens=1024` or `password_policy: strong` are left
readable. Zero-width, bidi and control characters are stripped before matching, so a
secret split by an invisible character is still found.

Limits, stated plainly: it is pattern-based, with no entropy guessing. An unquoted value
is cut at `&`, `;` or `,` (a password containing those leaks its tail); a secret with
no recognisable prefix or key name, in free text, is not found; and only simple base64
(no nesting, no other encodings) is decoded. The recall numbers below come from a corpus we
wrote ourselves; treat them as a regression guard, not an independent audit.

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

### Measured on one machine (2026-11-07)

Install footprint, measured by installing each into a fresh Python 3.13 virtual
environment (an empty one is 13 MB) from PyPI, on a 2-CPU Linux VM. These are the
client libraries only: Langfuse and Phoenix also run a server (Langfuse's self-hosted
stack was not run here, so its footprint is **unverified**).

| | install time | size on disk | packages | what you get |
|---|---|---|---|---|
| **warden 0.2.0** | copy one file | **12.3 MB** (Linux, stripped; 12.4 MB Windows) | 0 dependencies | recorder + gate + kill + dashboard + CLI |
| [aileron 0.1.6](https://pypi.org/project/aileron/) | 1 s | 32 MB | 8 | hash-chained log, checkpoints, HTML report, MCP proxy |
| [langfuse](https://pypi.org/project/langfuse/) (SDK) | 4 s | 37 MB | 31 | tracing SDK |
| [agentops](https://pypi.org/project/agentops/) | 4 s | 41 MB | 39 | tracing SDK |
| [traceloop-sdk](https://pypi.org/project/traceloop-sdk/) (OpenLLMetry) | 11 s | 66 MB | 88 | tracing SDK |
| [arize-phoenix](https://pypi.org/project/arize-phoenix/) | 29 s | 635 MB | 146 | tracing + evals server and UI |

What each does, from its own docs or from running it (anything else is "unverified"):

| Capability | warden | aileron | Langfuse / Phoenix / AgentOps / Traceloop | Microsoft Agent Governance Toolkit | Teleport (agent access) |
|---|---|---|---|---|---|
| Blocks a tool call before it runs | yes (hooks, wrap, gate) | yes (MCP stdio proxy rules; ran its demo) | no: observability and evals | yes: stateless policy engine on every action, p99 under 0.1 ms reported ([source](https://www.helpnetsecurity.com/2026/04/03/microsoft-ai-agent-governance-toolkit/)) | yes: RBAC on MCP tools ([source](https://goteleport.com/use-cases/agentic-ai/)) |
| Kill switch (run / agent / fleet / tool) | yes | not in its CLI | no | yes ("emergency termination") | not described on the page we read |
| Claude Code and Codex hook adapters | yes | not in its CLI | no (SDK or OTel instrumentation) | unverified | unverified |
| Tamper-evident signed record | yes: Ed25519 receipts, chain, signed trace digest | yes: hash chain, signed checkpoints | no | not stated in the article we read | audit log and session recording; signing unverified |
| Verify an export offline, with only a public key | yes | unverified | no | unverified | unverified |
| Anchor the chain off-machine | yes (`anchor`) | unverified (checkpoints are the closest) | no | unverified | unverified |
| Secret redaction before storage | yes (see above) | none found: no redaction code in the 0.1.6 package | varies by product, unverified | unverified | unverified |
| Incident replay | yes: timeline, state at a step, what-if policy, HTML | yes: single-file HTML report; `detect` replays a log | trace viewers; session replay in AgentOps (per [summary](https://www.morphllm.com/ai-agent-observability-tools)) | unverified | session recording |
| Counterfactual ("would policy B have stopped this?") | yes | not found | no | unverified | unverified |
| Runs on Windows | builds and vets; **not yet run on a real Windows host** | pure Python | yes | yes (.NET and Python) | yes |

Other vendors (LangSmith, Helicone, Datadog LLM Observability, Invariant Labs, Lasso,
Endor Labs) are described in the first table above; we did not run them, and we cannot
say how they compare on speed or footprint.

### Benchmarks you can re-run

```bash
warden bench                      # hook latency (fresh process per tool call), policy and redaction cost
go test ./internal/redact -run 'Corpus' -v     # secret redaction recall + false-positive guard
go test ./internal/policy -run 'Evasion|Benign' -v   # shell-policy evasion corpus + false-positive guard
```

| Measure | Before (0.1.0 code) | Now (0.2.0) |
|---|---|---|
| Shell-policy evasion corpus (57 commands that must not be allowed) | 18 blocked, **39 bypasses** | **57 blocked**, 0 bypasses; 28 benign commands still allowed |
| Secret-redaction corpus (46 cases: vendor tokens, URLs, headers, flags, assignments, encodings) | 14 redacted, 32 leaked | **46 redacted**; 13 benign strings untouched |
| Hook calls wrongly denied under 8-way concurrency ("database is locked", fail-closed) | 12-32% of calls | 0 of 2400 (4 to 32-way, fresh and existing data dir) |
| Hook round trip p50 / p99 (2-CPU VM, `warden bench`) | not measured | about 9 ms / 14 ms |
| Policy decision for a compound shell line | n/a | about 60 us |
| Redaction, 1 KB of clean text | n/a | about 80 us (13 MB/s); 5 MB of padding in under 0.5 s |

The two corpora were written by us after hands-on testing, so the "before" numbers
show the gaps we found, not an independent score. They are committed so anyone can add
a case that breaks us.

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
| `verify [--run ID] [--pubkey K] [--anchors FILE]` / `verify --bundle F --pubkey K [--allow-unsigned] [--anchors FILE]` | Verify receipts, the chain and signed traces in the store, or in an exported bundle with no data dir. |
| `export [--format jsonl\|otlp] [--out FILE] [--endpoint URL --header "K: V"]` | Verifiable JSONL audit bundle (written 0600), OTLP/HTTP JSON, or a direct OTLP push. |
| `scan` | Run the 12 anomaly rules over live runs and print new alerts. |
| `runs [--limit N --agent A --status S]` | List recent runs (find the id to replay). |
| `replay <run\|prefix\|last> [--step N] [--only-gated] [--what-if FILE] [--json] [--html FILE]` | Step through a recorded run (see above). `--bundle FILE --pubkey KEY` replays an export with no data dir. Exits 3 when the trail fails verification. |
| `anchor [--out FILE]` | Emit a signed chain-head anchor to ship off the machine. `verify --anchors FILE` checks it. |
| `bench [--n N]` | Measure hook latency, policy and redaction cost on this machine. |
| `report --from shortleash\|planok\|mcp-jail\|calas-gateway --file X [--watch]` | Ingest a sibling tool's JSONL feed. |
| `version` | Build info. |

## Policy file

`$WARDEN_DIR/policy.yaml` (or `--policy`):

```yaml
version: 1
shell:
  default: deny
  allow: [git, ls, cat, grep]        # see "What to allowlist" below
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

Each simple command is also parsed so it can't sneak around the allowlist:

- **Paths.** `./git`, `/tmp/git` and `/usr/local/bin/git` are not `git`. Only
  `/bin`, `/usr/bin`, `/sbin` and `/usr/sbin` count as the allowlisted name,
  because an agent can't write there. Any other path must be allowlisted
  exactly as written.
- **Environment.** Assigning or `export`ing variables that change what code
  runs is denied: `PATH`, `LD_*`, `DYLD_*`, `GIT_*`, `HOME`, `BASH_ENV`,
  `PYTHON*`, `NODE_*`, `EDITOR`/`PAGER`, `WARDEN_*` and others. `FOO=1 git
  status` is fine.
- **Wrappers.** `env` and `sudo` options are parsed exactly. `env -S`,
  `sudo -s`, `sudo -i` and unknown options are denied, never guessed.
- **git.** Known ways to make git run arbitrary code are denied: `-c`,
  `--config-env`, `--exec-path`, `--upload-pack`, `clone -u`, `rebase -x`,
  `config`, `submodule`, `bisect`, `difftool` and similar. git still runs
  repository hooks and aliases, so allowlisting git means trusting the repo.
- **warden itself.** An agent may not run `warden`, so it can't approve its
  own requests.
- **rm.** Flags are normalized before deny patterns run, so `rm -r -f /`,
  `rm -fr /` and `rm --recursive --force /` all meet an `rm -rf /` pattern.
  Recursive force-deletes of `/`, `/*`, `~` and `$HOME` are always denied.

- **Writes.** Output redirections (`>`, `>>`, `&>`), `-o`/`--output` options and the
  arguments of writer programs (`cp`, `mv`, `tee`, `dd`, `sed`, ...) to shell startup
  files (`.bashrc`, `.zshrc`, `authorized_keys`, ...), system paths (`/etc`, `/usr`, ...),
  git hooks, autostart/systemd user units and similar are sent for approval (or denied
  with `credential_adjacent: deny`). Raw devices (`/dev/sda`, `/dev/nvme0n1`) are always
  denied. This applies even when the writer is an allowlisted command.
- **git leaving the machine.** `git push|fetch|pull|clone|ls-remote|remote` with a URL or
  `user@host:path` argument must name a host in `egress.allow_hosts`. A bare remote name
  (`git push origin main`) is allowed: it trusts the remotes you configured.
- **Environment dumps.** `env`, `printenv`, `set`, `export -p`, `declare -p` and
  `/proc/<pid>/environ` can print every secret in the process; they need approval.
- **Long commands.** A shell command over 256 KiB is refused, not analyzed.

**What to allowlist.** The default allowlist is `git ls cat echo mkdir pwd
head tail wc grep diff sort which`: commands that can't run other code or
reach the network. Interpreters and build tools (`python3`, `node`, `npm`,
`go`, `make`, …) run whatever code they are handed, and `curl`/`wget` move data
past the egress policy. Allowlisting any of them allowlists *everything*. Add
them only if you accept that, ideally with a sandbox.

**warden protects itself.** The policy denies any tool call that mentions or
touches warden's data dir (`~/.warden` or `WARDEN_DIR`), its policy file,
`receipt.key`, or a harness hook config. This covers globs and brace
expansion (`~/.war*/receipt.ke?`, `~/.{warden,x}`) and paths inside
interpreter code. The harness hook configs are `.claude/settings*.json`,
`.codex/hooks.json` and `.codex/config.toml`; reading those is allowed,
changing them is not. Credential directories (`.ssh`, `.aws`, `.gnupg`,
`.kube`, …) match with or without a trailing slash. Also covered: `.pgpass`, `.my.cnf`,
`.vault-token`, `~/.config/gh`, keychains, browser profiles, `terraform.tfstate`, `*.tfvars`,
`/etc/shadow`, `*.kdbx`, and similar.

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
automatically (schema v4 adds the `late` flag on spans, v5 the `tool_call_id`). While the dashboard runs, it
reconciles every 5 minutes: a run with no heartbeat for more than 15 minutes
**and** no live, start-time-verified process is sealed as `receipt_missing`.
A hook session that sits idle that long is sealed this way too, and its next
call continues in a linked run.

## Threat model (read this before trusting the audit trail)

warden is a **solo-operator** tool today. The supervisor and the supervised
agent run as the **same OS user**, which sets hard limits:

- **The signing key is only policy-protected.** warden denies the tool calls
  it can see that touch `~/.warden` (see "warden protects itself"). Under the
  same OS user, though, anything the policy misses can still read
  `receipt.key`: a script on disk, an allowlisted interpreter, or a variable
  expanded at runtime. Whoever holds the key can re-sign the whole chain. **The
  real fix is outside warden's reach today**, so do one of these:
  - run the agent as a **separate OS user** (or in a container) with
    `WARDEN_DIR` owned by the operator and mode 0700;
  - or anchor the chain externally: run `warden anchor --out FILE` on a schedule and
    ship the file (or each export, whose signed header carries the chain head) to a
    SIEM or write-once store the agent can't reach, and keep `receipt.pub` there.
    `warden verify --anchors FILE` then fails if history was rewritten or newest
    receipts were deleted, even with a stolen key. Anything exported before a
    compromise stays verifiable.

  `verify` detects tampering after the fact; it does not prevent it.
  OS-keychain storage and third-party timestamping (RFC 3161) are on the 1.0 list.
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

- Linux and macOS are the tested platforms. **Windows is experimental**: warden builds
  and passes `go vet` for windows/amd64 and windows/arm64, `wrap` uses `cmd /C` and
  kills the process tree with `taskkill /T`, but nobody has run it on a real Windows
  host yet, and the test suite has not been run there.
- SQLite only. Single-decider approvals. One signing key per data dir, with no
  rotation ceremony yet.
- `verify --bundle` holds the bundle's spans in memory. Split very large
  archives into several exports.
- Codex hook failures and timeouts are fail-open by Codex's design (see the
  hooks section).

## Path to 1.0

| Area | 0.2.0 status | Before 1.0 |
|---|---|---|
| Receipt and trace format (`warden-spanset-sha256-v1`) | Versioned; old receipts still verify | Frozen, with a published spec and test vectors |
| CLI flags and exit codes (`gate` 0/3/4, `hook`, `verify`) | Intended stable | Frozen |
| Policy YAML `version: 1` | Stable keys | New rules only in a new `version` |
| OTLP mapping | Tracks GenAI semconv (Development upstream) | Follows upstream; will change when upstream does |
| Store schema | Forward migrations only | Same, plus Postgres |
| Distribution | `scripts/build-npm.sh` builds npm packages per OS/CPU, including experimental win32 (not yet published) | Signed release binaries + checksums |
| Open items | | Key rotation, OS-keychain/separate-user key storage, RFC 3161 timestamping of anchors, two-person approvals, tested Windows support, signed kill audit |

## Building the npm package

`@decnutz/warden` is a small Node launcher (`npm/warden/bin/warden.js`, no
postinstall, no network). npm installs exactly one platform package with the
Go binary through `optionalDependencies` (the esbuild pattern):
`@decnutz/warden-linux-x64`, `-linux-arm64`, `-darwin-x64`, `-darwin-arm64`, `-win32-x64`, `-win32-arm64` (the last two experimental).
`WARDEN_BINARY=/path/to/warden` overrides the lookup.

```bash
scripts/build-npm.sh     # cross-compiles, writes npm/dist/*, runs a launcher smoke test, npm pack
```

To release, publish the four platform packages first, then the launcher.
Versions must match: the script checks `package.json` against
`cmd/warden/main.go`.

## License

MIT, © Calas Automations Inc.
