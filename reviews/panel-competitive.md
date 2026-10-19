# Competitive Strategist Brief — Gap #12: Agent Action Governance / "What Did the Agent Do?"

**Date:** 2026-10-18 | **Panel role:** Competitive Strategist | **Product:** Gap #12 (enterprise AI-agent pilot blocker: security + monitoring at scale)

## Bottom line

The "wide-open gap" claim is **wrong as stated, right once you narrow it.** Nobody owns "LLM-call observability." But *agent-action governance* — what the agent DID: shell commands run, files touched, MCP tools called, packages installed — is not unclaimed. **Endor Labs shipped exactly this in May 2026.** Runlayer ($42M raised) owns the MCP gateway layer, Mintive (ex-MintMCP) covers governed MCP + agent identity, Apono (acquired by 1Password, June 2026) owns just-in-time agent privilege, and Cisco/CrowdStrike/Cloudflare are all pushing into the execution layer. The wide-open field has armed occupants.

The real hole is narrower but genuine: **harness-agnostic, production-runtime action governance for ALL agents — not just coding agents — with cost and anomaly fused into the same console, and a buyable (local-first, transparent-priced) package instead of an enterprise sales motion.** Nobody does that. Dan's existing five tools (shortleash, planok, mcp-audit, mcp-jail, calas-gateway) are the puzzle pieces; this product is the frame that turns them into one thing.

---

## 1. Who touches this today — scope by scope

### Runlayer — the funded threat ($11M seed Nov 2025 + $30M Series A, Felicis + Khosla, ~$42M total)
- **What they sell:** an MCP security gateway. Okta-style directory of pre-approved MCP servers mapped to employee identities (Okta/Entra), real-time risk scoring *per MCP request*, approval workflows for sensitive actions, and full-chain audit logs for compliance. GA planned this year, with on-prem and multi-cloud coming.
- **What they miss:** they govern **MCP protocol traffic only**. An agent that shells out, writes files, opens PRs, or calls a raw API outside MCP is outside their field of view. Their audit unit is the MCP request, not the agent's action history. They are a pipe, not a runtime supervisor. Also enterprise sales motion, quote-based pricing — the $500+/mo pain point stands for the long tail.
- **Threat level:** HIGH in the medium term. If Runlayer extends from "MCP request audit" to "all agent side effects + policy," they eat this space. Watch their on-prem GA and any "EU AI Act evidence pack."

### Endor Labs — Coding Agent Governance (launched May 12, 2026) — the direct occupant
- **What they sell:** deterministic policy enforcement on agent actions via harness hooks (Claude Code `permissionDecision: "deny"`, Cursor hooks). Logs *every* prompt, tool call, shell command, file read; 29 default policies; blocks `rm -rf`, `.env`/`.pem` reads, DROP queries, prompt injection; plus Package Firewall (blocks malicious package installs at install time), MCP server allow/deny lists, and Endor Scores rating MCP servers/skills against OWASP Top-10-for-LLM. Evidence export for EU AI Act / ISO 42001 / customer security reviews.
- **What they miss:** it is **coding-agent governance for developer machines** — Cursor, Claude Code, Copilot, Google Antigravity. It works through *per-harness hook integrations*, so every new harness needs a new adapter, and it does not cover production agents (support agents, data agents, scheduled RPA-style agents) that never touch an IDE. It is also sold as part of a supply-chain-security platform (AURI engine) — heavy, enterprise, no transparent entry price. Nothing here fuses spend/cost monitoring or fleet anomaly detection.
- **Threat level:** HIGHEST near-term. Their normalization layer across Claude/Cursor vocabularies is one step away from a generic runtime collector. If they announce "agent governance beyond coding harnesses," the wedge closes.

### Mintive (formerly MintMCP) — enterprise MCP governance
- **What they sell:** MCP Gateway (Virtual MCP bundles with SCIM-driven RBAC, credential injection, tool curation), Agent Gateway (first-class non-human agent identities with bearer/M2M tokens, independent rotation/revocation), Agent Monitor (visibility into prompts, commands, file access, MCP tool calls, token costs), Mint Guard (prompt-injection/PII/secret detection). SOC 2 Type II, HIPAA BAAs. Official Cursor Hooks partner.
- **What they miss:** employee-facing AI governance (internal Copilots, data permissions), not the autonomous-agent runtime fleet. Pricing is enterprise quote-only. Their Monitor is *visibility*, not deterministic pre-execution policy on arbitrary actions.
- **Threat level:** MEDIUM. They're drifting toward this space (Agent Gateway + Monitor) but from the identity/governance side, not the runtime-action side.

### Apono Agent Privilege Guard (acquired by 1Password, June 2026)
- **What they sell:** zero-standing-privilege for agents — just-in-time, task-scoped, ephemeral credentials; intent-based access control; human-in-the-loop approvals with full audit trails; prevents non-human identity sprawl.
- **What they miss:** they answer "what CAN the agent reach" (privilege), not "what DID the agent do, second by second" (behavior). This is Dan's planok territory, not Gap #12 territory — adjacent, complementary, and now 1Password-owned, which means it'll get bundled, not sold standalone.
- **Threat level:** LOW as a direct competitor; validates that approval/JIT is table stakes, not the differentiator.

### The observability five — LangSmith / Langfuse / Helicone / Laminar / Arize
- **What they cover (all of them):** LLM-call tracing (multi-step chains, prompts, tokens, latency, cost per model), prompt versioning, LLM-as-judge evals. Prices: LangSmith $39/seat/mo, Langfuse $29/mo (MIT core, acquired by ClickHouse Jan 2026), Helicone $79/mo (Apache 2.0, acquired by Mintlify Mar 2026), Laminar $30/mo (Apache 2.0), Arize AX $50/mo.
- **What they miss:** their audit unit is the **prompt/completion**, not the action. They will happily show you the 47 LLM calls of a run; they will not show you the `rm -rf` the agent executed, and none of them *enforces policy* on it. None produces auditor-consumable evidence of *what was done* — they produce debugger views of *what was said*.
- **Threat level:** MEDIUM-HIGH. They are all OTel-native or OTel-compatible now. Adding "tool-span policy decisions" plus a rules UI is an easy feature, not a hard product. They own the installed base (the "monitoring agents at scale" buyers already pay them). **This is the most likely "kill" vector.**

### The platform giants — Cloudflare, Cisco, CrowdStrike
- **Cloudflare:** AI Gateway (routing, caching, rate limits, request logs), Zero Trust MCP traffic detection (beta `experimental.is_mcp` selector, Aug 2026), Identity-Aware AI Gateway (Aug 2026: who sent what to which model), MCP portal with Access policies. This is *network-perimeter* thinking: they see MCP over HTTP, not local shell/file actions.
- **Cisco AI Defense:** added runtime protections against tool abuse and supply-chain manipulation at the MCP layer (Feb 2026).
- **CrowdStrike:** moving into the execution layer per AGAT (2026).
- **What they miss:** they protect the wire and the identity; nobody watches the agent's *hands* (local process/file/syscall level). Also all enterprise-stack sales.
- **Threat level:** MEDIUM over 12 months; SLOW movers. They validate the category; they won't ship a crisp standalone product in 6 months.

### Cloud sandboxes (E2B, Modal, Daytona)
- **What they cover:** isolated execution environments — *where* the agent runs, not *what it does* or *whether it should have*.
- **What they miss:** everything governance-shaped. A sandbox with no policy is just a nicer cage.

---

## 2. Is the gap real? Where exactly is the hole?

The hypothesis — "everyone does LLM-call observability OR sandboxing, but nobody does agent-action governance tied to policy" — is **half-right, and the half that's wrong matters**.

**What's claimed and actually taken:** deterministic policy on agent actions (shell, file, MCP tool calls) with audit evidence — Endor Labs owns it for coding agents on developer machines. MCP-level identity + request policy — Runlayer/Mintive own it. Agent privilege + approvals — Apono/1Password own it.

**The actual hole — three seams nobody sits in:**

1. **Production agents, not coding agents.** Everything agent-action-shaped today is aimed at the developer's laptop (Cursor/Claude Code hooks). The support agent refunding customers, the data agent touching Snowflake, the scheduled ops agent running nightly jobs — these have no black box. Endor's hook model can't reach them; Runlayer's gateway can't see non-MCP actions.

2. **Harness-agnostic enforcement at the runtime layer, not the hook layer.** Endor needs a per-harness adapter (Claude's hook format ≠ Cursor's ≠ the next framework's). A supervisor that sits *under* the harness — at the process/syscall boundary — works with every agent framework and survives framework churn. Nobody ships this standalone; the sandbox vendors don't do policy, the observability vendors don't sit at the syscall layer.

3. **One fused console: actions + policy + approvals + spend + anomaly.** Today these are five separate purchases: Langfuse for traces, Endor for coding-agent policy, Apono/planok for approvals, Helicone for cost, Runlayer for MCP. The "52% blocked by security, 51% by monitoring at scale" stat is a *budget-consolidation* signal: nobody wants a sixth dashboard. Dan already owns four of the five pieces.

So: the gap is not "agent governance" — it's **the fleet black box: every agent, every action, every dollar, one policy engine, one receipt per run, any harness, with a buy button instead of a sales call.**

---

## 3. Kill criteria — what kills this in 6 months, and the tripwires

Ranked by likelihood:

| # | Kill event | Why it's the threat | Mechanical tripwire |
|---|---|---|---|
| 1 | **Langfuse or LangSmith ships tool-span policies** — rules on tool calls (allow/deny/approve) evaluated in their tracer, since they're already OTel-native | They own the installed base; a "policy" tab is a feature, not a product; pricing already accepted ($29–$39) | Changelog/PR mentioning "tool policies," "action policies," or "policy decisions" on traces; Langfuse v4+ minor release notes |
| 2 | **Endor Labs goes beyond coding agents** — generic runtime agent governance for production agents | They already normalize cross-harness events and have 29 policies + evidence export; this is their natural expansion | Endor blog/changelog: "beyond the IDE," "production agents," "server-side agents," or a non-hook collector |
| 3 | **Cloudflare adds tool-level allow/deny in the MCP portal + Gateway** — full agent-action policy on the wire | They already detect MCP traffic and have the Zero Trust policy engine; fastest enterprise distribution on earth | `is_mcp` selector moves out of beta; MCP portal docs gain per-tool rules; Guardrails add masking/approval actions |
| 4 | **Runlayer GA + on-prem with EU AI Act evidence packs** | Turns "MCP audit" into the de-facto compliance artifact; auditors accept it, and the budget is gone | Runlayer GA announcement; pricing page appears; "evidence pack" or "EU AI Act" in their docs |
| 5 | **A second player raises $20M+ for "agent runtime governance"** | Validates the hole and funds a direct competitor with distribution | Funding announcements; TechCrunch keyword watch: "agent runtime," "agent action governance" |

**Leading indicator to watch monthly:** any of the observability five adding a *decision* field (allowed/blocked/approved) to their span model. The day traces carry policy decisions, the observability layer absorbs the governance layer — and the standalone window closes.

---

## 4. The wedge — the 60-second demo nobody else has

**The product is the agent's black box — a harness-agnostic runtime supervisor that records every action of every agent into a signed per-run receipt, enforces policy before execution, and fuses cost and anomaly into one fleet console.** In the demo: you start any agent (any framework, any CLI) under the supervisor. A live ticker shows every shell command, every file touched, every API call, every dollar as it happens. One command tries to read `.env` — the ticker flashes BLOCKED, the agent gets a human-readable reason and a safe alternative, and the run continues. At the end, one signed artifact — the run receipt — answers "what did this agent do, with which credential, and why" for an auditor, a customer security review, or EU AI Act evidence. Nobody else demos cross-harness, because Endor needs your harness's hooks, Runlayer needs your MCP traffic, and Langfuse needs you to look at prompts. This watches the agent's *hands*, not its mouth.

Why Dan wins the race here: he already built the components (shortleash = the circuit breaker, planok = the approval gate, mcp-audit/mcp-jail = the MCP layer, calas-gateway = the cost layer). This product is the frame that turns five repos into one buyable thing. First-to-market is credible because the incumbents are each expanding *from their side* (hooks, gateways, traces) and none starts from the runtime layer.

Entry strategy: local-first, transparent pricing (the $500/mo pain point is real — every competitor is quote-only or seat-based enterprise). Land on solo/small teams running coding agents *today*, grow into the fleet console as their agents go to production.

---

## 5. Names (style: ShortLeash, Flakebox — short, vivid)

1. **RunTape** — the black-box recorder metaphor; "run the agent, read the tape." Instantly demoable, says exactly what it does.
2. **Tattler** — mischievous, memorable; it tells on your agent. Stands out in a field of serious-sounding governance products. (Risk: slightly unserious for enterprise buyers — but so was Flakebox.)
3. **AgentAlibi** — the audit-receipt angle: cryptographic proof of what the agent did. Strong for the compliance-evidence story; slightly longer but sticky.

Runner-up: **Blackbox** (taken as a generic term, but the metaphor is the right one — RunTape captures it without the collision).
