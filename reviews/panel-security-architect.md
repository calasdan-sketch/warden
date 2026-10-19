# Gap #12 — Enterprise Agent Security & Governance
## Expert Panel Brief: Enterprise Security Architect

**Verdict: build it. This is the highest-leverage gap in the dev-tool line.** Dan's existing tools are endpoint controls; nobody has shipped the *control plane* that lets a CISO sign the purchase order. The buyer is not the developer — it's the security team that currently says "no."

**What this product is in one sentence:** the policy, identity, and audit layer that sits between an enterprise's agent fleet and everything those agents can touch — the thing a CISO points at and says "our agent governance lives there."

---

## 1. The top 5 concrete security requirements (what a CISO actually asks for)

**R1 — Immutable, attributable audit trail of every agent action.**
Not "logs." A tamper-evident record per agent run: run ID, agent identity, human owner/sponsor, tool invoked, full arguments (with secrets redacted and replaced by hashes), return values (classified), timestamps, policy decision made, and the policy version that made it. Hash-chained, signed, append-only. Exportable to the enterprise's SIEM (syslog/CEF + S3/GCS sink) within minutes, because if it doesn't land in Splunk/Datadog/Sentinel, the SOC team will never adopt it. Retention configurable (90 days default, 7 years for regulated). **This is requirement zero** — every compliance conversation (SOC 2, ISO 27001, HIPAA) starts here.

**R2 — Policy gates at the tool-call boundary, deny-by-default on the dangerous three.**
Policy is enforced at the single choke point every agent tool call passes through. Minimum viable policy set a CISO will accept:
- **Shell/exec:** deny by default; allowlist of commands, sandboxing, no network in shell unless explicitly permitted.
- **Network egress:** deny by default; allowlist of hosts/domains per agent/team; block known exfiltration patterns (webhooks, pastebins, file-sharing).
- **Credential use:** agents never hold credentials. The product brokers short-lived scoped tokens; the agent gets an opaque handle. No standing API keys in agent config, ever.
- Policies are versioned in git, diffable, reviewed like code. Per-team and per-run overrides with expiry.

**R3 — Agent identity and least-privilege credentials.**
Every agent run is a security principal: named identity (e.g. `agent/billing-recon/team-finance`), tied to a human sponsor, issued credentials scoped to the run with a TTL (minutes, not months). Kill the identity, kill the access. Standing credentials in `.env` files and MCP configs are how pilots die in security review — this requirement is what unblocks them.

**R4 — Data-boundary controls (DLP on tool inputs/outputs).**
Classification of data crossing the boundary (PII/PHI/secrets/customer data), redaction in the audit trail, blocking exfiltration to unapproved destinations. Plus prompt-injection handling on *untrusted tool output* (web content, email bodies, file contents): sanitize or flag before it reaches the agent's context. This is where injection-firewall work (toolwash) belongs.

**R5 — Global kill switch + human approval gates for high-blast-radius actions.**
One button: pause/cancel any agent run, any fleet, org-wide, instantly — with a per-run receipt of what was terminated and what state it left behind. Plus step-up approval (planok's lane) wired into policy: destructive actions (delete, spend, send, publish) require a human approval inside the SLA the team configures. A CISO will not greenlight autonomy without a demonstrable "we can stop it and we can see everything it did."

---

## 2. The smallest shippable wedge — the one feature that gets "ok, proceed"

**The agent flight recorder: immutable audit + live fleet view + one-tap kill switch.**

Ship exactly this and nothing else for v1:
1. A proxy/enforcement point agents route tool calls through (or an SDK shim — 5 lines to integrate).
2. Every tool call recorded: who, what, arguments (redacted), outcome, policy decision. Hash-chained, tamper-evident.
3. A live dashboard: all agent runs right now, what each is doing, click any run to pause/kill it.
4. One-click SIEM export.

Why this wedge and not policy engine first: **security teams approve what they can observe and stop.** Full policy engines take quarters to configure; the flight recorder gets a pilot signed in a demo. The conversation goes: "Show me everything your agents did yesterday" → scroll → "kill that run" → click → dead → "ok, proceed." Audit is also the requirement no existing Dan tool covers — shortleash guards budgets, mcp-jail guards MCP calls, planok gates approvals, but nothing records the *complete* picture a compliance officer needs.

**Explicitly out of v1:** ML-based anomaly detection, auto-remediation, multi-cloud identity federation, pretty analytics. Those are upsell modules, not the wedge.

---

## 3. Relationship to the existing tools: sit above, don't subsume

Layer it like this:

```
┌─────────────────────────────────────────────┐
│  Gap #12 product — CONTROL PLANE            │
│  org policy, identity brokering, audit,     │
│  kill switch, SIEM export, dashboard        │
└──────────────┬──────────────┬───────────────┘
               │              │
   ┌───────────▼──────┐  ┌────▼──────────┐  ┌──────────────┐
   │ mcp-jail         │  │ shortleash    │  │ toolwash     │
   │ MCP data plane   │  │ run guardrails│  │ output DLP / │
   │ (policy enforced │  │ (budgets,     │  │ injection    │
   │ at stdio proxy)  │  │ timeouts,     │  │ firewall     │
   │                  │  │ receipts)     │  │              │
   └──────────────────┘  └───────────────┘  └──────────────┘
   planok = approval-gate module inside the control plane
   mcp-audit = pre-flight scanner feeding policy decisions
   calas-gateway = can stay independent (cost lane), but the
                   control plane should log through it, not around it
```

- **mcp-audit** stays standalone — it's a scanner, runs in CI, feeds "don't deploy this server config" signals into the control plane's policy. Don't merge; integrate (import its findings).
- **mcp-jail** becomes the MCP data plane. The control plane writes its policy; mcp-jail enforces at the stdio proxy and streams telemetry up. Reuse the code, don't rewrite it.
- **shortleash** becomes the run-guardrail engine under the control plane. Its receipts feed R1's audit trail. Keep it usable standalone for indie devs (it's a good open-source funnel into the enterprise product).
- **planok** folds in as the approval-gate module — the control plane's "require human" policy action. It's already built; wiring it in is integration, not new code.
- **toolwash** (injection firewall) slots into R4 as the untrusted-output handler.

**The pitch this enables:** "Install mcp-jail and shortleash free — they're open source. When security asks how you govern the fleet, that's [product]: the control plane that makes the free tools auditable and policy-driven." The free tools are the wedge into the dev team; the control plane is what the CISO pays for.

---

## 4. Self-hosted vs SaaS for v1

**v1 must be self-hostable. SaaS-only kills the deal. Full stop.**

The reasoning a CISO will give Dan, verbatim: "You want me to route my agents' tool calls — which include source code, customer data, and credentials — through a pre-revenue startup's cloud? No."

- **What they accept:** a single Docker image / binary they deploy in their own VPC. No data leaves their network. License key for commercial features; the enforcement point and audit store stay on their metal. Air-gap-capable is a bonus that wins regulated verticals (finance, health, gov).
- **What kills the deal:** any architecture where agent traffic or the audit log transits Dan's infrastructure in v1. Also kills it: requiring their SIEM credentials to be stored in Dan's cloud, or a "send us your logs" telemetry model.
- **The SaaS play comes later** and it's the *management* plane, not the data plane: multi-cluster policy dashboards, cross-org analytics, hosted policy-as-code repo. Data plane stays in-customer forever. This is the same split every successful security startup lands on (think: the sensor lives on-prem, the console can be cloud).
- **Pricing anchor:** $500+/mo/org is the floor for this category and it's cheap — comparable governance tooling (think Vanta/Drata for agents, or enterprise Wiz-style pricing) runs 5–50x that. Anchor v1 at ~$499–999/mo self-hosted per org with unlimited agents; the per-agent meter is what makes CISOs flinch at scale. Sell "governance for your whole fleet," not per-seat.

---

## 5. Top 3 security failure modes this product itself must not have

**F1 — Becoming the god-key.** This product brokers credentials, holds the policy that permits destruction, and stores the audit log. If its own admin auth or credential store is compromised, the attacker inherits the entire agent fleet. Non-negotiables: no single superadmin token; break-glass access that is itself audited; the credential broker's secrets in a real KMS/HSM-backed store, never in its own config files; the product's own admin actions logged to the same tamper-evident trail (the auditor must audit itself). A CISO's first pentest target will be this product — design like it.

**F2 — Forgable audit trail.** If a compromised agent (or a malicious insider) can rewrite, delete, or backdate audit entries, the product's core promise — "prove what your agents did" — is worthless, and every compliance claim built on it collapses. Requirements: append-only storage, hash chaining, signatures on batches, and the external SIEM sink as the second copy (an attacker would have to compromise both the product and Splunk). Build log-verification as a first-class CLI command (`verify --since <date>`), because auditors will ask for it.

**F3 — Enforcement bypass (guardrails as theater).** If an agent can reach a tool, API, or network destination *without* passing the enforcement point — direct SDK calls, a second MCP server not under management, curl from inside a sandbox — then every policy is decoration. Non-negotiables: deny-by-default network egress for agent sandboxes (the enforcement point isn't just a proxy, it's the only door); agent runtime attestation where feasible (prove the agent binary/config matches what policy approved); and a coverage report — "these are all the tool-call paths we can see; anything else is blocked at the network layer." Ship the coverage report in v1; it's what separates this from every "AI firewall" slide deck.

---

## Name candidates

Keep the one-word lowercase convention: **warden**, **overwatch**, **gatehouse**. My pick: **warden** — short, says what it does, npm/PyPI likely clear (verify). Runner-up: **overwatch** (Blizzard trademark risk — check). Avoid anything with "AI" or "agent" in the name; those age badly and crowd the namespace.

## One-paragraph summary for Dan

The enterprise agent-security product is a self-hosted control plane — policy, identity brokering, tamper-evident audit, SIEM export, and a global kill switch — that sits above mcp-jail/shortleash/planok/toolwash as their governing layer. V1 is the flight recorder: observe everything, stop anything, export to the SIEM. That single demo gets the pilot signed. SaaS-only is a deal-killer; ship a Docker image for their VPC at ~$499–999/mo flat. And the product must be hardened against its own god-key status, log forgery, and enforcement bypass — because the first thing a CISO's team will do is try to break it.
