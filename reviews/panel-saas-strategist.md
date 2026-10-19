# Gap #12: Enterprise Agent-Governance — Business Model Brief
**Role:** B2B SaaS Strategist (expert panel)
**Date:** 2026-10-18
**Status:** Strategy proposal, not decided. Nothing here is locked.

---

## 1. The one-line thesis

Don't sell "agent monitoring." Sell **the approval layer between AI agents and production systems** — the thing that lets a CISO say yes to the pilot. Enterprises aren't stuck because agents don't work; they're stuck because nobody can answer "who approved that, and who watched it?" at audit time. That's a compliance story, and compliance stories carry $500/mo+ budgets.

---

## 2. Packaging: per-managed-agent + platform tier, not per-seat

Per-seat is wrong here. The buyer is not adding seats — agents multiply, humans don't. Per-agent-run is also wrong: it punishes the exact behavior you want (more agent usage) and turns every invoice into a fight about "what counts as a run."

**Recommended unit: per-managed-agent-per-month (per concurrent agent identity under policy), plus a base platform fee.**

- A "managed agent" = one agent identity (service principal / API key / MCP client) enrolled in the governance plane. Human users are free unlimited — this is key for land-and-expand: you never tax the humans.
- The base platform fee covers the dashboard, audit log storage, policy engine, SSO — the enterprise table stakes. Per-agent price covers marginal cost (event ingestion, policy evaluation).

**The free→paid seam (critical for Dan's OSS core):**
- Free OSS CLIs (mcp-audit, mcp-jail, shortleash, planok) stay fully functional forever, including local audit logs and JSON policies. No crippling. Dan's credibility is the OSS line; crippling it kills the story and the HN funnel.
- Paid seam = **centralization + attestation**: multi-agent fleet view, org-wide policy push, immutable audit trail with retention, SSO/SAML, SOC 2 evidence export, anomaly alerts to Slack/PagerDuty, and the CISO-ready "agent governance report." The solo dev loses nothing; the org pays for visibility and proof.
- This seam is honest and defensible: "the tools are free, the *proof* is paid." CISOs buy proof.

---

## 3. Land-and-expand motion: CLI → team → CISO

| Stage | Who | What they do | Trigger to next stage |
|---|---|---|---|
| **Land** | Individual dev | `npm i -g mcp-audit`, scans their MCP config, posts their A-grade on social. shortleash HN post drives this. | Hits the paid wall: "your 5 teammates each have their own logs — want one view?" |
| **Team** | Eng manager / tech lead | Signs up Team tier ($99/mo), enrolls 10-30 agent identities, gets fleet dashboard + shared policies. | An incident or audit: someone asks "show me every tool this agent was allowed to call in March." |
| **Expand** | Security team + CISO | Compliance tier ($500+/mo): retention, SSO, evidence export, custom retention, SLA. | Contract. Annual prepay discount. |

**Motion mechanics:**
- The CLI should detect multi-agent usage and *suggest* the platform, not nag. E.g., `mcp-jail` prints once: "3 agents sharing policies — sync them at paddock.calasautomations.com" (name TBD).
- PLG-to-sales handoff: Team-tier accounts that cross ~25 managed agents or invite a second workspace admin get a human email from Dan (founder-led sales is fine at this scale — it's a feature, not a gap).
- Compliance tier is sold, not bought: 30-min "agent governance readiness" call → scoped pilot (2 weeks, their real agents) → annual contract. Pilot converts because the product *generates the audit artifact they lacked*.

**Buyer at each stage is different, and the pitch changes:**
- Dev: "know your agents aren't pwned in 30 seconds" (mcp-audit A–F score).
- Eng manager: "see every agent, every tool call, one dashboard; stop babysitting."
- CISO: "approve the pilot with an audit trail, policy enforcement, and an evidence pack for the board."

---

## 4. Positioning vs. the existing line

**Opinion: this becomes the flagship platform the other tools plug into. It does not replace the "agent-safety company" story — it *is* the "agent-safety company" story, monetized.**

- Today the line reads as a bag of CLIs. That's fine for dev mindshare, but enterprises buy platforms, not bags. The governance product is the roof; mcp-audit/mcp-jail/shortleash/planok become "the enforcement fleet" — each one is a sensor+enforcer that reports into the platform.
- Concretely: the platform's pitch is "one pane of glass for every agent guardrail you already installed for free." The OSS tools each get a `--report-to <platform>` flag (or env var). This makes the paid product feel like the *natural consequence* of the free tools, not a separate SKU.
- calas-gateway (token proxy) slots in as the cost-governance module of the platform — "security + spend in one pane." That's a genuinely differentiated bundle: nobody else pairs runtime permission enforcement with token accounting.
- **Standalone enterprise SKU? No.** A separate SKU fragments the story and forces Dan to maintain two narratives. One story: "the agent-safety company." Free tools = the guards. Platform = the command center. Keep it that simple.
- Naming architecture: keep tool names (they're good). The platform gets its own name (see §6). Marketing line: "*ShortLeash, mcp-audit, mcp-jail and planok — governed by [Platform].*"

**Risk to flag:** platform-first positioning tempts Dan into building the dashboard before the fleet is real. Don't. Ship the paid tier as: CLI telemetry upload + a dead-simple web dashboard + policy sync. The "platform" is 80% data plumbing, 20% UI. Resist the enterprise-UI trap.

---

## 5. Pricing: concrete tiers

All prices USD. Annual = 2 months free (~17% off).

| Tier | Price | What's in it | Who converts |
|---|---|---|---|
| **Open** (OSS) | $0 | All CLIs, local policies, local audit logs, community support | Everyone. The funnel. |
| **Team** | **$99/mo** flat, up to 25 managed agents; then **$3/agent/mo** overage | Fleet dashboard, org policy sync, 90-day audit retention, Slack alerts, shared A–F posture scores, unlimited human seats | Eng manager with 5–30 agents in pilot. Entry price converts because it's under the "expense it, don't procure it" threshold (~$100). |
| **Compliance** | **$549/mo** base, includes 100 managed agents; then **$2.50/agent/mo** | Everything in Team + SSO/SAML, 1-yr+ immutable audit retention, SOC 2 evidence export, anomaly detection + PagerDuty, custom data residency note, 99.9% SLA, onboarding call | CISO / security team. This is the $500+/mo SKU. The number that justifies it: one failed audit or one leaked credential costs 50–500× this. Price it against the *incident*, not against Datadog. |
| **Enterprise** | Custom (floor **$2,000/mo**) | Self-hosted option (air-gapped), custom retention, dedicated support, security review assistance, custom contracts/DPA | Regulated orgs, banks, healthcare. The self-hosted option is the unlock — 52% blocked by security means some buyers literally cannot send telemetry to your cloud. |

**Why $549 not $500:** anchoring just above the round number signals "we know what this is worth." Also keeps distance from the $99 tier — three tiers need daylight between them.

**Why per-agent overage declines with tier:** it rewards expansion (land 25 agents at Team, grow to 200 at Compliance where marginal agents are cheaper). Expansion revenue without renegotiation.

**What justifies $500+/mo (the CISO math):**
1. Audit-readiness: SOC 2 Type II auditors now ask about AI-agent controls. An evidence export that answers "which agents touched production data in Q1, under whose policy" is worth more than the subscription in *auditor hours alone*.
2. Incident containment: one prompt-injection exfiltration through an MCP tool = breach notification territory. mcp-jail's deny-by-default + immutable log is the control the postmortem wishes existed.
3. Pilot unblock: the CISO's alternative isn't a cheaper tool — it's *killing the pilot*. $549/mo to unblock a 500-person eng org's AI program is a rounding error.

**Anti-patterns to avoid:**
- No per-seat pricing (agents scale, humans don't).
- No "contact us" on the Compliance tier — put the price on the page. CISOs comparison-shop; hiding the price reads as $10k+.
- No free tier of the *platform* beyond a 14-day trial. The OSS tools are the free tier. A free hosted tier creates support load with zero conversion signal.

---

## 6. Name proposals (not locked — Dan decides)

Dan's style: short, vivid, physical metaphors (ShortLeash, Flakebox). The platform is the thing that *holds the herd*. Three proposals:

1. **Paddock** — where you keep the animals. Short, vivid, slightly playful, pairs naturally with ShortLeash ("short leash in the paddock"). My pick.
2. **Corral** — rounding up the agents. Punchy, Western, memorable. Slightly more aggressive energy.
3. **Stable** — calm, enterprise-friendly ("keep your agents stable" doubles as a reliability pun). Safest of the three, least exciting.

Runner-up considered and dropped: *Kennel* (too jokey for a CISO invoice), *Watchtower* (overused in security), *Harness* (collides with Harness.io — hard no).

**Flag:** check npm/PyPI/domain availability before committing, same as the dev-tool renames.

---

## 7. Go-to-market sequencing (first 90 days)

1. **Weeks 1–2:** Ship telemetry upload + minimal dashboard for mcp-jail and shortleash (the two with runtime data worth centralizing). Team tier live at $99. This is the paid product v1 — ugly is fine.
2. **Weeks 3–4:** shortleash HN launch ("Show HN: a circuit breaker for runaway AI agents") — volume driver per the monetization review. Every HN visitor sees the Team tier.
3. **Weeks 5–8:** Add SSO + evidence export → Compliance tier live. Founder-led outreach: 20 CISOs / heads of platform eng at mid-size SaaS companies, offer the 2-week scoped pilot.
4. **Weeks 9–12:** First 3 paying Team accounts → case studies → the Compliance pitch writes itself ("[Company] governs 40 agents with Paddock").

**Metrics that matter:** CLI installs → telemetry-enabled workspaces (activation) → Team trials → paid conversion → agents-per-account (expansion). If agents-per-account isn't growing, the pricing is wrong, not the product.

---

## 8. Open questions for Dan / the panel

1. Self-hosted Enterprise tier: real demand or imagined? It doubles engineering surface. Consider gating it behind 3 signed LOIs before building.
2. Does the Compliance tier need the anomaly-detection ML story, or is deterministic policy + alerting enough for v1? (My vote: deterministic. ML is a roadmap slide.)
3. Agensi marketplace ($19 skills) as a channel — does a $19 skill buyer ever become a $549/mo buyer? Probably not directly, but it's brand surface. Keep it, don't depend on it.
4. One-person support for a $549/mo SLA product: Dan needs a status page and a runbook before the first Compliance signature, not after.
