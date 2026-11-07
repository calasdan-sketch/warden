# Round 3 panel (2026-11-07)

Method: each specialist used the built binary and the README only, then wrote what broke.
Nothing here called a paid or live service. Where something could not be tested it is
marked.

## Pass A: panel and findings

| Specialist | What they did | Found |
|---|---|---|
| Red-team operator (attacker) | ~150 hand-written evasions against the default allowlist, hooks and MCP/search tools | 33 gaps: `sort --compress-program`, `git grep -O`, scp-style remotes without a user (`host.tld:path`) and `--repo=URL`, wildcard write targets (`~/.b*`), 12 more persistence paths, recursive `grep` of the home directory, history files and `~/.codex/auth.json`, macOS browser stores with escaped spaces, and **MCP filesystem tools and Glob/Grep patterns that read credential files with no check at all** |
| Performance engineer | 60,000-span run through verify, export, OTLP, replay, HTML replay, dashboard | `replay` was quadratic: 2,000 steps took 2.8 s, 20,000 took 3 min, 60,000 never finished. Dashboard run detail sent every span (50 MB for a long run) and the page spread them into `Math.max(...)` |
| Auditor / compliance reviewer | Edited the live SQLite file under `verify` | **The run record (agent, status, kill reason) could be rewritten and `verify` still said OK**, and `replay` showed the edited values under a VERIFIED banner |
| Platform engineer (first-day user) | Followed the README with a typo in `policy.yaml` | A misspelled key (`deny_pattern:`, `alow:`) was ignored silently, so protections vanished without a word. A broken policy file also blocked `kill` and `verify` (openApp refused) |
| DX / docs lead | Looked for how to tune, check and debug an install | No way to validate a policy, ask why a command was stopped, learn what to allowlist, or check hook wiring. No summary of a day's activity |
| Competitor engineer | Re-read aileron 0.1.6 on PyPI (unchanged since last round) and the Microsoft Agent Governance Toolkit page | AGT is now `agent-governance-toolkit` 4.1.0, "Public Preview", MIT (PyPI metadata). Its hook adapters, signed audit and redaction remain unverified here. aileron still has no kill switch in its CLI |

## Brainstorm and scoring

Scores 1-5. Value = user value, Diff = difference from named competitors, Effort and Risk: lower is better.
"Built" means done in round 3.

| # | Idea | Value | Diff | Effort | Risk | Decision |
|---|---|---|---|---|---|---|
| 1 | Linear-time replay + windowed HTML | 5 | 2 | 2 | 1 | Built |
| 2 | Strict policy parsing, value checks, friendly errors | 5 | 2 | 1 | 1 | Built |
| 3 | `verify`/`replay` compare run record with signed receipt | 5 | 4 | 2 | 2 | Built |
| 4 | Close 33 policy gaps found by the attacker | 5 | 3 | 2 | 2 | Built |
| 5 | Judge paths in MCP arguments and Glob/Grep patterns | 5 | 3 | 2 | 2 | Built |
| 6 | `policy check` (lint) | 4 | 3 | 1 | 1 | Built |
| 7 | `policy explain` (per-command reasons, hint) | 4 | 3 | 2 | 1 | Built |
| 8 | `policy suggest` from recorded history, never suggests code runners | 5 | 4 | 2 | 2 | Built |
| 9 | `doctor` (key, policy, trail, hook wiring) | 4 | 3 | 2 | 1 | Built |
| 10 | `summary` digest of a window | 4 | 3 | 2 | 1 | Built |
| 11 | Kill switch and verify usable with a broken policy | 5 | 3 | 1 | 1 | Built |
| 12 | Cap dashboard run detail | 3 | 1 | 1 | 1 | Built |
| 13 | `bench` reports replay speed | 2 | 1 | 1 | 1 | Built |
| 14 | RFC 3161 timestamping of anchors | 4 | 4 | 4 | 3 | Not built: needs a third-party service and a verified TSA list |
| 15 | Key rotation ceremony | 4 | 3 | 4 | 4 | Not built: format change, needs a spec |
| 16 | Signed kill audit | 3 | 3 | 3 | 2 | Not built |
| 17 | Streaming `verify --bundle` (bounded memory) | 3 | 2 | 3 | 2 | Not built |
| 18 | Per-agent policy profiles | 4 | 4 | 4 | 3 | Not built |
| 19 | Honeytoken files that alert when read | 3 | 5 | 3 | 3 | Not built |
| 20 | Prompt-injection markers on tool output | 3 | 3 | 5 | 5 | Not built: no reliable detector, would give false assurance |
| 21 | `export --since`/CSV/SARIF for SOC tooling | 3 | 2 | 2 | 1 | Not built |
| 22 | OS keychain / separate-user key storage | 5 | 3 | 5 | 4 | Not built, still the biggest threat-model gap |
| 23 | Luhn/PII redaction | 2 | 2 | 3 | 3 | Not built |
| 24 | Real Windows run of the suite | 4 | 1 | 3 | 1 | Not possible here (no Windows host) |

## Pass B: fresh review of the new code

Same specialists, adversarial re-read of the diff:

- Attacker: wildcard-write check fired on bare `*` bases (`cp src/* dest/` would ask).
  Fixed: a pure-wildcard base is ignored. The "lint says `*` matches every host" claim was wrong:
  `*` matches no host (only `*.domain` works). Fixed the message and the test.
- Auditor: the run-record check must not fail on running totals, because a joined emitter
  record can legitimately update them after the seal. Identity and outcome fields fail;
  totals are reported as notes. Receipts with a bad row still count in the chain
  (the first draft reported a false "chain broken").
- Compliance/safety: `policy suggest` first classed `sed`, `tar`, `rm`, `dd` as "fine to allow".
  `sed` (the `e` command) and `tar` (`--checkpoint-action`) run commands. Now `sed`, `tar`,
  `cpio` are code runners, and only read-only programs are put in the snippet; programs that
  change files are listed with a warning.
- Perf: measured the policy decision and redaction cost at HEAD versus now on the same
  shared, loaded VM (3 runs each): no measurable change.
- DX: `init` now prints next steps; `doctor` text no longer claims to change nothing while
  opening the database.

## Known limits left (also in the README)

- A dotted branch refspec such as `my.branch:my.branch` can be mistaken for an scp-style host and
  be sent to a human. Failing closed was chosen over guessing.
- `SpansSince` compares RFC 3339 timestamps as text. Trailing-zero trimming can misorder two
  spans that start in the exact second of the cutoff; reports are digests, not evidence.
- The HTML replay embeds every span: a 60,000-span run is a 32 MB page.
