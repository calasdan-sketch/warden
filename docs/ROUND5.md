# Round 5 (2026-11-08)

Maintainer: Calas Automations Inc. One repo, branch `expert-2`.

**How this was done.** No sub-agent tool was available in this session, so one reviewer played
each specialist role in turn. Every finding below names the command that proved it. Nothing was
published, tagged, pushed or uploaded; no live service or paid API was called. The machine was
shared (load average 17 to 49), so timings are noisy.

## Package name

| Name | Status (read-only `npm view` / PyPI JSON, 2026-11-08) |
|---|---|
| `warden` on npm | taken: version 0.1.1, other maintainer |
| `warden` on PyPI | taken: another project (Windows-oriented, different author) |
| `@decnutz/warden` on npm | placeholder 0.0.1 published, author "Calas Automations Inc.", maintainer account `decnutz`: ours |
| `@decnutz/warden-linux-x64` and the other five platform packages | not published (404) |
| `@calas/warden` | 404, but a 404 does not prove the `@calas` scope is free or ours: **unverified** |

Recommendation: keep `@decnutz/warden` for 0.2.0. It exists, it is ours, the scope is not a person's
real name, and the command people type is still `warden`. A cleaner brand scope (for example an npm
organisation named after the company) is a decision for Dan; renaming later means a new package and a
deprecation notice on the old one. Not a Python project, so there is nothing to name on PyPI.
A search on the GitHub name `warden` was not run (could not check ownership of the word read-only).

## Specialists and findings

| # | Specialist | Finding | Proving command |
|---|---|---|---|
| 1 | Browser-side attacker (web-app security tester) | The dashboard with no tokens answered any request that reached 127.0.0.1: DNS rebinding reads traces; a cross-site form post presses kill and approve. **Fixed** (Host and Origin guard). | `curl -H "Host: evil.example:18431" http://127.0.0.1:18431/api/v1/runs` gave 200 before, 403 now; `curl -X POST -H "Origin: https://evil.example" ... /api/v1/kill` gave 400 (reached the handler) before, 403 now |
| 2 | Same | `dashboard --listen 0.0.0.0:8420` with no tokens served the kill buttons to the network and printed "localhost only". **Fixed**: exits 2. | `warden dashboard --listen 0.0.0.0:18420` -> exit 2 |
| 3 | Upgrade / migration QA | Built the 0.1.0, 0.1.x (19b33aa) and 0.2.0 (7553a05) binaries from git, made a data dir with each (hook calls, wrap, export), then ran this tree on it. Stores, `runs`, `replay`, `summary`, `doctor` all fine. **0.1.0 exports failed `verify --bundle`** ("header was edited"): 0.1.0 wrote blank agent, fleet and start fields. **Fixed** with a note; partial blanks and real edits still fail. Old default policies keep their looser allowlist (warned, documented). | `warden verify --bundle old.jsonl --pubkey receipt.pub` (rc 1 before, 0 now); fixtures kept in `internal/audit/testdata` |
| 4 | Shell-semantics specialist (differential testing) | Wrote a generator of hostile command lines and ran each the policy allowed through real `sh` and `bash` with stub programs. 15,979 distinct lines, 2,186 allowed and replayed in two shells: 0 programs ran off the allowlist. (First run flagged `env`, which is a transparent wrapper; fixed in the test, not the policy.) | `go test ./internal/policy -run Differential -v` |
| 5 | Property-based testing specialist | Secrets of 16 formats buried in random text: **`TOKEN=Bearer abc...` and `X-Api-Key: Bearer abc...` stored the token** (the key rule masked only the word "Bearer"). **Fixed** (rule order). Idempotence and "plain text is untouched" hold. | `go test ./internal/redact -run Property\|Secrets\|Bearer` |
| 6 | Mutation-testing specialist | 16 conditions broken one at a time: 11 caught on the first run, 5 survived (status compare in the header check, call-count in the legacy shape, `Bearer`, `gh[pousr]_`, span count). Tests were added and the first four are now caught; the span-count one is equivalent (the span digest also covers the count). The script also covers strict base64 and the Host and Origin checks: final result 17 of 18 caught, the one survivor being the equivalent span-count mutant. `scripts/mutation-sanity.py` re-runs it in a temp copy. | `python3 scripts/mutation-sanity.py` |
| 7 | Audit-evidence reviewer (auditor) | Flipped 7,500 random bytes across three real exports. One class passed: **signature text with changed padding bits decodes to the same bytes**. **Fixed**: strict base64. The rest were rejected, or changed nothing the verifier reads (label fields, run summary rows, spelling variants Go's decoder treats alike). Golden files now pin replay (text, step, JSON) and OTLP bytes. | `go test ./internal/audit -run ByteFlip -v`; `go test ./internal/replay ./internal/otel` |
| 8 | Claude Code / Codex integrator | `hook --print-config` run through `npx` writes a path inside npx's temporary cache into the settings snippet. When the cache is cleaned, the hook command is missing and the harness lets calls through. **Fixed**: stderr warning with the fix. | `warden hook claude-code --print-config` from a temp install |
| 9 | Release / supply-chain engineer | Scoped npm packages publish as private unless `publishConfig.access` is public; neither the launcher nor the six platform packages set it. Platform packages had no author, homepage or bugs fields. README said "four" platform packages (there are six). **Fixed**; version, maintainer and access are pinned by tests. Launcher pass-through (args, exit code, missing-binary message) now tested. | `tar -xzOf npm/dist/*/*.tgz package/package.json`; `go test ./cmd/warden -run 'Maintainer\|Version\|Launcher'` |
| 10 | Windows engineer (static review only) | Backslash, drive-letter and UNC paths are judged like Unix ones (now a test). Open: the hook snippet single-quotes a path with spaces, which works in Git Bash but not in PowerShell; not changed because it cannot be tested here. `wrap` uses `cmd /C`, taskkill and `os.Rename`; reviewed, not run. | `go test ./internal/policy -run Windows`; `GOOS=windows go vet ./...` (clean in earlier rounds) |
| 11 | Hostile-input tester | 30 MB hook input (denied in 0.2 s), invalid UTF-8, ESC and bidi characters in commands (stripped), empty and garbage input (fail closed), no HOME, a data dir with spaces: no crash, no escape sequence reached the terminal. HTML replay: markup in recorded text cannot close the script block (now a test). | commands in the transcript; `go test ./internal/replay -run HTML` |

## Packaging, from the built tarballs

Built with `scripts/build-npm.sh` for linux-x64 and win32-x64 only (see "could not test"). Installed
the launcher and the linux-x64 package into an empty prefix with `npm install --offline`, then ran the
README quick start from that install: `--version`, `about`, `demo`, `init`, `doctor`, `wrap`, `runs`,
`replay last`, `verify`, `summary`, `policy suggest`, `bench`, `export` + `verify --bundle`, `replay
--html`, all in a data directory whose path contains a space. All worked.

Author proof (tarball metadata, all three): `author: "Calas Automations Inc."`, `license: MIT`,
`publishConfig.access: public`. LICENSE reads `Copyright (c) 2026 Calas Automations Inc.` `warden
about` prints "Maintained by Calas Automations Inc." Launcher tarball holds exactly LICENSE, README.md,
bin/warden.js, package.json; platform tarballs hold LICENSE, package.json and the one binary.

## Competitors, re-checked read-only (2026-11-08)

aileron: PyPI 0.1.6, Apache-2.0, released 2026-10-19, unchanged since the last check.
Microsoft Agent Governance Toolkit (`agent-governance-toolkit` on PyPI): 4.1.0, MIT, released 2026-06-11,
"Public Preview", unchanged. Pages were read, nothing was installed or run, so the "unverified" cells in
the README comparison stand.

## Scored ideas (value, differentiation, effort, risk: 1 low to 5 high; for effort and risk, low is good)

| # | Idea | Value | Diff. | Effort | Risk | Status |
|---|---|---|---|---|---|---|
| 1 | Dashboard Host and Origin guard | 5 | 4 | 2 | 1 | DONE |
| 2 | Refuse network listen with no tokens | 5 | 3 | 1 | 1 | DONE |
| 3 | Accept 0.1.0 exports (blank header shape) | 4 | 2 | 2 | 2 | DONE |
| 4 | Bearer-after-key redaction fix | 5 | 3 | 1 | 1 | DONE |
| 5 | Warn when hook config points into a temp / npx folder | 4 | 3 | 1 | 1 | DONE |
| 6 | Strict base64 signatures | 2 | 3 | 1 | 1 | DONE |
| 7 | `publishConfig.access` and full platform-package metadata | 5 | 1 | 1 | 1 | DONE |
| 8 | Maintainer, version and access pinned by tests; `warden about` | 3 | 1 | 1 | 1 | DONE |
| 9 | Differential test against real `sh` and `bash` | 5 | 5 | 3 | 1 | DONE |
| 10 | Property tests for redaction | 4 | 4 | 2 | 1 | DONE |
| 11 | Golden files for replay and OTLP | 3 | 3 | 2 | 1 | DONE |
| 12 | Byte-flip test on real exports of three builds | 4 | 5 | 2 | 1 | DONE |
| 13 | Mutation sanity script | 3 | 3 | 2 | 1 | DONE |
| 14 | Windows-path judgment tests | 3 | 2 | 1 | 1 | DONE |
| 15 | Launcher pass-through test | 2 | 1 | 1 | 1 | DONE |
| 16 | HTML replay hostile-text test | 3 | 2 | 1 | 1 | DONE |
| 17 | PowerShell-correct hook snippet on Windows | 3 | 2 | 2 | 3 | NOT-DONE (cannot test) |
| 18 | Constant-time dashboard token compare | 1 | 1 | 1 | 1 | NOT-DONE (map lookup; remote timing over HTTP is impractical; cheap, do it next) |
| 19 | Signed release binaries and checksums | 5 | 3 | 4 | 2 | NOT-DONE (Dan's signing key / CI) |
| 20 | RFC 3161 timestamping of anchors | 4 | 4 | 4 | 2 | NOT-DONE |
| 21 | Key rotation | 4 | 3 | 4 | 3 | NOT-DONE |
| 22 | Signed kill audit table | 4 | 3 | 3 | 2 | NOT-DONE |
| 23 | Streaming bundle verification (large exports) | 3 | 2 | 3 | 2 | NOT-DONE |
| 24 | `verify --bundle` GitHub Action / CI recipe | 4 | 3 | 2 | 1 | NOT-DONE |
| 25 | MCP stdio proxy mode (aileron has one) | 4 | 3 | 5 | 3 | NOT-DONE |
| 26 | `policy migrate`: tighten an old default allowlist in place | 3 | 2 | 2 | 3 | NOT-DONE (editing a user's policy needs consent; `doctor` already warns) |
| 27 | Scheduled `go test -fuzz` job | 3 | 2 | 2 | 1 | NOT-DONE (no CI in repo) |
| 28 | Brand-scope npm organisation | 3 | 2 | 1 | 2 | NOT-DONE (Dan's decision) |

## What could not be tested

- **Windows**: still never run. Static review and path tests only.
- **macOS and arm64**: not run. Only linux-x64 and win32-x64 packages were built here (cross-building
  all six took more than 8 minutes on the shared machine and was stopped); the other four use the same
  script and the same Go code. Build all six before publishing (see PUBLISH-CHECKLIST.md).
- **A real `npx @decnutz/warden` from the registry**: the 0.2.0 packages are not published. The
  tarballs were installed from disk with `--offline`.
- **Read-only filesystem**: the session runs as root, so permission bits do not stop writes.
- **Real Claude Code / Codex sessions** driving the hook: simulated through the same code path only.
- **Python**: this is a Go project; there is no PyPI package, no wheel, no venv.

## Numbers

- Tests (top-level `go test -v ./...` passes): **180 before, 202 after**, all green; `gofmt`, `go vet` clean,
  and `go vet` for windows/amd64 and darwin/arm64 clean. The full suite takes about 25 s on an idle machine.
- `warden bench`, best of three on a quiet 2-CPU VM (load average 4), before / after: hook round trip p50
  8.4 / 8.2 ms, p99 14.0 / 15.3 ms; policy decision for a compound line 56.8 / 59.1 us; redaction of 1 KB
  67 / 64 us; 20,000-step replay 36 / 35 ms. No measurable change (the redaction rule that moved is a
  regex that only runs when the text contains "bearer"). Stripped linux-x64 binary: 12.4 MB.
- Differential test: 15,979 distinct lines, 2,186 allowed by the policy and replayed in `sh` and `bash`: 0
  off-allowlist programs run. Byte-flip test: 2,500 damaged copies of each of three real exports. Property
  test: 16 secret formats times 150 random surroundings.

## Release version

Keep **0.2.0**. It has never been published (npm has only the 0.0.1 placeholder), so every Round 5 change
lands in the first real release and nothing needs a bump or a migration. Version is pinned by
`cmd/warden/release_test.go` in package.json, the six platform pins, CHANGELOG and README.
