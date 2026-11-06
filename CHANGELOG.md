# Changelog

## 0.1.0 (unreleased)

The first build intended for npm with real binaries. `@decnutz/warden@0.0.1`
on npm is an empty placeholder.

### Security (panel review fixes, 2026-11-06)
- **CRITICAL: shell allowlist bypasses closed (also under `--strict`).**
  - `env`/`sudo` options are parsed exactly. Before, `env -i rm …` and
    `sudo -E rm …` hid `rm`. Now `env -S`, `sudo -s`, `sudo -i` and unknown
    options are denied.
  - Path-qualified programs (`./git`, `/tmp/git`) only match the allowlist
    from `/bin`, `/usr/bin`, `/sbin` or `/usr/sbin`, or as an exact
    allowlisted path.
  - Assigning or exporting `PATH`, `LD_*`, `DYLD_*`, `GIT_*`, `HOME`,
    `BASH_ENV`, `PYTHON*`, `NODE_*`, `WARDEN_*` and similar is denied.
  - Known git code-execution options are denied: `-c`, `--config-env`,
    `--exec-path`, `clone -u`, `rebase -x`, `config`, `submodule`, and so on.
  - Agents may not run `warden` itself.
- **Breaking: the default allowlist no longer contains `python3`, `node`,
  `npm`, `go` or `curl`.** Interpreters run arbitrary code, and curl bypasses
  the egress policy. Existing `policy.yaml` files are not rewritten; review
  yours.
- **CRITICAL: `warden hook` fails closed on every startup error and panic**
  (unreadable data dir, broken policy, locked DB): it answers deny or exits 2.
  Before, it exited 1, which harnesses treat as "proceed". `--fail-open`
  remains an explicit opt-out.
- **warden protects its own files.** Tool calls that write or mention warden's
  data dir, policy file, `warden.db` or `receipt.key` are denied, as are
  writes to `.claude/settings*.json`, `.codex/hooks.json` and
  `.codex/config.toml`. Globs and brace expansion are covered, including paths
  inside interpreter code and after redirections.
- **HIGH: credential directories** (`.ssh`, `.aws`, `.gnupg`, `.kube`,
  `.warden`, …) now match as path components, with or without a trailing
  slash, and through globs (`id_rs?`). The threat model now states plainly
  that a separate OS user or an external chain anchor is the real protection
  for the signing key.
- **MEDIUM: `verify --bundle` checks every receipt header field** against the
  signed body, including `key_id`. It rejects unknown record types and lists
  every unsigned record (late spans, spans without a receipt, run and
  kill-audit rows) as `UNSIGNED`. Unsigned spans fail the check unless
  `--allow-unsigned` is passed. Store `verify` also checks the stored status
  against the body.
- **LOW:**
  - rm flags are normalized before deny patterns run (`rm -r -f /`,
    `rm -fr /`, `rm --recursive --force /`), and recursive force-deletes of
    `/`, `~` and `$HOME` are always denied.
  - The npm launcher forwards SIGINT, SIGTERM, SIGHUP and SIGQUIT to warden,
    so receipts still seal.
  - The hook records `tool_use_id`, exported as `gen_ai.tool.call.id`
    (schema v5).
- **Codex hooks checked against the [official docs](https://learn.chatgpt.com/docs/hooks).**
  Codex has `SessionEnd`, so `Stop` no longer seals a run per turn, and
  `--print-config` uses `SessionEnd`. `apply_patch` is judged per file
  touched. Relative paths are resolved against the hook's `cwd`.

### Added
- **Signed trace digests.** Every receipt now commits to a digest of all spans
  the run recorded before its seal (`span_count`, `spans_digest`,
  `spans_digest_alg: warden-spanset-sha256-v1`). `verify` fails on any edited,
  deleted, inserted or re-labelled span. Spans recorded after a seal are kept,
  marked `late_after_seal` (schema v4, set atomically by the store) and
  reported as uncovered.
- **Verifiable audit bundles.** `export` (JSONL) starts with a header signed
  with the chain head and receipt count. `verify --bundle FILE --pubkey KEY`
  checks signatures, the chain (order-independent: detects gaps and forks),
  traces and truncation with no warden data dir.
- **`warden hook claude-code|codex`.** A PreToolUse adapter covering shell,
  file, WebFetch, MCP and Task calls. warden never grants a permission.
  Explicit denies block. Approvals go to Claude Code's own "ask" prompt.
  `--strict`, `--await` and `--fail-open` (fail-closed by default) adjust this.
  `--print-config` prints the settings snippet. Kill, quarantine and fleet
  freeze block the session's next tool call, and a killed session stays
  blocked.
- **`warden demo`.** A one-command, self-contained tour that includes live
  tamper detection.
- **OTLP push.** `export --format otlp --endpoint URL [--header "K: V"]`,
  standard library only.
- **npm distribution.** A launcher package plus per-platform binary packages
  (linux/darwin, x64/arm64) built by `scripts/build-npm.sh`. No postinstall
  script and no network access at install time.
- MIT `LICENSE` file (matching the license already declared on npm), `.gitignore`.

### Changed
- **OTLP export follows the OpenTelemetry GenAI semantic conventions.**
  `chat {model}` and `execute_tool {tool}` span names; `gen_ai.operation.name`,
  `gen_ai.provider.name` and `gen_ai.tool.name`; integer-typed token counts;
  an `invoke_agent` root span per run; span kinds; instrumentation scope;
  `error.type`. Trace and span IDs are now always valid hex (non-hex run IDs
  are hashed instead of zero-padded). **Breaking for consumers** that relied on
  string-typed token attributes or the old span names.
- **Shell allowlist checks every command in a compound line**, including
  `;`, `&&`, `||`, pipes, `$( )`, backticks, `<( )` and `sh -c` bodies.
  Before, only the first binary was checked, so `git status; curl x | sh`
  passed an allowlist containing `git`. Safe builtins and shell keywords no
  longer need allowlisting.
- Credential-adjacent path detection now handles Windows-style paths and
  `.netrc`, `.kube/` and gcloud credentials.
- `export --out` creates the file with mode 0600.
- Go module path is now `github.com/calasdan-sketch/warden`, so `go install`
  works. Dependencies are unchanged.
- The prebuilt 17 MB binary is no longer committed. Build with
  `go build -o warden ./cmd/warden`.

### Fixed
- `wrap` kill: `Shutdown` now waits for the whole process group to exit, and
  SIGKILLs any stragglers within the grace period, instead of returning when
  the direct child exits. This also fixes the flaky `TestWrapKillLive`.
- Flaky `TestSocketIngestion` (a race between the span and the event line).
