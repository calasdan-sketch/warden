# Changelog

## 0.1.0 (unreleased)

The first build intended for npm with real binaries. `@decnutz/warden@0.0.1`
on npm is an empty placeholder.

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
