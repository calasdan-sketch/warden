# Gap #12 "warden" v1 — Scrutiny + Hardening Report

**Date:** 2026-10-18 · **Coordinator:** Odin (scrutiny+harness loop for Dan)
**Scope:** `~/workspace/gap12/` — Go single binary, 12 packages.
**Method:** 4-expert panel (security, systems, Go, adversarial-agent). Every
finding below was either demonstrated live against the pre-fix binary or
proven by code inspection; every critical/high was fixed and pinned by a
regression test. Final state: **108/108 tests green, `go vet` clean,
`gofmt` clean, `go test -race -count=1` clean.**

---

## Panel verdicts

### Security engineer
**Verdict: two critical-class issues found, both fixed.** The redaction
layer itself is solid (pattern library + credential-key map + redact-before-
emission ordering is the right architecture, and it held up live). The holes
were *around* it: an unauthenticated trust flag on the socket, and secret
echo in policy reasons on the wrap-deny path.

### Systems engineer
**Verdict: three high-severity lifecycle bugs, all fixed.** The receipt chain
could fork under concurrent seals; the stale-run reconciler could seal a
live run as `receipt_missing`; kill paths could signal a recycled PID.
SQLite posture (WAL, busy_timeout, single-writer) is appropriate for v1 solo;
export paths were unbounded-memory and are now streaming.

### Go specialist
**Verdict: no data races (`-race` clean before and after).** Found: swallowed
insert error on the wrap-deny path (empty PK), EPERM misread as "dead" in
`waitPGIDExit`, ignored DB error in anomaly rule 6, nondeterministic span
ordering on timestamp ties. All fixed.

### Adversarial agent simulator
**Verdict: the pre-fix build fell to three live attacks** — policy-gate
bypass via `pre_decided` smuggling, identity spoofing on socket spans, and
secret exfiltration into the audit trail via the wrap-deny event. All three
were re-run post-fix and defeated. Residual accepted risks are documented in
the README threat model (same-UID operation, pattern-based shell policy,
hook trust).

---

## Findings by severity

### CRITICAL

**C1 — Socket `pre_decided` smuggling: full policy-gate bypass.**
`internal/collect/collector.go` — `handleLine` honored a client-supplied
`pre_decided:true` + `policy_decision:"allow"`. The supervised agent inherits
`WARDEN_SOCK` and can write anything to it — *demonstrated live*: a span for
`rm -rf / --no-preserve-root` was stored as `policy_decision=allow`.
**Fix:** the wire can never set `PreDecided`; forced `false` on every
socket-ingested span (collector.go:437). Only the in-process join layer may
set it. **Test:** `TestSocketPreDecidedStripped` — asserts the smuggled span
lands `denied`.

### HIGH

**H1 — Socket spans dropped run identity.** `handleLine` set `RunID` but not
`AgentID`/`FleetID` — *demonstrated live*: socket spans stored with empty
agent/fleet, silently breaking per-agent anomaly baselines and dashboard
attribution. **Fix:** the per-run socket resolves the run's identity once per
connection; hostile `agent_id`/`fleet_id` fields on the wire are overwritten
(collector.go:429). **Test:** `TestSocketSpanInheritsRunIdentity`.

**H2 — Wrap-deny path leaked raw secrets into the audit trail.**
`Runner.NewRunner` evaluated policy on the *raw* command, then stored
`res.Reason` (which echoes the command) in the denied span and the
`policy_deny` event. *Demonstrated live*: `wrap -- evilbinary --key
AKIAIOSFODNN7EXAMPLE` left the raw AWS key in `events.message`.
**Fix:** redact-before-evaluate in `NewRunner`, mirroring `EmitSpan`
(runner.go:74). **Test:** `TestWrapDenyRedactsSecrets` (asserts zero raw-secret
rows across spans/events/runs).

**H3 — Denied wrap spans silently not recorded.** The deny path built
`gateSpan` with no `SpanID` and called `store.InsertSpan` directly (not
`EmitSpan`, which assigns one); every denied wrap after the first failed the
PK insert and the error was swallowed with `_ =`. *Demonstrated live*: only
the first-ever denied wrap produced a span row.
**Fix:** `SpanID: newID()` at construction (runner.go:66).
**Test:** `TestWrapDenySpanRecorded` (3 denies → 3 distinct spans).

**H4 — Hash-chain fork on concurrent seals.** Two `wrap` processes sealing
simultaneously both read `LatestReceiptHash` → same `prev_hash` → two
receipts sharing a parent; `verify` then reports CHAIN broken. Second-order
bug found during the fix: `SealedAt` was captured *before* the transaction,
so commit order could disagree with `sealed_at` order even with locking.
**Fix:** `store.SealChained` — `BEGIN IMMEDIATE` transaction covering
read-head → seal → insert (receipts_kill.go:26); `SealRun` captures the seal
timestamp *inside* the lock. **Test:** `TestConcurrentSealChainIntact`
(8 parallel seals, separate store handles, chain verified).

**H5 — Reconciler sealed live runs as `receipt_missing`.** The `Runner`
never heartbeat; the dashboard reconciler seals anything stale >15 min.
A long, quiet `wrap` (no spans) would be sealed `receipt_missing` while its
child was still alive — then the real exit would no-op against the existing
receipt, permanently mislabeling the run.
**Fix:** runner heartbeat loop (2 min, runner.go:173) + reconciler skips
runs whose pidfile points at a live, start-time-verified process
(collector.go `Reconcile`; proctime.go:69).
**Tests:** `TestReconcileSkipsLivePidfile`, `TestReconcileDetectsRecycledPID`.

**H6 — Kill paths could signal a recycled PID.** `killPGID` trusted the
pidfile unconditionally: a stale pidfile (warden SIGKILLed, PID recycled by
the OS) → `SIGTERM`/`SIGKILL` to an innocent process group. Also
`waitPGIDExit` treated *any* error (including EPERM = "exists but no
permission") as dead.
**Fix:** pidfiles record `/proc` start time at spawn; every kill path
verifies liveness + start-time match first (`killPGIDVerified`, kill.go:89);
stale → recorded as "not signaled", never signaled. EPERM fix (kill.go:113).
**Tests:** `TestKillRefusesStalePidfile`, `TestWaitPGIDExitNoSuchGroup`,
`TestProcStartTimeSane`.

**H7 — Tool deny-list case bypass.** `kill --scope tool --target Bash`
wrote key `deny:tool:Bash`; `Evaluate` looked up the raw (lowercase) tool
name → miss. *Demonstrated live*: `gate --tool bash` → allow after denying
`Bash`. **Fix:** deny-list keys lowercased at write, read, and clear
(receipts_kill.go:343). **Test:** `TestToolDenyCaseInsensitive`.

### MEDIUM

**M1 — `*secret*` glob false-positives on bare secret values.**
`IsCredentialAdjacentPath("hunter2-super-secret")` → true (substring
match), pushing the command into require_approval *and* echoing the secret
value into the policy reason as "the path". **Fix:** the broad glob now
applies only to path-like tokens or the bare names `secret`/`secrets`
(redact.go:143). **Test:** `TestCredentialAdjacentBareSecretValue`.

**M2 — Export OOM.** Dashboard `handleExport` and CLI `export`
materialized all runs (and all spans for OTLP) in RAM; any viewer-role caller
could OOM the dashboard. **Fix:** `store.ListRunsPage` (runs.go:181);
JSONL and OTLP both stream in 1000-run pages; new `otel.EncodeStream`
(otel.go:27) emits one valid OTLP envelope in bounded memory.
**Tests:** `TestListRunsPage`, `TestSpansForRunOrderStable`,
`TestEncodeStreamSingleEnvelope`, `TestEncodeStreamPropagatesError`.

**M3 — `gate` shell-policy footgun.** Shell allowlist/deny-patterns only
applied to 6 hardcoded tool names; a hook reporting `--tool myexec` got a
free `allow`. (The hook is trusted code, so this is a footgun, not an
adversary bypass.) **Fix:** `gate --shell` forces the shell branch;
`gate` now evaluates redacted args and builds approval gate names from
redacted text (span_gate.go:113,127,163).

**M4 — FreezeFleet sealed soft-stopped runs as `completed`.** Receipt
dishonesty: operator-SIGTERMed runs looked like clean exits.
**Fix:** seal-first as `killed_operator`/fleet_freeze before signaling
(kill.go `FreezeFleet`), mirroring `KillRun`.

**M5 — Rule 6 swallowed its baseline error.** `seen, _ := …` → on DB error
every host counted as first-seen → false exfiltration criticals.
**Fix:** error → rule not applicable (anomaly.go).

**M6 — Span order nondeterministic on timestamp ties.** `SpansForRun`
ordered by `started_at` only; equal timestamps (common in tests and fast
hooks) scrambled loop detection. **Fix:** `, rowid ASC` tiebreak.

**M7 — Long socket paths broke ingestion.** Unix path cap (~108 chars): a
long `WARDEN_DIR` made `serveSocket` fail with EINVAL — found when a test's
temp path exceeded the cap. **Fix:** length check with transparent fallback
to a short temp-dir socket (collector.go:323); close path tracked per run.

**M8 — README was dishonest in 4 places** (fixed): the anomaly rule list
named rules that don't exist (`tool-24h spike`, `fleet 429 wave`,
`quiet-tool resurgence`, `dead run`); `scan` was claimed to reconcile (it
doesn't) with a wrong threshold; a `--token` flag was documented that doesn't
exist (it's `WARDEN_TOKENS`); the file ended mid-word (`(Complia\n...[truncated
1223 chars]` — a truncated paste from the build session). Also added the
missing **threat-model** and **enforcement-points** sections (same-UID
limits, socket/join trust, pattern-policy limits, kill best-effort,
deterministic-rule rampability, SSE `?token=`).

### LOW (noted, not changed)

- `verify --run X` checks one receipt's signature but not its chain position
  (full `verify` covers the chain).
- No signing-key rotation ceremony (documented as v1.1).
- SSE `?token=` leaks tokens into logs (EventSource limitation; documented).
- Deterministic baselines are rampable by a patient adversary (inherent;
  documented).
- `handleReport` trusts operator-supplied JSONL per the join-layer contract
  (documented trust boundary).

---

## Deferred with reasons

- **Two-person rule** → v1.1 (was already deferred in the build brief; unchanged).
- **Postgres** → v1.1 (unchanged).
- **Key rotation** → v1.1 (new; the single-key story is documented).
- **Cost-proportional sampling** → v1.1 (unchanged).
- **Real network/process sandboxing for `wrap`** (eBPF/seccomp, network
  namespace) — out of scope for v1; the README now states plainly that
  `wrap` gates command *text* and true enforcement lives in hooks.
- **Per-connection socket rate limits** — the agent is same-UID; limits
  would be theater. Noted.

## Deviation check (from the build brief)

- Freeze default = manual unfreeze — kept, correct.
- Two-person rule deferred — kept.
- No cost-proportional sampling — kept.
- Rule 6 size/proxy heuristic — kept; hardened (M5).

## Final state

- `go test -count=1 ./...` — **108/108 green** (92 pre-existing + 16 new
  regression tests), 12 packages.
- `go test -race -count=1 ./...` — clean.
- `go vet ./...` — clean. `gofmt -l .` — clean.
- `warden` binary rebuilt (17.7 MB, CGO-free).
- Live re-attacks post-fix: `pre_decided` smuggling → **denied**; identity
  spoof → **overwritten with run identity**; wrap-deny secret →
  **zero raw-secret rows**, denied span recorded; tool deny `Bash` →
  `bash` **denied**; kill → receipt `killed_operator`, `verify` 2/2 chain
  intact; dashboard burn/runs/export/OTLP all serving; empty kill reason →
  400.
- No git init/push; no other repos touched.
