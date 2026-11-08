#!/usr/bin/env python3
"""Mutation sanity check: break one key condition at a time in a COPY of the
tree and confirm the test suite notices. Nothing in the real tree is touched.

    python3 scripts/mutation-sanity.py          # prints KILLED / SURVIVED per mutant

A SURVIVED line means no test depends on that condition (or the change does not
alter behaviour); look at it before trusting that code path.
"""
import os, shutil, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
M = [
 ("internal/receipt/receipt.go", "if !ed25519.Verify(pub, sum[:], sig) {", "if false && !ed25519.Verify(pub, sum[:], sig) {", "./internal/receipt ./internal/audit"),
 ("internal/receipt/receipt.go", "if r.PrevHash != prev {", "if false && r.PrevHash != prev {", "./internal/receipt ./internal/audit"),
 ("internal/receipt/receipt.go", "hex.EncodeToString(sum[:]) != rec.BodyHash", "false", "./internal/receipt ./internal/audit"),
 ("internal/receipt/receipt.go", 'cmp("status", string(rec.Status) == b.Status)', 'cmp("status", true)', "./internal/receipt ./internal/audit"),
 ("internal/receipt/receipt.go", "rec.StartedAt.IsZero() && rec.ToolCalls == 0 &&", "rec.StartedAt.IsZero() &&", "./internal/receipt ./internal/audit"),
 ("internal/receipt/receipt.go", "base64.StdEncoding.Strict().DecodeString(rec.Signature)", "base64.StdEncoding.DecodeString(rec.Signature)", "./internal/audit"),
 ("internal/receipt/spans.go", "if d != tc.SpansDigest {", "if false {", "./internal/receipt ./internal/audit ./internal/store"),
 ("internal/receipt/spans.go", "if n != tc.SpanCount {", "if false {", "./internal/receipt ./internal/audit ./internal/store"),  # expected to survive: the digest covers the count
 ("internal/policy/policy.go", "case c == ';' || c == '&' || c == '|' || c == '\\n' || c == '(' || c == ')':", "case c == '&' || c == '|' || c == '\\n' || c == '(' || c == ')':", "./internal/policy"),
 ("internal/policy/policy.go", "case c == ';' || c == '&' || c == '|' || c == '\\n' || c == '(' || c == ')':", "case c == ';' || c == '&' || c == '|' || c == '(' || c == ')':", "./internal/policy"),
 ("internal/policy/policy.go", "case c == ';' || c == '&' || c == '|' || c == '\\n' || c == '(' || c == ')':", "case c == ';' || c == '&' || c == '\\n' || c == '(' || c == ')':", "./internal/policy"),
 ("internal/policy/policy.go", "case c == '`':", "case c == '`' && false:", "./internal/policy"),
 ("internal/redact/redact.go", "(bearer\\s+)", "(bearerx\\s+)", "./internal/redact"),
 ("internal/redact/redact.go", "gh[pousr]_", "gh[pous]_", "./internal/redact"),
 ("internal/redact/redact.go", "sk-ant-[A-Za-z0-9_-]{20,}", "sk-ant-[A-Za-z0-9_-]{200,}", "./internal/redact"),
 ("internal/audit/verify.go", "if sp.LateAfterSeal {\n\t\t\t\trep.Unsigned", "if false {\n\t\t\t\trep.Unsigned", "./internal/audit"),
 ("internal/server/server.go", "if s.localOnly && !loopbackHost(r.Host) {", "if false {", "./internal/server"),
 ("internal/server/server.go", "!strings.EqualFold(u.Host, r.Host)", "false", "./internal/server"),
]

def main():
    work = tempfile.mkdtemp(prefix="warden-mut-")
    try:
        dst = os.path.join(work, "tree")
        shutil.copytree(ROOT, dst, ignore=shutil.ignore_patterns(".git", "dist", "*.tgz"))
        env = dict(os.environ, GOFLAGS="-mod=mod")
        killed = 0
        for f, old, new, pk in M:
            p = os.path.join(dst, f)
            src = open(p).read()
            if old not in src:
                print("NOAPPLY ", f, "|", old[:50].replace("\n", " "))
                continue
            open(p, "w").write(src.replace(old, new, 1))
            r = subprocess.run(["go", "test", "-count=1"] + pk.split(), cwd=dst, env=env, capture_output=True, text=True)
            open(p, "w").write(src)
            k = r.returncode != 0
            killed += k
            print("KILLED  " if k else "SURVIVED", f, "|", old[:60].replace("\n", " "))
        print(killed, "of", len(M), "mutants caught")
    finally:
        shutil.rmtree(work, ignore_errors=True)

if __name__ == "__main__":
    sys.exit(main())
