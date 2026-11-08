package redact

import (
	"math/rand"
	"strings"
	"testing"
)

// Property tests: for secrets of every vendor format, buried in random
// surroundings, the secret never survives, redaction is idempotent, and
// ordinary text without secrets passes through unchanged. Secrets are built
// at run time from a seeded generator, so no secret-shaped string sits in the
// source tree.
const (
	alnum   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	upperD  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	lowerD  = "abcdef0123456789"
	urlsafe = alnum + "-_"
)

func rnd(r *rand.Rand, set string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = set[r.Intn(len(set))]
	}
	return string(b)
}

type secretGen struct {
	name string
	gen  func(r *rand.Rand) string
}

func secretGens() []secretGen {
	return []secretGen{
		{"aws", func(r *rand.Rand) string { return "AKIA" + rnd(r, upperD, 16) }},
		{"github", func(r *rand.Rand) string { return "ghp_" + rnd(r, alnum, 20+r.Intn(30)) }},
		{"github_oauth", func(r *rand.Rand) string { return "gho_" + rnd(r, alnum, 20+r.Intn(30)) }},
		{"github_user", func(r *rand.Rand) string { return "ghu_" + rnd(r, alnum, 20+r.Intn(30)) }},
		{"github_server", func(r *rand.Rand) string { return "ghs_" + rnd(r, alnum, 20+r.Intn(30)) }},
		{"github_refresh", func(r *rand.Rand) string { return "ghr_" + rnd(r, alnum, 20+r.Intn(30)) }},
		{"bearer", func(r *rand.Rand) string { return "Bearer " + rnd(r, alnum+"-._~+/", 30+r.Intn(30)) }},
		{"github_pat", func(r *rand.Rand) string { return "github_pat_" + rnd(r, alnum+"_", 30+r.Intn(30)) }},
		{"slack", func(r *rand.Rand) string { return "xoxb-" + rnd(r, alnum+"-", 12+r.Intn(30)) }},
		{"stripe", func(r *rand.Rand) string { return "sk_live_" + rnd(r, alnum, 16+r.Intn(20)) }},
		{"anthropic", func(r *rand.Rand) string { return "sk-ant-" + rnd(r, urlsafe, 30+r.Intn(60)) }},
		{"openai", func(r *rand.Rand) string { return "sk-proj-" + rnd(r, urlsafe, 30+r.Intn(60)) }},
		{"npm", func(r *rand.Rand) string { return "npm_" + rnd(r, alnum, 30+r.Intn(10)) }},
		{"hf", func(r *rand.Rand) string { return "hf_" + rnd(r, alnum, 30+r.Intn(10)) }},
		{"google", func(r *rand.Rand) string { return "AIza" + rnd(r, urlsafe, 35) }},
		{"jwt", func(r *rand.Rand) string {
			return "eyJ" + rnd(r, urlsafe, 12) + "." + rnd(r, urlsafe, 20) + "." + rnd(r, urlsafe, 20)
		}},
		{"shopify", func(r *rand.Rand) string { return "shpat_" + rnd(r, lowerD, 32) }},
	}
}

var wrappers = []string{
	"%s",
	"export TOKEN_VALUE=%s",
	"curl -H 'X-Api-Key: %s' https://example.test/x",
	"{\"note\":\"use %s here\"}",
	"echo %s | tr a b",
	"line one\nkey is %s\nline three",
	"(%s)",
	"https://example.test/?q=1&k=%s&z=2",
	"git push https://user:%s@example.test/r.git",
}

func TestSecretsNeverSurviveAndRedactionIsIdempotent(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	for _, g := range secretGens() {
		for i := 0; i < 150; i++ {
			sec := g.gen(r)
			w := wrappers[r.Intn(len(wrappers))]
			in := strings.Replace(w, "%s", sec, 1)
			out, changed := RedactString(in)
			if !changed {
				t.Fatalf("%s: nothing redacted in %q", g.name, in)
			}
			// Compare on the random body, which is long enough to be unique.
			body := sec[len(sec)-12:]
			if strings.Contains(out, body) {
				t.Fatalf("%s: secret survived.\n in : %q\n out: %q", g.name, in, out)
			}
			again, _ := RedactString(out)
			if again != out {
				t.Fatalf("%s: not idempotent.\n once : %q\n twice: %q", g.name, out, again)
			}
		}
	}
}

func TestOrdinaryTextIsLeftAlone(t *testing.T) {
	r := rand.New(rand.NewSource(11))
	words := []string{"git", "status", "ls", "-la", "src/main.go", "the", "quick", "brown", "fox", "tokens", "are", "counted",
		"max_tokens=4096", "input_tokens: 120", "README.md", "v1.2.3", "2026-11-08", "build", "ok", "--verbose", "/tmp/a/b", "42"}
	for i := 0; i < 2000; i++ {
		n := 1 + r.Intn(12)
		parts := make([]string, n)
		for j := range parts {
			parts[j] = words[r.Intn(len(words))]
		}
		in := strings.Join(parts, " ")
		out, changed := RedactString(in)
		if changed || out != in {
			t.Fatalf("plain text altered.\n in : %q\n out: %q", in, out)
		}
	}
}

func TestSanitizeNeverLeavesControlOrBidiCharacters(t *testing.T) {
	r := rand.New(rand.NewSource(13))
	bad := []rune{0x1b, 0x07, 0x00, 0x08, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069, 0x200b, 0x200e, 0x200f, 0xfeff, 0x9b}
	for i := 0; i < 3000; i++ {
		var sb strings.Builder
		for j := 0; j < 1+r.Intn(30); j++ {
			if r.Intn(3) == 0 {
				sb.WriteRune(bad[r.Intn(len(bad))])
			} else {
				sb.WriteRune(rune('a' + r.Intn(26)))
			}
		}
		out := Sanitize(sb.String())
		for _, c := range out {
			for _, b := range bad {
				if c == b {
					t.Fatalf("U+%04X survived Sanitize in %q -> %q", c, sb.String(), out)
				}
			}
		}
	}
}

// Regression: a key-value rule used to mask only the word "Bearer" and leave
// the token after it in the clear.
func TestBearerTokenAfterAKeyIsMasked(t *testing.T) {
	tok := "q" + strings.Repeat("Zx9", 8)
	for _, in := range []string{
		"TOKEN_VALUE=Bearer " + tok,
		"X-Api-Key: Bearer " + tok,
		"api_key: Bearer " + tok,
	} {
		if out, _ := RedactString(in); strings.Contains(out, tok) {
			t.Errorf("token survived: %q -> %q", in, out)
		}
	}
}
