package redact

import (
	"encoding/base64"
	"strings"
	"testing"
)

// j joins fragments at runtime so no contiguous fake credential appears in the
// repository (secret scanners would flag it, and so would a reader).
func j(p ...string) string { return strings.Join(p, "") }

type secretCase struct {
	name   string
	input  string
	secret string // substring that must NOT survive redaction
}

func secretCorpus() []secretCase {
	awsSecret := j("wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYEXAMPLEKEY")
	return []secretCase{
		{"aws access key", j("key=AKIA", "IOSFODNN7EXAMPLE"), j("AKIA", "IOSFODNN7EXAMPLE")},
		{"aws temp key", j("ASIA", "IOSFODNN7EXAMPLE"), j("ASIA", "IOSFODNN7EXAMPLE")},
		{"aws secret (ini)", "aws_secret_access_key = " + awsSecret, awsSecret},
		{"aws secret (env)", "AWS_SECRET_ACCESS_KEY=" + awsSecret, awsSecret},
		{"github pat", j("github_pat_", "11ABCDEFG0abcdefghijkl_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ"), "11ABCDEFG0"},
		{"github classic", j("ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"), "abcdefghijklmnopqrstuvwxyz0123"},
		{"gitlab pat", j("glpat-", "abcdefghijklmnopqrst"), "abcdefghijklmnopqrst"},
		{"npm token", j("npm_", "abcdefghijklmnopqrstuvwxyz0123456789"), "abcdefghijklmnopqrstuvwxyz0123"},
		{"hugging face", j("hf_", "abcdefghijklmnopqrstuvwxyzABCDEFGH"), "abcdefghijklmnopqrstuvwxyzABCDEFGH"},
		{"openai project key", j("sk-", "proj-abc_DEF-ghi123456789012345678901234"), "abc_DEF-ghi1234567890"},
		{"openai svc key", j("sk-", "svcacct-abc_DEF-ghi123456789012345678901234"), "abc_DEF-ghi1234567890"},
		{"anthropic key", j("sk-ant-", "api03-abcdefghijklmnop_qrstuv-wxyz"), "abcdefghijklmnop_qrstuv"},
		{"sendgrid", j("SG.", "abcdefghijklmnopqrstuv.", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"), "abcdefghijklmnopqrstuv"},
		{"slack bot", j("xoxb-", "123456789012-abcdefghij"), "123456789012-abcdefghij"},
		{"slack webhook", "https://hooks.slack.com/services/" + j("T01234567/B01234567/", "abcdefghijklmnopqrstuvwx"), "abcdefghijklmnopqrstuvwx"},
		{"discord webhook", "https://discord.com/api/webhooks/123456789012345678/" + j("abcdefghijklmnopqrstuvwxyz_-0123456789"), "abcdefghijklmnopqrstuvwxyz_-0123456789"},
		{"stripe live", j("sk_", "live_abcdefghijklmnop1234"), "abcdefghijklmnop1234"},
		{"stripe webhook", j("whsec_", "abcdefghijklmnop1234"), "abcdefghijklmnop1234"},
		{"google api key", j("AIza", "SyB-abcdefghijklmnopqrstuvwxyz12345"), "SyB-abcdefghijklmnop"},
		{"google oauth", j("ya29.", "a0AbCdEfGhIjKlMnOpQrStUv"), "a0AbCdEfGhIjKlMnOpQrStUv"},
		{"shopify token", j("shpat_", "0123456789abcdef0123456789abcdef"), "0123456789abcdef0123456789abcdef"},
		{"jwt", j("eyJhbGciOiJIUzI1NiJ9.", "eyJzdWIiOiIxIn0.", "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"), "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJ"},
		{"pem block", "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END RSA PRIVATE KEY-----", "MIIBOgIBAAJBAKj34Gkx"},
		{"pem truncated", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC", "MIIEvQIBADANBgkqhkiG9w0"},
		{"pem encrypted", "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkq\n-----END ENCRYPTED PRIVATE KEY-----", "MIIFHDBOBgkqhkiG9w0"},
		{"postgres url", "postgres://user:" + "hunter2pass" + "@db.internal:5432/x", "hunter2pass"},
		{"mongodb srv url", "mongodb+srv://app:" + "s3cr3tPw0rd" + "@cluster0.example.net/db", "s3cr3tPw0rd"},
		{"redis url", "redis://:" + "r3disPassw0rd" + "@cache:6379/0", "r3disPassw0rd"},
		{"https url creds", "https://bob:" + "tok3nvalue99" + "@example.com/x", "tok3nvalue99"},
		{"azure conn string", "DefaultEndpointsProtocol=https;AccountName=x;AccountKey=" + j("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUV", "abcdefghijkl==") + ";", "abcdefghijklmnopqrstuvwxyz0123456789"},
		{"sas signature", "https://x.blob.core.windows.net/c/b?sv=2022&sig=" + "abcdefghijklmnopqrstuvwxyz0123456789%2B%2F%3D", "abcdefghijklmnopqrstuvwxyz0123"},
		{"auth basic header", `curl -H "Authorization: Basic ` + "dXNlcjpwYXNzd29yZA==" + `" x`, "dXNlcjpwYXNzd29yZA"},
		{"auth bearer header", "Authorization: Bearer " + "abcd1234efgh5678ijkl", "abcd1234efgh5678ijkl"},
		{"x-api-key header", "X-API-Key: " + "abcd1234efgh5678ijkl", "abcd1234efgh5678ijkl"},
		{"cli --password space", "mysql --password hunter2 -u root", "hunter2"},
		{"cli --password=", "tool --password=hunter2 run", "hunter2"},
		{"cli --token", "gh --token " + "abcd1234efgh5678", "abcd1234efgh5678"},
		{"mysql -p", "mysql -phunter2 -u root", "hunter2"},
		{"env spaces", "api_key = abcd1234efgh", "abcd1234efgh"},
		{"env quoted spaces", `export SECRET_KEY="abc def ghi"`, "abc def ghi"},
		{"yaml password", "password: 'hunter2 with space'", "hunter2 with space"},
		{"db password env", "DB_PASSWORD=" + "Tr0ub4dor&3", "Tr0ub4dor"},
		{"json nested key", `{"client_secret": "` + "abcd1234efgh" + `"}`, "abcd1234efgh"},
		{"json prefixed key", `{"github_token": "` + "abcd1234efgh" + `"}`, "abcd1234efgh"},
		{"zero-width split", j("AKIA", "​", "IOSFODNN7EXAMPLE"), j("IOSFODNN7EXAMPLE")},
		{"base64 of a key", "echo " + base64.StdEncoding.EncodeToString([]byte(j("AKIA", "IOSFODNN7EXAMPLE"))) + " | base64 -d", base64.StdEncoding.EncodeToString([]byte(j("AKIA", "IOSFODNN7EXAMPLE")))},
	}
}

// benign strings that must come through unchanged (false-positive guard).
func benignCorpus() []string {
	return []string{
		"git log --oneline -n 5",
		"max_tokens=4096 temperature=0.2",
		`{"max_tokens": 1024, "tokens_in": 12, "total_tokens": 99}`,
		"token_count: 512",
		"password_policy: strong",
		"commit 9fceb02d0ae598e95dc970b74767f19372d61af8",
		"id=550e8400-e29b-41d4-a716-446655440000",
		"https://github.com/calasdan-sketch/warden/pull/1",
		"ls -la /usr/local/bin && cat README.md",
		"sk-learn is a library; sk_users table",
		"skeleton-key-rotation docs",
		"https://example.com/a/b?x=1&y=2",
		"secret_santa_list.txt",
	}
}

func TestSecretCorpusRecall(t *testing.T) {
	cases := secretCorpus()
	missed := 0
	for _, c := range cases {
		out, hit := RedactString(c.input)
		if strings.Contains(out, c.secret) || !hit {
			missed++
			t.Errorf("LEAK %-22s -> %q", c.name, out)
		}
	}
	t.Logf("redaction recall: %d/%d", len(cases)-missed, len(cases))
}

func TestBenignCorpusUnchanged(t *testing.T) {
	for _, s := range benignCorpus() {
		if out, hit := RedactString(s); out != s || hit {
			t.Errorf("false positive: %q -> %q", s, out)
		}
	}
}

func TestSanitizeStripsControlAndBidi(t *testing.T) {
	in := "ok\x1b[31mred\x1b[0m ‮evil‬ a​b"
	out, hit := RedactString(in)
	if hit {
		t.Error("sanitizing alone is not a redaction hit")
	}
	for _, r := range out {
		if invisible(r) {
			t.Errorf("invisible rune %U survived in %q", r, out)
		}
	}
	if !strings.Contains(out, "red") || !strings.Contains(out, "ab") {
		t.Errorf("visible text lost: %q", out)
	}
}

func TestRedactIsIdempotent(t *testing.T) {
	for _, c := range secretCorpus() {
		once, _ := RedactString(c.input)
		twice, _ := RedactString(once)
		if once != twice {
			t.Errorf("%s: not idempotent: %q vs %q", c.name, once, twice)
		}
	}
}

func BenchmarkRedact1KB(b *testing.B) {
	s := strings.Repeat("git log --oneline -n 5 && echo hello world; ", 24)
	b.SetBytes(int64(len(s)))
	for i := 0; i < b.N; i++ {
		RedactString(s)
	}
}

func TestRedactHugeInputBounded(t *testing.T) {
	s := strings.Repeat("A", 5<<20) + j("AKIA", "IOSFODNN7EXAMPLE")
	out, _ := RedactString(s)
	if strings.Contains(out, j("IOSFODNN7EXAMPLE")) {
		t.Error("secret after 5MB of padding leaked")
	}
}

// FuzzRedact: never panics, never grows output without bound, and a second
// pass changes nothing (so redacting at several layers is safe).
func FuzzRedact(f *testing.F) {
	for _, c := range secretCorpus() {
		f.Add(c.input)
	}
	f.Add("-----BEGIN PRIVATE KEY-----")
	f.Add("a=" + strings.Repeat("=", 100))
	f.Fuzz(func(t *testing.T, s string) {
		once, _ := RedactString(s)
		if len(once) > 3*len(s)+64 {
			t.Fatalf("output grew from %d to %d bytes", len(s), len(once))
		}
		twice, _ := RedactString(once)
		if once != twice {
			t.Fatalf("not idempotent:\n%q\n%q", once, twice)
		}
	})
}
