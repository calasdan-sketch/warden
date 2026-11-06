package redact

import (
	"strings"
	"testing"
)

func TestRedactStringPatterns(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantSub string // must appear in output
		mustNot string // must NOT appear in output
	}{
		{"aws", "key=AKIAIOSFODNN7EXAMPLE", "[redacted:aws_access_key]", "AKIA"},
		{"github", "token ghp_abcdefghijklmnopqrstuvwx", "[redacted:github_token]", "ghp_abc"},
		{"slack", "xoxb-123456789012-abcdefghij", "[redacted:slack_token]", "xoxb-"},
		{"stripe", "sk_live_abcdefghijklmnop1234", "[redacted:stripe_key]", "sk_live"},
		{"openai", "sk-abcdefghijklmnopqrstuvwx", "[redacted:openai_key]", "sk-abc"},
		{"google", "AIzaSyB-abcdefghijklmnopqrstuvwxyz12345", "[redacted:google_api_key]", "AIza"},
		{"anthropic", "sk-ant-api03-abcdefghijklmnopqrst", "[redacted:anthropic_key]", "sk-ant"},
		{"jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c", "[redacted:jwt]", "eyJhbGci"},
		{"private_key", "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----", "[redacted:private_key]", "MIIB"},
		{"url_creds", "https://admin:hunter2@example.com/api", "example.com", "hunter2"},
		{"bearer", "Authorization: Bearer abcdef123456", "Bearer", "abcdef123456"},
		{"env_assign", "API_KEY=hunter2secret", "API_KEY=", "hunter2secret"},
		{"json_value", `{"api_key": "hunter2secret"}`, `"api_key":`, "hunter2secret"},
		{"cli_flag", "--password=hunter2", "--password=", "hunter2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, hit := RedactString(tc.in)
			if !hit {
				t.Fatalf("expected redaction to fire for %q", tc.in)
			}
			if !strings.Contains(out, tc.wantSub) {
				t.Errorf("output %q missing %q", out, tc.wantSub)
			}
			if tc.mustNot != "" && strings.Contains(out, tc.mustNot) {
				t.Errorf("output %q still contains secret %q", out, tc.mustNot)
			}
		})
	}
}

func TestRedactStringClean(t *testing.T) {
	clean := []string{
		"npm test -- --watch",
		`{"tool": "bash", "command": "ls -la"}`,
		"2026-10-18T12:00:00Z INFO run completed",
		"The password policy requires 12 characters",
	}
	for _, in := range clean {
		out, hit := RedactString(in)
		if hit {
			t.Errorf("false positive redaction: %q -> %q", in, out)
		}
		if out != in {
			t.Errorf("clean string modified: %q -> %q", in, out)
		}
	}
}

func TestRedactStringDeterministic(t *testing.T) {
	in := "sk_live_abcdefghijklmnop1234"
	a, _ := RedactString(in)
	b, _ := RedactString(in)
	if a != b {
		t.Errorf("redaction not deterministic: %q vs %q", a, b)
	}
}

func TestRedactMap(t *testing.T) {
	in := map[string]string{
		"command": "curl https://api.example.com",
		"api_key": "sk_live_abcdefghijklmnop1234",
		"note":    "token=abc123 in text",
	}
	out, hit := RedactMap(in)
	if !hit {
		t.Fatal("expected hit")
	}
	if out["api_key"] != "[redacted]" {
		t.Errorf("api_key not masked: %q", out["api_key"])
	}
	if out["command"] != in["command"] {
		t.Errorf("clean value modified: %q", out["command"])
	}
	if strings.Contains(out["note"], "abc123") {
		t.Errorf("pattern in value not redacted: %q", out["note"])
	}
}

func TestIsCredentialAdjacentPath(t *testing.T) {
	positive := []string{
		"/home/dan/.env", "/home/dan/.env.production", "/x/id_rsa",
		"/x/server.pem", "/x/key.pem", "/x/credentials.json",
		"/x/aws_credentials", "/home/dan/.aws/config", "/home/dan/.ssh/known_hosts",
		"/x/secrets.yaml", "/x/cert.p12",
	}
	for _, p := range positive {
		if !IsCredentialAdjacentPath(p) {
			t.Errorf("%q should be credential-adjacent", p)
		}
	}
	negative := []string{
		"/x/main.go", "/x/README.md", "/x/app.env.example", "/x/monkey.txt",
	}
	for _, p := range negative {
		if IsCredentialAdjacentPath(p) {
			t.Errorf("%q should NOT be credential-adjacent", p)
		}
	}
}

// TestCredentialAdjacentBareSecretValue (scrutiny 2026-10-18): a bare secret
// VALUE that merely contains the substring "secret" must not trip the
// credential-adjacent gate — that path is fail-closed into a human approval
// and would echo the value into the policy reason as "the path".
func TestCredentialAdjacentBareSecretValue(t *testing.T) {
	for _, p := range []string{"hunter2-super-secret", "mysecret", "secret"} {
		// "secret" alone is a well-known bare name; values with it embedded are not.
		if p == "secret" {
			continue
		}
		if IsCredentialAdjacentPath(p) {
			t.Errorf("%q is a secret value, not a credential path", p)
		}
	}
	for _, p := range []string{"secrets", "secret", "/x/secrets.yaml", "/x/my.secret.key"} {
		if !IsCredentialAdjacentPath(p) {
			t.Errorf("%q should stay credential-adjacent", p)
		}
	}
}

func TestCredentialAdjacentWindowsAndMore(t *testing.T) {
	for _, p := range []string{`C:\Users\dan\.ssh\id_rsa`, `C:\Users\dan\.ssh\known_hosts`, "/home/u/.netrc",
		"/home/u/.kube/config", "/home/u/.config/gcloud/application_default_credentials.json"} {
		if !IsCredentialAdjacentPath(p) {
			t.Errorf("%s should be credential-adjacent", p)
		}
	}
	for _, p := range []string{`C:\src\main.go`, "src/environment.ts", "README.md"} {
		if IsCredentialAdjacentPath(p) {
			t.Errorf("%s should not be credential-adjacent", p)
		}
	}
}
