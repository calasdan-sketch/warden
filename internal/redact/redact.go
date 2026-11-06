// Package redact implements secret redaction at the collector, BEFORE emission.
// Nothing secret-bearing ever leaves the collector: spans, receipts, events,
// and JSONL lines are all passed through here first.
//
// The rules are deliberately conservative: an over-redaction is a cosmetic
// blemish in the dashboard; an under-redaction is a credential leak in an
// audit trail that may land in a SIEM.
package redact

import (
	"path/filepath"
	"regexp"
	"strings"
)

// rule is one named redaction pattern.
type rule struct {
	name string
	re   *regexp.Regexp
}

var rules []rule

func add(name, pattern string) {
	rules = append(rules, rule{name: name, re: regexp.MustCompile(pattern)})
}

func init() {
	// AWS access key IDs.
	add("aws_access_key", `AKIA[0-9A-Z]{16}`)
	// GitHub tokens.
	add("github_token", `gh[pousr]_[A-Za-z0-9]{20,}`)
	add("github_pat", `github_pat_[A-Za-z0-9_]{20,}`)
	// Slack tokens.
	add("slack_token", `xox[baprs]-[A-Za-z0-9-]{10,}`)
	// Stripe keys.
	add("stripe_key", `(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}`)
	// OpenAI-style keys.
	add("openai_key", `sk-[A-Za-z0-9]{20,}`)
	// Google API keys.
	add("google_api_key", `AIza[0-9A-Za-z_-]{35}`)
	// Anthropic keys.
	add("anthropic_key", `sk-ant-[A-Za-z0-9-]{20,}`)
	// Private key material (whole block value).
	add("private_key", `-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----`)
	// JWTs (header.payload — enough to be dangerous, redact the signature too).
	add("jwt", `eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)
	// Basic-auth credentials embedded in URLs.
	add("url_credentials", `(?i)(https?://)[^:/\s@]+:[^@\s]+@`)
	// JSON string values: {"api_key": "secret..."} — case-insensitive key match.
	add("json_secret_value", `(?i)("(?:api[_-]?key|secret|password|passwd|pwd|token|auth[_-]?token|access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key|bearer)["']?\s*:\s*["']?)([^"',}\s]+)(["']?)`)
	// Shell/env assignment: API_KEY=secret, --password hunter2, password: hunter2
	add("kv_secret_value", `(?i)((?:api[_-]?key|secret|password|passwd|pwd|token|auth[_-]?token|access[_-]?token|client[_-]?secret)[=:]["']?)([^\s"'&;]+)`)
	// Bearer tokens in headers.
	add("bearer_token", `(?i)(bearer\s+)([A-Za-z0-9\-._~+/]+=*)\b`)
}

// RedactString redacts secrets from s. It returns the redacted string and
// whether any redaction happened. Redactions are stable and deterministic:
// the same secret always maps to the same placeholder, so arg hashes computed
// over redacted text stay consistent.
func RedactString(s string) (string, bool) {
	out := s
	hit := false
	for _, r := range rules {
		out = r.re.ReplaceAllStringFunc(out, func(m string) string {
			hit = true
			// Preserve capture-group structure for the kv/json rules so the
			// key name stays visible and only the value is masked.
			sub := r.re.FindStringSubmatch(m)
			switch r.name {
			case "json_secret_value", "kv_secret_value", "bearer_token", "url_credentials":
				if len(sub) == 4 {
					return sub[1] + "[redacted]" + sub[3]
				}
				if len(sub) == 3 {
					return sub[1] + "[redacted]"
				}
			}
			return "[redacted:" + r.name + "]"
		})
	}
	return out, hit
}

// credentialKeyNames are map keys whose values are always treated as secrets,
// regardless of whether the value matches a pattern.
var credentialKeyNames = []string{
	"api_key", "apikey", "api_secret", "secret", "password", "passwd", "pwd",
	"token", "auth_token", "access_token", "refresh_token", "id_token",
	"client_secret", "private_key", "bearer", "session", "cookie", "set-cookie",
	"authorization", "x-api-key",
}

// RedactMap redacts a string map (e.g. tool args). Keys matching
// credentialKeyNames are always masked; values are pattern-scanned.
func RedactMap(m map[string]string) (map[string]string, bool) {
	out := make(map[string]string, len(m))
	hit := false
	for k, v := range m {
		lk := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(k, "-", "_"), " ", "_"))
		sensitive := false
		for _, ck := range credentialKeyNames {
			if lk == ck || strings.HasSuffix(lk, "_"+ck) {
				sensitive = true
				break
			}
		}
		if sensitive {
			out[k] = "[redacted]"
			hit = true
			continue
		}
		rv, h := RedactString(v)
		out[k] = rv
		hit = hit || h
	}
	return out, hit
}

// credentialAdjacent reports whether a path looks like it holds secrets.
// Used by the collector for detector #7 (credential-adjacent file access).
//
// The broad "*secret*" glob only applies to path-like tokens (containing a
// dot, e.g. secrets.yaml) or the bare names "secret"/"secrets": a bare
// secret VALUE that merely contains the substring "secret" (e.g. a
// --password hunter2-super-secret argument) must not trip the
// credential-adjacent gate — that path is fail-closed into a human approval
// and would also echo the value into the policy reason as "the path".
func credentialAdjacent(path string) bool {
	// Windows-style paths (from harnesses on Windows/WSL) use backslashes;
	// judge them by the same rules.
	path = strings.ReplaceAll(path, `\`, "/")
	base := strings.ToLower(filepath.Base(path))
	patterns := []string{
		"*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore",
		".env*", "*.env", "id_rsa*", "id_ed25519*", "id_ecdsa*",
		"*credentials*", ".npmrc", ".pypirc",
		"kubeconfig", "config.json", ".netrc", "_netrc",
	}
	for _, p := range patterns {
		if ok, _ := filepath.Match(p, base); ok {
			return true
		}
	}
	if strings.Contains(base, "secret") &&
		(strings.Contains(base, ".") || base == "secret" || base == "secrets") {
		return true
	}
	// dotfiles in home-ish credential dirs
	lower := strings.ToLower(path)
	for _, d := range []string{".aws/", ".ssh/", ".gnupg/", ".docker/", ".kube/", "gcloud/"} {
		if strings.Contains(lower, d) {
			return true
		}
	}
	return false
}

// IsCredentialAdjacentPath reports whether path looks like it holds secrets.
func IsCredentialAdjacentPath(path string) bool { return credentialAdjacent(path) }
