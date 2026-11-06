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
	for _, p := range ExpandBraces(path, 32) {
		if credentialAdjacentOne(p) {
			return true
		}
	}
	return false
}

// credentialBasePatterns are file-name patterns that hold secrets.
var credentialBasePatterns = []string{
	"*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore",
	".env*", "*.env", "id_rsa*", "id_ed25519*", "id_ecdsa*", "id_dsa*",
	"*credentials*", ".npmrc", ".pypirc", ".netrc", "_netrc",
	"kubeconfig", "config.json", ".git-credentials",
}

// CredentialDirs are directory names whose whole subtree is
// credential-adjacent. Matched as a path component, with or without a
// trailing slash (".ssh", "~/.ssh", "/root/.ssh/x").
var CredentialDirs = []string{".ssh", ".aws", ".gnupg", ".docker", ".kube", "gcloud", ".warden", ".azure"}

func credentialAdjacentOne(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	for _, p := range credentialBasePatterns {
		if globMatch(p, base) {
			return true
		}
	}
	if !hasGlob(base) && strings.Contains(base, "secret") &&
		(strings.Contains(base, ".") || base == "secret" || base == "secrets") {
		return true
	}
	for _, comp := range strings.Split(strings.ToLower(path), "/") {
		if comp == "" {
			continue
		}
		for _, d := range CredentialDirs {
			if comp == d || (hasGlob(comp) && matchQuiet(comp, d)) {
				return true
			}
		}
	}
	return false
}

// globMatch matches a credential pattern against a base name; when the
// base name itself is a shell glob (cat ~/.ssh/id_rs?), it also checks
// whether the glob could expand to a name the pattern covers, using
// representative names.
func globMatch(pattern, base string) bool {
	if matchQuiet(pattern, base) {
		return true
	}
	if !hasGlob(base) {
		return false
	}
	for _, rep := range credentialRepresentatives {
		if matchQuiet(pattern, rep) && matchQuiet(base, rep) {
			return true
		}
	}
	return false
}

// credentialRepresentatives are concrete names a glob is tested against.
var credentialRepresentatives = []string{
	"cert.pem", "server.key", "receipt.key", "store.p12", "store.pfx", "store.jks", "app.keystore",
	".env", ".env.local", "prod.env", "id_rsa", "id_rsa.pub", "id_ed25519", "id_ecdsa", "id_dsa",
	"credentials", "credentials.json", "application_default_credentials.json",
	".npmrc", ".pypirc", ".netrc", "_netrc", "kubeconfig", "config.json", ".git-credentials",
}

func hasGlob(s string) bool { return strings.ContainsAny(s, "*?[") }

func matchQuiet(pattern, name string) bool {
	ok, err := filepath.Match(pattern, name)
	return err == nil && ok
}

// ExpandBraces performs shell brace expansion ("~/.{ssh,aws}/x") so path
// checks see every name the shell would. It is bounded: past max results
// the unexpanded remainder is returned as-is (still checked by globs).
func ExpandBraces(s string, max int) []string {
	out := []string{s}
	for i := 0; i < 8; i++ { // nesting / repeat bound
		var next []string
		changed := false
		for _, x := range out {
			open := strings.IndexByte(x, '{')
			if open < 0 {
				next = append(next, x)
				continue
			}
			depth, close := 0, -1
			var commas []int
			for j := open; j < len(x); j++ {
				switch x[j] {
				case '{':
					depth++
				case '}':
					depth--
				case ',':
					if depth == 1 {
						commas = append(commas, j)
					}
				}
				if depth == 0 {
					close = j
					break
				}
			}
			if close < 0 || len(commas) == 0 {
				next = append(next, x)
				continue
			}
			changed = true
			bounds := append(append([]int{open}, commas...), close)
			for k := 0; k+1 < len(bounds); k++ {
				next = append(next, x[:open]+x[bounds[k]+1:bounds[k+1]]+x[close+1:])
			}
		}
		out = next
		if !changed || len(out) > max {
			break
		}
	}
	if len(out) > max {
		out = out[:max]
	}
	return out
}

// IsCredentialAdjacentPath reports whether path looks like it holds secrets.
func IsCredentialAdjacentPath(path string) bool { return credentialAdjacent(path) }
