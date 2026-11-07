// Package redact implements secret redaction at the collector, BEFORE emission.
// Nothing secret-bearing ever leaves the collector: spans, receipts, events,
// and JSONL lines are all passed through here first.
//
// The rules are deliberately conservative: an over-redaction is a cosmetic
// blemish in the dashboard; an under-redaction is a credential leak in an
// audit trail that may land in a SIEM.
package redact

import (
	"encoding/base64"
	"path/filepath"
	"regexp"
	"strings"
)

// rule is one named redaction pattern.
type rule struct {
	name string
	re   *regexp.Regexp
	// repl is an optional template ($1, $2 ...) for keep-the-key rules. When
	// empty the whole match becomes [redacted:name].
	repl string
	// guard, when set, can veto a match (false = leave it alone), so a rule
	// can be broad without redacting telemetry such as max_tokens=1000.
	guard func(sub []string) bool
	// hints are lowercase literals; the regexp only runs when the text holds
	// at least one of them. It is a pure speed-up (about 40x on large, clean
	// input) and never changes what is matched.
	hints []string
}

// hintsByRule lists the cheap literal pre-filters. A rule absent here always
// runs.
var hintsByRule = map[string][]string{
	"aws_access_key": {"akia", "asia"}, "github_token": {"gh"}, "github_pat": {"github_pat_"},
	"gitlab_token": {"gl"}, "slack_token": {"xox"}, "slack_webhook": {"hooks.slack.com"},
	"discord_webhook": {"/webhooks/"}, "stripe_key": {"_live_", "_test_"}, "stripe_webhook_secret": {"whsec_"},
	"google_api_key": {"aiza"}, "google_oauth_token": {"ya29."}, "anthropic_key": {"sk-ant-"},
	"openai_key": {"sk-"}, "npm_token": {"npm_"}, "huggingface_token": {"hf_"}, "sendgrid_key": {"sg."},
	"shopify_token": {"shp"}, "digitalocean_token": {"dop_v1_"}, "docker_pat": {"dckr_pat_"},
	"private_key": {"private key"}, "jwt": {"eyj"}, "url_credentials": {"://"},
	"azure_secret": {"key", "signature"}, "sas_signature": {"sig="},
	"auth_header":       {"authorization"},
	"api_key_header":    {"api-key", "apikey", "auth-token", "access-token", "gitlab-token", "github-token", "private-token", "subscription-key"},
	"json_secret_value": {"key", "secret", "pass", "pwd", "token", "credential", "bearer"},
	"cli_secret_flag":   {"-"}, "mysql_password": {"mysql", "mariadb"},
	"kv_secret_value": {"key", "secret", "pass", "pwd", "token", "credential"},
	"bearer_token":    {"bearer"},
}

func mayMatch(low string, hints []string) bool {
	if len(hints) == 0 {
		return true
	}
	for _, h := range hints {
		if strings.Contains(low, h) {
			return true
		}
	}
	return false
}

var rules []rule

func add(name, pattern string) {
	rules = append(rules, rule{name: name, re: regexp.MustCompile(pattern), hints: hintsByRule[name]})
}

func addKeep(name, pattern, repl string, guard func([]string) bool) {
	rules = append(rules, rule{name: name, re: regexp.MustCompile(pattern), repl: repl, guard: guard, hints: hintsByRule[name]})
}

// counterKey reports key names that carry a count or a setting, not a
// credential ("max_tokens", "tokens_in", "token_count", "password_policy");
// they must stay readable in the trail.
var counterKey = regexp.MustCompile(`(?i)(?:tokens|(?:max|min|num|total|input|output|prompt|completion|cached|reasoning)[_.-]?tokens?|token[_.-]?(?:count|limit|usage|budget|used|type|ttl|expiry|expires)|(?:password|passwd|pwd|secret)[_.-]?(?:policy|strategy|rotation|length|min|max|file|path|name|manager|store|ref|type|age))$`)

func notCounter(sub []string) bool {
	return len(sub) < 2 || !counterKey.MatchString(sub[1])
}

func init() {
	// --- Vendor token formats (whole token masked). Order matters: the more
	// specific prefixes run before generic ones.
	add("aws_access_key", `\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|AKIA[0-9A-Z]{16}`)
	add("github_token", `gh[pousr]_[A-Za-z0-9]{20,}`)
	add("github_pat", `github_pat_[A-Za-z0-9_]{20,}`)
	add("gitlab_token", `gl(?:pat|dt|rt|ptt|cbt|soat|ft|imt|agent|oas)-[A-Za-z0-9_-]{20,}`)
	add("slack_token", `xox[baprs]-[A-Za-z0-9-]{10,}`)
	add("slack_webhook", `https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]{20,}`)
	add("discord_webhook", `https://(?:discord|discordapp)\.com/api/webhooks/\d+/[A-Za-z0-9_-]{20,}`)
	add("stripe_key", `(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}`)
	add("stripe_webhook_secret", `whsec_[A-Za-z0-9]{16,}`)
	add("google_api_key", `AIza[0-9A-Za-z_-]{35}`)
	add("google_oauth_token", `ya29\.[A-Za-z0-9_-]{20,}`)
	add("anthropic_key", `sk-ant-[A-Za-z0-9_-]{20,}`)
	// OpenAI-style keys, including sk-proj-/sk-svcacct- forms with - and _.
	add("openai_key", `sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}`)
	add("npm_token", `npm_[A-Za-z0-9]{30,}`)
	add("huggingface_token", `hf_[A-Za-z0-9]{30,}`)
	add("sendgrid_key", `SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}`)
	add("shopify_token", `shp(?:at|ss|ca|pa)_[A-Fa-f0-9]{32}`)
	add("digitalocean_token", `dop_v1_[a-f0-9]{64}`)
	add("docker_pat", `dckr_pat_[A-Za-z0-9_-]{20,}`)
	// Private key material. Also redacts a block cut off before its END line
	// (a truncated argument), to the end of the text.
	add("private_key", `-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|$)`)
	// JWTs (header.payload.signature).
	add("jwt", `eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)

	vendorRules = len(rules)

	// --- Credentials embedded in text.
	// user:password@ in any URL scheme (postgres, mysql, mongodb+srv, redis,
	// amqp, ftp, https, ...). The user name is kept; the password is masked.
	addKeep("url_credentials", `(?i)\b([a-z][a-z0-9+.-]{1,20}://[^:/\s@]*:)[^@\s/]+@`, "${1}[redacted]@", nil)
	// Azure storage / SAS style secrets.
	addKeep("azure_secret", `(?i)((?:AccountKey|SharedAccessKey|SharedAccessSignature|EndpointSuffix=[^;]*;?\s*SharedAccessKey)\s*=\s*)[^;\s"']+`, "${1}[redacted]", nil)
	addKeep("sas_signature", `(?i)([?&]sig=)[A-Za-z0-9%+/=]{16,}`, "${1}[redacted]", nil)
	// HTTP credential headers: Authorization (any scheme), API-key headers.
	addKeep("auth_header", `(?i)(authorization["']?\s*[:=]\s*["']?(?:(?:basic|bearer|token|digest|negotiate|aws4-hmac-sha256)\s+)?)[^\s"',;]{8,}`, "${1}[redacted]", nil)
	addKeep("api_key_header", `(?i)((?:x-api-key|x-auth-token|x-access-token|x-gitlab-token|x-github-token|private-token|api-key|apikey|ocp-apim-subscription-key)["']?\s*[:=]\s*["']?)[^\s"',;]+`, "${1}[redacted]", nil)
	// JSON string values: {"api_key": "secret..."}.
	addKeep("json_secret_value", `(?i)("(?:[A-Za-z0-9_.-]*(?:api[_-]?key|secret|password|passwd|pwd|token|credential|private[_-]?key|bearer))["']?\s*:\s*["']?)([^"',}\s]+)(["']?)`,
		"${1}[redacted]${3}", func(sub []string) bool {
			// sub[1] holds the quoted key here; strip to the name.
			return notCounter([]string{"", strings.Trim(strings.SplitN(sub[1], ":", 2)[0], " \"'")})
		})
	// Command-line flags: --password hunter2, --token=abc, --api-key abc.
	addKeep("cli_secret_flag", `(?i)(--?(?:password|passwd|pwd|token|api[_-]?key|apikey|secret|client[_-]?secret|auth[_-]?token|access[_-]?token|bearer|credential)(?:=|\s+)["']?)([^\s"'-][^\s"']*)`, "${1}[redacted]", nil)
	// mysql-family -pSECRET (no space).
	addKeep("mysql_password", `(\b(?:mysql|mysqldump|mysqladmin|mariadb)\b[^\n|;&]*?\s-p)([^\s-][^\s]*)`, "${1}[redacted]", nil)
	// Assignments: API_KEY=..., DB_PASSWORD = "a b", AWS_SECRET_ACCESS_KEY: ...
	addKeep("kv_secret_value",
		`(?i)\b([A-Za-z0-9_.-]*(?:api[_-]?key|apikey|secret|passw(?:or)?d|passwd|pwd|token|credential|private[_-]?key|auth[_-]?key|access[_-]?key|signing[_-]?key)[A-Za-z0-9_.-]*)(\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s"'&;,)}\]]+)`,
		"${1}${2}[redacted]", notCounter)
	// Bearer tokens anywhere.
	addKeep("bearer_token", `(?i)(bearer\s+)([A-Za-z0-9\-._~+/]+=*)`, "${1}[redacted]", nil)
}

// invisible reports characters that must not survive into an audit trail:
// zero-width and bidirectional controls (used to hide or reorder text), and
// control bytes including ESC (terminal escape sequences). \t \n \r are kept.
func invisible(r rune) bool {
	switch {
	case r == '\t' || r == '\n' || r == '\r':
		return false
	case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
		return true
	case r == 0x00ad || r == 0x061c || r == 0x180e:
		return true
	case r >= 0x200b && r <= 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x2060 && r <= 0x206f, r == 0xfeff:
		return true
	}
	return false
}

// Sanitize removes zero-width, bidi and terminal-control characters. The
// redactor runs it first so a secret split by an invisible character is still
// found, and so stored text cannot spoof or reorder what a reviewer reads.
func Sanitize(s string) string {
	clean := true
	for _, r := range s {
		if invisible(r) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	return strings.Map(func(r rune) rune {
		if invisible(r) {
			return -1
		}
		return r
	}, s)
}

var b64Candidate = regexp.MustCompile(`[A-Za-z0-9+/]{24,}={0,2}`)

// vendorRules is the number of leading rules that match self-identifying
// token formats; encoded copies are tested against these only.
var vendorRules int

func encodedSecrets(s string) string {
	if len(s) > 1<<20 {
		return s
	}
	n := 0
	return b64Candidate.ReplaceAllStringFunc(s, func(m string) string {
		if n++; n > 64 || len(m) > 8192 {
			return m
		}
		t := strings.TrimRight(m, "=")
		for _, enc := range []*base64.Encoding{base64.RawStdEncoding} {
			b, err := enc.DecodeString(t)
			if err != nil || len(b) < 16 {
				continue
			}
			ds := string(b)
			for _, r := range rules[:vendorRules] {
				if r.re.MatchString(ds) {
					return "[redacted:encoded_secret]"
				}
			}
		}
		return m
	})
}

// RedactString redacts secrets from s. It returns the redacted string and
// whether any redaction happened. Redactions are stable and deterministic:
// the same secret always maps to the same placeholder, so arg hashes computed
// over redacted text stay consistent. Invisible/bidi/control characters are
// stripped (see Sanitize); stripping alone does not count as a redaction hit.
func RedactString(s string) (string, bool) {
	out := Sanitize(s)
	hit := false
	low := strings.ToLower(out)
	for _, r := range rules {
		r := r
		if !mayMatch(low, r.hints) {
			continue
		}
		out = r.re.ReplaceAllStringFunc(out, func(m string) string {
			if r.repl == "" {
				hit = true
				return "[redacted:" + r.name + "]"
			}
			if strings.Contains(m, "[redacted") {
				return m // already masked: keeps redaction idempotent
			}
			sub := r.re.FindStringSubmatch(m)
			if sub == nil || (r.guard != nil && !r.guard(sub)) {
				return m
			}
			hit = true
			return r.re.ReplaceAllString(m, r.repl)
		})
	}
	if enc := encodedSecrets(out); enc != out {
		out, hit = enc, true
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
	".pgpass", ".my.cnf", ".vault-token", ".s3cfg", ".boto", ".dockercfg", ".htpasswd", ".rclone.conf",
	"*.kdbx", "*.keychain", "*.keychain-db", "shadow", "gshadow", "master.key", "wallet.dat",
	"terraform.tfstate*", "*.tfvars", "service-account*.json", "login data", "cookies.sqlite", "key4.db", "logins.json",
}

// credentialSubpaths are path fragments (lower-case, forward slashes) that
// mark credential stores whose file names are too generic to match alone.
var credentialSubpaths = []string{
	"/.config/gh/", "/.config/op/", "/.config/rclone", "/.cargo/credentials", "/.m2/settings", "/.gem/credentials",
	"/.password-store", "/library/keychains", "/.mozilla/", "/.config/google-chrome/", "/.config/chromium/",
	"/library/application support/google/chrome", "/.terraform.d/", "/.local/share/keyrings", "/.config/1password", "/.codex/auth", "/.claude/.credentials", "/.config/claude/", "/.bash_history", "/.zsh_history", "/.python_history", "/.psql_history", "/.mysql_history", "/.node_repl_history", "/.config/fish/fish_history",
	"/.ethereum/keystore", "/.bitcoin/", "/etc/sudoers", "/appdata/roaming/microsoft/credentials",
}

// CredentialSubpathIn reports a credential-store path fragment found anywhere
// in free text (a shell command), tolerant of quotes and escaped spaces, so
// "Application\ Support/Google/Chrome" and "Application Support" both match.
func CredentialSubpathIn(text string) (string, bool) {
	n := strings.ToLower(text)
	n = strings.NewReplacer(`\ `, " ", `\`, "/", `"`, "", `'`, "").Replace(n)
	for _, sub := range credentialSubpaths {
		if strings.Contains(n, sub) {
			return strings.TrimPrefix(sub, "/"), true
		}
	}
	return "", false
}

// procEnviron matches /proc/<pid|self>/environ, which holds a process's secrets.
var procEnviron = regexp.MustCompile(`/proc/[^/]+/(?:environ|mem|maps)$`)

// CredentialDirs are directory names whose whole subtree is
// credential-adjacent. Matched as a path component, with or without a
// trailing slash (".ssh", "~/.ssh", "/root/.ssh/x").
var CredentialDirs = []string{".ssh", ".aws", ".gnupg", ".docker", ".kube", "gcloud", ".warden", ".azure"}

func credentialAdjacentOne(path string) bool {
	norm := strings.ToLower(strings.ReplaceAll(path, `\`, "/"))
	if procEnviron.MatchString(norm) {
		return true
	}
	for _, sub := range credentialSubpaths {
		if strings.Contains(norm, sub) || strings.HasPrefix(norm, sub[1:]) {
			return true
		}
	}
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
