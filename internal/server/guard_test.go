package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDashboardRefusesRebindingAndCrossSitePosts(t *testing.T) {
	srv, _, _, _ := testServer(t, nil)
	srv.localOnly = true

	do := func(method, path, host, origin, secFetch, body string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Host = host
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if secFetch != "" {
			req.Header.Set("Sec-Fetch-Site", secFetch)
		}
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		return rr.Code
	}

	// Normal use.
	if c := do("GET", "/api/v1/burn", "127.0.0.1:8420", "", "", ""); c != http.StatusOK {
		t.Errorf("local GET = %d", c)
	}
	for _, h := range []string{"localhost:8420", "[::1]:8420", "127.0.0.1"} {
		if c := do("GET", "/api/v1/burn", h, "", "", ""); c != http.StatusOK {
			t.Errorf("Host %s = %d", h, c)
		}
	}
	// The dashboard's own page posting to itself, and curl (no Origin).
	if c := do("POST", "/api/v1/kill", "127.0.0.1:8420", "http://127.0.0.1:8420", "same-origin", `{"scope":"nope"}`); c != http.StatusBadRequest {
		t.Errorf("same-origin POST should reach the handler (400 for bad scope), got %d", c)
	}
	if c := do("POST", "/api/v1/kill", "127.0.0.1:8420", "", "", `{"scope":"nope"}`); c != http.StatusBadRequest {
		t.Errorf("POST without Origin should reach the handler, got %d", c)
	}
	// DNS rebinding: the page's own name resolves to 127.0.0.1.
	for _, h := range []string{"evil.example:8420", "evil.example", "127.0.0.1.evil.example:8420", "192.168.1.9:8420"} {
		if c := do("GET", "/api/v1/runs", h, "", "", ""); c != http.StatusForbidden {
			t.Errorf("rebinding Host %q = %d, want 403", h, c)
		}
	}
	// Cross-site form post to the kill and approval buttons.
	for _, path := range []string{"/api/v1/kill", "/api/v1/approvals/1", "/api/v1/scan"} {
		if c := do("POST", path, "127.0.0.1:8420", "https://evil.example", "cross-site", `{"scope":"fleet","target":"default","reason":"x"}`); c != http.StatusForbidden {
			t.Errorf("cross-site POST %s = %d, want 403", path, c)
		}
		// Another local page on a different port is also a different origin.
		if c := do("POST", path, "127.0.0.1:8420", "http://127.0.0.1:3000", "", `{}`); c != http.StatusForbidden {
			t.Errorf("other-port POST %s = %d, want 403", path, c)
		}
	}
}

func TestIsLoopbackListen(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8420": true, "localhost:8420": true, "[::1]:8420": true,
		":8420": false, "0.0.0.0:8420": false, "[::]:8420": false, "192.168.1.5:8420": false, "example.com:80": false, "8420": false,
	} {
		if got := IsLoopbackListen(addr); got != want {
			t.Errorf("IsLoopbackListen(%q) = %v, want %v", addr, got, want)
		}
	}
}
