package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"warden/internal/anomaly"
	"warden/internal/collect"
	"warden/internal/kill"
	"warden/internal/policy"
	"warden/internal/receipt"
	"warden/internal/store"
)

func testServer(t *testing.T, tokens map[string]Role) (*Server, *collect.Collector, *store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "warden.db"))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Parse([]byte("version: 1\nshell:\n  default: deny\n  allow: [sleep, echo]\n"))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := receipt.Generate()
	if err != nil {
		t.Fatal(err)
	}
	col := collect.New(st, pol, signer, dir)
	srv := New(Options{Store: st, Collector: col, Kills: kill.New(st, col, dir), Engine: anomaly.New(st), Tokens: tokens})
	t.Cleanup(func() {
		col.Close()
		st.Close()
	})
	return srv, col, st, dir
}

func get(t *testing.T, srv *Server, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	return rr
}

func postJSON(t *testing.T, srv *Server, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	return rr
}

func TestBurnAndRuns(t *testing.T) {
	srv, col, _, _ := testServer(t, nil)
	r, _, err := col.StartRun(collect.RunOptions{AgentID: "a", FleetID: "f"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := col.SealRun(r.RunID, "completed", nil, nil); err != nil {
		t.Fatal(err)
	}
	rr := get(t, srv, "/api/v1/burn", "")
	if rr.Code != 200 {
		t.Fatalf("burn: %d", rr.Code)
	}
	var b map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if _, ok := b["gross_usd"]; !ok {
		t.Errorf("burn missing gross_usd: %v", b)
	}
	rr = get(t, srv, "/api/v1/runs", "")
	var runs []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &runs); err != nil || len(runs) != 1 {
		t.Fatalf("runs: %v %v", runs, err)
	}
	rr = get(t, srv, "/api/v1/runs/"+r.RunID, "")
	if rr.Code != 200 {
		t.Fatalf("run detail: %d", rr.Code)
	}
	rr = get(t, srv, "/api/v1/runs/nope", "")
	if rr.Code != 404 {
		t.Errorf("missing run should 404, got %d", rr.Code)
	}
}

func TestKillAPI(t *testing.T) {
	srv, col, st, _ := testServer(t, nil)
	rn, err := col.NewRunner(collect.RunOptions{AgentID: "a", FleetID: "f", Command: "sleep 30"})
	if err != nil {
		t.Fatal(err)
	}
	if err := rn.Start(); err != nil {
		t.Fatal(err)
	}
	// Reason required.
	rr := postJSON(t, srv, "/api/v1/kill", "", `{"scope":"run","target":"`+rn.RunID()+`"}`)
	if rr.Code != 400 {
		t.Errorf("kill without reason should 400, got %d: %s", rr.Code, rr.Body.String())
	}
	// Bad scope.
	rr = postJSON(t, srv, "/api/v1/kill", "", `{"scope":"planet","target":"x","reason":"y"}`)
	if rr.Code != 400 {
		t.Errorf("bad scope should 400, got %d", rr.Code)
	}
	// Real kill.
	rr = postJSON(t, srv, "/api/v1/kill", "", `{"scope":"run","target":"`+rn.RunID()+`","reason":"api test"}`)
	if rr.Code != 200 {
		t.Fatalf("kill: %d %s", rr.Code, rr.Body.String())
	}
	rn.Wait()
	got, _ := st.GetRun(rn.RunID())
	if got.Status != "killed_operator" {
		t.Errorf("status = %s", got.Status)
	}
}

func TestAuth(t *testing.T) {
	tokens := map[string]Role{"view-secret": RoleViewer, "op-secret": RoleOperator, "ad-secret": RoleAdmin}
	srv, _, _, _ := testServer(t, tokens)

	if rr := get(t, srv, "/api/v1/burn", ""); rr.Code != 401 {
		t.Errorf("no token should 401, got %d", rr.Code)
	}
	if rr := get(t, srv, "/api/v1/burn", "view-secret"); rr.Code != 200 {
		t.Errorf("viewer should read, got %d", rr.Code)
	}
	// Operator-only endpoint with viewer token.
	if rr := postJSON(t, srv, "/api/v1/kill", "view-secret", `{"scope":"run","target":"x","reason":"y"}`); rr.Code != 403 {
		t.Errorf("viewer kill should 403, got %d", rr.Code)
	}
	// Agent-scope kill needs admin even for operator.
	if rr := postJSON(t, srv, "/api/v1/kill", "op-secret", `{"scope":"agent","target":"x","reason":"y"}`); rr.Code != 403 {
		t.Errorf("operator agent-kill should 403, got %d", rr.Code)
	}
	if rr := postJSON(t, srv, "/api/v1/kill", "ad-secret", `{"scope":"tool","target":"x","reason":"y"}`); rr.Code != 200 {
		t.Errorf("admin tool-deny should work, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestApprovalsAPI(t *testing.T) {
	srv, _, st, _ := testServer(t, nil)
	id, err := st.RequestApproval("run-1", "delete-bucket", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rr := get(t, srv, "/api/v1/approvals/pending", "")
	var pending []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &pending); err != nil || len(pending) != 1 {
		t.Fatalf("pending: %v %v", pending, err)
	}
	rr = postJSON(t, srv, "/api/v1/approvals/99999", "", `{"decision":"approved"}`)
	if rr.Code != 404 {
		t.Errorf("bad approval id should 404, got %d", rr.Code)
	}
	rr = postJSON(t, srv, "/api/v1/approvals/abc", "", `{"decision":"approved"}`)
	if rr.Code != 400 {
		t.Errorf("non-numeric id should 400, got %d", rr.Code)
	}
	rr = postJSON(t, srv, "/api/v1/approvals/1", "", `{"decision":"maybe"}`)
	_ = rr
	// Use the real id.
	rr = postJSON(t, srv, "/api/v1/approvals/"+itoa(id), "", `{"decision":"denied","reason":"too risky"}`)
	if rr.Code != 200 {
		t.Fatalf("decide: %d %s", rr.Code, rr.Body.String())
	}
	rr = get(t, srv, "/api/v1/approvals/pending", "")
	pending = nil
	_ = json.Unmarshal(rr.Body.Bytes(), &pending)
	if len(pending) != 0 {
		t.Errorf("approval should be decided, still pending: %v", pending)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestExport(t *testing.T) {
	srv, col, _, _ := testServer(t, nil)
	r, _, err := col.StartRun(collect.RunOptions{AgentID: "a", FleetID: "f"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := col.SealRun(r.RunID, "completed", nil, nil); err != nil {
		t.Fatal(err)
	}
	rr := get(t, srv, "/api/v1/export", "")
	if rr.Code != 200 {
		t.Fatalf("export: %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/x-ndjson" {
		t.Errorf("content-type = %s", ct)
	}
	lines := strings.Count(strings.TrimSpace(rr.Body.String()), "\n") + 1
	if lines < 2 {
		t.Errorf("export should have run+receipt lines, got %d", lines)
	}
	for _, line := range strings.Split(strings.TrimSpace(rr.Body.String()), "\n") {
		var v map[string]any
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Errorf("export line not JSON: %v", err)
		}
		if v["type"] == nil {
			t.Error("export line missing type")
		}
	}
}

func TestIndexAndStatic(t *testing.T) {
	srv, _, _, _ := testServer(t, nil)
	rr := get(t, srv, "/", "")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "fleet command") {
		t.Errorf("index: %d", rr.Code)
	}
	rr = get(t, srv, "/app.js", "")
	if rr.Code != 200 {
		t.Errorf("app.js: %d", rr.Code)
	}
	rr = get(t, srv, "/style.css", "")
	if rr.Code != 200 {
		t.Errorf("style.css: %d", rr.Code)
	}
	rr = get(t, srv, "/nope", "")
	if rr.Code != 404 {
		t.Errorf("unknown path should 404, got %d", rr.Code)
	}
}

func TestParseTokens(t *testing.T) {
	toks, err := ParseTokens("a=viewer,b=operator,c=admin")
	if err != nil {
		t.Fatal(err)
	}
	if toks["a"] != RoleViewer || toks["b"] != RoleOperator || toks["c"] != RoleAdmin {
		t.Errorf("tokens wrong: %v", toks)
	}
	toks, err = ParseTokens("")
	if err != nil || len(toks) != 0 {
		t.Errorf("empty should give empty map: %v %v", toks, err)
	}
	for _, bad := range []string{"novalue", "a=bogus", "=viewer", "a="} {
		if _, err := ParseTokens(bad); err == nil {
			t.Errorf("bad tokens %q should fail", bad)
		}
	}
}
