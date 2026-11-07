// Package server is warden's embedded web dashboard and HTTP API: the Fleet
// Command view — burn bar, live run table with per-row kill, anomaly feed,
// run-detail trace waterfall, approvals, and one-click SIEM export.
//
// Auth (v1, deliberately minimal — SSO is a Compliance-tier feature):
//   - Default listens on 127.0.0.1 only, no token required (solo mode: it's you).
//   - With --token / WARDEN_TOKENS="secret=role,...", every /api/* call needs
//     `Authorization: Bearer <secret>`. Roles: viewer < operator < admin.
//     Kill-run needs operator; quarantine/freeze/tool-deny need admin.
//     The dashboard is a single static page; the token lives in sessionStorage.
package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/calasdan-sketch/warden/internal/anomaly"
	"github.com/calasdan-sketch/warden/internal/collect"
	"github.com/calasdan-sketch/warden/internal/join"
	"github.com/calasdan-sketch/warden/internal/kill"
	"github.com/calasdan-sketch/warden/internal/model"
	"github.com/calasdan-sketch/warden/internal/otel"
	"github.com/calasdan-sketch/warden/internal/store"
)

//go:embed web/*
var webFS embed.FS

// Role is an API role. Empty role = solo mode (all allowed).
type Role string

const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

// Server serves the dashboard and API.
type Server struct {
	st     *store.Store
	col    *collect.Collector
	kills  *kill.Manager
	engine *anomaly.Engine
	mux    *http.ServeMux
	tokens map[string]Role // secret -> role; empty = no auth
	budget float64         // daily budget USD for the burn bar (0 = unset)
}

// Options configures the server.
type Options struct {
	Store     *store.Store
	Collector *collect.Collector
	Kills     *kill.Manager
	Engine    *anomaly.Engine
	Tokens    map[string]Role
	BudgetUSD float64
}

// New builds the server.
func New(o Options) *Server {
	s := &Server{
		st: o.Store, col: o.Collector, kills: o.Kills, engine: o.Engine,
		tokens: o.Tokens, budget: o.BudgetUSD,
		mux: http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("/", s.handleIndex)
	s.mux.HandleFunc("/app.js", s.handleStatic("web/app.js", "application/javascript"))
	s.mux.HandleFunc("/style.css", s.handleStatic("web/style.css", "text/css"))
	s.mux.HandleFunc("/api/v1/burn", s.authed(RoleViewer, s.handleBurn))
	s.mux.HandleFunc("/api/v1/runs", s.authed(RoleViewer, s.handleRuns))
	s.mux.HandleFunc("/api/v1/runs/", s.authed(RoleViewer, s.handleRunDetail))
	s.mux.HandleFunc("/api/v1/alerts", s.authed(RoleViewer, s.handleAlerts))
	s.mux.HandleFunc("/api/v1/kill", s.authed(RoleOperator, s.handleKill))
	s.mux.HandleFunc("/api/v1/approvals/pending", s.authed(RoleViewer, s.handlePendingApprovals))
	s.mux.HandleFunc("/api/v1/approvals/", s.authed(RoleOperator, s.handleDecideApproval))
	s.mux.HandleFunc("/api/v1/export", s.authed(RoleViewer, s.handleExport))
	s.mux.HandleFunc("/api/v1/live", s.authed(RoleViewer, s.handleLive))
	s.mux.HandleFunc("/api/v1/scan", s.authed(RoleOperator, s.handleScan))
	s.mux.HandleFunc("/api/v1/report", s.authed(RoleOperator, s.handleReport))
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler { return s.mux }

// StartTicker runs anomaly evaluation + stale-run reconciliation in the background.
func (s *Server) StartTicker(stop <-chan struct{}) {
	tick := time.NewTicker(30 * time.Second)
	recon := time.NewTicker(5 * time.Minute)
	defer tick.Stop()
	defer recon.Stop()
	s.scanOnce()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			s.scanOnce()
		case <-recon.C:
			_, _ = s.col.Reconcile(15 * time.Minute)
		}
	}
}

func (s *Server) scanOnce() {
	runs, err := s.st.ListRuns(store.RunFilter{LiveOnly: true, Limit: 500})
	if err != nil {
		return
	}
	fleets := map[string]bool{}
	for _, r := range runs {
		fleets[r.FleetID] = true
		_, _ = s.engine.EvaluateRun(r.RunID)
	}
	for f := range fleets {
		_, _ = s.engine.EvaluateFleet(f)
	}
}

// --- auth ---

func (s *Server) authed(min Role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(s.tokens) == 0 {
			next(w, r)
			return
		}
		secret := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		secret = strings.TrimSpace(secret)
		if secret == "" {
			// EventSource (SSE) can't set headers; allow ?token= there.
			secret = r.URL.Query().Get("token")
		}
		role, ok := s.tokens[secret]
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if roleRank(role) < roleRank(min) {
			http.Error(w, "forbidden: role "+string(role)+" < "+string(min), http.StatusForbidden)
			return
		}
		r.Header.Set("X-Warden-Role", string(role))
		next(w, r)
	}
}

func roleRank(r Role) int {
	switch r {
	case RoleAdmin:
		return 3
	case RoleOperator:
		return 2
	case RoleViewer:
		return 1
	}
	return 0
}

func actor(r *http.Request) string {
	if a := r.Header.Get("X-Warden-Actor"); a != "" {
		return a
	}
	if role := r.Header.Get("X-Warden-Role"); role != "" {
		return "dashboard:" + role
	}
	return "dashboard"
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "no dashboard", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

func (s *Server) handleStatic(path, ctype string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := webFS.ReadFile(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", ctype)
		_, _ = w.Write(b)
	}
}

// --- API ---

type burnResp struct {
	Date      string  `json:"date"`
	GrossUSD  float64 `json:"gross_usd"`
	SavedUSD  float64 `json:"saved_usd"`
	NetUSD    float64 `json:"net_usd"`
	LiveRuns  int     `json:"live_runs"`
	BudgetUSD float64 `json:"budget_usd,omitempty"`
}

func (s *Server) handleBurn(w http.ResponseWriter, r *http.Request) {
	today := time.Now().UTC().Format("2006-01-02")
	var gross, saved float64
	_ = s.st.DB().QueryRow(`SELECT COALESCE(SUM(cost_usd),0), COALESCE(SUM(cost_saved_usd),0)
		FROM runs WHERE substr(started_at,1,10)=?`, today).Scan(&gross, &saved)
	live, _ := s.st.CountLive()
	resp := burnResp{Date: today, GrossUSD: gross, SavedUSD: saved, NetUSD: gross - saved, LiveRuns: live}
	if s.budget > 0 {
		resp.BudgetUSD = s.budget
	}
	writeJSON(w, resp)
}

func (s *Server) handleRuns(w http.ResponseWriter, r *http.Request) {
	f := store.RunFilter{Limit: 100}
	if v := r.URL.Query().Get("status"); v != "" {
		f.Status = model.RunStatus(v)
	}
	if v := r.URL.Query().Get("live"); v == "1" || v == "true" {
		f.LiveOnly = true
	}
	f.FleetID = r.URL.Query().Get("fleet")
	f.AgentID = r.URL.Query().Get("agent")
	runs, err := s.st.ListRuns(f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, runs)
}

type runDetailResp struct {
	Run     *model.Run     `json:"run"`
	Spans   []*model.Span  `json:"spans"`
	Events  []*model.Event `json:"events"`
	Receipt any            `json:"receipt,omitempty"`
	// SpansTotal is the run's real span count; Spans holds at most
	// maxDetailSpans of them (the oldest), so a 100,000-span run does not
	// become a 50 MB response. Use `warden replay` for the whole run.
	SpansTotal int `json:"spans_total"`
}

const maxDetailSpans = 2000

func (s *Server) handleRunDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/runs/")
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	run, err := s.st.GetRun(id)
	if err != nil {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}
	spans, _ := s.st.SpansForRun(id)
	events, _ := s.st.EventsForRun(id, 200)
	if spans == nil {
		spans = []*model.Span{}
	}
	if events == nil {
		events = []*model.Event{}
	}
	total := len(spans)
	if total > maxDetailSpans {
		spans = spans[:maxDetailSpans]
	}
	resp := runDetailResp{Run: run, Spans: spans, Events: events, SpansTotal: total}
	if rec, body, err := s.st.GetReceipt(id); err == nil {
		resp.Receipt = map[string]any{"receipt": rec, "body": json.RawMessage(body)}
	}
	writeJSON(w, resp)
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	alerts, err := s.st.ListAlerts(r.URL.Query().Get("status"), 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, alerts)
}

type killReq struct {
	Scope        string `json:"scope"`
	Target       string `json:"target"`
	Reason       string `json:"reason"`
	TTLMinutes   int    `json:"ttl_minutes,omitempty"`
	HardDeadline int    `json:"hard_deadline_minutes,omitempty"`
	Enforce      bool   `json:"enforce,omitempty"`
}

func (s *Server) handleKill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req killReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad JSON", http.StatusBadRequest)
		return
	}
	scope := model.KillScope(req.Scope)
	if !scope.Valid() {
		http.Error(w, "invalid scope", http.StatusBadRequest)
		return
	}
	// Agent/fleet/tool scopes are admin-only (blast radius).
	if scope != model.KillScopeRun && roleRank(Role(r.Header.Get("X-Warden-Role"))) < roleRank(RoleAdmin) && len(s.tokens) > 0 {
		http.Error(w, "forbidden: agent/fleet/tool kill requires admin", http.StatusForbidden)
		return
	}
	a := actor(r)
	var err error
	var result string
	switch scope {
	case model.KillScopeRun:
		err = s.kills.KillRun(req.Target, req.Reason, a)
		result = "run kill requested"
	case model.KillScopeAgent:
		if req.Enforce {
			err = s.kills.ClearAgentQuarantine(req.Target, req.Reason, a)
			result = "quarantine cleared"
		} else {
			ttl := time.Duration(req.TTLMinutes) * time.Minute
			err = s.kills.QuarantineAgent(req.Target, ttl, req.Reason, a)
			result = "agent quarantined"
		}
	case model.KillScopeFleet:
		if req.Enforce {
			err = s.kills.EnforceFleetFreeze(req.Target, req.Reason, a)
			result = "freeze enforced"
		} else {
			hd := time.Duration(req.HardDeadline) * time.Minute
			err = s.kills.FreezeFleet(req.Target, hd, req.Reason, a)
			result = "fleet frozen"
		}
	case model.KillScopeTool:
		if req.Enforce {
			err = s.kills.EnableTool(req.Target, "", req.Reason, a)
			result = "tool re-allowed"
		} else {
			err = s.kills.DisableTool(req.Target, "", req.Reason, a)
			result = "tool denied"
		}
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": result})
}

func (s *Server) handlePendingApprovals(w http.ResponseWriter, r *http.Request) {
	pending, err := s.st.PendingApprovals()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, pending)
}

type decideReq struct {
	Decision string `json:"decision"` // approved | denied
	Reason   string `json:"reason"`
}

func (s *Server) handleDecideApproval(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var id int64
	if _, err := fmt.Sscanf(strings.TrimPrefix(r.URL.Path, "/api/v1/approvals/"), "%d", &id); err != nil {
		http.Error(w, "bad approval id", http.StatusBadRequest)
		return
	}
	var req decideReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad JSON", http.StatusBadRequest)
		return
	}
	if req.Decision != "approved" && req.Decision != "denied" {
		http.Error(w, "decision must be approved|denied", http.StatusBadRequest)
		return
	}
	if err := s.st.DecideApproval(id, req.Decision, actor(r), req.Reason, time.Now().UTC()); err != nil {
		http.Error(w, "approval not found or already decided", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	s.scanOnce()
	writeJSON(w, map[string]any{"ok": true})
}

// handleReport is the --report-to push endpoint: emitters POST JSONL records.
// Body: {"source": "shortleash|planok|mcp-jail|calas-gateway", "lines": ["{...}", ...]}
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Source string   `json:"source"`
		Lines  []string `json:"lines"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad JSON", http.StatusBadRequest)
		return
	}
	imp := join.New(s.st, s.col)
	n := 0
	for _, line := range req.Lines {
		if err := imp.ImportLine(join.Source(req.Source), line); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		n++
	}
	writeJSON(w, map[string]any{"ok": true, "imported": n})
}

// handleExport streams the audit trail as append-only JSONL (one-click SIEM export).
// Pass ?format=otlp for the OTLP/HTTP JSON span bridge instead.
// Both formats stream in pages: a viewer-role caller must not be able to
// OOM the dashboard by requesting a full export.
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	const pageSize = 1000
	if r.URL.Query().Get("format") == "otlp" {
		w.Header().Set("Content-Type", "application/json")
		offset := 0
		err := otel.EncodeStream(w, func() ([]*model.Span, error) {
			runs, err := s.st.ListRunsPage(pageSize, offset)
			if err != nil {
				return nil, err
			}
			if len(runs) == 0 {
				return nil, nil
			}
			offset += pageSize
			var spans []*model.Span
			for _, run := range runs {
				rs, err := s.st.SpansForRun(run.RunID)
				if err != nil {
					return nil, err
				}
				spans = append(spans, rs...)
			}
			return spans, nil
		})
		// Note: headers are already sent, so a mid-stream DB error truncates
		// the body; the JSONL path above fails before writing instead.
		_ = err
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="warden-export.jsonl"`)
	enc := json.NewEncoder(w)
	for offset := 0; ; offset += pageSize {
		runs, err := s.st.ListRunsPage(pageSize, offset)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(runs) == 0 {
			break
		}
		for _, run := range runs {
			_ = enc.Encode(map[string]any{"type": "run", "run": run})
			spans, _ := s.st.SpansForRun(run.RunID)
			for _, sp := range spans {
				_ = enc.Encode(map[string]any{"type": "span", "span": sp})
			}
			if rec, body, err := s.st.GetReceipt(run.RunID); err == nil {
				_ = enc.Encode(map[string]any{"type": "receipt", "receipt": rec, "body": json.RawMessage(body)})
			}
		}
		if len(runs) < pageSize {
			break
		}
	}
	kills, _ := s.st.ListKills(100000)
	for _, k := range kills {
		_ = enc.Encode(map[string]any{"type": "kill_audit", "kill": k})
	}
}

// handleLive is the SSE live tail for the Fleet Command view.
func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "no SSE", http.StatusInternalServerError)
		return
	}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	send := func() {
		runs, _ := s.st.ListRuns(store.RunFilter{LiveOnly: true, Limit: 100})
		alerts, _ := s.st.ListAlerts("active", 50)
		pending, _ := s.st.PendingApprovals()
		today := time.Now().UTC().Format("2006-01-02")
		var gross, saved float64
		_ = s.st.DB().QueryRow(`SELECT COALESCE(SUM(cost_usd),0), COALESCE(SUM(cost_saved_usd),0)
			FROM runs WHERE substr(started_at,1,10)=?`, today).Scan(&gross, &saved)
		payload, _ := json.Marshal(map[string]any{
			"live_runs": runs, "alerts": alerts, "approvals": pending,
			"gross_usd": gross, "saved_usd": saved, "net_usd": gross - saved,
			"at": time.Now().UTC(),
		})
		fmt.Fprintf(w, "data: %s\n\n", payload)
		fl.Flush()
	}
	send()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			send()
		}
	}
}

// ParseTokens parses WARDEN_TOKENS="secret=role,secret=role".
func ParseTokens(s string) (map[string]Role, error) {
	out := map[string]Role{}
	if strings.TrimSpace(s) == "" {
		return out, nil
	}
	for _, part := range strings.Split(s, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 || kv[0] == "" || kv[1] == "" {
			return nil, fmt.Errorf("bad token entry %q (want secret=role)", part)
		}
		role := Role(strings.ToLower(kv[1]))
		if role != RoleViewer && role != RoleOperator && role != RoleAdmin {
			return nil, fmt.Errorf("bad role %q in %q", kv[1], part)
		}
		out[kv[0]] = role
	}
	return out, nil
}
