package otel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/calasdan-sketch/warden/internal/model"
)

func TestPushPostsOTLPJSON(t *testing.T) {
	var gotBody map[string]any
	var gotAuth, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotCT = r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	p := &Pusher{Endpoint: srv.URL + "/v1/traces", Headers: map[string]string{"Authorization": "Bearer x"}}
	run := &model.Run{RunID: "0123456789abcdef0123456789abcdef", AgentID: "a", StartedAt: time.Now()}
	if err := p.Push(context.Background(), []RunTrace{{Run: run}}); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer x" || gotCT != "application/json" {
		t.Errorf("headers: auth=%q ct=%q", gotAuth, gotCT)
	}
	if len(gotBody["resourceSpans"].([]any)) != 1 {
		t.Errorf("body: %v", gotBody)
	}
}

func TestPushReportsHTTPErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad span", http.StatusBadRequest)
	}))
	defer srv.Close()
	p := &Pusher{Endpoint: srv.URL}
	err := p.Push(context.Background(), []RunTrace{{Run: &model.Run{RunID: "r", StartedAt: time.Now()}}})
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("want 400 error, got %v", err)
	}
}
