package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"warden/internal/server"
)

func (a *app) cmdDashboard(args []string) int {
	fs := newFlagSet("dashboard")
	listen := fs.String("listen", "127.0.0.1:8420", "listen address (bind 127.0.0.1 to keep it local)")
	budget := fs.Float64("budget", 0, "daily budget USD for the burn bar (0 = unset)")
	if !parseArgs(fs, args) {
		return 2
	}

	tokens, err := server.ParseTokens(os.Getenv("WARDEN_TOKENS"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "dashboard:", err)
		return 1
	}
	srv := server.New(server.Options{
		Store: a.st, Collector: a.col, Kills: a.kills, Engine: a.engine,
		Tokens: tokens, BudgetUSD: *budget,
	})
	stop := make(chan struct{})
	defer close(stop)
	go srv.StartTicker(stop)

	url := "http://" + *listen
	fmt.Printf("warden fleet command: %s\n", url)
	if len(tokens) == 0 {
		fmt.Println("auth: none (localhost only — set WARDEN_TOKENS=secret=role to require tokens)")
	} else {
		fmt.Printf("auth: %d token(s) required\n", len(tokens))
	}
	s := &http.Server{Addr: *listen, Handler: srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second}
	if err := s.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "dashboard:", err)
		return 1
	}
	return 0
}
