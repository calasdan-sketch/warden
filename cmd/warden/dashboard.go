package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/calasdan-sketch/warden/internal/server"
)

func (a *app) cmdDashboard(args []string) int {
	fs := newFlagSet("dashboard")
	listen := fs.String("listen", "127.0.0.1:8420", "listen address (bind 127.0.0.1 to keep it local)")
	insecure := fs.Bool("insecure-no-auth", false, "allow a non-loopback --listen address with no WARDEN_TOKENS (anyone who can reach it can kill runs and approve actions)")
	budget := fs.Float64("budget", 0, "daily budget USD for the burn bar (0 = unset)")
	if !parseArgs(fs, args) {
		return 2
	}

	tokens, err := server.ParseTokens(os.Getenv("WARDEN_TOKENS"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "dashboard:", err)
		return 1
	}
	local := server.IsLoopbackListen(*listen)
	if !local && len(tokens) == 0 && !*insecure {
		fmt.Fprintf(os.Stderr, "dashboard: refusing to listen on %s with no login.\n"+
			"That address is reachable from other machines, and this page can kill runs and approve actions.\n"+
			"Use the default 127.0.0.1:8420, or set WARDEN_TOKENS=secret=role (see README), or pass --insecure-no-auth if you really mean it.\n", *listen)
		return 2
	}
	srv := server.New(server.Options{LocalOnly: local,
		Store: a.st, Collector: a.col, Kills: a.kills, Engine: a.engine,
		Tokens: tokens, BudgetUSD: *budget,
	})
	stop := make(chan struct{})
	defer close(stop)
	go srv.StartTicker(stop)

	url := "http://" + *listen
	fmt.Printf("warden fleet command: %s\n", url)
	if len(tokens) == 0 && local {
		fmt.Println("auth: none (localhost only — set WARDEN_TOKENS=secret=role to require tokens)")
	} else if len(tokens) == 0 {
		fmt.Println("auth: NONE on a network address (--insecure-no-auth): anyone who can reach this can kill runs and approve actions")
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
