package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/calasdan-sketch/warden/internal/collect"
	"github.com/calasdan-sketch/warden/internal/policy"
)

func (a *app) cmdInit(args []string) int {
	if _, err := os.Stat(a.dataDir + "/policy.yaml"); os.IsNotExist(err) {
		if err := os.WriteFile(a.dataDir+"/policy.yaml", []byte(policy.DefaultYAML), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "init:", err)
			return 1
		}
		fmt.Println("wrote", a.dataDir+"/policy.yaml")
	}
	fmt.Println("data dir: ", a.dataDir)
	fmt.Println("signing key:", a.signer.KeyID())
	fmt.Println("policy: default (deny-by-default on shell, egress, credential files)")
	return 0
}

func (a *app) cmdWrap(args []string) int {
	fs := newFlagSet("wrap")
	agent := fs.String("agent", "", "agent id (default: basename of command)")
	fleet := fs.String("fleet", "default", "fleet id")
	operator := fs.String("operator", "", "human operator (default: $USER)")
	model := fs.String("model", "", "model name")
	approvalTimeout := fs.Duration("approval-timeout", 10*time.Minute, "how long to wait for a human approval")
	// Parse manually: everything after "--" (or the first non-flag arg) is the command.
	var cmdArgs []string
	for i, arg := range args {
		if arg == "--" {
			cmdArgs = args[i+1:]
			args = args[:i]
			break
		}
	}
	_ = fs.Parse(args)
	if cmdArgs == nil {
		cmdArgs = fs.Args()
	}
	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "wrap: no command given")
		return 2
	}
	command := strings.Join(cmdArgs, " ")
	if *agent == "" {
		*agent = "cmd:" + cmdArgs[0]
	}
	if *operator == "" {
		*operator = actorName()
	}

	r, err := a.col.NewRunner(collect.RunOptions{
		AgentID: *agent, FleetID: *fleet, Operator: *operator,
		Model: *model, Command: command,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "wrap:", err)
		return 1
	}
	fmt.Printf("run %s  agent=%s fleet=%s\n", r.RunID(), *agent, *fleet)

	// If the command needs human approval, wait for it before starting.
	if needsApproval(a, r.RunID()) {
		fmt.Println("policy requires human approval; waiting…")
		fmt.Printf("  approve with: warden approve --id <n> --decision approved\n")
		if err := r.AwaitApproval(*approvalTimeout); err != nil {
			fmt.Fprintln(os.Stderr, "wrap:", err)
			return 1
		}
	}

	if err := r.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "wrap:", err)
		return 1
	}

	// Seal the receipt even when WE are killed.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		fmt.Fprintf(os.Stderr, "\nwrap: received %s, stopping run…\n", sig)
		_ = r.Shutdown("wrap received "+sig.String(), actorName())
		os.Exit(143)
	}()

	r.Wait()
	if code := r.ExitCode(); code != 0 {
		return code
	}
	return 0
}

func needsApproval(a *app, runID string) bool {
	pending, err := a.st.PendingApprovals()
	if err != nil {
		return false
	}
	for _, p := range pending {
		if p.RunID == runID {
			return true
		}
	}
	return false
}
