package main

import (
	"fmt"
	"os"

	"warden/internal/model"
)

func (a *app) cmdKill(args []string) int {
	fs := newFlagSet("kill")
	scope := fs.String("scope", "run", "run|agent|fleet|tool")
	target := fs.String("target", "", "run id | agent id | fleet id | tool name")
	reason := fs.String("reason", "", "required: why (\"oops\" is acceptable, empty is not)")
	actor := fs.String("actor", actorName(), "who is killing")
	ttl := fs.Duration("ttl", 0, "agent quarantine TTL (default 1h)")
	hardDeadline := fs.Duration("hard-deadline", 0, "fleet freeze drain deadline (default 5m)")
	enforce := fs.Bool("enforce", false, "fleet: hard-kill stragglers past the deadline; tool: re-allow")
	clear := fs.Bool("clear", false, "agent: lift quarantine; fleet: unfreeze")
	fleet := fs.String("fleet", "", "tool: fleet scope for the deny-list")
	if !parseArgs(fs, args) {
		return 2
	}

	s := model.KillScope(*scope)
	if !s.Valid() {
		fmt.Fprintln(os.Stderr, "kill: scope must be run|agent|fleet|tool")
		return 2
	}
	var err error
	switch s {
	case model.KillScopeRun:
		err = a.kills.KillRun(*target, *reason, *actor)
	case model.KillScopeAgent:
		if *clear {
			err = a.kills.ClearAgentQuarantine(*target, *reason, *actor)
		} else {
			err = a.kills.QuarantineAgent(*target, *ttl, *reason, *actor)
		}
	case model.KillScopeFleet:
		switch {
		case *clear:
			err = a.kills.UnfreezeFleet(*target, *reason, *actor)
		case *enforce:
			err = a.kills.EnforceFleetFreeze(*target, *reason, *actor)
		default:
			err = a.kills.FreezeFleet(*target, *hardDeadline, *reason, *actor)
		}
	case model.KillScopeTool:
		if *clear {
			err = a.kills.EnableTool(*target, *fleet, *reason, *actor)
		} else {
			err = a.kills.DisableTool(*target, *fleet, *reason, *actor)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "kill:", err)
		return 1
	}
	fmt.Printf("kill %s %s: done (audited)\n", s, *target)
	return 0
}
