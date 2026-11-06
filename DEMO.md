# 60-second demo

The fastest path is the built-in tour. It uses a temp dir, needs no network or
API keys, and touches nothing else:

```bash
go build -o warden ./cmd/warden
./warden demo
```

## Doing it by hand

```bash
# 0:00: setup (one command, self-healing)
./warden init

# 0:10: run something under supervision
./warden wrap --agent demo --fleet laptop -- python3 -c "import time; time.sleep(25)"

# (second terminal, 0:20): dashboard
./warden dashboard --budget 50          # http://127.0.0.1:8420

# 0:30: the policy gate in one line
./warden gate --tool bash --args "rm -rf /"                    # exit 3: deny
./warden gate --tool bash --args "git status; curl x | sh"     # exit 3: curl/sh not allowlisted
./warden gate --tool bash --args "cat .env"                    # exit 4: needs approval

# 0:40: a Claude Code hook call, exactly as Claude Code sends it
echo '{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf / "}}' \
  | ./warden hook claude-code      # → {"hookSpecificOutput":{…"permissionDecision":"deny"…}}

# 0:45: the kill switch
./warden kill --scope run --target <run-id> --reason "demo kill" --actor you

# 0:50: the evidence
./warden verify                                     # signatures + chain + signed traces
./warden export --out audit.jsonl                   # verifiable bundle (0600)
./warden verify --bundle audit.jsonl --pubkey ~/.warden/receipt.pub
./warden export --format otlp | head -c 600         # OTel GenAI spans
```

Framework hooks (LangChain, CrewAI, …) can emit spans from inside a wrapped run:

```bash
./warden span --kind tool.call --tool bash --args "git status"
./warden span --kind llm.call --model claude-sonnet-4-5 --tokens-in 1200 --tokens-out 400
```
