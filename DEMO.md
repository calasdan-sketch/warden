# 60-second demo script

Prereqs: `./warden` built, a terminal.

```bash
# 0:00 — setup (one command, self-healing)
./warden init

# 0:10 — run something under supervision
./warden wrap --agent demo --fleet laptop -- python3 -c "import time; time.sleep(25)"

# (in a second terminal, 0:20) — dashboard
./warden dashboard --budget 50
# open http://127.0.0.1:8420 — live burn bar, the run in the table

# 0:30 — policy gate in one line
./warden gate --tool bash --args "rm -rf /"        # exit 3: deny
./warden gate --tool bash --args "cat .env"        # exit 4: needs approval

# 0:40 — the kill switch
./warden kill --scope run --target <run-id> --reason "demo kill" --actor you
# dashboard row flips to killed_operator; receipt sealed

# 0:50 — the money trail
./warden verify          # all receipts: signature + chain OK
./warden export --format otlp | head   # spans, OTLP-flavored, for your Datadog
```

Hooks for framework integration (LangChain/CrewAI/etc.): set
`WARDEN_RUN_ID` and `WARDEN_SOCK` in the child env (done automatically by
`wrap`), then emit spans from anywhere:

```bash
./warden span --kind tool.call --tool bash --args "git status"
./warden span --kind llm.call --model claude-sonnet-4-5 \
  --tokens-in 1200 --tokens-out 400 --cost 0.012
```
