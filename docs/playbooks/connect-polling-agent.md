# Playbook: connect a polling agent (CLI + inbox)

**Goal:** an agent with a shell holds its own credential (never shown in a
chat), reports work, asks the owner, and is woken by a cron poller that runs
a command only when something is new.

**You need:** a running server (`AGG_PUBLIC_URL`, for example
`https://aggregator.example.com`, or `http://127.0.0.1:8787` locally), the
owner CLI configured ([quickstart](quickstart-local.md) steps 4-7), and on
the agent's machine either Node.js 20+ (for `agg`) or `sh` + `curl` (for
`scripts/poll-inbox.sh`), plus `crontab` or another scheduler.

**Conventions:** run each command, compare with *Expected*, run *Check*
(prints `PASS` or `FAIL`), stop at the first `FAIL`. "Owner" steps run where
`agg-owner` is configured; "Agent" steps run on the agent's machine.

The agent CLI is `agg`. Install it with `npm install -g @agent-aggregator/agent-cli`,
or from a clone of this repository (`npm ci && npm run build`) use
`node <clone>/packages/agent-cli/bin/agg.js` wherever this playbook says `agg`.

## 1. Owner: create the connection

```sh
export AGG_PUBLIC_URL=http://127.0.0.1:8787     # your server's base URL
CONN=$(npx agg-owner connection create --provider my_shell_agent --name "My shell agent" --mode cli_poll \
  --scope hub:read --scope hub:write --scope hub:ask | node -pe 'JSON.parse(require("fs").readFileSync(0)).connection.id')
echo "$CONN"
```

Grant only the scopes the agent needs; add `--scope hub:handoff` if it should
hand goals to your primary agent. Expected: a UUID.

Check:

```sh
npx agg-owner connection get --id "$CONN" | grep -q '"status":"pending"' && echo PASS || echo FAIL
```

## 2. Owner: issue a one-time setup code and the setup playbook

```sh
npx agg-owner claim-code --connection "$CONN" --ttl 900
npx agg-owner setup-prompt --connection "$CONN" > setup-prompt.md
```

Expected: `{"code":"XXXXX-XXXXX-XXXXX-XXXXX","expires_at":"<15 minutes from now>"}`.
Give the agent the code, the API base URL (`<AGG_PUBLIC_URL>/api`) and
`setup-prompt.md`. The code works once; the prompt contains no secrets. The
prompt's `agg setup --claim` line has no `--server`: on a machine where `agg`
has never been configured, the agent must add `--server <AGG_PUBLIC_URL>/api`
(step 3) or set `AGG_URL`, otherwise the command exits 2.

Check:

```sh
grep -Eq 'agg_[A-Za-z0-9_-]{20,}|aggown_' setup-prompt.md && echo FAIL || echo PASS
```

## 3. Agent: exchange the code

```sh
agg setup --claim 'XXXXX-XXXXX-XXXXX-XXXXX' --server "$AGG_PUBLIC_URL/api"
```

Expected: `{"ok":true,"connection":{...,"mode":"cli_poll"},"scopes":[...],"stored":"<home>/.config/agent-aggregator/hub.json"}`.
To keep the credential in a vault instead, add `--print-token`, store the
printed value, and export it as `AGG_TOKEN` (plus `AGG_URL="$AGG_PUBLIC_URL/api"`)
whenever `agg` runs.

Check (read-only):

```sh
agg doctor >/dev/null; test $? -eq 0 && echo PASS || echo FAIL
```

Exit code 4 means the code was wrong, used or expired: ask for a new one (step 2).

## 4. Agent: report work

```sh
agg item put --id task-backup --kind task --title "Rotate the backup drive" --status in_progress --next-step "Confirm the swap date"
agg checkpoint --item task-backup --id cp-backup-1 --summary "New drive formatted and verified"
```

Expected: `{"item":{...,"revision":1,...},"changed":true}` and
`{"checkpoint":{...},"created":true}`. Re-running either is a no-op
(`"changed":false` / `"created":false`).

Check (owner):

```sh
npx agg-owner items --connection "$CONN" | grep -q '"id":"task-backup"' && echo PASS || echo FAIL
```

## 5. Agent: install the poller

The hook receives new events as JSON lines on stdin and runs only when there
is something new; the cursor advances only if the hook exits 0. Replace the
example hook with the command that wakes your agent.

```sh
mkdir -p "$HOME/.config/agent-aggregator"
cat > "$HOME/.config/agent-aggregator/wake.sh" <<'EOF'
#!/bin/sh
# Example hook: keep the events for the agent to process on its next run.
cat >> "$HOME/.config/agent-aggregator/events.jsonl"
EOF
chmod 700 "$HOME/.config/agent-aggregator/wake.sh"
agg install-poller --every-minutes 1 --exec "$HOME/.config/agent-aggregator/wake.sh"
```

Cron has a minimal `PATH`. If `agg` is not in `/usr/bin` or `/bin`, pass the
full command with `--bin`, for example
`--bin "$(command -v node) <clone>/packages/agent-cli/bin/agg.js"`.

Expected: `{"ok":true,"installed":true,"entry":"* * * * * agg inbox --cursor-file '...inbox.cursor' --exec '...wake.sh' >> '...poller.log' 2>&1 # agent-aggregator-poller"}`.
Running the command again replaces the entry instead of adding a second one.

Check:

```sh
test "$(crontab -l | grep -c '# agent-aggregator-poller')" -eq 1 && echo PASS || echo FAIL
```

No `crontab` on the machine: `agg install-poller --print ...` prints the line
for your scheduler and changes nothing.

## 6. End to end: ask, answer, wake, acknowledge

Agent:

```sh
agg ask --id q-backup-swap --prompt "Swap the backup drive on Saturday?" --option yes=Yes --option no=No --item task-backup
agg answer --id q-backup-swap; echo "exit $?"
```

Expected: the question with `"status":"pending"`, then the short status and `exit 3`.

Owner:

```sh
npx agg-owner questions --connection "$CONN"
npx agg-owner answer --connection "$CONN" --id q-backup-swap --revision 1 --choice yes
```

Within one poll interval the hook receives the event. Check (agent, after a
minute):

```sh
grep -q '"name":"answer.created"' "$HOME/.config/agent-aggregator/events.jsonl" && echo PASS || echo FAIL
```

Agent: act on the answer, then acknowledge it with the revision you read:

```sh
agg answer --id q-backup-swap        # exit 0; prints the question with "answer":{"choice":"yes",...}
agg ack --id q-backup-swap --revision 1
```

Check:

```sh
agg answer --id q-backup-swap | grep -q '"acknowledged_at":"20' && echo PASS || echo FAIL
```

## 7. Shell-only alternative: `poll-inbox.sh`

Use this instead of steps 3 and 5 on a machine without Node.js. Copy
`scripts/poll-inbox.sh` and `scripts/install-poller.sh` from this repository
into one directory and make them executable (`chmod 700 poll-inbox.sh
install-poller.sh`; the installer refuses a poller it cannot execute). Get the
credential with `curl` from a setup code (the `curl -fsS -X POST ... /v1/claim`
line at the end of `setup-prompt.md`). Each claim issues a new credential and
revokes the connection's previous one, so a connection uses either `agg` or
`poll-inbox.sh`, not both. Put the credential in an owner-only env file:

```sh
mkdir -p "$HOME/.config/agent-aggregator"
(umask 077 && printf "AGG_URL='%s'\nAGG_TOKEN='%s'\n" "$AGG_PUBLIC_URL/api" '<agg_ credential>' > "$HOME/.config/agent-aggregator/poller.env")
AGG_ENV_FILE="$HOME/.config/agent-aggregator/poller.env" sh poll-inbox.sh; echo "exit $?"
```

Expected: each page with new events as one JSON line and `exit 0`, or
`exit 3` when nothing is new; `exit 4` means the credential was rejected.

```sh
sh install-poller.sh --every-minutes 1 --exec "$HOME/.config/agent-aggregator/wake.sh"
```

Expected: `{"ok":true,"installed":true,"entry":"* * * * * AGG_ENV_FILE='...poller.env' AGG_POLL_EXEC='...wake.sh' '.../poll-inbox.sh' >> '...poll-inbox.log' 2>&1 # agent-aggregator-poll-inbox"}`.

Check:

```sh
test "$(crontab -l | grep -c '# agent-aggregator-poll-inbox')" -eq 1 && echo PASS || echo FAIL
```

The page JSON for the hook is `{"events":[...],"cursor":"...","has_more":...}`
(not one line per event as with `agg inbox`).

## 8. Remove the poller

```sh
agg uninstall-poller                 # the agg poller (marker: # agent-aggregator-poller)
sh install-poller.sh --uninstall     # the poll-inbox.sh poller (marker: # agent-aggregator-poll-inbox)
```

Check (for the poller you installed; use `# agent-aggregator-poll-inbox` for the shell one):

```sh
crontab -l | grep -q '# agent-aggregator-poller$' && echo FAIL || echo PASS
```

## Rehearse locally

`node examples/cli-poll/run.mjs` runs every step above against a throwaway
local server and prints a PASS/FAIL table.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `agg` exits 2 with `no server configured` | No `hub.json` and no `AGG_URL` | Run step 3, or export `AGG_URL` |
| `agg` exits 4 | Credential missing, revoked, or the connection was revoked | Owner: new setup code (step 2); agent: step 3 |
| `agg inbox` exits 1 with `hook exited N; cursor not advanced` | The hook failed | Fix the hook; the same events are delivered again next run |
| `agg inbox` exits 3 with `another inbox run holds the lock` | A previous run is still going, or crashed less than 10 minutes ago | Wait; a lock older than 10 minutes is removed automatically |
| Poller never runs | Cron cannot find `agg` or `node` | Use `--bin` with absolute paths (step 5); read `poller.log` next to `hub.json` |
| `rate_limited` | More than 120 reads per minute | Poll less often; `Retry-After` gives the wait in seconds |
