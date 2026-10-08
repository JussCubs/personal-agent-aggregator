# Playbook: quickstart on one machine (SQLite)

**Goal:** from a clean clone, a running aggregator on `http://127.0.0.1:8787`
with an owner, one connected polling agent, and one question answered end to end.

**Time:** about 5 minutes. **You need:** Node.js 22.5 or newer, git, a POSIX
shell, two terminals. Run every command from the repository root.

**How to use this playbook:** run each step's command, compare with
*Expected*, then run *Check*: it prints `PASS` or `FAIL`. Stop at the first
`FAIL` and read [Troubleshooting](#troubleshooting). Values such as ids,
timestamps and credentials differ on every run.

## 1. Check Node.js

```sh
node -e 'const [a, b] = process.versions.node.split(".").map(Number); process.exit(a > 22 || (a === 22 && b >= 5) ? 0 : 1)' && echo PASS || echo FAIL
```

Expected: `PASS`.

## 2. Install and build

```sh
git clone <repository-url> personal-agent-aggregator
cd personal-agent-aggregator
npm ci
npm run build
```

Expected: `npm ci` ends with `found 0 vulnerabilities`; `npm run build` prints
no errors.

Check:

```sh
test "$(npx agg-server --version)" = "0.2.1" && echo PASS || echo FAIL
```

## 3. Run the demo (optional, 10 seconds)

```sh
npm run demo
```

Expected: a table of steps for `mcp-webhook`, `oauth-events` and `cli-poll`,
each `PASS`, ending with:

```text
PASS: 65 checks, 65 passed, 0 failed
```

Check:

```sh
npm run demo | tail -n 1 | grep -q '^PASS:' && echo PASS || echo FAIL
```

## 4. Create the encryption key

The key encrypts stored webhook secrets. Keep it in an owner-only file so the
server can be restarted with the same key.

```sh
(umask 077 && printf 'AGG_ENCRYPTION_KEY=%s\n' "$(npx agg-server keygen)" > .env)
```

Check:

```sh
grep -Eq '^AGG_ENCRYPTION_KEY=[0-9a-f]{64}$' .env && ls -l .env | grep -q '^-rw-------' && echo PASS || echo FAIL
```

`.env` is ignored by git.

## 5. Create the owner

```sh
npx agg-owner init --name "Your name" --save
```

Expected (one line):

```text
{"ok":true,"owner_id":"<uuid>","name":"Your name","hint":"aggown_XXXX…","stored":"<home>/.config/agent-aggregator/owner.json"}
```

This creates `./data/aggregator.db` (mode 0600) and stores the owner
credential in `owner.json` (mode 0600). Without `--save` the credential is
printed once instead.

Check:

```sh
ls -l "${XDG_CONFIG_HOME:-$HOME/.config}/agent-aggregator/owner.json" | grep -q '^-rw-------' && echo PASS || echo FAIL
```

## 6. Start the server (terminal 1)

```sh
set -a && . ./.env && set +a
npx agg-server
```

Expected first line:

```text
{"ts":"...","level":"info","msg":"listening","url":"http://127.0.0.1:8787","mcp":"http://127.0.0.1:8787/mcp","agent_api":"http://127.0.0.1:8787/api/v1","owner_api":"http://127.0.0.1:8787/owner","version":"0.2.1","storage":"sqlite","sqlite_path":"./data/aggregator.db",...}
```

Leave it running. Every request is logged as one JSON line without
credentials or bodies.

Check (terminal 2):

```sh
curl -fsS http://127.0.0.1:8787/healthz | grep -q '"ok":true' && echo PASS || echo FAIL
```

## 7. Check the owner and the storage (terminal 2)

```sh
npx agg-owner whoami
npx agg-server doctor
```

Expected: `{"owner":{"id":"<uuid>","name":"Your name"}}`, then
`{"ok":true,"storage":"sqlite","checks":[...]}` with every check `"pass":true`.

Check:

```sh
npx agg-owner whoami >/dev/null && npx agg-server doctor >/dev/null && echo PASS || echo FAIL
```

## 8. Connect an agent with a shell

The owner creates a connection and a one-time setup code; the agent exchanges
the code for its credential, which is written to a 0600 file and never shown.

```sh
CONN=$(npx agg-owner connection create --provider my_shell_agent --name "My shell agent" --mode cli_poll | node -pe 'JSON.parse(require("fs").readFileSync(0)).connection.id')
CODE=$(npx agg-owner claim-code --connection "$CONN" | node -pe 'JSON.parse(require("fs").readFileSync(0)).code')
npx agg setup --claim "$CODE" --server http://127.0.0.1:8787/api
```

Expected:

```text
{"ok":true,"connection":{"id":"<CONN>","provider":"my_shell_agent","display_name":"My shell agent","mode":"cli_poll"},"scopes":["hub:read","hub:write","hub:ask","hub:handoff","hub:chat"],"stored":"<home>/.config/agent-aggregator/hub.json"}
```

Check:

```sh
npx agg doctor >/dev/null && echo PASS || echo FAIL
```

## 9. Ask, answer, receive, acknowledge

```sh
npx agg ask --id q-first --prompt "Ship the release today?" --option yes=Yes --option no=No
npx agg inbox; echo "exit $?"
npx agg-owner answer --connection "$CONN" --id q-first --revision 1 --choice yes
npx agg inbox; echo "exit $?"
npx agg ack --id q-first --revision 1
```

Expected:

- `agg ask` prints `{"question":{"id":"q-first",...,"status":"pending",...,"revision":1,...},"created":true,"revised":false}`;
- the first `agg inbox` prints nothing and `exit 3` (nothing new);
- `agg-owner answer` prints the question with `"status":"answered"` and
  `"author":{"kind":"owner","name":"Your name","verified":true,"surface":"cli"}`;
- the second `agg inbox` prints one line
  `{"eventId":"evt_...","name":"answer.created",...,"cursor":"c1.MQ"}` and `exit 0`;
- `agg ack` prints the question with `"acknowledged_at":"<timestamp>"`.

Check:

```sh
npx agg answer --id q-first | grep -q '"acknowledged_at":"20' && echo PASS || echo FAIL
```

## 10. Stop

Press Ctrl-C in terminal 1. Expected: `{"...","msg":"shutting down","signal":"SIGINT"}`.

To remove everything this playbook created:

```sh
rm -rf data .env "${XDG_CONFIG_HOME:-$HOME/.config}/agent-aggregator"
```

## Next steps

- [Connect an MCP + webhook agent](connect-mcp-webhook-agent.md),
  [an OAuth + events agent](connect-oauth-events-agent.md), or
  [install the poller](connect-polling-agent.md) for the agent above.
- Move to Postgres: [deploy on Postgres](deploy-postgres.md).

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `{"error":{"code":"config","message":"AGG_ENCRYPTION_KEY must be 64 hex characters..."}}` | `.env` not loaded in terminal 1 | Run `set -a && . ./.env && set +a` in that terminal |
| `{"error":{"code":"startup","message":"Error EADDRINUSE: listen EADDRINUSE: address already in use 127.0.0.1:8787"}}` | Another process uses port 8787 | Stop it, or `export AGG_PORT=8788` in terminal 1 and `export AGG_OWNER_URL=http://127.0.0.1:8788` in terminal 2 (and use `:8788` in step 8) |
| `agg-owner init` exits 5 with `an owner already exists` | Step 5 ran before | Use the saved `owner.json`; if it is lost, `npx agg-owner reset-credential --save` |
| `agg setup` exits 4 | Code mistyped, used or older than 15 minutes | Run the `CODE=...` line again |
| `agg-owner ...` exits 4 | No or wrong owner credential | Check `owner.json` exists; `npx agg-owner reset-credential --save` |
| `fetch failed` (exit 1) | Server not running | Start it (step 6) |
