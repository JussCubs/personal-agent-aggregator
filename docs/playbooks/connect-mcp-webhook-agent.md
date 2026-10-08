# Playbook: connect an MCP agent woken by a webhook

**Goal:** an MCP-capable agent calls the aggregator's tools with a bearer
credential and is woken by a signed webhook when the owner answers or a
handed-off job changes.

**You need:** the server reachable by the agent's platform at a public https
`AGG_PUBLIC_URL` ([deploy on Postgres](deploy-postgres.md) or a tunnel to a
local server); the owner CLI configured; an agent whose MCP settings accept a
URL plus an `Authorization` header and whose platform can start a run from an
incoming HTTPS request (a "routine" or webhook trigger) with a public https URL.

**Conventions:** run each command, compare with *Expected*, run *Check*
(prints `PASS` or `FAIL`), stop at the first `FAIL`.

## 1. Owner: check the server

```sh
export AGG_PUBLIC_URL=https://aggregator.example.com
curl -fsS "$AGG_PUBLIC_URL/healthz"
```

Expected: `{"ok":true}`.

Check:

```sh
curl -fsS "$AGG_PUBLIC_URL/" | grep -q "\"mcp\":\"$AGG_PUBLIC_URL/mcp\"" && echo PASS || echo FAIL
```

A FAIL here usually means `AGG_PUBLIC_URL` on the server differs from the URL
you use; they must be identical.

## 2. Owner: create the connection and issue the credential

```sh
CONN=$(npx agg-owner connection create --provider my_mcp_agent --name "My MCP agent" --mode mcp_webhook | node -pe 'JSON.parse(require("fs").readFileSync(0)).connection.id')
TOKEN=$(npx agg-owner credential issue --connection "$CONN" | node -pe 'JSON.parse(require("fs").readFileSync(0)).token')
```

The credential is shown only now. Issuing again revokes the previous one.

Check:

```sh
printf '%s' "$TOKEN" | grep -Eq '^agg_[A-Za-z0-9_-]{43}$' && echo PASS || echo FAIL
```

## 3. Owner: add the MCP server to the agent

In the agent's MCP (connector) settings add:

| Setting | Value |
| --- | --- |
| URL | `<AGG_PUBLIC_URL>/mcp` |
| Header | `Authorization: Bearer <TOKEN>` |

Paste the credential only into that settings field, never into a chat. Then
confirm the endpoint accepts it exactly as the agent will call it (the
credential goes to curl on stdin, not the command line):

```sh
printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" | curl -fsS -K - -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami","arguments":{}}}' "$AGG_PUBLIC_URL/mcp"
```

Expected: `{"jsonrpc":"2.0","id":1,"result":{"content":[...],"structuredContent":{"connection_id":"<CONN>",...,"mode":"mcp_webhook",...,"callback":{"configured":false,"url_host":null}},"isError":false}}`.

Check:

```sh
printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" | curl -fsS -K - -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami","arguments":{}}}' "$AGG_PUBLIC_URL/mcp" | grep -q "\"connection_id\":\"$CONN\"" && echo PASS || echo FAIL
```

## 4. Owner: give the agent its setup playbook

```sh
npx agg-owner setup-prompt --connection "$CONN" > setup-prompt.md
```

Give `setup-prompt.md` to the agent. It tells the agent to call `whoami`,
create a webhook-triggered routine with exact instructions, and register it
with `set_callback_webhook`. It contains no secrets.

Check:

```sh
grep -q 'set_callback_webhook' setup-prompt.md && ! grep -Eq 'agg_[A-Za-z0-9_-]{20,}' setup-prompt.md && echo PASS || echo FAIL
```

## 5. Agent: register the wake-up webhook

The agent calls `set_callback_webhook` with `url` = its routine's https URL
and, if the routine requires a key, `auth_header_value` (and
`auth_header_name` when the header is not `Authorization`). The response
contains `signing_secret` (`whsec_...`) once; the routine verifies every
delivery with it.

Check (owner):

```sh
npx agg-owner connection get --id "$CONN" | grep -q '"webhook":{"url_host":"' && echo PASS || echo FAIL
```

Refusals and their meaning: `url must use https`, `url port must be one of
443, 8443`, `url host must be a public internet hostname`, `url must not point
at a private or reserved address`: the routine URL must be a public https
endpoint. A host name is resolved only when a delivery is sent: a name that
resolves to a private or reserved address is accepted here, but every
delivery to it then fails at once (server log `"failed":1`), and a name that
does not resolve is retried.

## 6. End to end

Ask the agent: "Ask me a test question with id `q-webhook-test` and two options."
Then, as the owner:

```sh
npx agg-owner questions --connection "$CONN"
npx agg-owner answer --connection "$CONN" --id q-webhook-test --revision 1 --choice opt_1
```

(Use the option id and revision shown by `questions`.) Within seconds the
server delivers `answer.created` to the routine; the server log shows
`{"...","msg":"deliveries","delivered":1,"failed":0,"retried":0}`. The routine
calls `get_answer`, continues, and `acknowledge_answer`.

Check (owner, after the routine ran):

```sh
npx agg-owner question get --connection "$CONN" --id q-webhook-test | grep -q '"acknowledged_at":"20' && echo PASS || echo FAIL
```

## 7. Optional: handoff round trip

Ask the agent to hand off a goal. Then:

```sh
JOB=$(npx agg-owner jobs --connection "$CONN" | node -pe 'JSON.parse(require("fs").readFileSync(0)).jobs[0].job.id')
npx agg-owner job decide --connection "$CONN" --id "$JOB" --approve
npx agg-owner job progress --connection "$CONN" --id "$JOB" --status done --summary "Done by the primary agent"
```

The routine receives `job.updated` three times (`needs_user`, `running`,
`done`). Check:

```sh
npx agg-owner job get --connection "$CONN" --id "$JOB" | grep -q '"status":"done"' && echo PASS || echo FAIL
```

## Rehearse locally

`node examples/mcp-webhook/run.mjs` plays the agent (legacy `initialize` and
2026-07-28 `server/discover`), runs a local receiver that verifies the
signatures, and prints a PASS/FAIL table. It needs no public URL because it
sets `AGG_ALLOW_PRIVATE_CALLBACKS=1` on a throwaway local server.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Step 3 returns `"code":-32001` (HTTP 401) | Wrong or revoked credential, or header missing | Re-issue (step 2) and update the agent's settings |
| `"code":-32000,"message":"Origin not allowed"` (403) | A browser-based client sends an `Origin` other than `AGG_PUBLIC_URL` | Use a server-side MCP client |
| Log shows `"retried":1` repeatedly | The routine answers non-2xx or times out (10 s) | Make the routine answer 2xx at once and work afterwards |
| Routine rejects deliveries as unsigned | It verifies with an old secret | Call `set_callback_webhook` again and store the new `signing_secret` |
| Nothing delivered | Webhook cleared, or connection revoked | `agg-owner connection get --id "$CONN"`: check `webhook` and `status` |
