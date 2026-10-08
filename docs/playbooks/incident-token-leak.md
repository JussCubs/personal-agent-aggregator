# Playbook: incident, a credential or secret leaked

**Goal:** within minutes, make a leaked value useless, find out what it was
used for, restore service, and record what happened.

**Use when:** any value starting with `agg_`, `aggo_`, `aggr_`, `aggc_`,
`aggown_` or `whsec_`, a setup code (`XXXXX-XXXXX-XXXXX-XXXXX`), a routine
key, `AGG_ENCRYPTION_KEY` or the database password appeared somewhere it
should not (a chat, a log, a ticket, a commit, a screenshot).

**Conventions:** each step has a command and a *Check* that prints `PASS` or
`FAIL`. Contain first (steps 1-2), investigate second. Write down the time
of every step.

```sh
export AGG_PUBLIC_URL=https://aggregator.example.com
agent_status() { printf 'header = "Authorization: Bearer %s"\n' "$1" | curl -s -o /dev/null -w '%{http_code}' -K - "$AGG_PUBLIC_URL/api/v1/me"; }
LEAKED='<the leaked value>'
```

## 1. Identify what leaked

| Prefix or shape | What it is | Grants | Contain with |
| --- | --- | --- | --- |
| `agg_` | Agent credential | One connection, its scopes | 2a |
| `aggo_` / `aggr_` | OAuth access / refresh token | One OAuth connection, its scopes (access: 1 hour) | 2b |
| `aggc_` | OAuth authorization code | Nothing after 5 minutes or after exchange; a replay revokes what it issued | 2b if fresh |
| `XXXXX-XXXXX-XXXXX-XXXXX` | Setup code | One credential, once, within its expiry | 2c |
| `aggown_` | Owner credential | Everything of that owner | 2d |
| `whsec_` | Webhook or subscription signing secret | Forging deliveries to that receiver | 2e |
| Routine key | The receiver's own key | Triggering the receiver | 2e, and rotate it at the receiver |
| 64 hex characters | `AGG_ENCRYPTION_KEY` | Decrypting stored delivery secrets (needs the database too) | 2f |
| `postgres://...:password@` | Database password | Everything | 2g |

For an `agg_` or `aggr_` credential, find its connection from the hint
(prefix plus four characters):

```sh
HINT=$(printf '%s' "$LEAKED" | cut -c1-$(( $(printf '%s' "$LEAKED" | cut -d_ -f1 | wc -c) + 4 )))
npx agg-owner connection list | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{for(const c of JSON.parse(s).connections) for(const k of c.credentials) if(k.hint.startsWith(process.argv[1])) console.log(c.id, c.display_name, k.kind, k.hint)})' "$HINT"
```

Expected: one line `<connection id> <name> <kind> <hint>…`. Set `CONN` to that id.

Only active agent credentials (`agg_`) and refresh tokens (`aggr_`) are
listed. For an `agg_` credential that does not match, confirm it is already
dead with `agent_status "$LEAKED"` (prints `401`). Do not use that check for
`aggo_` tokens: the REST API refuses OAuth tokens even while they are valid,
so go straight to 2b (it needs no connection id) and check with the MCP
`ping` there. For codes, find the connection in the audit log: the latest
`claim_code.issue` (setup codes) or `oauth.approve` (OAuth) entries in
`npx agg-owner audit --limit 200`.

## 2. Contain

### 2a. Agent credential

```sh
npx agg-owner credential issue --connection "$CONN" > /dev/null   # revokes every earlier agent credential of the connection
```

Check:

```sh
test "$(agent_status "$LEAKED")" = 401 && echo PASS || echo FAIL
```

Hand the agent a new setup code (`npx agg-owner claim-code --connection "$CONN"`)
or the new credential through its settings. If you do not trust the agent
any more, disconnect it instead: `npx agg-owner connection revoke --id "$CONN"`.

### 2b. OAuth token or fresh code

```sh
curl -fsS -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode "token=$LEAKED" "$AGG_PUBLIC_URL/oauth/revoke"
```

This revokes the token's whole family. For a leaked code, or if unsure,
revoke the connection: `npx agg-owner connection revoke --id "$CONN"`.

Check (access tokens):

```sh
printf 'header = "Authorization: Bearer %s"\n' "$LEAKED" | curl -s -o /dev/null -w '%{http_code}' -K - -X POST -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"ping"}' "$AGG_PUBLIC_URL/mcp" | grep -qx 401 && echo PASS || echo FAIL
```

### 2c. Setup code

```sh
npx agg-owner claim-code --connection "$CONN" > /dev/null   # revokes unused earlier codes
```

Check (from the audit log; never test a leaked code by claiming it: if
containment missed, claiming would redeem it and revoke the agent's working
credential):

```sh
npx agg-owner audit --connection "$CONN" --limit 5 | grep -q '"action":"claim_code.issue"' && echo PASS || echo FAIL
```

If the audit log shows a `credential.issue` entry with `actor: "system"`
after the leak that the agent did not make, the code was already claimed by
someone else: treat it as 2a and issue a new credential.

### 2d. Owner credential

```sh
npx agg-owner rotate-credential --save
```

If the attacker may have rotated it first, use direct database access:
`npx agg-owner reset-credential --save --server "$AGG_PUBLIC_URL"` (with
`AGG_DATABASE_URL` or `AGG_SQLITE_PATH` set as for the server).

Check:

```sh
test "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $LEAKED" "$AGG_PUBLIC_URL/owner/me")" = 401 && npx agg-owner whoami >/dev/null && echo PASS || echo FAIL
```

An owner credential can create connections and credentials: in step 3 also
list connections created after the leak and revoke any you did not create.

### 2e. Signing secret or routine key

Set the webhook again (the agent calls `set_callback_webhook`, or
`npx agg-owner webhook set --connection "$CONN" --url <same url> --header <name> --value <routine key>`;
always pass the routine key, the current one or a new one, because setting
the webhook without it stores none),
store the new secret at the receiver, and rotate the routine key at the
receiver's platform. For a subscription secret, the client re-subscribes
with a new secret.

Check:

```sh
npx agg-owner audit --connection "$CONN" --limit 5 | grep -q '"action":"webhook.set"' && echo PASS || echo FAIL
```

### 2f. Encryption key

Rotate it ([secrets](../security/secrets.md#rotating-the-encryption-key)), then
treat every stored signing secret and routine key as leaked (2e for each
connection with a webhook or subscription).

### 2g. Database password

Change the API role's password (`ALTER ROLE aggregator_api PASSWORD '<new>'`
as an admin, or the provider's dashboard), update `AGG_DATABASE_URL` in the
environment file, and restart the server. Then assume the database was read:
credential digests are useless to an attacker, but rotate the encryption key
if it could also have leaked (2f), and review step 3 for every connection.

## 3. Investigate

```sh
npx agg-owner connection get --id "$CONN"
npx agg-owner audit --connection "$CONN" --limit 200
npx agg-owner connection list
```

Look for:

- `last_seen_at` on the connection and `last_used_at` on its credentials
  (updated at most once a minute) after the time of the leak;
- audit entries you cannot explain: `actor: "agent"` writes
  (`work_item.upsert`, `question.create`, `job.create`, `webhook.set`,
  `subscription.upsert` with a `host` you do not know), `actor: "owner"`
  actions you did not take (`question.answer`, `job.approve`,
  `credential.issue`, `connection.create`);
- connections you did not create.

Server request logs (JSON lines: `method`, `path`, `status`, `ms`, `ip`, no
credentials) show which addresses called which endpoints and when:

```sh
journalctl -u agent-aggregator --since '<time of leak>' | grep '"msg":"request"' | grep -v '"status":401'
```

Check (the leaked value never reached the logs):

```sh
journalctl -u agent-aggregator | grep -qF "$LEAKED" && echo FAIL || echo PASS
```

## 4. Recover

- Undo what the attacker did: dismiss questions they created
  (`npx agg-owner dismiss --connection "$CONN" --id <question>`), decline jobs
  (`npx agg-owner job decide --connection "$CONN" --id <job> --decline`),
  remove work items through the agent, revoke unknown connections.
- If an answer or approval was given by the attacker, tell the agent that
  asked; the answer's `author.surface` and the audit entry show where it came from.
- Reconnect the legitimate agent with a fresh setup code or credential.

## 5. Record

Write down: what leaked and where, when it leaked and when it was contained,
what the audit and request logs showed, what was undone, and what changes
prevent a repeat (for example: switch the agent to a setup code or OAuth so
no credential is pasted anywhere). If the leak came from a weakness in this
project, report it privately as described in [SECURITY.md](../../SECURITY.md).
