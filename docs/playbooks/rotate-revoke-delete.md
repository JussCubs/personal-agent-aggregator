# Playbook: rotate, revoke and delete

**Goal:** replace any credential or secret, disconnect an agent, and delete
its data, each with a check that the old value no longer works.

**You need:** `agg-owner` configured for the server; `AGG_PUBLIC_URL` set to
the server's base URL; `CONN` set to the connection id (find it with
`npx agg-owner connection list`).

**Conventions:** run each command, compare with *Expected*, run *Check*
(prints `PASS` or `FAIL`), stop at the first `FAIL`. Sections are independent.

Helper used by the checks (status code of an agent call; the credential goes
to curl on stdin):

```sh
agent_status() { printf 'header = "Authorization: Bearer %s"\n' "$1" | curl -s -o /dev/null -w '%{http_code}' -K - "$AGG_PUBLIC_URL/api/v1/me"; }
```

## Rotate an agent credential

```sh
OLD_TOKEN='<current agg_ credential, if you have it>'
NEW_TOKEN=$(npx agg-owner credential issue --connection "$CONN" | node -pe 'JSON.parse(require("fs").readFileSync(0)).token')
```

Put `NEW_TOKEN` into the agent's settings (MCP header, vault or `AGG_TOKEN`).
For an agent with a shell, prefer a setup code so the credential never leaves
its machine: `npx agg-owner claim-code --connection "$CONN"`, then on the
agent `agg setup --claim <code> --server "$AGG_PUBLIC_URL/api"` (claiming also
revokes the previous credential).

Check:

```sh
test "$(agent_status "$NEW_TOKEN")" = 200 && test "$(agent_status "$OLD_TOKEN")" = 401 && echo PASS || echo FAIL
```

## Rotate the owner credential

```sh
npx agg-owner rotate-credential --save
```

Expected: `{"ok":true,"hint":"aggown_XXXX…","stored":"<home>/.config/agent-aggregator/owner.json"}`.
Without `--save` the new credential is printed once. Lost the credential?
Run `npx agg-owner reset-credential --save --server "$AGG_PUBLIC_URL"` on a
machine with the server's database settings (`AGG_SQLITE_PATH` or
`AGG_DATABASE_URL`); add `--owner-id <id>` when there are several owners.

Check:

```sh
npx agg-owner whoami >/dev/null && echo PASS || echo FAIL
```

## Rotate a webhook signing secret or routine key

The agent calls `set_callback_webhook` again with the same `url` and
`auth_header_value` (the current routine key, or the new one if that
changed). If the routine uses a key, always pass it: setting the webhook
replaces the whole configuration, and without `auth_header_value` no key is
stored and the routine rejects the deliveries. As the owner, the equivalent is:

```sh
npx agg-owner webhook set --connection "$CONN" --url 'https://hooks.example.com/routine/abc' --header Authorization --value '<new routine key>'
```

Expected: `{"url":"https://hooks.example.com/routine/abc","auth_header_name":"Authorization","signing_secret":"whsec_..."}`.
Give the new `signing_secret` to the receiver; deliveries from now on are
signed only with it.

Check:

```sh
npx agg-owner connection get --id "$CONN" | grep -q '"webhook":{"url_host":"hooks.example.com"}' && echo PASS || echo FAIL
```

## Revoke OAuth tokens of one client

Revoking one token revokes its whole family (access and refresh):

```sh
curl -fsS -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'token=<aggo_ or aggr_ token>' "$AGG_PUBLIC_URL/oauth/revoke"
```

Expected: HTTP 200, empty body. To cut off every client of the connection,
revoke the connection instead.

## Disconnect an agent (keep its data)

```sh
npx agg-owner connection revoke --id "$CONN"
```

Expected: `{"connection":{...,"status":"revoked","revoked_at":"<timestamp>",...}}`.
In the same transaction every credential of the connection is revoked, its
webhook and subscriptions are deleted, pending questions are cancelled
(`status_reason: "connection_revoked"`) and open jobs are cancelled. Work
items, checkpoints, answers and audit entries stay for review.

Check:

```sh
npx agg-owner connection get --id "$CONN" | grep -q '"status":"revoked"' && test "$(agent_status "$NEW_TOKEN")" = 401 && echo PASS || echo FAIL
```

A revoked connection cannot be re-activated; create a new connection to
reconnect the agent.

## Delete a connection and everything it produced

```sh
npx agg-owner connection delete --id "$CONN" --yes
```

Expected: `{"deleted":{"work_items":N,"checkpoints":N,"questions":N,"jobs":N,"events":N,"deliveries":N,"credentials":N,"threads":N,"messages":N}}`.
The connection is revoked first, then every row it produced is deleted; one
`connection.delete` audit entry with these counts remains (until the
180-day history retention removes it).

Check:

```sh
npx agg-owner connection get --id "$CONN"; test $? -eq 1 && echo PASS || echo FAIL
```

(`connection get` now fails with `{"error":{"status":404,"code":"not_found",...}}`, exit 1.)

## Delete an owner and all their data

Postgres only, run as the API role. Deleting the owner row cascades to their
connections and every row those produced; audit and OAuth request rows carry
no foreign key and are deleted explicitly:

```sh
OWNER_ID='<owner id from agg-owner whoami>'
psql "$AGG_DATABASE_URL" -v ON_ERROR_STOP=1 -v owner="$OWNER_ID" <<'SQL'
BEGIN;
DELETE FROM aggregator_audit WHERE owner_id = :'owner';
DELETE FROM aggregator_oauth_requests WHERE owner_id = :'owner';
DELETE FROM aggregator_owners WHERE id = :'owner';
COMMIT;
SQL
```

Check:

```sh
test "$(psql "$AGG_DATABASE_URL" -Atc "SELECT (SELECT count(*) FROM aggregator_connections WHERE owner_id = '$OWNER_ID') + (SELECT count(*) FROM aggregator_audit WHERE owner_id = '$OWNER_ID')")" = 0 && echo PASS || echo FAIL
```

On SQLite (one owner), stop the server and delete `data/aggregator.db` with
its `-wal` and `-shm` files.

## Rotate the encryption key

Follow [secrets: rotating the encryption key](../security/secrets.md#rotating-the-encryption-key).
Check after the restart and after re-registering every webhook and
subscription: for new events the server log shows `"msg":"deliveries"` lines
with `"failed":0`.
