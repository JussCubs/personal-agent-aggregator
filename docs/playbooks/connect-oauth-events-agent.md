# Playbook: connect an OAuth MCP client woken by MCP Events

**Goal:** an MCP client that supports OAuth 2.1 connects without any pasted
credential: it discovers the authorization server, the owner approves on the
consent page, and the client subscribes to signed MCP event deliveries.

**You need:** the server at a public https `AGG_PUBLIC_URL` (clients refuse
plain http except on loopback); the owner CLI configured and the owner
credential at hand (password manager, or `owner.json`); an MCP client with
OAuth support, and MCP Events support for push wake-ups.

**Conventions:** run each command, compare with *Expected*, run *Check*
(prints `PASS` or `FAIL`), stop at the first `FAIL`.

## 1. Check discovery

```sh
export AGG_PUBLIC_URL=https://aggregator.example.com
curl -s -o /dev/null -D - -X POST -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"ping"}' "$AGG_PUBLIC_URL/mcp" | grep -i '^www-authenticate'
curl -fsS "$AGG_PUBLIC_URL/.well-known/oauth-protected-resource/mcp"
curl -fsS "$AGG_PUBLIC_URL/.well-known/oauth-authorization-server"
```

Expected:

```text
www-authenticate: Bearer resource_metadata="https://aggregator.example.com/.well-known/oauth-protected-resource/mcp", scope="hub:read hub:write hub:ask hub:handoff hub:chat"
{"resource":"https://aggregator.example.com/mcp","authorization_servers":["https://aggregator.example.com"],"scopes_supported":[...],"bearer_methods_supported":["header"],"resource_name":"Agent aggregator"}
{"issuer":"https://aggregator.example.com","authorization_endpoint":".../oauth/authorize","token_endpoint":".../oauth/token","registration_endpoint":".../oauth/register","revocation_endpoint":".../oauth/revoke",...,"code_challenge_methods_supported":["S256"],...}
```

Check:

```sh
curl -fsS "$AGG_PUBLIC_URL/.well-known/oauth-authorization-server" | grep -q "\"issuer\":\"$AGG_PUBLIC_URL\"" && \
curl -fsS "$AGG_PUBLIC_URL/.well-known/oauth-protected-resource/mcp" | grep -q "\"resource\":\"$AGG_PUBLIC_URL/mcp\"" && echo PASS || echo FAIL
```

## 2. Add the server to the client

In the MCP client, add a server with URL `<AGG_PUBLIC_URL>/mcp` and no
header. The client registers itself (dynamic client registration) or uses
its client ID metadata document URL, then opens the authorization page in
your browser.

## 3. Owner: review and approve

The consent page shows:

| Field | What to check |
| --- | --- |
| Application name (supplied by the application) | Self-declared; never trust it alone |
| Approval is sent to | The host that receives the code. It must be the client you just started |
| Client identity | `Metadata document published at <host>` (verified by fetching it) or `Registered itself with this server` (not verified) |
| Requested access | Each scope with its meaning; deny if it asks for more than it needs |
| This request expires | 15 minutes after the client started the flow |

To approve, type the owner credential and press **Approve**. To keep using an
existing OAuth connection (for example after the client lost its tokens),
open "Reconnect an existing OAuth connection" and enter that connection's id
first. **Deny** sends `error=access_denied` back to the client.

Expected: the browser returns to the client, which reports the server as
connected.

Check (owner):

```sh
CONN=$(npx agg-owner connection list | node -pe 'JSON.parse(require("fs").readFileSync(0)).connections.find((c) => c.mode === "oauth_events" && c.status === "active").id')
npx agg-owner connection get --id "$CONN" | grep -q '"mode":"oauth_events"' && echo PASS || echo FAIL
```

The connection's `provider` is `oauth_client` and its name is the client's
name (or `OAuth client at <host>`); rename it with
`PATCH /owner/connections/{id}` if you like.

## 4. Client: subscribe to events

The client calls `events/subscribe` for `answer.created`, `job.updated`,
`question.updated` and (to take your messages) `message.created` with
`delivery: {mode: "webhook", url, secret}`. The server POSTs a signed
`{"type":"verification","challenge":"..."}` to the URL
and stores the subscription only after the endpoint echoes the challenge.

Check (owner):

```sh
npx agg-owner connection get --id "$CONN" | node -pe 'JSON.parse(require("fs").readFileSync(0)).connection.subscriptions >= 1 ? "PASS" : "FAIL"'
```

A client without MCP Events support still works: it reads `check_inbox` when it runs.

## 5. End to end

Ask the agent to ask you a test question. Then:

```sh
npx agg-owner questions --connection "$CONN"
npx agg-owner answer --connection "$CONN" --id <question id> --revision <revision> --choice <option id>
```

Within seconds the server log shows `"msg":"deliveries","delivered":1`, and the
client receives a signed `answer.created` with header
`x-mcp-subscription-id: sub_...`. The agent calls `get_answer`, acts, and
`acknowledge_answer`.

Check (owner):

```sh
npx agg-owner question get --connection "$CONN" --id <question id> | grep -q '"acknowledged_at":"20' && echo PASS || echo FAIL
```

## 6. Token lifecycle

Nothing to do: access tokens last 1 hour and the client refreshes them;
each refresh returns a new refresh token, and reusing an old one revokes the
whole family (the client must then authorize again). Subscriptions last 7
days unless the client asks for up to 30 and must be refreshed before
`refreshBefore`. To disconnect: `npx agg-owner connection revoke --id "$CONN"`.

## Rehearse locally

`node examples/oauth-events/run.mjs` performs this whole flow against a
throwaway local server: discovery, dynamic registration, a client ID
metadata document served on localhost, PKCE, the HTML consent form with the
owner credential, token exchange, `events/subscribe` with the verification
challenge, signed event receipt, refresh rotation and reuse detection, and
revocation.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Error page "The redirect URI is not registered for this client" | The client's redirect URI differs from its registration | Re-add the server in the client so it registers again |
| Error page "Unknown client." | Registration expired from the client's cache, or its metadata document is unreachable | Re-add the server; for a metadata document, check it is served over https and names itself as `client_id` |
| Page says "That owner credential is not valid" | Typo, or the owner credential was rotated | Use the current credential (`agg-owner reset-credential` if lost) |
| Page says "This form expired..." | The form was opened in another browser, or 15 minutes passed | Reload the page or restart the flow in the client |
| `-32015` "Callback endpoint error" on subscribe | The callback did not echo the signed challenge (`reason`: `challenge_failed`, `http_error`, `timeout`, `unreachable`) | Fix the client's event endpoint; it must be public https |
| Client gets 401 after an hour | It does not refresh, or reused a refresh token | Re-authorize; reconnect the same connection id on the consent page |
