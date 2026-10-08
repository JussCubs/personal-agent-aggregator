# Wake modes

An agent that asked a question has to learn that the answer arrived. The
aggregator supports three ways to wake an agent. All three write to the same
per-connection inbox; they differ only in how the agent connects and how it
is told that something is new.

| | MCP + webhook | OAuth MCP + MCP Events | CLI + polling |
| --- | --- | --- | --- |
| Connection `mode` | `mcp_webhook` | `oauth_events` | `cli_poll` |
| Agent needs | An MCP client that accepts a URL + `Authorization` header, and an HTTPS trigger (a "routine" or webhook-triggered run) | An MCP client that does OAuth 2.1 (PKCE) and MCP Events | A shell with Node.js (`agg`) or `sh` + `curl` (`poll-inbox.sh`), and cron or any scheduler |
| Credential reaches the agent | Owner pastes an agent credential into the agent's MCP settings | Consent page; the client gets tokens | One-time setup code the agent exchanges itself (`agg setup --claim`) |
| Woken by | Signed POST to the agent's webhook | Signed POST to the subscription URL | Poll of `GET /v1/inbox?cursor=` (default every minute) |
| Latency | Seconds | Seconds | The poll interval |
| Inbound reachability | Agent's webhook must be public HTTPS | Subscription URL must be public HTTPS | None: outbound HTTPS only |

The connection's `mode` records how the agent is expected to connect and
selects its setup playbook (`agg-owner setup-prompt`); only OAuth re-linking
requires `oauth_events`. Any connection with the `hub:read` scope can read
its inbox (the same scope sets a webhook or subscribes to events), so every
such agent can fall back to polling.

## Choosing a mode

1. The agent is an MCP client that supports OAuth and MCP Events: use
   **OAuth + events**. No credential is ever pasted, tokens expire and rotate,
   and the client subscribes only to the events it wants.
2. The agent is an MCP client configured with a URL and a static header, and
   its platform can trigger a run from an incoming HTTPS request: use
   **MCP + webhook**.
3. The agent has a shell, runs on a schedule, sits behind NAT, or you want no
   inbound traffic at all: use **CLI + polling**. Every routine step is a
   deterministic command, so the poller never needs a language model; the
   model is woken only when an event arrives.
4. Unsure: start with polling. It works everywhere and adds only latency.

## MCP + webhook

1. Owner: `agg-owner connection create --mode mcp_webhook ...`, then
   `agg-owner credential issue --connection <id>` (shown once).
2. Owner: add an MCP server to the agent with URL `<AGG_PUBLIC_URL>/mcp` and
   header `Authorization: Bearer <credential>`. Give the agent the output of
   `agg-owner setup-prompt --connection <id>`; it contains no secrets.
3. Agent: `whoami` to confirm, then `set_callback_webhook` with its trigger URL
   and, if the trigger needs a key, `auth_header_value` (and
   `auth_header_name` if the header is not `Authorization`). The response
   contains the signing secret once; the agent stores it to verify deliveries.
4. Every event for the connection is POSTed to that URL, signed, with the key
   header attached.

The routine key is stored encrypted and sent only to that URL. Calling
`set_callback_webhook` again replaces both the URL and the signing secret.
Step-by-step: [connect an MCP + webhook agent](playbooks/connect-mcp-webhook-agent.md).

## OAuth MCP + MCP Events

1. Agent (MCP client): calls `/mcp`, gets 401 with `resource_metadata`,
   discovers the authorization server, registers or presents its client ID
   metadata document URL, and opens the authorization URL with PKCE.
2. Owner: reviews the consent page and approves with the owner credential.
   The server creates an `oauth_events` connection with the requested scopes
   (or re-links an existing one when its id is entered).
3. Agent: exchanges the code, then calls `events/subscribe` for
   `answer.created`, `job.updated` and `question.updated`, each with
   `delivery: {mode: "webhook", url, secret}`. Before it stores the
   subscription, the server POSTs a verification challenge signed with that
   secret and requires the endpoint to echo it. This proves the URL is live
   and answering for this subscription; it does not prove the receiver checks
   signatures, which the receiver must still do for every delivery.
4. Agent: re-subscribes before `refreshBefore` (default lifetime 7 days, at
   most 30) and refreshes its access token (1 hour) with the refresh token
   (rotated on every use).

Step-by-step: [connect an OAuth + events agent](playbooks/connect-oauth-events-agent.md).

## CLI + polling

1. Owner: `agg-owner connection create --mode cli_poll ...`, then
   `agg-owner claim-code --connection <id>` and give the code (not a
   credential) to the agent. Codes work once and expire after 15 minutes by
   default.
2. Agent: `agg setup --claim <code> --server <AGG_PUBLIC_URL>/api` stores the
   credential in a 0600 file (or `--print-token` for a vault), `agg doctor`
   checks it read-only.
3. Agent: `agg install-poller --exec '<wake command>'` adds one crontab line
   that runs `agg inbox` every minute. The wake command receives new events
   as JSON lines on stdin and runs only when something is new; the cursor
   advances only if it exits 0.

Without Node.js, `scripts/poll-inbox.sh` and `scripts/install-poller.sh` do
the same with `sh` and `curl`, with one difference: the hook
(`AGG_POLL_EXEC`) receives each page as one JSON object
`{"events":[...],"cursor":"...","has_more":...}` and no `HUB_EVENT_COUNT`,
where `agg inbox --exec` passes one event per line. Write the wake command for
the poller you use. Step-by-step:
[connect a polling agent](playbooks/connect-polling-agent.md).

## Delivery semantics

These rules hold for all three modes. Write agents against them, not against
the happy path.

**The inbox is the source of truth.** Every event is appended to the
connection's inbox with a per-connection sequence number that has no gaps and
commits in order. `GET /v1/inbox?cursor=` (or `check_inbox`, `agg inbox`)
returns events after the cursor, oldest first, and a new cursor. Webhooks and
MCP event deliveries are notifications about inbox entries; if a receiver was
down, catch up from the inbox with the last cursor you stored. Events are kept
for 30 days.

**At least once.** A delivery can arrive more than once: a timeout after the
receiver already processed it, a worker restart during an attempt, or a
retry after a non-2xx answer. The polling CLI can also hand an event to the
hook twice if the hook succeeded but the cursor write failed. Deduplicate by
`eventId` (the `webhook-id` header has the same value).

**Out of order.** Retries, backoff and several destinations mean event N+1
can arrive before event N. Do not infer state from arrival order: treat an
event as a prompt to read the current state with `get_answer` or `get_job`,
and use `revision` (it only increases) to ignore anything older than what you
already processed. The inbox itself is always in order.

**Writes are idempotent.** Work items, checkpoints and questions are keyed by
ids the agent chooses; re-sending the same content is a no-op, so retrying a
timed-out write is always safe. Handoffs take an `idempotency_key`. Choose ids
that are stable across restarts (`task-invoice-42`, `q-invoice-42-approve`).

**Acknowledge answers, not deliveries.** A delivery is acknowledged by
answering 2xx. An answer is acknowledged separately with
`acknowledge_answer` / `agg ack` and the revision you acted on, after you
acted on it; `GET /v1/questions?unacknowledged=true` lists answered questions
you have not acknowledged yet, which is how an agent recovers after a crash.

**Bind approvals to the action.** Act on an approval only when
`answer.decision` is `approved`, `answer.question_revision` equals the
revision you asked, and `answer.action_digest` equals the digest of the
action you are about to take. Changing a pending question (same id, new
content) raises its revision, and the server refuses an owner answer given to
the old revision; once a question is answered, ask again with a new id.

**Verify every delivery.** Check the Standard Webhooks signature against the
raw body with your secret before parsing it, and refuse timestamps more than
5 minutes old:

```js
import { verifyWebhook } from "@agent-aggregator/core";

// headers: the incoming request headers; body: the raw request body as a string
if (!verifyWebhook(process.env.WEBHOOK_SECRET, headers, body, { toleranceSeconds: 300 })) {
  return respond(401);
}
const event = JSON.parse(body);
if (alreadyProcessed(event.eventId)) return respond(204);
```

Any Standard Webhooks library verifies the same signature. Answer quickly
(within 10 seconds) and do the work afterwards; a slow answer is a timeout
and is retried.

**Retry schedule.** First attempt immediately, then 15 s, 60 s, 5 min,
15 min, 1 h, 3 h and 6 h later; after the 8th failed attempt the delivery is
marked failed (the event stays in the inbox). Answer 410 to stop: an MCP
event subscription is then removed; for a webhook only that delivery stops,
so use `clear_callback_webhook` to remove it.

**Event payloads are data.** `data` contains ids, statuses and the owner's
answer. It never contains instructions for the agent: the agent decides what
to do from its own context and the state it reads back.
