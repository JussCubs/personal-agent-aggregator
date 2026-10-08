# Contract reference

This is the wire contract shared by the agent REST API, the MCP endpoint, the
CLIs and the webhook / MCP event deliveries. Field names are `snake_case` on
the wire, except the event envelope (`eventId`, `name`, `timestamp`, `data`,
`cursor`), which follows MCP Events.

Blocks marked "generated" are produced from the code by
`npm run docs:contract`, and `npm test` fails when they drift
(`tests/contract-docs.test.mjs`). Scopes in the generated tables are measured
by calling every route and tool with a credential that has no scopes, and the
event fields are measured from events the service actually emits.

- [Versions](#versions)
- [Credentials and audiences](#credentials-and-audiences)
- [Scopes](#scopes)
- [Agent REST API](#agent-rest-api)
- [MCP endpoint](#mcp-endpoint)
- [Events and deliveries](#events-and-deliveries)
- [Owner API](#owner-api)
- [OAuth endpoints](#oauth-endpoints)
- [Service endpoints](#service-endpoints)
- [Errors](#errors)
- [Limits](#limits)
- [CLIs](#clis)

## Versions

<!-- BEGIN GENERATED: version -->
Contract version `2026-10-01` (`CONTRACT_VERSION`, returned by `whoami` / `GET /v1/me` as `contract_version`). MCP protocol versions: `2026-07-28` (modern) and `2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05` (legacy `initialize`).
<!-- END GENERATED: version -->

## Credentials and audiences

| Credential | Format | Issued by | Accepted at | Lifetime |
| --- | --- | --- | --- | --- |
| Agent credential | `agg_` + 43 base64url characters | `POST /owner/connections/{id}/credential`, or `POST /api/v1/claim` | `/api/v1/*` and `/mcp` | Until revoked; issuing a new one revokes the previous one |
| One-time setup code | `XXXXX-XXXXX-XXXXX-XXXXX` (30-symbol alphabet, no `0 O 1 I L U`) | `POST /owner/connections/{id}/claim-code` | `POST /api/v1/claim` only, once | 900 s by default (`ttl_seconds` 60-86400) |
| OAuth access token | `aggo_` + 43 characters | `POST /oauth/token` | `/mcp` only, and only if issued for `<AGG_PUBLIC_URL>/mcp` | 3600 s |
| OAuth refresh token | `aggr_` + 43 characters | `POST /oauth/token` | `POST /oauth/token` (`grant_type=refresh_token`), once | 60 days; rotated on every use |
| OAuth authorization code | `aggc_` + 43 characters | consent form redirect | `POST /oauth/token`, once | 300 s |
| Owner credential | `aggown_` + 43 characters | `agg-owner init`, `agg-owner reset-credential`, `POST /owner/credential/rotate` | `/owner/*` and the consent form | Until rotated |

Credentials are sent as `Authorization: Bearer <credential>`. An OAuth access
token presented to `/api/v1/*` is rejected with 401: OAuth tokens are bound to
the MCP resource. A credential stops working the moment its connection is
revoked. The server stores only SHA-256 digests of all of these
([secrets](security/secrets.md)).

## Scopes

<!-- BEGIN GENERATED: scopes -->
| Scope | Grants |
| --- | --- |
| `hub:read` | Read the work items, answers, inbox and jobs this agent created |
| `hub:write` | Create and update this agent's tasks, goals, projects, state and checkpoints |
| `hub:ask` | Ask the owner questions and request approvals |
| `hub:handoff` | Hand goals to the owner's primary agent (each one waits for the owner's OK) |
<!-- END GENERATED: scopes -->

A connection holds a set of scopes. A credential's effective scopes are the
intersection of the scopes it was issued with and the connection's current
scopes, so narrowing a connection (`PATCH /owner/connections/{id}`) takes
effect on existing credentials at once.

## Agent REST API

Base: `<AGG_PUBLIC_URL>/api`. The core handler is mounted there, so the
routes below are requested as `<AGG_PUBLIC_URL>/api/v1/...`. Every route
except `POST /v1/claim` needs an agent credential. Request bodies are JSON
(at most `requestBodyBytes`); responses are JSON with `cache-control: no-store`.

<!-- BEGIN GENERATED: rest-routes -->
| Method | Path (below the API base) | Scope (any of) | Route key | Rate bucket |
| --- | --- | --- | --- | --- |
| `POST` | `/v1/claim` | none (one-time setup code in the body) | `claim` | per IP |
| `GET` | `/v1/me` | any | `me` | read |
| `GET` | `/v1/work-items` | `hub:read` or `hub:write` | `work_items.list` | read |
| `POST` | `/v1/work-items` | `hub:write` | `work_items.upsert` | write |
| `PUT` | `/v1/work-items/{id}` | `hub:write` | `work_items.upsert` | write |
| `GET` | `/v1/work-items/{id}` | `hub:read` or `hub:write` | `work_items.get` | read |
| `DELETE` | `/v1/work-items/{id}` | `hub:write` | `work_items.delete` | write |
| `POST` | `/v1/checkpoints` | `hub:write` | `checkpoints.create` | write |
| `GET` | `/v1/checkpoints` | `hub:read` or `hub:write` | `checkpoints.list` | read |
| `PUT` | `/v1/snapshot` | `hub:write` | `snapshot.push` | write |
| `POST` | `/v1/questions` | `hub:ask` | `questions.create` | question |
| `GET` | `/v1/questions` | `hub:read` or `hub:ask` | `questions.list` | read |
| `GET` | `/v1/questions/{id}` | `hub:read` or `hub:ask` | `questions.get` | read |
| `POST` | `/v1/questions/{id}/ack` | `hub:ask` | `questions.ack` | write |
| `POST` | `/v1/questions/{id}/cancel` | `hub:ask` | `questions.cancel` | write |
| `GET` | `/v1/inbox` | `hub:read` | `inbox.read` | read |
| `POST` | `/v1/jobs` | `hub:handoff` | `jobs.create` | handoff |
| `GET` | `/v1/jobs` | `hub:read` or `hub:handoff` | `jobs.list` | read |
| `GET` | `/v1/jobs/{id}` | `hub:read` or `hub:handoff` | `jobs.get` | read |
| `POST` | `/v1/jobs/{id}/cancel` | `hub:handoff` | `jobs.cancel` | write |
| `PUT` | `/v1/webhook` | `hub:read` | `webhook.set` | write |
| `DELETE` | `/v1/webhook` | `hub:read` | `webhook.clear` | write |
<!-- END GENERATED: rest-routes -->

A known path with an unsupported method returns 404 with an `Allow` header.
Unknown paths return 404 `not_found`.

### Requests and responses

| Route | Body or query | Response |
| --- | --- | --- |
| `GET /v1/me` | none | `{connection_id, provider, display_name, mode, scopes, owner_name, contract_version, callback: {configured, url_host}}`; `owner_name` is always `null` |
| `POST /v1/claim` | `{code}` | `{token, connection: {id, provider, display_name, mode}, scopes}`; 401 if the code is wrong, used, revoked or expired |
| `GET /v1/work-items` | `?kind=&after=&limit=` (limit 1-100, default 50; ordered by id) | `{items, next_after}`; pass `next_after` as `after` for the next page |
| `PUT /v1/work-items/{id}`, `POST /v1/work-items` | work item | `{item, changed}`; `changed: false` when the stored item is identical |
| `GET /v1/work-items/{id}` | none | `{item}` |
| `DELETE /v1/work-items/{id}` | none | `{deleted}` |
| `POST /v1/checkpoints` | `{id?, work_item_id?, summary, status?, data?}` | 201 `{checkpoint, created: true}`, or 200 `{checkpoint, created: false}` when the id exists |
| `GET /v1/checkpoints` | `?work_item_id=&limit=` (newest first) | `{checkpoints}` |
| `PUT /v1/snapshot` | `{identity?, tasks?, goals?, projects?, memory_summary?, connected_apps?}` | `{upserted, unchanged, state}` |
| `POST /v1/questions` | question | 201 `{question, created: true, revised: false}`; 200 with `created: false` for a retry (`revised: true` if the pending question changed) |
| `GET /v1/questions` | `?status=pending\|answered\|cancelled\|expired&unacknowledged=true&limit=` | `{questions}` (newest first) |
| `GET /v1/questions/{id}` | none | `{question}` |
| `POST /v1/questions/{id}/ack` | `{revision?}` | `{question}`; 409 unless answered; 409 `stale_revision` if `revision` differs |
| `POST /v1/questions/{id}/cancel` | none | `{question}`; a no-op unless pending |
| `GET /v1/inbox` | `?cursor=&limit=&names=` | `{events, cursor, has_more}` |
| `POST /v1/jobs` | `{goal, idempotency_key?, context?, success_criteria?, work_item_id?}` | 201 `{job, created: true}`, or 200 `{job, created: false}` for a known `idempotency_key` |
| `GET /v1/jobs` | `?status=&limit=` | `{jobs}` |
| `GET /v1/jobs/{id}` | none | `{job}` |
| `POST /v1/jobs/{id}/cancel` | none | `{job}`; a no-op for terminal jobs |
| `PUT /v1/webhook` | `{url, auth_header_name?, auth_header_value?}` | `{url, auth_header_name, signing_secret}` (the secret is returned only here) |
| `DELETE /v1/webhook` | none | `{removed}` |

**Work item** (`kind` is `task`, `goal`, `project` or `state`):
`id` (optional on POST; generated as `wi_...`), `kind`, `title` (single line),
`status` (single line), `summary`, `blocker`, `next_step`, `due_at` (ISO 8601;
alias `due`), `parent_id`, `data` (JSON object), `expected_revision`
(optimistic concurrency: 409 `stale_revision` if the stored revision differs).
A changed upsert increments `revision`.

**Snapshot**: `tasks`, `goals` and `projects` (at most `snapshotItems` each)
are upserted as work items of that kind (an entry without `id` gets
`task-1`, `goal-2`, ...; `project_id` or `goal_id` are accepted as
`parent_id`). `identity`, `memory_summary` and `connected_apps` (at most
`connectedApps` entries) are stored on the work item `snapshot` (kind
`state`). A snapshot never raises questions to the owner.

**Question**: `id` (optional; generated as `q_...`), `kind` (`question` or
`approval`), `prompt`, `details`, `options` (questions only: strings or
`{id, label}`, default ids `opt_1`, `opt_2`, ...; approvals always get
`approve` / `deny`), `allow_free_text` (default `true` for questions, `false`
for approvals; a question needs options or free text), `work_item_id`,
`affected_action`, `action_digest` (1-128 characters of
`A-Z a-z 0-9 : _ = + / . -`), `urgency` (`low`, `normal`, `high`),
`expires_at` (future, at most 31 days ahead) or `expires_in_seconds`
(60-2592000; the deadline is fixed when the question is first asked, so
re-sending the same `expires_in_seconds` never moves it). Re-sending an id
with identical content is a no-op; with
different content it raises `revision` while the question is pending and
returns 409 `conflict` once it is answered, cancelled or expired.

`status_reason` tells why a closed question closed: `cancelled_by_agent`,
`dismissed_by_owner`, `connection_revoked` or `expired` (`null` while pending
and once answered).

**Answer** (on an answered question): `choice`, `choice_label`, `text`,
`decision` (`approved` / `denied` for approvals, else `null`),
`question_revision` (the revision the owner saw), `action_digest` (echo of the
question's digest at answer time), `author` (`{kind: "owner", name, verified:
true, surface}`), `answered_at`, `acknowledged_at`.

**Job** statuses: `needs_user`, `running`, `blocked`, `done`, `declined`,
`cancelled`, `failed`; the last four are terminal and set `completed_at`.
`status_reason` values set by the service: `awaiting_owner_approval`,
`approved_by_owner`, `declined_by_owner`, `cancelled_by_agent`,
`connection_revoked`; progress reports set their own `reason`.

**Inbox**: `cursor` is opaque (`c1.` + base64url); omit it to read from the
beginning. The response `cursor` is positioned after the last event returned;
store it and pass it next time. `has_more: true` means another page is ready.
`names` is a comma-separated subset of event names; filtered-out events are
skipped and the cursor still moves past them.

**Webhook**: one per connection; it receives every event. Setting it again
replaces the URL and returns a new signing secret (the old secret stops
signing at once); deliveries still pending for the old webhook are dropped,
not re-sent to the new URL, so catch up from the inbox after a change.
Clearing it drops them too. `auth_header_value` (single line, at most 2048 characters)
is sent with every delivery under `auth_header_name` (default
`Authorization`; for `Authorization` a value without a scheme is sent as
`Bearer <value>`). Reserved header names are refused: `host`,
`content-length`, `content-type`, `transfer-encoding`, `connection`,
`upgrade`, `te`, `trailer`, `keep-alive`, `proxy-authorization`, `cookie`,
`user-agent`, `webhook-id`, `webhook-timestamp`, `webhook-signature`,
`x-mcp-subscription-id`.

**Callback URLs** (webhooks and event subscriptions) must be `https`, on port
443 or 8443, with a public host name (not `localhost`, a single label, or a
name ending in `.localhost`, `.local`, `.internal`, `.intranet`, `.lan`,
`.home.arpa`, `.corp`), without credentials; every resolved address must be
public, the connection is pinned to the checked address, redirects are not
followed, and each request times out after 10 s. `AGG_ALLOW_PRIVATE_CALLBACKS=1`
lifts the scheme, host, address and port rules for local development.

## MCP endpoint

`POST <AGG_PUBLIC_URL>/mcp`, Streamable HTTP with JSON responses, stateless
(no sessions, no SSE stream; `GET` returns 405). One JSON-RPC object per
request; batches are refused. Every request is authenticated, including
`initialize`. Requests that carry an `Origin` header are refused (403) unless
the origin is `AGG_PUBLIC_URL`'s origin.

- **Legacy clients** call `initialize` (`protocolVersion` one of the legacy
  versions; unknown versions are answered with `2025-11-25`), then
  `tools/list` and `tools/call`.
- **2026-07-28 clients** send `MCP-Protocol-Version: 2026-07-28` and/or
  `params._meta["io.modelcontextprotocol/protocolVersion"]`; `Mcp-Method` and
  `Mcp-Name` headers, when present, must match the body. Results carry
  `resultType: "complete"`. `server/discover` returns `supportedVersions`,
  `capabilities: {tools, events}`, `_meta["io.modelcontextprotocol/serverInfo"]`,
  `instructions`, `ttlMs: 3600000`, `cacheScope: "private"`.
- Also answered: `ping`, `resources/list` (empty), `prompts/list` (empty),
  `events/list`, `events/subscribe`, `events/unsubscribe`. Notifications
  (no `id`) get 202 with an empty body.

### Tools

<!-- BEGIN GENERATED: mcp-tools -->
| Tool | Title | Required arguments | Scope (any of) | readOnly | destructive | idempotent | openWorld | Rate bucket |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `whoami` | Check connection | none | any | true | false | true | false | read |
| `upsert_work_item` | Save a task, goal, project or state | `kind`, `title` | `hub:write` | false | false | true | false | write |
| `list_work_items` | List saved work items | none | `hub:read` or `hub:write` | true | false | true | false | read |
| `post_checkpoint` | Post a checkpoint | `summary` | `hub:write` | false | false | true | false | write |
| `push_snapshot` | Push a full snapshot | none | `hub:write` | false | false | true | false | write |
| `create_question` | Ask the owner | `prompt` | `hub:ask` | false | false | true | false | question |
| `get_answer` | Get the owner's answer | `question_id` | `hub:read` or `hub:ask` | true | false | true | false | read |
| `acknowledge_answer` | Acknowledge an answer | `question_id` | `hub:ask` | false | false | true | false | write |
| `cancel_question` | Withdraw a question | `question_id` | `hub:ask` | false | true | true | false | write |
| `check_inbox` | Check for new answers and job updates | none | `hub:read` | true | false | true | false | read |
| `handoff_goal` | Hand a goal to the owner's primary agent | `goal` | `hub:handoff` | false | false | true | false | handoff |
| `get_job` | Get a handed-off job | `job_id` | `hub:read` or `hub:handoff` | true | false | true | false | read |
| `cancel_job` | Cancel a handed-off job | `job_id` | `hub:handoff` | false | true | true | false | write |
| `set_callback_webhook` | Set the wake-up webhook | `url` | `hub:read` | false | true | false | true | write |
| `clear_callback_webhook` | Remove the wake-up webhook | none | `hub:read` | false | true | true | false | write |
<!-- END GENERATED: mcp-tools -->

Arguments mirror the REST bodies above (`get_answer`, `acknowledge_answer`
and `cancel_question` take `question_id`; `get_job` and `cancel_job` take
`job_id`). A tool result is
`{content: [{type: "text", text: <JSON>}], structuredContent: <object>, isError}`.
A failed call returns `isError: true` with `structuredContent` = the core
error object (`{error: {code, message, details?}}`); an `insufficient_scope`
failure also carries `_meta["mcp/www_authenticate"]` with a challenge naming
the tool's scopes. Each tool also advertises
`securitySchemes: [{type: "oauth2", scopes: [<first scope>]}]`.

### JSON-RPC errors

<!-- BEGIN GENERATED: jsonrpc-codes -->
| Code | HTTP status | Meaning |
| --- | --- | --- |
| `-32700` | 400 | Parse error: the body is not JSON |
| `-32600` | 400 / 413 | Invalid request: not a single JSON-RPC 2.0 object (batches are refused), or the body exceeds requestBodyBytes (413) |
| `-32001` | 401 | Unauthorized: missing, invalid, revoked or wrong-audience credential (with WWW-Authenticate) |
| `-32020` | 400 | Header mismatch: MCP-Protocol-Version, Mcp-Method or Mcp-Name disagree with the body (2026-07-28 requests) |
| `-32022` | 400 | Unsupported protocol version; error.data.supported lists the versions |
| `-32601` | 200 (legacy) / 404 (2026-07-28) | Method not found |
| `-32602` | 200 | Invalid params: unknown tool, invalid subscription request, insufficient scope or not found outside tools/call; error.data carries the core error |
| `-32015` | 200 | Callback endpoint error: events/subscribe could not verify the delivery URL; error.data.reason is challenge_failed, http_error, timeout or unreachable |
| `-32000` | 403 / 405 / 429 | Origin not allowed (403), method not allowed: use POST (405), or rate limited (429, with Retry-After) |
| `-32603` | 200 / 503 | Internal error (details are logged server-side without arguments); 503 "Temporarily unavailable" when the credential could not be checked |
<!-- END GENERATED: jsonrpc-codes -->

### Event subscriptions

`events/subscribe` params:
`{name, arguments?, delivery: {mode: "webhook", url, secret}, ttlMs?, cursor?}`.

- `arguments` filters deliveries: `{question_id}` for `answer.created` and
  `question.updated`, `{job_id}` for `job.updated`.
- `secret` is chosen by the subscriber: `whsec_` + base64 of 24-64 bytes.
- `ttlMs`: an integer from 1 ms to 365 days (anything else is refused with
  -32602), then clamped to 1 hour - 30 days; default 7 days; `null` means 30 days.
- `cursor`: an inbox cursor; up to 500 missed events of that name after it are
  queued for delivery.
- Before storing anything the server POSTs
  `{"type":"verification","challenge":"chal_..."}`, signed with `secret` and
  carrying `x-mcp-subscription-id`. The endpoint must answer 2xx with
  `{"challenge": "<same value>"}` within 10 s, else the call fails with -32015.
  This proves the URL is live and answers for the subscription; the challenge
  is readable in the body, so it does not prove the receiver verifies
  signatures. Receivers must verify every delivery.
- Result: `{id, refreshBefore, cursor, truncated}`. `id` is `sub_` + 32 hex
  characters, deterministic per (connection, url, name, arguments), so
  subscribing again refreshes the same subscription (new secret and expiry)
  instead of duplicating it. `cursor` is the current head; `truncated` is
  `true` when events after the given cursor were already pruned.
- `events/unsubscribe` params: `{name, arguments?, delivery: {url}}`; result `{}`.

## Events and deliveries

<!-- BEGIN GENERATED: events -->
Envelope (inbox entry, webhook body and MCP event body): `eventId`, `name`, `timestamp`, `data`, `cursor`.

| Event | When | Payload fields (data) | Required in events/list payloadSchema |
| --- | --- | --- | --- |
| `answer.created` | The owner answered one of this connection's questions. | `question_id`, `kind`, `revision`, `status`, `work_item_id`, `answer` | `question_id`, `revision`, `status`, `answer` |
| `question.updated` | A question was dismissed by the owner or expired. | `question_id`, `status`, `reason`, `revision` | `question_id`, `status` |
| `job.updated` | A handed-off job changed status (needs_user, running, blocked, done, declined, cancelled, failed). | `job_id`, `status`, `status_reason`, `summary`, `result`, `revision`, `work_item_id`, `updated_at` | `job_id`, `status`, `revision` |

`answer.created` `data.answer` fields: `choice`, `choice_label`, `text`, `decision`, `question_revision`, `action_digest`, `author`, `answered_at`, `acknowledged_at`.
<!-- END GENERATED: events -->

Events are appended per connection with a gap-free sequence number:

- `answer.created`: the owner answered (`POST .../answer`).
- `question.updated`: the owner dismissed the question (`reason:
  "dismissed_by_owner"`) or it expired during a sweep (`reason: "expired"`).
- `job.updated`: a handoff was created (`needs_user`), the owner approved or
  declined it, or the owner reported progress.

An agent's own cancellations (`cancel_question`, `cancel_job`) emit no event.
Nothing is emitted for a revoked connection.

Every event is in the inbox. It is also delivered to the connection's webhook
(all events) and to each matching MCP event subscription. A delivery is a
`POST` of the envelope with these headers:

| Header | Value |
| --- | --- |
| `content-type` | `application/json` |
| `webhook-id` | the event's `eventId` (the same on every retry) |
| `webhook-timestamp` | Unix seconds of this attempt |
| `webhook-signature` | `v1,<base64 HMAC-SHA256 of "<webhook-id>.<webhook-timestamp>.<body>">` ([Standard Webhooks](https://www.standardwebhooks.com)) |
| `x-mcp-subscription-id` | the subscription id (MCP event subscriptions only) |
| `<auth_header_name>` | the routine key (webhooks with `auth_header_value` only) |
| `user-agent` | `agent-aggregator/0.1` |

Outcome handling: 2xx is delivered; 410 marks the delivery failed and removes
an MCP event subscription; 413 is final; any other status, a timeout or a
network error, including a host name that does not resolve, is retried.
Attempts: the first immediately, then after 15 s, 60 s, 5 min, 15 min, 1 h,
3 h and 6 h; after the 8th failed attempt the delivery is marked failed. A
URL that fails the callback rules at send time (for example a name that now
resolves to a private or reserved address), an expired subscription or an
undecryptable secret is final at once. A body
larger than `eventBodyBytes` is replaced by `data: {truncated: true, ...}`
keeping only fields ending in `_id`, `status` and `revision`. Delivery
semantics (at-least-once, out of order, idempotency, acknowledgements) are in
[wake modes](wake-modes.md#delivery-semantics).

## Owner API

Base: `<AGG_PUBLIC_URL>`. Every route needs `Authorization: Bearer aggown_...`.
An optional `x-agg-surface` header (`^[a-z][a-z0-9_-]{0,19}$`, default `api`;
`agg-owner` sends `cli`, the consent form records `web`) is stored as
`answer.author.surface`. Path ids: `{connection_id}` is a UUID;
`{question_id}` and `{job_id}` follow the id pattern. Errors use the core
error shape below.

<!-- BEGIN GENERATED: owner-routes -->
| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/owner/me` | The authenticated owner |
| `POST` | `/owner/credential/rotate` | Replace the owner credential (shown once); the old one stops working |
| `GET` | `/owner/connections` | List connections with counts, webhook host and credential hints |
| `POST` | `/owner/connections` | Create a connection {provider, display_name, mode, scopes?, settings?} |
| `GET` | `/owner/connections/{connection_id}` | One connection with counts |
| `PATCH` | `/owner/connections/{connection_id}` | Rename, change scopes or settings {display_name?, scopes?, settings?} |
| `DELETE` | `/owner/connections/{connection_id}` | Disconnect and delete every row the connection produced |
| `POST` | `/owner/connections/{connection_id}/revoke` | Disconnect: credentials die, deliveries stop, open questions and jobs close |
| `POST` | `/owner/connections/{connection_id}/credential` | Issue an agent credential (shown once); earlier agent credentials are revoked |
| `POST` | `/owner/connections/{connection_id}/claim-code` | Issue a one-time setup code {ttl_seconds?} |
| `GET` | `/owner/connections/{connection_id}/setup-prompt` | Setup playbook for the agent (Markdown, contains no secrets) |
| `PUT` | `/owner/connections/{connection_id}/webhook` | Set the connection's wake-up webhook {url, auth_header_name?, auth_header_value?}; returns the signing secret once |
| `DELETE` | `/owner/connections/{connection_id}/webhook` | Remove the connection's webhook |
| `GET` | `/owner/questions` | Questions across connections ?status=pending\|answered\|cancelled\|expired\|all&connection_id=&limit= |
| `GET` | `/owner/connections/{connection_id}/questions/{question_id}` | One question |
| `POST` | `/owner/connections/{connection_id}/questions/{question_id}/answer` | Answer {revision, choice?, text?, decision?} |
| `POST` | `/owner/connections/{connection_id}/questions/{question_id}/dismiss` | Dismiss without answering (the agent gets question.updated) |
| `GET` | `/owner/jobs` | Handed-off jobs ?status=open\|all\|<status>&connection_id=&limit= |
| `GET` | `/owner/connections/{connection_id}/jobs/{job_id}` | One job |
| `POST` | `/owner/connections/{connection_id}/jobs/{job_id}/decision` | Approve or decline a job waiting for the owner {approve, note?} |
| `POST` | `/owner/connections/{connection_id}/jobs/{job_id}/progress` | Report progress on an approved job {status, summary?, reason?, result?} |
| `GET` | `/owner/work-items` | Tasks, goals, projects and states across connections ?connection_id=&kind=&limit= |
| `GET` | `/owner/checkpoints` | Checkpoints across connections ?connection_id=&work_item_id=&limit= |
| `GET` | `/owner/audit` | Audit log ?connection_id=&limit= (max 200) |
<!-- END GENERATED: owner-routes -->

Bodies:

- `POST /owner/connections`: `provider` (`^[a-z][a-z0-9_]{1,39}$`),
  `display_name` (1-80 characters, single line), `mode` (`mcp_webhook`,
  `oauth_events`, `cli_poll`), `scopes` (array; default all four),
  `settings` (JSON object). `scopes` may be an array of scope names or one
  space- or comma-separated string; unknown names are ignored and at least
  one known scope is required. A new connection is `pending` until a credential
  is issued, a setup code is claimed or an OAuth request is approved. At most
  50 non-revoked connections per owner.
- `.../answer`: `revision` (required; must equal the question's current
  revision, else 409 `stale_revision` with the current question in
  `details.question`), and `choice` (an option id; for approvals `approve` or
  `deny`, or `decision: "approved" | "denied"`) and/or `text` (only when the
  question allows free text). An expired or already answered question is 409.
- `.../decision`: `approve` (boolean, default `false`), `note` (stored as the
  job summary). Only a `needs_user` job awaiting approval can be decided.
- `.../progress`: `status` (`running`, `blocked`, `needs_user`, `done`,
  `failed`), `summary`, `reason` (at most 80 characters), `result` (JSON
  object). Refused (409) before approval and after a terminal status.
- `GET /owner/questions` defaults to `status=pending` and sorts high urgency
  first; `GET /owner/jobs` defaults to `status=open` (`needs_user`, `running`,
  `blocked`).
- `DELETE /owner/connections/{id}` returns
  `{deleted: {work_items, checkpoints, questions, jobs, events, deliveries, credentials}}`
  (row counts) and leaves one `connection.delete` audit entry.

## OAuth endpoints

| Endpoint | Method | Notes |
| --- | --- | --- |
| `/.well-known/oauth-protected-resource/mcp` (also `/.well-known/oauth-protected-resource`) | GET | RFC 9728: `resource` = `<AGG_PUBLIC_URL>/mcp`, `authorization_servers` = [`AGG_PUBLIC_URL`], `scopes_supported`, `bearer_methods_supported: ["header"]` |
| `/.well-known/oauth-authorization-server` | GET | RFC 8414: issuer `AGG_PUBLIC_URL`; `S256` only; `token_endpoint_auth_methods_supported: ["none"]`; `client_id_metadata_document_supported: true`; `authorization_response_iss_parameter_supported: true` |
| `/oauth/register` | POST (JSON) | RFC 7591 dynamic registration of a public client: `redirect_uris` (1-10, https or loopback http), `client_name`, `grant_types` (`authorization_code`, `refresh_token`), `token_endpoint_auth_method: "none"`. 201 `{client_id, client_id_issued_at, client_name, redirect_uris, grant_types, response_types, token_endpoint_auth_method}` |
| `/oauth/authorize` | GET | `response_type=code`, `client_id`, `redirect_uri`, `code_challenge` + `code_challenge_method=S256`, `state`, `scope` (default all), `resource` (must be `<AGG_PUBLIC_URL>/mcp` if given). Unknown client or redirect: an HTML error page, never a redirect. Other errors redirect with `error`, `error_description`, `state`, `iss`. Valid requests redirect (303) to `/oauth/authorize?request_id=<uuid>`, the consent page |
| `/oauth/authorize` | POST (form) | Consent form: `request_id`, `csrf`, `action` (`approve` / `deny`), `owner_credential` (approve only), `connection_id` (optional: re-link an existing `oauth_events` connection). Approve redirects (303) to `redirect_uri?code&state&iss`; deny to `redirect_uri?error=access_denied&error_description&state&iss` |
| `/oauth/token` | POST (form) | `grant_type=authorization_code` (`code`, `code_verifier`, `client_id`, `redirect_uri`, `resource?`) or `grant_type=refresh_token` (`refresh_token`, `client_id`, `resource?`). 200 `{access_token, token_type: "Bearer", expires_in, refresh_token, scope}`; 400 `invalid_request`, `invalid_grant`, `invalid_target` or `unsupported_grant_type` |
| `/oauth/revoke` | POST (form) | RFC 7009: `token` (access or refresh). Revokes the whole token family. Always 200 for a well-formed request |

A `client_id` that is an https URL with a path is a client ID metadata
document: the server fetches it (SSRF-guarded, 5 s, 16 KB), requires
`client_id` in the document to equal the URL and at least one valid
`redirect_uri`, and caches it for one hour. With
`AGG_ALLOW_PRIVATE_CALLBACKS=1` an `http://127.0.0.1`, `http://localhost` or
`http://[::1]` document URL is also accepted. A replayed authorization code
or refresh token revokes every token issued from that authorization.

## Service endpoints

| Endpoint | Response |
| --- | --- |
| `GET /` | `{name, version, contract_version, endpoints: {mcp, agent_api, owner_api, oauth_authorization_server, oauth_protected_resource}}` |
| `GET /healthz` | `{"ok":true}` after a database round trip; 500 `internal` when the database is unreachable |

Every response carries `x-content-type-options: nosniff`,
`referrer-policy: no-referrer` and `cache-control: no-store` (the two
metadata documents use `cache-control: public, max-age=300`).

## Errors

Every REST and owner API error, and every failed MCP tool call, uses one shape:

```json
{"error": {"code": "stale_revision", "message": "the agent changed this question; review it again", "details": {"revision": 2}}}
```

`message` never contains secrets or other tenants' data. Unexpected errors
are reported as `internal` with the message `Internal error`.

<!-- BEGIN GENERATED: errors -->
| Code | HTTP status |
| --- | --- |
| `invalid_request` | 400 |
| `unauthorized` | 401 |
| `insufficient_scope` | 403 |
| `forbidden` | 403 |
| `not_found` | 404 |
| `conflict` | 409 |
| `stale_revision` | 409 |
| `limit_exceeded` | 409 |
| `payload_too_large` | 413 |
| `rate_limited` | 429 |
| `unavailable` | 503 |
| `internal` | 500 |
<!-- END GENERATED: errors -->

401 responses carry `WWW-Authenticate` (REST: `Bearer realm="agent-aggregator"`;
MCP: `Bearer resource_metadata="...", scope="..."`; owner API:
`Bearer realm="owner"`), except a refused `POST /v1/claim`, which has none.

Rate-limit refusals by surface:

| Surface | Response |
| --- | --- |
| REST (`/api/v1/*`) and owner API | 429, `Retry-After` header, core error `rate_limited` with `details.retry_after` |
| MCP `tools/call` | HTTP 200 with `isError: true` and `structuredContent.error.code` `rate_limited` (`details.retry_after`) |
| MCP `events/subscribe`, `events/unsubscribe` | HTTP 429, JSON-RPC error -32000, no `Retry-After` |
| MCP, address blocked after failed authentications | HTTP 429, JSON-RPC error -32000, `Retry-After` |
| `/oauth/token`, `/oauth/revoke`, `/oauth/register` | 429 with an OAuth-style `{error, error_description}` body and `Retry-After` |
| `GET /oauth/authorize` | 429 HTML page, no `Retry-After` |

## Limits

<!-- BEGIN GENERATED: limits -->
| Limit | Value |
| --- | --- |
| `idLength` | 128 |
| `titleLength` | 200 |
| `statusLength` | 40 |
| `summaryLength` | 4000 |
| `detailsLength` | 8000 |
| `promptLength` | 1000 |
| `affectedActionLength` | 500 |
| `actionDigestLength` | 128 |
| `optionLabelLength` | 120 |
| `maxOptions` | 8 |
| `answerTextLength` | 4000 |
| `dataBytes` | 16384 |
| `dataDepth` | 8 |
| `goalLength` | 4000 |
| `contextLength` | 8000 |
| `snapshotItems` | 200 |
| `connectedApps` | 50 |
| `openQuestionsPerConnection` | 100 |
| `workItemsPerConnection` | 5000 |
| `checkpointsPerConnection` | 20000 |
| `activeJobsPerConnection` | 20 |
| `pageSize` | 100 |
| `requestBodyBytes` | 262144 |
| `eventBodyBytes` | 262144 |
<!-- END GENERATED: limits -->

Text fields are normalized (NFC; C0/C1 control characters and bidirectional
overrides removed; trimmed) before the length check, which counts Unicode code
points. Single-line fields (`title`, `status`, option labels, `display_name`)
also turn tabs and newlines into spaces. `data` objects drop `__proto__`,
`constructor` and `prototype` keys and truncate keys to 200 characters.

### Rate limits

<!-- BEGIN GENERATED: rate-limits -->
| Budget | Value | Applies to |
| --- | --- | --- |
| `readsPerMinute` | 120 | per connection, by rate bucket |
| `writesPerMinute` | 60 | per connection, by rate bucket |
| `questionsPerHour` | 60 | per connection, by rate bucket |
| `handoffsPerHour` | 20 | per connection, by rate bucket |
| `claimsPerMinutePerIp` | 10 | per client IP |
| `registrationsPerHourPerIp` | 20 | per client IP |
| `tokenRequestsPerMinutePerIp` | 60 | per client IP (reference server) |
| `authorizeRequestsPerMinutePerIp` | 60 | per client IP (reference server) |
| `failedAuthPerMinutePerIp` | 30 | per client IP (reference server) |
<!-- END GENERATED: rate-limits -->

Agent budgets are fixed windows (reads and writes per minute, questions and
handoffs per hour) keyed by connection, so issuing or refreshing a credential
does not reset them. The reference server keeps them in process memory
(single instance). After `failedAuthPerMinutePerIp` rejected credentials
(agent or owner) from one IP within a minute, that IP gets 429 on
`/api/v1/*`, `/mcp` and `/owner/*`, and the consent form refuses approval
(it redirects back with `error=blocked`), until the window ends.
`/oauth/token` and `/oauth/revoke` are limited only by
`tokenRequestsPerMinutePerIp`; invalid codes and refresh tokens do not count
as failed authentications.

## CLIs

### `agg` (agent side)

<!-- BEGIN GENERATED: agent-cli -->
```text
Usage: agg <command> [options]

Setup
  setup --claim CODE [--server URL] [--print-token]   Exchange a one-time setup code; store the credential (0600) or print it for your vault
  doctor                                              Read-only connection check (exit 0 ok, 4 bad credential)

Report
  item put --id ID --kind task|goal|project|state --title T [--status S] [--summary S] [--blocker S] [--next-step S] [--due ISO] [--parent ID] [--data JSON]
  item list [--kind K]        item rm --id ID
  checkpoint --summary S [--id ID] [--item ID] [--status S] [--data JSON]
  snapshot --file PATH|-      Push an explicit JSON snapshot (tasks, goals, projects, identity, memory_summary, connected_apps)

Ask
  ask --id ID --prompt TEXT [--option id=Label ...] [--approval] [--no-free-text] [--details TEXT] [--item ID] [--action TEXT] [--digest D] [--urgency low|normal|high] [--expires-in SECONDS]
  answer --id ID [--wait SECONDS] [--interval SECONDS]   Exit 0 answered (JSON on stdout), 3 still pending, 5 cancelled/expired
  ack --id ID [--revision N]
  cancel --id ID

Inbox
  inbox [--cursor-file PATH] [--limit N] [--exec CMD]     Exit 0 new events (JSON lines), 3 nothing new. With --exec, the cursor only advances if CMD exits 0
  install-poller [--every-minutes N] [--exec CMD] [--cursor-file PATH] [--print]   Idempotent crontab entry
  uninstall-poller

Hand off
  handoff --goal TEXT [--key K] [--context TEXT] [--criteria TEXT] [--item ID]
  job --id ID [--wait SECONDS] [--interval SECONDS]       Exit 0 when the job is terminal, 3 while open

Wake-up webhook
  webhook set --url URL [--header NAME] [--value VALUE]   webhook clear

Environment: AGG_TOKEN, AGG_URL override the stored config.
```

| Exit code | Name | Meaning |
| --- | --- | --- |
| 0 | ok | Success, or something new (inbox events, an answer, a terminal job) |
| 1 | error | Network, server or hook failure; the inbox cursor did not advance |
| 2 | usage | Bad arguments, invalid JSON input, or no server configured |
| 3 | nothingNew | Nothing new, question still pending, job still open, or another inbox run holds the lock |
| 4 | auth | Credential missing, invalid, revoked or expired (HTTP 401) |
| 5 | closed | The question was cancelled or expired without an answer |
<!-- END GENERATED: agent-cli -->

Configuration: `AGG_URL` (the API base, e.g. `https://aggregator.example.com/api`)
and `AGG_TOKEN` override `${XDG_CONFIG_HOME:-~/.config}/agent-aggregator/hub.json`
(written by `agg setup`, mode 0600). `agg inbox` keeps its cursor in
`inbox.cursor` next to it (or `--cursor-file`), reads at most 20 pages per run,
holds `<cursor-file>.lock` while running (a lock older than 10 minutes is
removed), passes events to `--exec` as JSON lines on stdin with
`HUB_EVENT_COUNT` set, and advances the cursor only after the hook exits 0.
Every request sends `User-Agent: agent-aggregator-cli/<version>`.

### `agg-owner` (owner side)

<!-- BEGIN GENERATED: owner-cli -->
```text
Usage: agg-owner <command> [options]

Bootstrap (direct database access; uses AGG_SQLITE_PATH or AGG_DATABASE_URL like agg-server)
  init [--name NAME] [--save] [--server URL] [--additional]   Create the owner; prints the owner credential once (or stores it with --save)
  reset-credential [--owner-id ID] [--save] [--server URL]    Replace a lost or leaked owner credential

Owner API (uses AGG_OWNER_URL + AGG_OWNER_TOKEN, or the file written by --save)
  whoami
  rotate-credential [--save]
  connection create --provider P --name NAME --mode mcp_webhook|oauth_events|cli_poll [--scope S ...]
  connection list | get --id ID | revoke --id ID | delete --id ID --yes
  credential issue --connection ID                    Agent credential, shown once
  claim-code --connection ID [--ttl SECONDS]          One-time setup code for an agent with a shell
  setup-prompt --connection ID                        Setup playbook (Markdown) to give the agent
  questions [--status pending|answered|cancelled|expired|all] [--connection ID] [--limit N]   Exit 3 when empty
  question get --connection ID --id QID
  answer --connection ID --id QID --revision N (--choice OPTION | --approve | --deny | --text TEXT) [--text TEXT]
  dismiss --connection ID --id QID
  jobs [--status open|all|needs_user|running|blocked|done|declined|cancelled|failed] [--connection ID] [--limit N]   Exit 3 when empty
  job get --connection ID --id JID
  job decide --connection ID --id JID (--approve | --decline) [--note TEXT]
  job progress --connection ID --id JID --status running|blocked|needs_user|done|failed [--summary TEXT] [--reason CODE] [--result JSON]
  items [--connection ID] [--kind task|goal|project|state] [--limit N]
  checkpoints [--connection ID] [--item ID] [--limit N]
  audit [--connection ID] [--limit N]
  webhook set --connection ID --url URL [--header NAME --value VALUE] | webhook clear --connection ID

Exit codes: 0 ok, 1 error, 2 usage, 3 empty list, 4 owner credential missing or invalid, 5 conflict (re-read and retry).
```

| Exit code | Name | Meaning |
| --- | --- | --- |
| 0 | ok | Success |
| 1 | error | Network or server error |
| 2 | usage | Bad arguments or configuration |
| 3 | empty | A list command returned no entries (questions, jobs, items, checkpoints, audit, connection list) |
| 4 | auth | Owner credential missing or invalid (HTTP 401) |
| 5 | conflict | HTTP 409: stale revision, already answered/decided, or init found an existing owner |
<!-- END GENERATED: owner-cli -->

Configuration: `AGG_OWNER_URL` (server base URL) and `AGG_OWNER_TOKEN`
override `${XDG_CONFIG_HOME:-~/.config}/agent-aggregator/owner.json` (written
by `--save`, mode 0600). Without either, the URL defaults to `AGG_PUBLIC_URL`,
then `http://127.0.0.1:${AGG_PORT:-8787}`. Non-loopback URLs must use https.
Output is one JSON line per command (`setup-prompt` prints Markdown). API
errors are one JSON line on stderr, `{"error": {"status", "code", "message", "details"?}}`,
where `details` keeps only `status`, `revision`, `field` and `retry_after`;
`init` refusing a second owner prints `{"error": {"code": "conflict", "message"}}`;
usage and network errors are plain text.

### `scripts/poll-inbox.sh` and `scripts/install-poller.sh`

POSIX `sh` + `curl` versions of the poller for hosts without Node.js. See the
header of each script and [connect a polling agent](playbooks/connect-polling-agent.md).
`poll-inbox.sh` exit codes: 0 new events, 3 nothing new (or locked), 4
credential missing or rejected, 1 any other error. `install-poller.sh` exit
codes: 0 ok, 1 error, 2 usage.
