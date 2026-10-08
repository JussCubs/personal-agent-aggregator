# Threat model

Scope: `@agent-aggregator/core`, the reference server (`@agent-aggregator/server`),
the CLIs and scripts in this repository, deployed as documented. Code
references are `file: function` so they survive refactors; tests that prove a
mitigation are named where they exist.

## Assets

| Id | Asset | Property that matters |
| --- | --- | --- |
| A1 | The owner's shared state: work items, checkpoints, questions, answers, jobs, audit log | Confidentiality across owners and across connections; integrity |
| A2 | Credentials: agent credentials, OAuth access/refresh tokens and codes, setup codes, owner credentials | Confidentiality; prompt revocation |
| A3 | Delivery secrets: webhook signing secrets, routine keys, subscription secrets | Confidentiality |
| A4 | `AGG_ENCRYPTION_KEY` | Confidentiality (decrypts A3) |
| A5 | Owner decisions: answers and approvals | Integrity: an approval applies only to what the owner saw |
| A6 | Availability of the server, and the owner's attention | Not exhaustible by one agent or one address |
| A7 | Networks reachable from the server (loopback, private ranges, cloud metadata) | Not reachable through agent-supplied URLs |

## Actors

| Actor | Trust | Notes |
| --- | --- | --- |
| Owner | Trusted after authentication | Holds the owner credential |
| Connected agent | **Untrusted input**, scoped capability | May be buggy, compromised, or prompt-injected by content it processed |
| Another owner (Postgres, multi-tenant) | Hostile | Has valid credentials of their own |
| OAuth client and its developer | Untrusted | Registration is open (DCR) and client names are self-declared |
| Unauthenticated internet user | Hostile | Can reach every public endpoint |
| Network attacker | Hostile | Between agents, server, database and callback receivers |
| Operator and database host | Trusted | Out of scope beyond the configuration guidance |

## Trust boundaries

```text
 agent ──TB1──> server <──TB3── owner's browser (consent page) / agg-owner
                  │  │
                  │  └──TB2──> callback URLs (webhooks, MCP event endpoints, client metadata documents)
                  │
                  ├──TB4──> database (scoped roles + RLS | privileged role)
                  └──TB5──> logs
```

- **TB1** agent → server: authentication, audience, scopes, validation, rate limits.
- **TB2** server → outside URLs: SSRF guard, signing, bounded requests.
- **TB3** browser/CLI → server: owner credential, CSRF, framing, escaping.
- **TB4** server → database: every agent/owner query in a scoped transaction under a `NOLOGIN` role with forced RLS.
- **TB5** server → logs: only redacted primitive fields.

## Threats and mitigations

### T1 Cross-tenant reads and writes

An owner (or their agent) reads or modifies another owner's rows.

- Every agent and owner query runs in `scoped()`: `stores/postgres.ts:
  createPostgresDriver.scoped` sets `aggregator.owner_id` /
  `aggregator.connection_id` with transaction-local `set_config` and
  `SET LOCAL ROLE` to `aggregator_agent` or `aggregator_owner`.
- `schema.ts: postgresSchemaSql` enables and **forces** RLS on every table,
  with per-owner policies (`owner_id = aggregator_ctx_owner()`) for the owner
  role and per-connection policies for the agent role; both roles are
  `NOLOGIN` without `BYPASSRLS`, and the API role holds only a `SET`
  membership in them. A missing principal resolves to `NULL`, so nothing
  matches.
- Composite foreign keys `(connection_id, owner_id) → connections (id, owner_id)`
  make a row that names one owner and another owner's connection impossible.
- The service also filters by owner and connection in every query
  (`service.ts`, `agentScope` / `ownerScope`), so SQLite gets the same
  predicates without RLS.
- Proven against a real Postgres by `packages/core/tests/rls-postgres.test.mjs`
  ("another owner cannot read or write"), including direct SQL attempts under
  the scoped roles.

Residual: SQLite has no RLS; it is documented and enforced (by `agg-owner
init`) as single-owner storage. `privileged()` paths are limited to work
that has no owner yet or spans owners: lookups keyed by secret digests
(`service.ts: authenticate, claim, exchangeAuthorizationCode,
refreshAccessToken, revokeOAuthToken`), OAuth client registration and the
client-metadata cache (`registerOAuthClient, getOAuthClient,
cacheCimdClient`), authorization requests (`createAuthorizationRequest,
getAuthorizationRequest, approveAuthorizationRequest,
denyAuthorizationRequest`), the delivery worker and sweeps (`deliverDue,
sweep`), and in the reference server owner records (`owners.ts:
createOwner, rotateOwnerCredential, authenticateOwner, listOwners,
countOwners`), `/healthz` and the doctor. Authorization requests are looked
up by a random request id (a UUID in the consent URL). Anyone holding that
URL can view the consent page and, with the CSRF token that page hands out,
deny the request; approving still needs the owner credential.

### T2 Sibling-connection reads

One of the owner's agents reads another agent's rows (for example to harvest
a prompt-injection target, or another agent's answers).

- Agent policies require `connection_id = aggregator_ctx_connection()`; the
  connections policy shows an agent only its own active row
  (`schema.ts: postgresSchemaSql`).
- Agents have no privileges at all on `credentials`, `oauth_clients` and
  `oauth_requests`, no `SELECT` on encrypted destination columns, and may
  update only `event_seq`, `last_seen_at` and `updated_at` on their own
  connection row (scopes and status are not writable).
- The connection id always comes from the authenticated principal, never from
  agent input (`service.ts: agentScope`; REST and MCP handlers take no
  connection id).
- Within its own connection, the agent role may update only listed columns
  of questions and jobs, and `BEFORE UPDATE` triggers
  (`schema.ts: guard_agent_question, guard_agent_job`) refuse every
  transition that belongs to the owner: an agent cannot answer or approve its
  own question, mark a job approved or done, or rewrite an answered question.
- A delivery row can only point at a destination of the same connection
  (composite foreign key `(destination_id, connection_id)`), and the delivery
  worker joins events on the delivery's own connection and owner.
- Tested: "another integration of the same owner cannot read or write" and
  "credentials and escalation paths are closed" in `rls-postgres.test.mjs`.

### T3 Credential theft and replay

- Credentials are 256-bit random values with a recognizable prefix
  (`secrets.ts: generateToken`), stored only as SHA-256 digests
  (`hashToken`), shown once. Setup codes carry about 98 bits, work once and
  expire after 15 minutes by default (60 s to 24 h with `--ttl`)
  (`generateClaimCode`, `service.ts: claim`).
- Revocation is immediate: `service.ts: authenticate` requires an unrevoked,
  unexpired credential on an `active` connection on every request.
- Least privilege: four scopes, checked per call (`service.ts: requireScope`);
  a credential's scopes are intersected with the connection's current scopes.
- Audience binding: REST accepts only agent credentials; OAuth access tokens
  are accepted only on `/mcp` and only for this server's MCP resource
  (`agent-routes.ts: authenticateAgent`). Access tokens live one hour.
- Transport: `AGG_PUBLIC_URL` must be https unless it is a loopback address
  (`config.ts: normalizePublicUrl`), or unless `AGG_ALLOW_PRIVATE_CALLBACKS=1`
  is set, which also permits a plain-http public URL (development only: the
  consent page and every credential would then travel unencrypted).
  Credentials travel only in the `Authorization` header (and the owner
  credential in the consent form body).
- Client storage: `agg setup` and `agg-owner --save` write 0600 files
  (`cli.ts: writePrivate`, `owner-cli.ts: writePrivate`); `poll-inbox.sh`
  passes the credential to curl on stdin, not on the command line;
  `install-poller.sh` refuses an env file readable by others.
- Guessing is throttled: after 30 rejected credentials in a minute, the
  address gets 429 on `/api/v1/*`, `/mcp` and `/owner/*` and the consent form
  refuses approval until the window ends (`limits.ts: authFailed`);
  setup-code claims are limited to 10 per minute per address, and the token
  and revocation endpoints to 60 per minute per address.

Residual: bearer credentials are replayable for their lifetime if stolen (no
sender-constrained tokens). Response: [incident playbook](../playbooks/incident-token-leak.md).

### T4 OAuth code and refresh-token replay, interception and mix-up

- PKCE with `S256` is mandatory; `plain` is refused (`oauth.ts:
  parseAuthorizeRequest`, `verifyPkceS256`).
- Codes are single-use and live 300 s; presenting a used code revokes every
  token issued from it (`service.ts: exchangeAuthorizationCode`).
- Refresh tokens rotate on every use; presenting a used or revoked refresh
  token revokes the whole family (`service.ts: refreshAccessToken`).
- Redirect URIs must be registered exactly and be https or loopback http; an
  unknown client or redirect URI is shown an error page and never redirected
  to (`oauth.ts: parseAuthorizeRequest`, `isAllowedRedirectUri`).
- Exchange checks `client_id`, `redirect_uri` and `resource`
  (`invalid_target`); every authorization response carries `iss` (RFC 9207)
  and the client's `state` (`oauth-routes.ts`).
- Client metadata documents must name themselves as `client_id`
  (`oauth.ts: validateClientMetadataDocument`) and are fetched through the
  SSRF guard.
- Tested: `oauth-cli.test.mjs` (core) and the OAuth test in
  `packages/server/tests/server.test.mjs`.

### T5 Consent phishing, CSRF and clickjacking

- Approving requires the owner credential typed into the form; a logged-in
  browser session is never enough (`oauth-routes.ts: handleConsentPost`).
- The form carries a CSRF token, HMAC-SHA256 of the request id and a nonce
  held in an `HttpOnly; SameSite=Strict` cookie (`csrfToken`).
- The page sends `Content-Security-Policy: default-src 'none'; style-src
  'nonce-…'; form-action 'self' <redirect origin>; frame-ancestors 'none';
  base-uri 'none'` and `X-Frame-Options: DENY`; it has no scripts
  (`consent.ts: htmlHeaders`).
- Every client-supplied value is escaped (`http.ts: escapeHtml`); the page
  labels the client name as supplied by the application and shows the host
  that will receive the code, the metadata-document host when there is one,
  each scope with its description, and the expiry (`consent.ts:
  renderConsentPage`). Tested with a `<script>` client name in
  `server.test.mjs`.
- Post/redirect/get: reloading never repeats an approval; a handled request
  returns 410.

Residual: an owner who approves a malicious client gives it the scopes shown,
on a new connection of its own; it cannot see other connections (T2), and the
owner can revoke it at any time.

### T6 Server-side request forgery through callbacks

Agents choose webhook URLs and subscription URLs; OAuth clients choose
metadata-document URLs.

- `url-guard.ts: validateOutboundUrl`: https only, ports 443 and 8443, no
  credentials in the URL, no `localhost`, single-label hosts or internal
  suffixes; literal IPs must be public.
- `url-guard.ts: resolvePublicDestination`: every DNS answer must be a public
  address (IPv4 private, loopback, link-local, CGNAT, documentation,
  benchmarking and multicast ranges; IPv6 loopback, unique local, link-local,
  multicast, NAT64, 6to4, Teredo, IPv4-mapped private addresses are refused).
- `url-guard.ts: guardedRequest` pins the checked address (no DNS rebinding
  between check and connect), follows no redirects, times out (10 s for
  deliveries, 5 s for metadata documents) and caps the response size.
- URLs are validated when registered (`service.ts: setWebhook, subscribeEvent`)
  and again on every send (`deliverDue → guardedRequest`).
- Header injection: routine-key header names are restricted and reserved
  names refused; values are single-line (`service.ts: parseWebhookConfig`).
- `AGG_ALLOW_PRIVATE_CALLBACKS=1` disables the scheme, address and port rules
  (and allows a plain-http `AGG_PUBLIC_URL`, T3) for local development only;
  the server logs a warning at startup.
- Tested: `packages/core/tests/security.test.mjs`.

Residual: an agent can make the server POST signed event JSON for its own
connection to any public https URL; volume is bounded by its rate limits.

### T7 Webhook spoofing and replay towards agents

- Every delivery is signed with Standard Webhooks (`webhooks.ts:
  webhookHeaders`) using a per-destination secret; retries keep the
  `webhook-id` (= `eventId`) and re-sign with a fresh timestamp.
- `verifyWebhook` rejects timestamps more than 300 s off and compares in
  constant time; [wake modes](../wake-modes.md#delivery-semantics) tells
  receivers to verify the raw body and deduplicate by `eventId`.
- Before storing an MCP event subscription, the server sends a verification
  challenge signed with the subscriber's secret and requires it echoed
  (`service.ts: subscribeEvent`). That proves the URL is live and answers for
  the subscription; the challenge itself is in the body, so it does not prove
  the receiver verifies signatures. Receivers must verify every delivery.

Residual: within the 5-minute tolerance a captured delivery can be replayed
to the receiver; deduplication by `eventId` neutralizes it.

### T8 Prompt injection through agent-supplied text

A compromised agent writes text meant to manipulate the owner, the owner's
UI, or another agent.

- Everything an agent sends is data (`contract.ts` header): stored, shown,
  never executed, never forwarded to another agent as an instruction.
- Text is NFC-normalized, stripped of control and bidirectional-override
  characters, trimmed and length-bounded (`validate.ts: cleanText`); JSON
  `data` is depth- and size-bounded and drops prototype keys (`cleanData`).
- Agents cannot read other agents' rows (T2), so there is no agent-to-agent
  channel. A handoff reaches the owner's primary agent only after the owner
  approves it (`service.ts: handoffJob` starts every job as `needs_user`).
- Answers are framed as the owner's decisions, not instructions, in the MCP
  instructions, tool descriptions and setup prompts (`mcp.ts:
  DEFAULT_MCP_INSTRUCTIONS`, `setup-prompts.ts: RULES`).
- The owner API's question, job and work-item views name the connection that
  wrote the text (`provider`, `display_name`); checkpoint and audit entries
  carry its `connection_id`, resolvable with `GET /owner/connections/{id}`.

Residual: an agent can still write misleading text into its own rows. Any UI
built on the owner API must render agent text as text (never HTML or
Markdown with links auto-followed).

### T9 Approval confusion

The agent changes what is being approved after the owner read it, or applies
an approval to a different action.

- Answering requires the question's current `revision`; any content change
  while pending increments it, so an answer to old wording fails with
  `stale_revision` (`service.ts: answerQuestion, createQuestion`).
- A question cannot be changed after it is answered, cancelled or expired
  (409), and on Postgres the agent-role trigger refuses it even if a query
  tried (`schema.ts: guard_agent_question`); only the owner role can set an
  answer or a decision.
- Approvals have fixed options (`approve` / `deny`); the answer echoes
  `question_revision` and `action_digest`, and agents are told to act only
  when both match (`setup-prompts.ts: RULES`, `mcp.ts` tool descriptions).
- The owner sees `affected_action` and `action_digest` before answering.

Residual: the digest is computed by the agent, so it binds the agent to its
own action; the server cannot check that `affected_action` describes the
action truthfully. Sensitive actions should still be confirmed by the agent's
own platform.

### T10 Denial of service and resource exhaustion

- Bodies are capped at 256 KiB (`http.ts: readBody`), forms at 16 KiB; every
  field has a limit ([contract](../contract.md#limits)).
- Per-connection quotas: 100 open questions, 5000 work items, 20000
  checkpoints, 20 open jobs; 50 non-revoked connections per owner (`service.ts`).
- Rate limits per connection (reads, writes, questions, handoffs) and per IP
  (claims, registrations, token and authorize requests, failed
  authentications) (`limits.ts`).
- Postgres statements time out after 15 s (`stores/postgres.ts`); HTTP
  request and header timeouts are 30 s and 15 s (`app.ts`).
- The worker leases at most 50 deliveries per pass and backs off each failing
  delivery (15 s up to 6 h between attempts, at most 8 attempts). The sweep bounds storage: events after 30 days, checkpoints
  and audit entries after 180 days, spent credentials after 7 days, and
  client registrations nobody uses after one day (`service.ts: deliverDue, sweep`).
- Rate-limit keys are per connection for agents (`agent:<bucket>:<connection id>`)
  and per address for unauthenticated endpoints, so an agent cannot reset its
  budget by rotating or refreshing credentials (`limits.ts`).

Residual: limits are in process memory, per instance; several instances
behind one load balancer each enforce their own.

### T11 Database disclosure

- No usable credential is stored: only digests (T3).
- Delivery secrets and routine keys are AES-256-GCM encrypted with a key that
  lives outside the database (`secrets.ts: createAesGcmSecretBox`).
- Even the owner role cannot select credential digests (column grants).

Residual: the database together with `AGG_ENCRYPTION_KEY` exposes delivery
secrets and routine keys. Keep them apart ([secrets](secrets.md)).

### T12 Supply chain

- The core has zero runtime dependencies; the server's only third-party
  runtime dependency is `postgres`, loaded only when `AGG_DATABASE_URL` is set.
- `package-lock.json` is committed and CI installs with `npm ci`; GitHub
  Actions are pinned to full commit SHAs; Dependabot proposes updates.
- Contributions require DCO sign-off and the security checklist in
  [CONTRIBUTING.md](../../CONTRIBUTING.md).

### T13 Secrets in logs

- `log.ts`: only primitive fields; every string passes `redact()` (bearer
  values, prefixed credentials, `whsec_` secrets, setup codes, long hex,
  credentials in URLs) and is truncated.
- Request logs carry method, path without query string, status, duration,
  route and client IP; never headers or bodies. Errors are logged by name,
  code and message, never with request arguments.
- Tested: "logs never contain credentials, codes, request bodies or
  authorization headers" in `server.test.mjs`; each example in `npm run demo`
  scans the server's logs for every secret it used.

### T14 Owner credential compromise

- The owner credential grants everything for that owner. It is shown once,
  stored as a digest, saved 0600 by `agg-owner --save`, and rotated with
  `agg-owner rotate-credential` (API) or `agg-owner reset-credential` (direct
  database access, for a lost or leaked credential); the old one stops
  working at once.
- It is typed only into the consent page served from `AGG_PUBLIC_URL`; check
  the address bar before typing it.

### T15 Network attackers and local exposure

- https for every non-loopback deployment (T3); `Referrer-Policy: no-referrer`
  on every response, and `cache-control: no-store` on every response except
  the two public OAuth metadata documents (`public, max-age=300`).
- The server binds to `127.0.0.1` by default and refuses a non-loopback bind
  without `AGG_PUBLIC_URL`.
- MCP requests with a foreign `Origin` are refused (DNS-rebinding protection
  for browser-based callers); the owner API and the consent form need the
  owner credential, so a rebinding page learns nothing.
- Database connections should use `sslmode=verify-full` ([storage](../storage.md#tls)).

### T16 SQL injection, and why role switching does not stop it

Scoped transactions switch roles with `SET LOCAL ROLE` on a connection that
logged in as the API role. That switch is a guard against *forgotten
predicates*, not a sandbox: SQL that an attacker could inject would run in
the same session and could `RESET ROLE` back to the API role, which has
`BYPASSRLS`. Injection is prevented only by never building SQL from input:

- every value is a bound parameter (`$1..$n`, `$n::jsonb`); drivers translate
  placeholders, never interpolate values (`db.ts: translateForPostgres,
  translateForSqlite`);
- the only interpolated identifiers are table names built from a validated
  prefix and schema (`db.ts: assertPrefix, quoteIdent`), fixed at startup;
- free text, ids and JSON from agents are validated and length-bounded before
  any query (`validate.ts`).

New queries must follow the same rule; the security checklist in
[CONTRIBUTING.md](../../CONTRIBUTING.md#security-review-checklist) requires it.

### T17 Failing open

Every failure path denies:

- an unknown, malformed, revoked, expired or wrong-audience credential
  resolves to no principal (401); an error while checking a credential is a
  503 on `/mcp` (`mcp.ts: handleMcpHttp`) and a 500 `internal` on REST, never
  an anonymous or default principal;
- a rate-limit refusal or a failure inside `beforeCall` stops the call
  (`rest.ts`, `mcp.ts`);
- a missing transaction-local principal makes every policy compare against
  `NULL`, so no row matches;
- unknown errors become `internal` without their message
  (`errors.ts: toAggregatorError`); an undecryptable secret makes a delivery
  fail instead of being sent unsigned (`service.ts: attemptDelivery`);
- an `Origin` that is not allowed, a protocol-version or header mismatch, or
  a callback that cannot answer the verification challenge is refused before
  any work is done.

## Out of scope

- A compromised server host, operator or database administrator.
- The security of each agent's own platform, including how it stores the
  signing secret and its credential.
- Owners acting against their own interests (for example approving everything).
