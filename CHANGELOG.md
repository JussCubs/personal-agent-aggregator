# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the packages
use [Semantic Versioning](https://semver.org/). The wire contract has its own
date-based version (`CONTRACT_VERSION`), listed with each release.

## [Unreleased]

## [0.2.0] - 2026-10-08

Contract version `2026-10-08`.

### Added

- Conversation bridge in `@agent-aggregator/core`: per-connection threads
  keyed by the host's conversation id (`thread_ref`) and messages with
  AES-256-GCM encrypted bodies. Owner side: `sendMessage` (idempotent by
  `idempotency_key`) and `listThreadMessages`. Agent side:
  `check_messages`, `acknowledge_message` and `post_message` over MCP,
  `GET /v1/messages`, `POST /v1/messages` and `POST /v1/messages/{id}/ack`
  over REST, and `agg messages | working | reply | say`. New scope
  `hub:chat`, new event `message.created` (MCP subscriptions can filter by
  `thread_id`). Owner messages move `queued` → `delivered` → `working` →
  `replied`, or to `failed` with `not_picked_up` (20 minutes),
  `no_reply` (120 minutes) or `connection_revoked`; both timeouts are
  configurable. Hooks `messagePosted` and `messageStatusChanged`.
- `create_question` accepts `thread_id` to ask inside a conversation;
  `agg ask --thread`.
- `checkpointPosted` hook: fired once per new checkpoint, not for idempotent
  retries.
- Reference server: `POST` and `GET /owner/connections/{id}/messages`,
  `agg-owner say` and `agg-owner thread [--wait]`, log lines for message
  statuses (failures as warnings), agent posts and checkpoints (ids only,
  never text), and a `hooks` option on `createAggregatorServer` for
  embedding hosts.
- `npm run demo`: each wake mode now runs a conversation round trip with a
  question asked in the thread.
- Documentation: [conversations](docs/conversations.md) (host contract,
  routing, statuses, timeouts, revocation, deletion, privacy, per-mode
  sequences); contract, threat model (T18), secrets, storage, architecture,
  wake modes and playbooks updated.

### Changed

- `migrate` adds columns introduced after 0.1.0 to existing SQLite and
  Postgres databases (`questions.thread_id`) and creates the `threads` and
  `messages` tables.
- `scripts/verify-rls.sql` and `agg-server doctor` cover the new tables and
  the message guard trigger.
- Rate buckets match exact read names, so `messages.post` and
  `messages.ack` spend the write budget like their MCP tools.

### Security

- Text normalization (`cleanText` and strings inside JSON `data`) turns the
  Unicode line separator U+2028, paragraph separator U+2029 and next line
  (NEL) U+0085 into `\n` before any other step (single-line fields then turn
  line breaks into one space). Line-based filters downstream can no longer
  be bypassed with them, and NEL no longer silently joins two lines.

## [0.1.0] - 2026-10-08

Contract version `2026-10-01`.

### Added

- `@agent-aggregator/core`: wire contract and limits; validation and text
  normalization; `AggregatorService` for work items, checkpoints, snapshots,
  questions and approvals (revision- and digest-bound answers), handoff jobs,
  per-connection inbox with opaque cursors, webhooks and MCP event
  subscriptions with a signed delivery worker; Postgres schema with
  `NOLOGIN` scoped roles, transaction-local principals, forced row-level
  security, composite foreign keys and agent guard triggers; SQLite schema for
  single-owner use; OAuth 2.1 helpers (PKCE S256, RFC 8414/9728/9207, DCR,
  client ID metadata documents); dual-era MCP over Streamable HTTP
  (2026-07-28 and `initialize` clients); framework-free REST handler; typed
  client; deterministic agent CLI; SSRF-guarded outbound requests; Standard
  Webhooks signing; AES-256-GCM secret box; in-memory rate limiter.
- `@agent-aggregator/server`: reference server on `node:http` with the agent
  REST API, MCP endpoint, OAuth authorization server and consent page, owner
  API, delivery loop, per-connection and per-IP rate limits, redacted JSON
  logs; `agg-server` (`start`, `keygen`, `migrate`, `doctor`) and `agg-owner`.
- `@agent-aggregator/agent-cli`: the `agg` executable.
- `scripts/poll-inbox.sh` and `scripts/install-poller.sh` (POSIX sh + curl),
  `scripts/verify-rls.sql`, `scripts/gen-contract-docs.mjs`.
- Examples for the three wake modes and `npm run demo`.
- Documentation: architecture, contract, wake modes, storage, threat model,
  secrets, and playbooks for local use, Postgres and Supabase deployment, RLS
  verification, connecting each kind of agent, rotation and incident response.

[Unreleased]: ../../compare/v0.2.0...HEAD
[0.2.0]: ../../compare/v0.1.0...v0.2.0
[0.1.0]: ../../releases/tag/v0.1.0
