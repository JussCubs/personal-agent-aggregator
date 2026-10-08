# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the packages
use [Semantic Versioning](https://semver.org/). The wire contract has its own
date-based version (`CONTRACT_VERSION`), listed with each release.

## [Unreleased]

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

[Unreleased]: ../../compare/v0.1.0...HEAD
[0.1.0]: ../../releases/tag/v0.1.0
