# @agent-aggregator/server

The reference server for the personal agent aggregator, on `node:http` with
no framework: agent REST API (`/api/v1`), MCP endpoint (`/mcp`), OAuth 2.1
authorization server with a consent page (`/oauth/*`, `/.well-known/*`),
owner API (`/owner/*`), a signed-delivery worker, rate limits and redacted
JSON logs. Storage: SQLite (`AGG_SQLITE_PATH`) or Postgres (`AGG_DATABASE_URL`).

```sh
export AGG_ENCRYPTION_KEY="$(agg-server keygen)"
agg-owner init --name "Your name" --save
agg-server                       # listens on http://127.0.0.1:8787
agg-server doctor                # storage and isolation checks
```

| Executable | Purpose |
| --- | --- |
| `agg-server` | `start` (default), `keygen`, `migrate`, `doctor` |
| `agg-owner` | Owner CLI for `/owner/*`, plus `init` and `reset-credential` with direct database access |

Conversations: `agg-owner say <connection> "<text>" [--thread REF]` sends a
connected agent a message (`POST /owner/connections/{id}/messages`) and
`agg-owner thread <connection> [REF] [--wait SECONDS]` shows the thread with
each message's status. The server logs `message_status`, `message_failed`
(warning), `message_posted` and `checkpoint_posted` lines with ids only, and
`createAggregatorServer(config, { hooks })` passes every service hook to an
embedding host ([conversations](../../docs/conversations.md)).

Configuration, endpoints and exit codes: [docs/contract.md](../../docs/contract.md);
deployment: [docs/playbooks](../../docs/playbooks). Requires Node.js 22.5+.
License: Apache-2.0.
