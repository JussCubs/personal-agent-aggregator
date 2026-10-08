# @agent-aggregator/core

Protocol, storage and security core of the personal agent aggregator: the
wire contract, validation, `AggregatorService` (work items, checkpoints,
questions and approvals, handoff jobs, conversations, inbox, webhooks and MCP
event subscriptions), Postgres and SQLite drivers with row-level security on
Postgres, dual-era MCP over Streamable HTTP, a framework-free REST handler,
OAuth 2.1 helpers, Standard Webhooks signing, SSRF-guarded outbound requests
and the deterministic agent CLI. No runtime dependencies; Node.js 20+
(`node:sqlite` needs 22.5+).

```js
import postgres from "postgres";
import { AggregatorService, createAesGcmSecretBox, handleAgentRest, handleMcpHttp } from "@agent-aggregator/core";
import { createPostgresDriver } from "@agent-aggregator/core/postgres";

const driver = createPostgresDriver(postgres(process.env.DATABASE_URL), { schema: "public" });
await driver.migrate();
const service = new AggregatorService({ driver, secretBox: createAesGcmSecretBox(process.env.AGG_ENCRYPTION_KEY) });
// Mount handleAgentRest / handleMcpHttp in your HTTP framework, run service.deliverDue() and service.sweep() on timers.
```

Entry points: `@agent-aggregator/core`, `@agent-aggregator/core/postgres`,
`@agent-aggregator/core/sqlite`, `@agent-aggregator/core/cli`.

The reference server in `packages/server` shows a complete integration. See
the repository's `docs/` for the [architecture](../../docs/architecture.md),
[contract](../../docs/contract.md) and [threat model](../../docs/security/threat-model.md).
License: Apache-2.0.
