# Personal Agent Aggregator

The reference stack for aggregating personal AI agents: one place where all of
a person's agents report their tasks, goals, projects and checkpoints, ask
questions and request approvals, and hand work to each other, with MCP, a
CLI and signed webhooks. Safe by default, storage-agnostic, Apache-2.0.

```text
npm ci && npm run demo      # three wake modes end to end, zero language-model calls, PASS/FAIL table
```

## The problem

A person who uses several AI agents (a chat assistant with MCP, a coding
agent with a shell, an automation that runs on a schedule) ends up with work
scattered across all of them. Each agent has its own idea of what is in
progress, each one interrupts in its own place, and none of them can safely
hand a goal to another. Wiring them together directly means giving every
agent access to every other agent, which is exactly what you do not want when
any of them can be prompt-injected.

The aggregator is the hub instead: every agent gets its own narrowly scoped
connection, writes only its own rows, and reaches the person through one
inbox. The person answers once; the answer goes back to the agent that asked,
signed, bound to the exact wording and action they approved.

## Features

- **One shared state.** Tasks, goals, projects and state items (`upsert_work_item`),
  append-only checkpoints, explicit snapshots. Idempotent by caller-chosen ids.
- **Questions and approvals.** Free-text or multiple-choice questions and
  approve/deny approvals with `affected_action` and `action_digest`. Answers
  carry the question revision the owner saw, so an agent can refuse an answer
  that was given to different wording.
- **Handoffs.** An agent hands a goal to the owner's primary agent; nothing
  runs until the owner approves; progress flows back as `job.updated`.
- **Three wake modes.** MCP + signed webhook; OAuth-protected MCP with MCP
  Events; CLI or plain HTTPS polling a cursor-based inbox from cron.
  See [wake modes](docs/wake-modes.md).
- **Dual-era MCP.** Streamable HTTP for 2026-07-28 clients (`server/discover`,
  per-request `_meta`, `events/*`) and legacy `initialize` clients, from one endpoint.
- **OAuth 2.1 authorization server.** PKCE (S256 only), dynamic client
  registration, client ID metadata documents, refresh-token rotation with
  reuse detection, RFC 9207 `iss`, RFC 9728 resource metadata, a
  server-rendered consent page.
- **Storage-agnostic.** SQLite for one person on one machine; Postgres (local,
  your own Supabase project, or any managed Postgres) with forced row-level
  security for everything else.
- **Deterministic tooling.** `agg` (agent side) and `agg-owner` (owner side)
  print JSON and use documented exit codes, so cron jobs, hooks and tests can
  drive them. A language model is only needed when an answer actually arrives.

## Architecture

```text
   agents (one connection each)                               the owner
 +---------------------------+                       +------------------------+
 | MCP agent + webhook       |---MCP, bearer-------+ | agg-owner CLI, or your |
 | OAuth MCP plugin          |---MCP, OAuth--------+ | own UI on /owner/*     |
 | agent with a shell (agg)  |---REST /api/v1------+ +-----------+------------+
 +-------------^-------------+                     |             | owner credential
               | signed webhook, signed MCP        v             v
               | event, or polled inbox  +------------------------------------+
               +-------------------------| reference server (node:http)        |
                                         | /mcp /api/v1 /owner /oauth /.well-  |
                                         | known: auth, limits, consent, logs  |
                                         +------------------------------------+
                                         | @agent-aggregator/core              |
                                         | service, validation, MCP, REST,     |
                                         | OAuth, webhooks, SSRF guard, worker |
                                         +------------------------------------+
                                         | SqlDriver: scoped() | privileged()  |
                                         +----------+---------------+---------+
                                                    v               v
                                         SQLite (one owner)   Postgres, FORCE RLS
```

Every agent request is authenticated by digest lookup, then runs in a
transaction scoped to exactly one owner and one connection. On Postgres that
transaction switches to a `NOLOGIN` role and row-level security policies, not
just `WHERE` clauses, keep owners and sibling connections apart. Events are
appended per connection with a gap-free sequence, delivered at least once by
a background worker, and always readable from the inbox.
[Architecture in depth](docs/architecture.md).

## Security model in brief

- Agents are untrusted: everything they send is stored and shown as data,
  normalized (control and bidirectional characters stripped) and size-bounded;
  nothing an agent writes is executed or forwarded as an instruction.
- Each connection sees only its own rows (owner and connection isolation,
  enforced by RLS on Postgres); scopes are least-privilege and checked per call.
- Credentials are random, prefixed, shown once and stored only as SHA-256
  digests; webhook secrets and routine keys are AES-256-GCM encrypted at rest.
- Approvals bind to a revision and an action digest; stale answers are refused.
- Outbound calls to agent-supplied URLs are SSRF-guarded (https, public
  addresses only, DNS pinned, no redirects, bounded time and size); every
  delivery is signed with Standard Webhooks.
- OAuth codes and refresh tokens are single-use; replay revokes the family.
- Logs never contain credentials, bodies or `Authorization` headers.

Full analysis: [threat model](docs/security/threat-model.md) and
[secrets handling](docs/security/secrets.md).

## Quickstart (5 minutes, SQLite)

Requires Node.js 22.5 or newer and git. Run every command from the repository root.

```sh
git clone <repository-url> personal-agent-aggregator
cd personal-agent-aggregator
npm ci
npm run build
npm run demo                       # PASS: 50 checks, 50 passed, 0 failed
```

Run your own server:

```sh
# terminal 1
export AGG_ENCRYPTION_KEY="$(npx agg-server keygen)"   # keep it: it decrypts stored webhook secrets
npx agg-owner init --name "Your name" --save            # creates ./data/aggregator.db and the owner
npx agg-server                                          # {"msg":"listening","url":"http://127.0.0.1:8787",...}
```

```sh
# terminal 2: connect an agent with a shell and ask it a question
CONN=$(npx agg-owner connection create --provider my_shell_agent --name "My shell agent" --mode cli_poll | node -pe 'JSON.parse(require("fs").readFileSync(0)).connection.id')
CODE=$(npx agg-owner claim-code --connection "$CONN" | node -pe 'JSON.parse(require("fs").readFileSync(0)).code')
npx agg setup --claim "$CODE" --server http://127.0.0.1:8787/api
npx agg doctor && echo PASS
npx agg ask --id q-first --prompt "Ship the release today?" --option yes=Yes --option no=No
npx agg-owner answer --connection "$CONN" --id q-first --revision 1 --choice yes
npx agg inbox                      # one answer.created event as a JSON line, exit 0
npx agg ack --id q-first --revision 1
```

The step-by-step version with a PASS/FAIL check per step is
[playbooks/quickstart-local.md](docs/playbooks/quickstart-local.md).

## Repository layout

| Path | What it is |
| --- | --- |
| [`packages/core`](packages/core) | `@agent-aggregator/core`: contract, validation, service, storage drivers and schema, MCP, REST, OAuth, webhooks, SSRF guard, agent CLI. Zero runtime dependencies. |
| [`packages/server`](packages/server) | `@agent-aggregator/server`: the reference server (`agg-server`) and the owner CLI (`agg-owner`) on `node:http`. |
| [`packages/agent-cli`](packages/agent-cli) | `@agent-aggregator/agent-cli`: the `agg` executable for agents with a shell. |
| [`scripts`](scripts) | `poll-inbox.sh` and `install-poller.sh` (POSIX sh + curl), contract doc generator. |
| [`examples`](examples) | Runnable, model-free clients for each wake mode, and `npm run demo`. |
| [`docs`](docs) | Architecture, contract, wake modes, storage, security, playbooks. |

## Documentation

- [Architecture](docs/architecture.md): components, data model, request and delivery flow.
- [Contract](docs/contract.md): REST routes, MCP tools and annotations, events, errors, CLIs, limits.
- [Wake modes](docs/wake-modes.md): which mode to use, delivery semantics.
- [Storage](docs/storage.md): SQLite, Postgres, Supabase, other hosts, backups, deletion.
- [Threat model](docs/security/threat-model.md) and [secrets](docs/security/secrets.md).
- Playbooks: [quickstart](docs/playbooks/quickstart-local.md),
  [deploy on Postgres](docs/playbooks/deploy-postgres.md),
  [deploy on Supabase](docs/playbooks/deploy-supabase.md),
  [verify RLS](docs/playbooks/verify-rls.md),
  [connect an MCP + webhook agent](docs/playbooks/connect-mcp-webhook-agent.md),
  [connect an OAuth + events agent](docs/playbooks/connect-oauth-events-agent.md),
  [connect a polling agent](docs/playbooks/connect-polling-agent.md),
  [rotate, revoke, delete](docs/playbooks/rotate-revoke-delete.md),
  [incident: leaked credential](docs/playbooks/incident-token-leak.md).

## Contributing and security

Contributions are welcome under the Developer Certificate of Origin; see
[CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as
described in [SECURITY.md](SECURITY.md), never in a public issue. This project
follows the [Contributor Covenant](CODE_OF_CONDUCT.md).

## License

[Apache License 2.0](LICENSE). See [NOTICE](NOTICE).
