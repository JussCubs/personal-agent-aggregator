# Contributing

Thank you for helping. This project is a reference stack: every change must
keep it safe by default, documented to the command, and verifiable by a
test. This guide covers setup, tests, style, sign-off, contract changes and
the security checklist every review uses.

Security vulnerabilities are not contributions to discuss in public: report
them privately as described in [SECURITY.md](SECURITY.md).

## Setup

Requirements: Node.js 22.5 or newer (CI uses Node 22), npm 10, git, a POSIX
shell. Postgres 16+ for the row-level security tests.

```sh
npm ci            # installs the workspace from package-lock.json
npm run build     # core → server (TypeScript to dist/); agent-cli has no build step
npm test          # build + every test except the Postgres ones (skipped without a database)
npm run demo      # the three wake modes end to end; must end with "PASS: ..."
```

Workspace layout and responsibilities are in
[docs/architecture.md](docs/architecture.md#packages).

## Tests

All tests use Node's built-in runner (`node --test`); there is no test
framework dependency.

| Command | Runs |
| --- | --- |
| `npm test` | `packages/*/tests/*.test.mjs` and `tests/*.test.mjs`: service, MCP, OAuth, security, CLI, reference server, owner CLI, POSIX scripts, contract-doc drift |
| `npm run test:postgres` | The RLS proof (`packages/core/tests/rls-postgres.test.mjs`), the server on Postgres, `scripts/verify-rls.sql`, and the core service tests on the Postgres driver. Fails fast if `AGG_TEST_DATABASE_URL` is unset |
| `npm run demo` | `examples/run-demo.mjs` |
| `npm run typecheck` | `tsc --noEmit` for every package |

The Postgres tests create and drop schemas, databases and roles. Use a
disposable server, never a shared or production database:

```sh
# a throwaway cluster on port 5433 (Postgres binaries on PATH)
initdb -D /tmp/agg-pg -U postgres --auth=trust
pg_ctl -D /tmp/agg-pg -o "-p 5433 -c listen_addresses=127.0.0.1 -k /tmp" -l /tmp/agg-pg.log start
export AGG_TEST_DATABASE_URL=postgres://postgres@127.0.0.1:5433/postgres
npm run test:postgres
```

or a container: `docker run --rm -d -e POSTGRES_PASSWORD=postgres -p 127.0.0.1:5433:5432 postgres:16`
with `AGG_TEST_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5433/postgres`.

Rules:

- Every behavior change comes with a test that fails without it.
- Schema or policy changes extend `rls-postgres.test.mjs` with a direct-SQL
  probe under the scoped roles (not only a service-level test), and
  `scripts/verify-rls.sql` when operators should check it too.
- A change to a command, output or exit code updates the playbook that shows it.
- Tests never make language-model calls or reach the internet; outbound
  calls go to `127.0.0.1` with `AGG_ALLOW_PRIVATE_CALLBACKS=1` or a stubbed `send`.

## Style

- TypeScript `strict` (with `noUncheckedIndexedAccess`), ES modules, Node
  built-ins only. `@agent-aggregator/core` has **no runtime dependencies**;
  the server's only one is `postgres`. Adding a dependency needs a reason in
  the pull request and a review of its install scripts and maintainers.
- No HTTP framework, ORM or logger library; keep the core embeddable.
- SQL: parameters only (`$1..$n`, `$n::jsonb`), dialect-neutral so both drivers
  run it, every agent/owner query inside `scoped()`.
- Errors: throw `AggregatorError` with a message that is safe to return to the
  caller; never include secrets, SQL or another tenant's data.
- Logs: one JSON line, primitive fields only, through the server's logger.
- Formatting follows `.editorconfig` (2 spaces, LF, final newline); keep the
  surrounding style.
- Shell scripts are POSIX `sh` and pass `shellcheck -s sh`.
- Documentation states exact commands, expected output and a PASS/FAIL check.
  Use `example.com` host names and placeholders such as `<password>`.

## Sign-off (Developer Certificate of Origin)

Every commit must be signed off, certifying the
[Developer Certificate of Origin 1.1](https://developercertificate.org/):
you wrote the change or have the right to submit it under the project's
license (Apache-2.0).

```sh
git commit -s -m "server: refuse repeated OAuth parameters"
```

This adds `Signed-off-by: Your Name <your-email>` with your git identity.
Pull requests with unsigned commits cannot be merged; fix them with
`git rebase --signoff main`.

## Proposing contract changes

The contract ([docs/contract.md](docs/contract.md)) is what connected agents
depend on: REST routes and bodies, MCP tool names, arguments, annotations and
scopes, event names and payloads, error codes, limits, CLI commands and exit
codes.

1. Open an issue with the **Contract change** template before writing code.
   Describe the wire change exactly and classify it: additive, behavior
   change, or breaking.
2. Prefer additive changes: new optional fields, new tools, new events.
   Never change the meaning or type of an existing field, and never reuse a
   removed name. A breaking change needs a deprecation period in which both
   forms work.
3. In the pull request:
   - update `CONTRACT_VERSION` in `packages/core/src/contract.ts` for any
     change visible to agents (date of the change, `YYYY-MM-DD`);
   - run `npm run docs:contract` to regenerate the tables, and update the prose
     around them; `npm test` fails until the document matches the code;
   - update `TOOL_DEFINITIONS` descriptions and annotations, `EVENT_DEFINITIONS`
     payload schemas, and `renderSetupMarkdown` if agents must behave differently;
   - add a `CHANGELOG.md` entry under "Unreleased".

## Security review checklist

Answer each item in the pull request for any change that touches
authentication, storage, outbound requests, validation, logging or the
consent page.

- [ ] **Isolation:** every new query runs in `scoped()` with the right role,
      filters by owner and connection, and works under forced RLS; new tables
      carry `(owner_id, connection_id)` with the composite foreign key, RLS
      enabled and forced, policies, minimal grants, and are added to the RLS
      test and `verify-rls.sql`.
- [ ] **Privileged paths:** any new `privileged()` use is cross-tenant by
      nature and keyed by a secret digest, an unguessable random id the
      caller was given (such as an authorization request id), or a system
      task; never by an owner, connection or row id taken from input.
- [ ] **SQL:** no string-built SQL from input; identifiers only from validated
      configuration.
- [ ] **Input:** every new field is validated (type, length, pattern), text goes
      through `cleanText`, JSON through `cleanData`; unknown input fails closed.
- [ ] **Scopes and limits:** the operation checks the narrowest scope, is
      charged to a rate-limit bucket, and is bounded by a quota where it creates rows.
- [ ] **Credentials:** new secrets are random (≥ 128 bits), shown once, stored
      as digests (or encrypted when the server must use them), and revoked with the
      connection.
- [ ] **Outbound requests:** go through `guardedRequest` (validated and
      re-validated URL, pinned DNS, no redirects, timeout, size cap) and are signed.
- [ ] **Agent text is data:** nothing an agent sends is executed, interpreted as
      an instruction, or rendered unescaped; owner-facing output escapes it.
- [ ] **Approvals:** owner decisions stay bound to `revision` and
      `action_digest`; the agent role still cannot perform owner transitions.
- [ ] **Failure:** every error path denies; messages are response-safe.
- [ ] **Logging:** no credential, code, body, header value or query string can
      reach a log line; a test asserts it where the change adds logging.
- [ ] **Docs:** threat model and playbooks updated when a mitigation or an
      operator step changes.

## Releases

Maintainers bump versions in every `package.json` together, move
"Unreleased" in `CHANGELOG.md` under the new version, tag `vX.Y.Z`, and publish
the packages with npm provenance.
