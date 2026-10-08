# Storage

The core talks to storage through one seam, `SqlDriver` (`scoped()` and
`privileged()`), with two drivers: SQLite on Node's built-in `node:sqlite`,
and Postgres over a postgres.js client. The reference server picks one from
the environment:

| Variable | Effect |
| --- | --- |
| `AGG_SQLITE_PATH` | SQLite file. Default `./data/aggregator.db` when `AGG_DATABASE_URL` is unset. |
| `AGG_DATABASE_URL` | `postgres://` or `postgresql://` connection string. Enables Postgres. Setting both variables is a configuration error. |
| `AGG_DB_SCHEMA` | Postgres schema for the tables (default `public`). Created if missing (needs `CREATE` on the database). |

| Option | Isolation | Use it for |
| --- | --- | --- |
| [SQLite](#sqlite-local-single-owner) | Service predicates only (no row-level security) | One person, one machine |
| [Local Postgres](#postgres) | Row-level security, forced, per owner and per connection | Self-hosting, development against the production shape |
| [Your own Supabase project](#your-own-supabase-project) | Same, plus the Data API roles revoked | A managed database you control |
| [Other managed Postgres](#other-postgres-hosts) | Same | Neon, Amazon RDS, Google Cloud SQL and others, after the checks below |

`agg-server doctor` checks whichever storage is configured and exits 0 only
when all of them pass. It changes no rows; like the server, it opens (and on
SQLite creates, if missing) the database file and its directory.

## SQLite (local, single owner)

```sh
export AGG_SQLITE_PATH=./data/aggregator.db   # optional; this is the default
npx agg-server doctor
```

Expected: `{"ok":true,"storage":"sqlite","checks":[{"name":"sqlite_file_mode","pass":true,...},{"name":"schema_tables","pass":true,"detail":"13 tables with prefix aggregator_"},...]}`.

- The server creates the directory with mode 0700 and the file with mode
  0600 before SQLite opens it; SQLite gives the `-wal` and `-shm` files the
  same mode. The database runs in WAL mode with foreign keys on and a 5 s busy
  timeout.
- SQLite has no roles and no row-level security. Every query still filters by
  owner and connection, but a bug in that filtering would not be caught by the
  database. Use SQLite for exactly one owner (`agg-owner init` refuses a second
  owner unless `--additional`), on a machine only that person controls.
- Writes are serialized inside the process; `agg-owner init` and
  `agg-owner reset-credential` can run while the server is up.
- Node.js 22.5-22.12 needs `--experimental-sqlite`; the `agg-server` and
  `agg-owner` executables add it themselves when it is needed.

## Postgres

```sh
export AGG_DATABASE_URL='postgres://aggregator_api:<password>@127.0.0.1:5432/postgres'
npx agg-server migrate     # {"ok":true,"storage":"postgres","schema":"public","schema_version":"<16 hex>"}
npx agg-server doctor      # {"ok":true,"storage":"postgres","checks":[...]} and exit 0
```

`agg-server` also migrates on every start. Migration is idempotent and cheap:
the schema writes a version marker (a comment on the connections table) and an
unchanged schema is skipped; concurrent migrations are serialized with an
advisory lock. One migration creates:

- two roles, `aggregator_agent` and `aggregator_owner`, as `NOLOGIN` roles
  without `BYPASSRLS`. On PostgreSQL 16+ they are created with
  `createrole_self_grant = 'set'` in effect, so the connecting role receives a
  `SET`-only membership (it can `SET ROLE` to them but does not inherit their
  privileges); migrate never grants that membership afterwards and stops with
  an error if it is missing. On PostgreSQL 15 and older, migrate grants
  membership with `GRANT`;
- `USAGE` on the schema for both roles, and two functions,
  `aggregator_ctx_owner()` and `aggregator_ctx_connection()`, that read the
  transaction-local settings `aggregator.owner_id` and `aggregator.connection_id`;
- 13 tables with composite foreign keys that pin every child row (all but
  audit entries) to its
  connection's owner, and row-level security **enabled and forced** on all of them;
- per-owner policies for `aggregator_owner`, per-connection policies for
  `aggregator_agent`, column-level grants (agents never see credential rows
  or encrypted secrets, and may update only listed columns), and
  `REVOKE ALL ... FROM PUBLIC`;
- two `BEFORE UPDATE` triggers that limit the agent role to revising or
  withdrawing its own pending questions, acknowledging answers, and
  cancelling its own open jobs (`aggregator_questions_agent_guard` and
  `aggregator_jobs_agent_guard`, running the functions
  `aggregator_guard_agent_question` and `aggregator_guard_agent_job`);
- `REVOKE ALL` on every aggregator table from `anon`, `authenticated` and
  `service_role` when those roles exist (they back Supabase's Data API).

The two scoped roles are cluster-wide. Several databases or schemas on one
cluster can share them, because every policy is per table.

Tested on PostgreSQL 16 and 17.

### Requirements for the connecting role

| Requirement | Why | Check |
| --- | --- | --- |
| `BYPASSRLS` (or superuser) | `privileged()` work: see below | doctor `role_bypassrls` |
| `CREATEROLE` during the first migration, or `SET` membership in both scoped roles | migrate creates `aggregator_agent` / `aggregator_owner` and needs to `SET ROLE` to them | doctor `role_can_switch` |
| `CREATE` on the schema (and on the database for a new `AGG_DB_SCHEMA`) | tables, functions, policies | `agg-server migrate` succeeds |
| Not a superuser (recommended) | least privilege | doctor `role_bypassrls` detail shows `superuser=false` |

A dedicated role, created once by a superuser (or, on PostgreSQL 16+, by a
role that itself has `BYPASSRLS` and `CREATEROLE`):

```sql
CREATE ROLE aggregator_api LOGIN BYPASSRLS CREATEROLE PASSWORD '<generate a long random password>';
GRANT CREATE ON SCHEMA public TO aggregator_api;   -- or: CREATE SCHEMA aggregator AUTHORIZATION aggregator_api;
```

If `aggregator_agent` and `aggregator_owner` already exist because another
role created them, migrate stops with
`aggregator_api needs SET membership in aggregator_agent; recreate the role under createrole_self_grant=set`.
Have the role that created them (or a superuser) run
`GRANT aggregator_agent, aggregator_owner TO aggregator_api;` (on PostgreSQL
16+ the membership then has `SET TRUE` by default), and migrate again.

### Why the API role needs BYPASSRLS and CREATEROLE

Every table forces row-level security, which applies even to the table's
owner. Agent and owner requests run under the scoped roles, where the policies
decide. Some work, however, is cross-tenant by nature and runs in
`privileged()` as the connecting role:

- resolving a bearer credential: the server only has the credential, so it
  must find the row by digest before it knows the owner or connection;
- claiming a one-time setup code and exchanging OAuth codes and refresh tokens;
- registering OAuth clients, caching client metadata documents, and the
  authorization requests behind the consent page (before approval there is no owner);
- the delivery worker leasing every due delivery, and the sweep expiring
  questions and pruning old rows across all owners;
- the reference server's owner records (creating, rotating and checking
  owner credentials), `/healthz` and `agg-server doctor`.

Without `BYPASSRLS` those queries would see no rows. `CREATEROLE` is needed
only so migration can create the two `NOLOGIN` roles (and so hold `SET` on
them); it is the narrowest attribute that allows this without a superuser.
Agents never connect to the database and the scoped roles cannot log in, so
the API role's attributes are never available to an agent request.

### TLS

postgres.js reads `sslmode` from the connection string:

- `?sslmode=require` encrypts the connection but does **not** verify the
  server certificate;
- `?sslmode=verify-full` encrypts and verifies the certificate and host name
  against Node's trusted CAs. When the provider signs with its own CA,
  download that CA certificate and start the server with
  `NODE_EXTRA_CA_CERTS=/path/to/provider-ca.crt`.

Use `verify-full` whenever the database is not on the same host or private network.

### Poolers and schemas

Use a direct connection or a session-mode pooler. The reference server is one
long-running process with its own pool of at most 10 connections, so it gains
nothing from a transaction-mode pooler. A custom `AGG_DB_SCHEMA` is applied
with the `search_path` connection startup parameter; poolers may not forward
startup parameters, so keep the default `public` schema behind a pooler.

### Embedding in an existing database

A product that embeds the core can point `owner_id` at its own users table
with the schema option `ownerReference` (for example `"users(id)"`) instead
of the `aggregator_owners` table. Only `aggregator_connections` references
it; every other table references the connection. Two consequences favor a
small dedicated table over a hot one:

- each new connection checks the key with a `FOR KEY SHARE` lock on the
  referenced row, which waits behind any `SELECT ... FOR UPDATE` or delete of
  that row in the product's own transactions;
- the reference is `ON DELETE CASCADE`, so deleting a user deletes all of
  their aggregator rows inside that same transaction.

An `owners` table keyed by the user id and maintained by the product keeps
both effects out of the product's hot paths.

## Your own Supabase project

These steps keep the aggregator in a Supabase project you own. The server
never uses Supabase API keys; it talks to Postgres directly.

1. **Connection string.** In the project dashboard, open **Connect**. Copy the
   **Direct connection** string if the server has IPv6 connectivity,
   otherwise the **Session pooler** string (port 5432 on the pooler host; the
   user is `postgres.<project-ref>`). Do not use the transaction pooler
   (port 6543). Put the database password in place of the placeholder.
2. **TLS.** Download the project's CA certificate from the database settings
   (SSL configuration), append `?sslmode=verify-full`, and set
   `NODE_EXTRA_CA_CERTS` to the downloaded file. `?sslmode=require` also works
   but does not verify the server.
3. **Schema.** Keep the default `public` schema (required behind the session
   pooler). The aggregator tables are protected from the Data API by the
   revoked grants (step 5 verifies them) and, for `anon` and `authenticated`,
   also by forced RLS with no policy for those roles. `service_role` bypasses
   RLS on Supabase, so for it the revoked grants are the protection. With the direct connection you may instead set
   `AGG_DB_SCHEMA=aggregator`, a schema the Data API does not expose.
4. **Migrate and check.**

   ```sh
   export AGG_DATABASE_URL='postgresql://postgres.<project-ref>:<password>@<session-pooler-host>:5432/postgres?sslmode=verify-full'
   export NODE_EXTRA_CA_CERTS=/path/to/supabase-ca.crt
   npx agg-server migrate
   npx agg-server doctor
   ```

   Expected: `migrate` prints `{"ok":true,"storage":"postgres","schema":"public",...}`;
   `doctor` exits 0 and its `role_bypassrls` detail reads
   `bypassrls=true superuser=false`. If `role_bypassrls` fails, the dashboard
   role lacks `BYPASSRLS` and the server cannot work with it.

   The `postgres` role is not a superuser on Supabase, so migrate creates
   `aggregator_agent` and `aggregator_owner` itself under
   `createrole_self_grant = 'set'`, which gives `postgres` the `SET`-only
   membership it needs; it does not try to grant that membership later. If
   the roles already exist from an earlier attempt and migrate stops with
   `postgres needs SET membership in aggregator_agent; ...`, run
   `GRANT aggregator_agent, aggregator_owner TO postgres;` as the role that
   created them and migrate again.
5. **Verify isolation** with the SQL in [verify RLS](playbooks/verify-rls.md)
   (SQL editor or `psql "$AGG_DATABASE_URL"`). In particular `anon`,
   `authenticated` and `service_role` must have no privileges on any
   `aggregator_` table, and every table must show RLS enabled and forced.
6. **Revoke manually only if step 5 shows a grant** (for example after
   restoring tables from a dump made elsewhere):

   ```sql
   DO $$ DECLARE t text; r text; BEGIN
     FOREACH r IN ARRAY ARRAY['anon', 'authenticated', 'service_role'] LOOP
       IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
         FOR t IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                  WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname LIKE 'aggregator\_%' LOOP
           EXECUTE format('REVOKE ALL ON public.%I FROM %I', t, r);
         END LOOP;
       END IF;
     END LOOP;
   END $$;
   ```

The full deployment, with a PASS/FAIL check per step, is
[deploy on Supabase](playbooks/deploy-supabase.md).

## Other Postgres hosts

The same requirements apply everywhere; managed "admin" roles differ in which
attributes they have, so run `agg-server doctor` and read `role_bypassrls`
and `role_can_switch` before going further.

- **Neon.** Use the direct connection string (its host name has no
  `-pooler` part). Neon requires TLS: add `?sslmode=require` or
  `?sslmode=verify-full`.
- **Amazon RDS and Aurora.** The master user is a member of `rds_superuser`,
  not a superuser; check its attributes with the doctor. Connect directly
  rather than through RDS Proxy, and use `sslmode=verify-full` with the RDS CA
  bundle in `NODE_EXTRA_CA_CERTS`.
- **Google Cloud SQL.** Users are members of `cloudsqlsuperuser`, not
  superusers; check with the doctor. Connect through the Cloud SQL Auth Proxy
  on `127.0.0.1` (the proxy encrypts the connection) or directly with TLS.
- **Any host.** If the role you can create lacks `BYPASSRLS`, follow the
  provider's documentation for granting it; there is no supported mode
  without it.

## Backups

The encryption key is part of every backup: stored webhook signing secrets
and routine keys can only be decrypted with the same `AGG_ENCRYPTION_KEY`.
Keep the key in a secret manager, separate from database backups. Without
it, a restore still works except that webhooks and event subscriptions must
be set again (deliveries fail with `secret_unavailable` until then).

**SQLite**, online, consistent, owner-only file:

```sh
(umask 077 && node --no-warnings --experimental-sqlite -e "new (require('node:sqlite').DatabaseSync)('data/aggregator.db').exec(\"VACUUM INTO 'aggregator-backup.db'\")")
```

To restore, stop the server and replace `data/aggregator.db` with the backup
(remove any `aggregator.db-wal` and `aggregator.db-shm` next to it first).

**Postgres**, data only, with a role that has `BYPASSRLS` (otherwise pg_dump
refuses tables with row-level security). With `sslmode=verify-full`, the
PostgreSQL client tools need a root certificate too: `export
PGSSLROOTCERT=system` (libpq 16+) or the path of the provider's CA file.

```sh
pg_dump --format=custom --data-only --table='public.aggregator_*' "$AGG_DATABASE_URL" > aggregator.dump
```

Restore into an empty database: create the schema with the server first, then load the rows.

```sh
AGG_DATABASE_URL="$TARGET_URL" npx agg-server migrate
pg_restore --data-only --single-transaction --dbname="$TARGET_URL" aggregator.dump
AGG_DATABASE_URL="$TARGET_URL" npx agg-server doctor
```

Managed hosts' own backups (point-in-time recovery, snapshots) cover the
tables too; the roles are cluster-level and are recreated by `migrate`.

## Data deletion

| What | How | What remains |
| --- | --- | --- |
| One work item | `DELETE /v1/work-items/{id}` (agent) | Only the `work_items` row is deleted: checkpoints, questions and jobs that reference it, and its earlier audit entries, stay; one `work_item.delete` audit entry is added |
| One connection and everything it produced | `agg-owner connection delete --id <id> --yes` | One `connection.delete` audit entry with row counts |
| Disconnect without deleting | `agg-owner connection revoke --id <id>` | Every row except the webhook, subscriptions and their pending deliveries (deleted) and credentials (revoked, then pruned after 7 days), for the owner to review or delete later |
| Old inbox events and deliveries | Automatic: the sweep deletes events and finished deliveries older than 30 days | Nothing |
| Old checkpoints and audit entries | Automatic: the sweep deletes them after 180 days | Nothing |
| Spent credentials | Automatic: deleted 7 days after they expired, were revoked or were used (setup codes, refresh tokens) | Nothing |
| An owner and all their data (Postgres) | SQL below | Nothing in the live database |
| Everything (SQLite) | Stop the server, delete `aggregator.db`, `-wal` and `-shm` | Nothing |

Deleting an owner (as the API role; the audit and OAuth request tables are not
linked by foreign key, so they are cleared explicitly):

```sql
BEGIN;
DELETE FROM aggregator_audit WHERE owner_id = '<owner id>';
DELETE FROM aggregator_oauth_requests WHERE owner_id = '<owner id>';
DELETE FROM aggregator_owners WHERE id = '<owner id>';   -- cascades to connections and every child row
COMMIT;
```

Deleted rows stay in backups until those expire. SQLite may keep deleted
content in free pages until the file is rewritten: run the backup command
above and keep the new file, or run `VACUUM` with the server stopped.
