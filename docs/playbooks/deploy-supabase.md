# Playbook: deploy on your own Supabase project

**Goal:** the aggregator's tables in a Supabase project you own, with forced
row-level security, the Data API roles locked out, and the reference server
running against it.

**You need:** a Supabase project and its database password; a host for the
server with Node.js 22.5+ (see [deploy on Postgres](deploy-postgres.md)
steps 3, 4 and 7-8 for the service and proxy parts); `psql` for the checks.
The server never uses Supabase API keys: it connects to Postgres directly.

**Conventions:** run each command, compare with *Expected*, run *Check*
(prints `PASS` or `FAIL`), stop at the first `FAIL`. Run the commands from a
clone of this repository after `npm ci && npm run build`.

## 1. Pick the connection string

In the project dashboard open **Connect**:

| Option | Use it when | Notes |
| --- | --- | --- |
| Direct connection | The server has IPv6 connectivity | Port 5432 on the database host; user `postgres` |
| Session pooler | The server is IPv4-only | Port 5432 on the pooler host; user `postgres.<project-ref>` |
| Transaction pooler | Never for this server | Port 6543; built for short-lived serverless connections |

Replace the password placeholder with the database password.

## 2. Turn on certificate verification

Download the project's CA certificate from the database settings (SSL
configuration section) and store it on the server host.

```sh
export NODE_EXTRA_CA_CERTS=/etc/ssl/certs/supabase-project-ca.crt
export AGG_DATABASE_URL='postgresql://postgres.<project-ref>:<password>@<session-pooler-host>:5432/postgres?sslmode=verify-full'
```

`?sslmode=require` also encrypts, but postgres.js does not verify the server
certificate in that mode. Keep the default schema (`public`) on the pooler;
see [storage](../storage.md#your-own-supabase-project) for the direct-connection
alternative.

Check:

```sh
psql "$AGG_DATABASE_URL" -Atc 'SELECT 1' | grep -qx 1 && echo PASS || echo FAIL
```

(`psql` verifies with `sslrootcert`; add `&sslrootcert=$NODE_EXTRA_CA_CERTS`
to the URL for this check if `psql` reports a certificate error.)

## 3. Check the role

```sh
psql "$AGG_DATABASE_URL" -Atc "SELECT rolname, rolsuper, rolbypassrls, rolcreaterole FROM pg_roles WHERE rolname = current_user"
```

Expected: `postgres|f|t|t` (not a superuser, `BYPASSRLS`, `CREATEROLE`).

Check:

```sh
test "$(psql "$AGG_DATABASE_URL" -Atc 'SELECT rolbypassrls AND rolcreaterole FROM pg_roles WHERE rolname = current_user')" = t && echo PASS || echo FAIL
```

A FAIL means this role cannot run the server ([why](../storage.md#why-the-api-role-needs-bypassrls-and-createrole)).

## 4. Migrate

```sh
npx agg-server migrate
```

Expected: `{"ok":true,"storage":"postgres","schema":"public","schema_version":"<16 hex>"}`.
Migrate creates `aggregator_agent` and `aggregator_owner` under
`createrole_self_grant = 'set'`, the 13 tables with forced RLS, the policies
and triggers, and revokes every privilege on them from `anon`,
`authenticated` and `service_role`.

Check:

```sh
npx agg-server migrate | grep -q '"ok":true' && echo PASS || echo FAIL
```

If it stops with `postgres needs SET membership in aggregator_agent`, the
roles exist from an earlier attempt: see
[storage](../storage.md#your-own-supabase-project), step 4.

## 5. Doctor

```sh
npx agg-server doctor
```

Expected: `"ok":true`; `role_bypassrls` reads `role postgres: bypassrls=true
superuser=false`; `public_roles_revoked` reads
`anon/authenticated/service_role table privileges: none`.

Check:

```sh
npx agg-server doctor >/dev/null && echo PASS || echo FAIL
```

## 6. Verify isolation in SQL

```sh
psql "$AGG_DATABASE_URL" -v ON_ERROR_STOP=1 -f scripts/verify-rls.sql
```

Expected: nine rows, all `PASS` ([what they prove](verify-rls.md)). You can
paste the same file into the dashboard's SQL editor.

Check:

```sh
psql "$AGG_DATABASE_URL" -v ON_ERROR_STOP=1 -At -F ' ' -f scripts/verify-rls.sql | grep -E ' (PASS|FAIL) ' | grep -c ' PASS ' | grep -qx 9 && echo PASS || echo FAIL
```

## 7. Confirm the Data API cannot read the tables

Every aggregator table must be unreachable for the Data API roles, whatever
API key is used:

```sh
psql "$AGG_DATABASE_URL" -Atc "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace CROSS JOIN (VALUES ('anon'), ('authenticated'), ('service_role')) r(role) WHERE n.nspname = 'public' AND c.relname LIKE 'aggregator\_%' AND c.relkind = 'r' AND has_table_privilege(r.role, c.oid, 'SELECT, INSERT, UPDATE, DELETE')"
```

Expected: `0`.

Check:

```sh
test "$(psql "$AGG_DATABASE_URL" -Atc "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace CROSS JOIN (VALUES ('anon'), ('authenticated'), ('service_role')) r(role) WHERE n.nspname = 'public' AND c.relname LIKE 'aggregator\_%' AND c.relkind = 'r' AND has_table_privilege(r.role, c.oid, 'SELECT, INSERT, UPDATE, DELETE')")" = 0 && echo PASS || echo FAIL
```

## 8. Create the owner and start the server

```sh
npx agg-owner init --name "Your name"
```

Store the printed credential in a password manager. Then run the server with
`AGG_DATABASE_URL`, `NODE_EXTRA_CA_CERTS`, `AGG_ENCRYPTION_KEY` (from
`npx agg-server keygen`), `AGG_PUBLIC_URL` and, behind a proxy,
`AGG_TRUST_PROXY=1`, as in [deploy on Postgres](deploy-postgres.md) steps 4 and 7-8.

Check (on the server host):

```sh
curl -fsS http://127.0.0.1:8787/healthz | grep -q '"ok":true' && echo PASS || echo FAIL
```

## 9. Backups

Supabase's own backups cover the tables. For an independent copy, run
`pg_dump` as in [storage](../storage.md#backups) with `$AGG_DATABASE_URL`
(the `postgres` role has `BYPASSRLS`, so the dump is complete), and keep
`AGG_ENCRYPTION_KEY` backed up separately.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `getaddrinfo ENOTFOUND` or timeouts on the direct host | The host has no IPv6 route | Use the session pooler string |
| `self-signed certificate in certificate chain` | `verify-full` without the project CA | Set `NODE_EXTRA_CA_CERTS` (step 2) |
| `password authentication failed` | Wrong password, or the pooler string's user is not `postgres.<project-ref>` | Copy the string again from **Connect** |
| doctor `public_roles_revoked` fails | Grants were added after migration | Revoke block in [storage](../storage.md#your-own-supabase-project), step 6 |
| Too many connections | The server pool (10) plus other clients exceed the plan's limit | Lower other clients' pools, or use the session pooler |
