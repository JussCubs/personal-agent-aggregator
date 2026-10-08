# Playbook: verify row-level security

**Goal:** prove, on the database you deploy to, that owners and connections
are isolated by the database itself, and that no Data API role can read the
aggregator tables.

**When:** after the first migration, after every upgrade, after restoring a
backup, and whenever the database's roles or grants were changed by hand.

**You need:** `psql` and a connection string for the API role
(`AGG_DATABASE_URL`) or a superuser. For a schema other than `public`, run the
statements with `search_path` set to it and replace `public` in the script.

**Conventions:** run each command, compare with *Expected*, run *Check*
(prints `PASS` or `FAIL`), stop at the first `FAIL`.

## 1. Server-side doctor

```sh
npx agg-server doctor
```

Expected: `{"ok":true,"storage":"postgres","checks":[...]}` with
`role_bypassrls`, `role_can_switch`, `schema_current`, `rls_forced`,
`public_roles_revoked` and `scoped_roles`, each `"pass":true`.

Check:

```sh
npx agg-server doctor >/dev/null && echo PASS || echo FAIL
```

## 2. SQL checks

`scripts/verify-rls.sql` is read-only: its probes run in transactions that
are rolled back.

```sh
psql "$AGG_DATABASE_URL" -v ON_ERROR_STOP=1 -f scripts/verify-rls.sql
```

Expected: four result sets, all rows `PASS` (details depend on your data).
psql prints `BEGIN`, `SET`, `ROLLBACK` and one-row `principal_set` results
between them; the check rows are:

```text
 check_name                                                 | result | detail
------------------------------------------------------------+--------+---------------------------------------------
 1 rls_enabled_and_forced                                   | PASS   | 15 of 15 tables
 2 scoped_roles_cannot_login_or_bypass                      | PASS   | aggregator_agent: login=false superuser=false bypassrls=false; aggregator_owner: ...
 3 policies_present                                         | PASS   | 23 policies; agent on 11 connection tables, owner on 12
 4 no_privileges_for_public_anon_authenticated_service_role | PASS   | none
 5 column_boundaries                                        | PASS   | agents: no credentials, no encrypted secrets, cannot change scopes or status or rewrite message text; ...
 6 agent_guard_triggers_enabled                             | PASS   | aggregator_jobs_agent_guard on aggregator_jobs, aggregator_messages_agent_guard on ...
 7 unknown_agent_sees_no_rows | PASS   | 0 rows visible
 8 no_principal_sees_no_rows | PASS   | 0 rows visible as aggregator_owner
 9 owner_sees_only_own_connections | PASS   | 1 visible, 1 owned, 2 in total
```

What each check proves:

| Check | Proves |
| --- | --- |
| 1 | Every aggregator table has RLS enabled and forced (forced applies it to the table owner too) |
| 2 | The scoped roles cannot log in, are not superusers and cannot bypass RLS |
| 3 | Agent policies exist on the 11 connection-scoped tables (including `threads` and `messages`) and owner policies on those plus `credentials` |
| 4 | `PUBLIC`, `anon`, `authenticated` and `service_role` hold no privilege on any aggregator table |
| 5 | Agents cannot read credentials or encrypted secrets, change their scopes or status, or rewrite a message's text or direction; only the API role reads OAuth requests |
| 6 | The triggers that stop the agent role from answering, approving or posting as the owner are present and enabled |
| 7 | An agent principal that matches no connection sees zero rows |
| 8 | With no principal set, the owner role sees zero rows |
| 9 | An owner principal sees exactly that owner's connections, not the others (positive control) |

Check:

```sh
psql "$AGG_DATABASE_URL" -v ON_ERROR_STOP=1 -At -F ' ' -f scripts/verify-rls.sql | grep -E ' (PASS|FAIL) ' | grep -c ' PASS ' | grep -qx 9 && echo PASS || echo FAIL
```

## 3. Optional: the full cross-tenant test suite

On a disposable database (it creates and drops schemas and roles), run the
repository's Postgres tests:

```sh
export AGG_TEST_DATABASE_URL='postgres://postgres:<password>@127.0.0.1:5432/postgres'
npm run test:postgres
```

Expected: every test passes, including the line
`# [rls] <n> cross-tenant and privilege checks passed`. The suite connects
as a non-superuser `BYPASSRLS CREATEROLE` role with Supabase-style default
grants and tries cross-owner and cross-connection reads, writes and deletes,
privilege escalation and owner-only transitions directly in SQL.

Check:

```sh
npm run test:postgres 2>&1 | grep -q '\[rls\] [0-9]* cross-tenant and privilege checks passed' && echo PASS || echo FAIL
```

Never point `AGG_TEST_DATABASE_URL` at a production database.

## If a check fails

| Failing check | Likely cause | Fix |
| --- | --- | --- |
| 1, 3, 6 | Schema older than this build, or edited by hand | `npx agg-server migrate` (with a changed schema it reapplies policies, grants and triggers), then re-run |
| 2 | Someone altered the roles | `ALTER ROLE aggregator_agent NOLOGIN NOBYPASSRLS; ALTER ROLE aggregator_owner NOLOGIN NOBYPASSRLS;` as a superuser |
| 4 | Grants added after migration (restore from elsewhere, default privileges, a `GRANT ... TO PUBLIC`) | The revoke block in [storage](../storage.md#your-own-supabase-project), step 6, covers `anon`, `authenticated` and `service_role`; for `PUBLIC` clear the version marker and migrate (as for check 5), which re-runs `REVOKE ALL ... FROM PUBLIC` |
| 5 | Column grants changed by hand | `npx agg-server migrate` after dropping the version marker: `COMMENT ON TABLE aggregator_connections IS NULL;` |
| 7, 8, 9 | A policy was changed or dropped | Same as 5; then investigate who changed it |

Migration is skipped while the version marker matches, so after a manual
change to policies or grants clear the marker as shown for check 5 before
running `migrate` again.
