-- verify-rls.sql: read-only isolation checks for the aggregator tables in schema "public".
--
--   psql "$AGG_DATABASE_URL" -f scripts/verify-rls.sql
--
-- Run it as the API role (or a superuser): the live probes switch to the
-- NOLOGIN scoped roles. Every result row must read PASS. Nothing is written;
-- each probe runs in a transaction that is rolled back.

-- 1-6: catalog checks.
WITH t AS (
  SELECT c.oid, c.relname, c.relrowsecurity, c.relforcerowsecurity
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname LIKE 'aggregator\_%'
),
connection_tables(name) AS (
  VALUES ('aggregator_connections'), ('aggregator_work_items'), ('aggregator_checkpoints'), ('aggregator_questions'), ('aggregator_jobs'),
         ('aggregator_events'), ('aggregator_destinations'), ('aggregator_deliveries'), ('aggregator_threads'), ('aggregator_messages'), ('aggregator_audit')
),
owner_tables(name) AS (
  SELECT name FROM connection_tables UNION ALL VALUES ('aggregator_credentials')
),
exposed(role) AS (
  SELECT 'public' UNION ALL SELECT rolname FROM pg_roles WHERE rolname IN ('anon', 'authenticated', 'service_role')
)
SELECT '1 rls_enabled_and_forced' AS check_name,
       CASE WHEN count(*) >= 15 AND bool_and(relrowsecurity AND relforcerowsecurity) THEN 'PASS' ELSE 'FAIL' END AS result,
       count(*) FILTER (WHERE relrowsecurity AND relforcerowsecurity) || ' of ' || count(*) || ' tables' AS detail
FROM t
UNION ALL
SELECT '2 scoped_roles_cannot_login_or_bypass',
       CASE WHEN count(*) = 2 AND bool_and(NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls) THEN 'PASS' ELSE 'FAIL' END,
       string_agg(rolname || ': login=' || rolcanlogin || ' superuser=' || rolsuper || ' bypassrls=' || rolbypassrls, '; ' ORDER BY rolname)
FROM pg_roles WHERE rolname IN ('aggregator_agent', 'aggregator_owner')
UNION ALL
SELECT '3 policies_present',
       CASE WHEN (SELECT count(*) FROM connection_tables ct WHERE EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname = 'public' AND p.tablename = ct.name AND 'aggregator_agent' = ANY (p.roles))) = 11
             AND (SELECT count(*) FROM owner_tables ot WHERE EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname = 'public' AND p.tablename = ot.name AND 'aggregator_owner' = ANY (p.roles))) = 12
            THEN 'PASS' ELSE 'FAIL' END,
       (SELECT count(*) FROM pg_policies WHERE schemaname = 'public' AND tablename LIKE 'aggregator\_%') || ' policies; agent on 11 connection tables, owner on 12'
UNION ALL
SELECT '4 no_privileges_for_public_anon_authenticated_service_role',
       CASE WHEN count(*) = 0 THEN 'PASS' ELSE 'FAIL' END,
       coalesce(string_agg(e.role || ' on ' || t.relname, ', '), 'none')
FROM exposed e CROSS JOIN t
WHERE has_table_privilege(e.role, t.oid, 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
UNION ALL
SELECT '5 column_boundaries',
       CASE WHEN NOT has_table_privilege('aggregator_agent', 'public.aggregator_credentials', 'SELECT')
             AND NOT has_column_privilege('aggregator_owner', 'public.aggregator_credentials', 'secret_hash', 'SELECT')
             AND NOT has_column_privilege('aggregator_agent', 'public.aggregator_destinations', 'signing_secret_enc', 'SELECT')
             AND NOT has_column_privilege('aggregator_agent', 'public.aggregator_destinations', 'auth_header_value_enc', 'SELECT')
             AND NOT has_column_privilege('aggregator_agent', 'public.aggregator_connections', 'scopes', 'UPDATE')
             AND NOT has_column_privilege('aggregator_agent', 'public.aggregator_connections', 'status', 'UPDATE')
             AND NOT has_table_privilege('aggregator_agent', 'public.aggregator_oauth_requests', 'SELECT')
             AND NOT has_table_privilege('aggregator_owner', 'public.aggregator_oauth_requests', 'SELECT')
             AND NOT has_column_privilege('aggregator_agent', 'public.aggregator_messages', 'body_enc', 'UPDATE')
             AND NOT has_column_privilege('aggregator_agent', 'public.aggregator_messages', 'direction', 'UPDATE')
            THEN 'PASS' ELSE 'FAIL' END,
       'agents: no credentials, no encrypted secrets, cannot change scopes or status or rewrite message text; nobody but the API role reads OAuth requests'
UNION ALL
SELECT '6 agent_guard_triggers_enabled',
       CASE WHEN count(*) = 3 AND bool_and(tg.tgenabled <> 'D') THEN 'PASS' ELSE 'FAIL' END,
       coalesce(string_agg(tg.tgname || ' on ' || c.relname, ', ' ORDER BY tg.tgname), 'missing')
FROM pg_trigger tg JOIN pg_class c ON c.oid = tg.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND tg.tgname IN ('aggregator_questions_agent_guard', 'aggregator_jobs_agent_guard', 'aggregator_messages_agent_guard');

-- 7: an agent principal that matches no connection sees nothing (every table the agent role may read;
-- it has no SELECT on audit, credentials or the OAuth tables at all).
BEGIN;
SELECT set_config('aggregator.owner_id', gen_random_uuid()::text, true) IS NOT NULL AND set_config('aggregator.connection_id', gen_random_uuid()::text, true) IS NOT NULL AS principal_set;
SET LOCAL ROLE aggregator_agent;
SELECT '7 unknown_agent_sees_no_rows' AS check_name, CASE WHEN n = 0 THEN 'PASS' ELSE 'FAIL' END AS result, n || ' rows visible' AS detail
FROM (SELECT (SELECT count(*) FROM aggregator_connections) + (SELECT count(*) FROM aggregator_work_items) + (SELECT count(*) FROM aggregator_checkpoints)
           + (SELECT count(*) FROM aggregator_questions) + (SELECT count(*) FROM aggregator_jobs) + (SELECT count(*) FROM aggregator_events)
           + (SELECT count(*) FROM aggregator_destinations) + (SELECT count(*) FROM aggregator_deliveries)
           + (SELECT count(*) FROM aggregator_threads) + (SELECT count(*) FROM aggregator_messages) AS n) AS probe;
ROLLBACK;

-- 8: no principal at all sees nothing, for either role.
BEGIN;
SET LOCAL ROLE aggregator_owner;
SELECT '8 no_principal_sees_no_rows' AS check_name, CASE WHEN n = 0 THEN 'PASS' ELSE 'FAIL' END AS result, n || ' rows visible as aggregator_owner' AS detail
FROM (SELECT (SELECT count(*) FROM aggregator_connections) + (SELECT count(*) FROM aggregator_questions) + (SELECT count(*) FROM aggregator_credentials) AS n) AS probe;
ROLLBACK;

-- 9: an owner sees exactly their own connections (positive control; PASS with zero owners too).
BEGIN;
SELECT set_config('aggregator.owner_id', coalesce((SELECT owner_id::text FROM aggregator_connections ORDER BY created_at, id LIMIT 1), gen_random_uuid()::text), true) IS NOT NULL AS principal_set;
CREATE TEMP TABLE aggregator_verify_expected ON COMMIT DROP AS
  SELECT count(*) AS own, (SELECT count(*) FROM aggregator_connections) AS total FROM aggregator_connections WHERE owner_id = current_setting('aggregator.owner_id')::uuid;
GRANT SELECT ON aggregator_verify_expected TO aggregator_owner;
SET LOCAL ROLE aggregator_owner;
SELECT '9 owner_sees_only_own_connections' AS check_name,
       CASE WHEN visible = e.own THEN 'PASS' ELSE 'FAIL' END AS result,
       visible || ' visible, ' || e.own || ' owned, ' || e.total || ' in total' AS detail
FROM (SELECT count(*) AS visible FROM aggregator_connections) AS probe CROSS JOIN aggregator_verify_expected e;
ROLLBACK;
