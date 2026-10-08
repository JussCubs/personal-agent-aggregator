import { createHash } from "node:crypto";
import { assertPrefix, quoteIdent } from "./db.js";

export interface PostgresSchemaOptions {
  /** Table name prefix, e.g. "aggregator_". */
  prefix?: string;
  /** Schema that holds the tables. Default "public". */
  schema?: string;
  /** NOLOGIN role used for agent-scoped transactions. */
  agentRole?: string;
  /** NOLOGIN role used for owner-scoped transactions. */
  ownerRole?: string;
  /** Prefix of the transaction-local settings that carry the principal, e.g. "aggregator" → aggregator.owner_id. */
  settingPrefix?: string;
  /** Optional foreign key target for owner_id, e.g. "users(id)". When omitted an owners table is created. */
  ownerReference?: string;
  /** Roles that must never read these tables (Supabase: anon, authenticated). Revoked when they exist. */
  revokeFrom?: readonly string[];
}

export interface ResolvedSchemaNames {
  prefix: string;
  schema: string;
  agentRole: string;
  ownerRole: string;
  settingPrefix: string;
  ownerReference: string;
}

export function resolveSchemaNames(opts: PostgresSchemaOptions = {}): ResolvedSchemaNames {
  const prefix = assertPrefix(opts.prefix ?? "aggregator_");
  const schema = opts.schema ?? "public";
  const agentRole = opts.agentRole ?? `${prefix}agent`;
  const ownerRole = opts.ownerRole ?? `${prefix}owner`;
  const settingPrefix = opts.settingPrefix ?? prefix.replace(/_$/, "");
  quoteIdent(schema);
  quoteIdent(agentRole);
  quoteIdent(ownerRole);
  if (!/^[a-z][a-z0-9_]{0,40}$/.test(settingPrefix)) throw new Error("settingPrefix must be a lowercase identifier");
  const ownerReference = opts.ownerReference ?? `${prefix}owners(id)`;
  if (!/^[a-z_][a-z0-9_]{0,62}\([a-z_][a-z0-9_]{0,62}\)$/.test(ownerReference)) throw new Error("ownerReference must look like table(column)");
  return { prefix, schema, agentRole, ownerRole, settingPrefix, ownerReference };
}

/** Child tables that carry (owner_id, connection_id) and are isolated per connection. */
export const CONNECTION_TABLES = ["work_items", "checkpoints", "questions", "jobs", "events", "destinations", "deliveries", "audit"] as const;

/**
 * Postgres DDL: tables, composite foreign keys that pin every child row to its
 * connection's owner, two NOLOGIN roles, transaction-local principal
 * settings, and FORCE'd row-level security with per-owner and per-connection
 * policies. Idempotent: safe to run on every boot.
 */
export function postgresSchemaSql(opts: PostgresSchemaOptions = {}): string {
  const n = resolveSchemaNames(opts);
  const s = quoteIdent(n.schema);
  const t = (name: string) => `${s}.${quoteIdent(`${n.prefix}${name}`)}`;
  const agent = quoteIdent(n.agentRole);
  const owner = quoteIdent(n.ownerRole);
  const ctxOwner = `${s}.${quoteIdent(`${n.prefix}ctx_owner`)}()`;
  const ctxConnection = `${s}.${quoteIdent(`${n.prefix}ctx_connection`)}()`;
  const ownerFk = n.ownerReference.replace(/^([a-z0-9_]+)\(/, (_m, table: string) => `${s}.${quoteIdent(table)}(`);
  const lit = (value: string) => `'${value.replace(/'/g, "''")}'`;
  const revokeFrom = opts.revokeFrom ?? ["anon", "authenticated"];

  // Managed Postgres (e.g. Supabase, PG16+): create the role under
  // createrole_self_grant=set so the creating role gets a SET-only membership.
  // An explicit GRANT ... TO current_user is not durable there, so on PG16+ a
  // missing membership is an error, never a grant. Superusers need no membership.
  const roleBlock = (role: string) => `DO $role$
DECLARE modern boolean := current_setting('server_version_num')::int >= 160000;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ${lit(role)}) THEN
    IF modern THEN
      PERFORM set_config('createrole_self_grant', 'set', true);
    END IF;
    EXECUTE format('CREATE ROLE %I NOLOGIN', ${lit(role)});
  END IF;
  IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
    IF modern THEN
      IF NOT EXISTS (
        SELECT 1 FROM pg_auth_members m
        WHERE m.roleid = (SELECT oid FROM pg_roles WHERE rolname = ${lit(role)})
          AND m.member = (SELECT oid FROM pg_roles WHERE rolname = current_user)
          AND m.set_option
      ) THEN
        RAISE EXCEPTION '% needs SET membership in %; recreate the role under createrole_self_grant=set', current_user, ${lit(role)};
      END IF;
    ELSIF NOT pg_has_role(current_user, ${lit(role)}, 'MEMBER') THEN
      EXECUTE format('GRANT %I TO %I', ${lit(role)}, current_user);
    END IF;
  END IF;
END
$role$;`;

  const ownersTable = opts.ownerReference
    ? ""
    : `CREATE TABLE IF NOT EXISTS ${t("owners")} (
  id uuid PRIMARY KEY,
  name text,
  secret_hash text UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE ${t("owners")} ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${t("owners")} FORCE ROW LEVEL SECURITY;
`;

  const child = (name: string) => `CONSTRAINT ${quoteIdent(`${n.prefix}${name}_connection_fk`)} FOREIGN KEY (connection_id, owner_id) REFERENCES ${t("connections")}(id, owner_id) ON DELETE CASCADE`;

  const policies = (name: string, agentCheck: string, grantsAgent: string | null, grantsOwner: string | null) => {
    const table = t(name);
    const lines = [
      `ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY;`,
      `ALTER TABLE ${table} FORCE ROW LEVEL SECURITY;`,
      `DROP POLICY IF EXISTS ${quoteIdent(`${n.prefix}${name}_agent`)} ON ${table};`,
      `DROP POLICY IF EXISTS ${quoteIdent(`${n.prefix}${name}_owner`)} ON ${table};`,
      `REVOKE ALL ON ${table} FROM PUBLIC;`,
      `REVOKE ALL ON ${table} FROM ${agent}, ${owner};`,
    ];
    if (grantsAgent) {
      lines.push(`CREATE POLICY ${quoteIdent(`${n.prefix}${name}_agent`)} ON ${table} FOR ALL TO ${agent} USING (${agentCheck}) WITH CHECK (${agentCheck});`);
      lines.push(`GRANT ${grantsAgent} ON ${table} TO ${agent};`);
    }
    if (grantsOwner) {
      lines.push(`CREATE POLICY ${quoteIdent(`${n.prefix}${name}_owner`)} ON ${table} FOR ALL TO ${owner} USING (owner_id = ${ctxOwner}) WITH CHECK (owner_id = ${ctxOwner});`);
      lines.push(`GRANT ${grantsOwner} ON ${table} TO ${owner};`);
    }
    return lines.join("\n");
  };
  const scopedToConnection = `owner_id = ${ctxOwner} AND connection_id = ${ctxConnection}`;

  const revokeBlock = revokeFrom.length
    ? `DO $revoke$
DECLARE r text; tbl text;
BEGIN
  FOREACH r IN ARRAY ARRAY[${revokeFrom.map(lit).join(", ")}]::text[] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      FOR tbl IN SELECT c.relname FROM pg_class c JOIN pg_namespace ns ON ns.oid = c.relnamespace
        WHERE ns.nspname = ${lit(n.schema)} AND c.relkind = 'r' AND c.relname LIKE ${lit(`${n.prefix.replace(/_/g, "\\_")}%`)} LOOP
        EXECUTE format('REVOKE ALL ON %I.%I FROM %I', ${lit(n.schema)}, tbl, r);
      END LOOP;
    END IF;
  END LOOP;
END
$revoke$;`
    : "";

  const usageBlock = `DO $usage$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY[${lit(n.agentRole)}, ${lit(n.ownerRole)}]::text[] LOOP
    IF NOT has_schema_privilege(r, ${lit(n.schema)}, 'USAGE') THEN
      EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', ${lit(n.schema)}, r);
    END IF;
  END LOOP;
END
$usage$;`;

  const body = `${roleBlock(n.agentRole)}
${roleBlock(n.ownerRole)}
${usageBlock}

CREATE OR REPLACE FUNCTION ${ctxOwner.replace(/\(\)$/, "")}() RETURNS uuid LANGUAGE sql STABLE
  AS $fn$ SELECT nullif(current_setting(${lit(`${n.settingPrefix}.owner_id`)}, true), '')::uuid $fn$;
CREATE OR REPLACE FUNCTION ${ctxConnection.replace(/\(\)$/, "")}() RETURNS uuid LANGUAGE sql STABLE
  AS $fn$ SELECT nullif(current_setting(${lit(`${n.settingPrefix}.connection_id`)}, true), '')::uuid $fn$;
GRANT EXECUTE ON FUNCTION ${ctxOwner.replace(/\(\)$/, "")}() TO ${agent}, ${owner};
GRANT EXECUTE ON FUNCTION ${ctxConnection.replace(/\(\)$/, "")}() TO ${agent}, ${owner};

${ownersTable}
CREATE TABLE IF NOT EXISTS ${t("connections")} (
  id uuid PRIMARY KEY,
  owner_id uuid NOT NULL REFERENCES ${ownerFk} ON DELETE CASCADE,
  provider text NOT NULL CHECK (provider ~ '^[a-z][a-z0-9_]{1,39}$'),
  display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 80),
  mode text NOT NULL CHECK (mode IN ('mcp_webhook','oauth_events','cli_poll')),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','revoked')),
  scopes text NOT NULL DEFAULT '',
  event_seq bigint NOT NULL DEFAULT 0,
  settings jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  last_seen_at timestamptz,
  revoked_at timestamptz,
  UNIQUE (id, owner_id)
);
CREATE INDEX IF NOT EXISTS ${quoteIdent(`${n.prefix}connections_owner`)} ON ${t("connections")} (owner_id, created_at DESC);

CREATE TABLE IF NOT EXISTS ${t("credentials")} (
  id uuid PRIMARY KEY,
  owner_id uuid NOT NULL,
  connection_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('agent','oauth_access','oauth_refresh','claim')),
  secret_hash text NOT NULL UNIQUE,
  hint text NOT NULL,
  scopes text NOT NULL DEFAULT '',
  resource text,
  client_id text,
  family_id uuid,
  expires_at timestamptz,
  used_at timestamptz,
  last_used_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL,
  ${child("credentials")}
);
CREATE INDEX IF NOT EXISTS ${quoteIdent(`${n.prefix}credentials_connection`)} ON ${t("credentials")} (connection_id, kind);

CREATE TABLE IF NOT EXISTS ${t("work_items")} (
  owner_id uuid NOT NULL,
  connection_id uuid NOT NULL,
  id text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('task','goal','project','state')),
  title text NOT NULL,
  status text,
  summary text,
  blocker text,
  next_step text,
  due_at timestamptz,
  parent_id text,
  data jsonb,
  revision integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (connection_id, id),
  ${child("work_items")}
);
CREATE INDEX IF NOT EXISTS ${quoteIdent(`${n.prefix}work_items_owner`)} ON ${t("work_items")} (owner_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS ${t("checkpoints")} (
  owner_id uuid NOT NULL,
  connection_id uuid NOT NULL,
  id text NOT NULL,
  work_item_id text,
  summary text NOT NULL,
  status text,
  data jsonb,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (connection_id, id),
  ${child("checkpoints")}
);
CREATE INDEX IF NOT EXISTS ${quoteIdent(`${n.prefix}checkpoints_owner`)} ON ${t("checkpoints")} (owner_id, created_at DESC);

CREATE TABLE IF NOT EXISTS ${t("questions")} (
  key uuid NOT NULL UNIQUE,
  owner_id uuid NOT NULL,
  connection_id uuid NOT NULL,
  id text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('question','approval')),
  prompt text NOT NULL,
  details text,
  options jsonb NOT NULL DEFAULT '[]'::jsonb,
  allow_free_text boolean NOT NULL DEFAULT true,
  work_item_id text,
  affected_action text,
  action_digest text,
  urgency text NOT NULL DEFAULT 'normal' CHECK (urgency IN ('low','normal','high')),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','answered','cancelled','expired')),
  status_reason text,
  revision integer NOT NULL DEFAULT 1,
  expires_at timestamptz,
  answer jsonb,
  answered_at timestamptz,
  acknowledged_at timestamptz,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (connection_id, id),
  ${child("questions")}
);
CREATE INDEX IF NOT EXISTS ${quoteIdent(`${n.prefix}questions_owner_status`)} ON ${t("questions")} (owner_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS ${quoteIdent(`${n.prefix}questions_expiry`)} ON ${t("questions")} (expires_at) WHERE status = 'pending' AND expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS ${t("jobs")} (
  key uuid NOT NULL UNIQUE,
  owner_id uuid NOT NULL,
  connection_id uuid NOT NULL,
  id text NOT NULL,
  idempotency_key text,
  goal text NOT NULL,
  context text,
  success_criteria text,
  work_item_id text,
  status text NOT NULL CHECK (status IN ('needs_user','running','blocked','done','declined','cancelled','failed')),
  status_reason text,
  summary text,
  result jsonb,
  revision integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  completed_at timestamptz,
  PRIMARY KEY (connection_id, id),
  UNIQUE (connection_id, idempotency_key),
  ${child("jobs")}
);
CREATE INDEX IF NOT EXISTS ${quoteIdent(`${n.prefix}jobs_owner_status`)} ON ${t("jobs")} (owner_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS ${t("events")} (
  owner_id uuid NOT NULL,
  connection_id uuid NOT NULL,
  seq bigint NOT NULL,
  id text NOT NULL UNIQUE,
  name text NOT NULL,
  data jsonb NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (connection_id, seq),
  ${child("events")}
);
CREATE INDEX IF NOT EXISTS ${quoteIdent(`${n.prefix}events_created`)} ON ${t("events")} (created_at);

CREATE TABLE IF NOT EXISTS ${t("destinations")} (
  id uuid PRIMARY KEY,
  owner_id uuid NOT NULL,
  connection_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('webhook','mcp_event')),
  external_id text NOT NULL,
  event_name text,
  filter jsonb,
  url text NOT NULL,
  auth_header_name text,
  auth_header_value_enc text,
  signing_secret_enc text NOT NULL,
  expires_at timestamptz,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  UNIQUE (connection_id, external_id),
  UNIQUE (id, connection_id),
  ${child("destinations")}
);

CREATE TABLE IF NOT EXISTS ${t("deliveries")} (
  id uuid PRIMARY KEY,
  owner_id uuid NOT NULL,
  connection_id uuid NOT NULL,
  destination_id uuid NOT NULL,
  event_seq bigint NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','delivered','failed')),
  attempts integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL,
  last_status integer,
  last_error text,
  delivered_at timestamptz,
  created_at timestamptz NOT NULL,
  UNIQUE (destination_id, event_seq),
  -- A delivery can only target a destination of its own connection.
  CONSTRAINT ${quoteIdent(`${n.prefix}deliveries_destination_fk`)} FOREIGN KEY (destination_id, connection_id) REFERENCES ${t("destinations")}(id, connection_id) ON DELETE CASCADE,
  ${child("deliveries")}
);
CREATE INDEX IF NOT EXISTS ${quoteIdent(`${n.prefix}deliveries_due`)} ON ${t("deliveries")} (next_attempt_at) WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS ${t("audit")} (
  id uuid PRIMARY KEY,
  owner_id uuid NOT NULL,
  connection_id uuid,
  actor text NOT NULL CHECK (actor IN ('agent','owner','system')),
  action text NOT NULL,
  target_type text,
  target_id text,
  detail jsonb,
  created_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS ${quoteIdent(`${n.prefix}audit_owner`)} ON ${t("audit")} (owner_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ${quoteIdent(`${n.prefix}audit_connection`)} ON ${t("audit")} (connection_id, created_at DESC);

CREATE TABLE IF NOT EXISTS ${t("oauth_clients")} (
  id text PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('dcr','cimd')),
  client_name text,
  redirect_uris jsonb NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL,
  refreshed_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS ${t("oauth_requests")} (
  id uuid PRIMARY KEY,
  client_id text NOT NULL,
  client_name text,
  redirect_uri text NOT NULL,
  state text,
  code_challenge text NOT NULL,
  scopes text NOT NULL,
  resource text NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','denied','exchanged','expired')),
  owner_id uuid,
  connection_id uuid,
  code_hash text UNIQUE,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  code_expires_at timestamptz
);

-- Connections: an agent sees only its own active connection row and may only
-- advance its event sequence and last-seen time.
ALTER TABLE ${t("connections")} ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${t("connections")} FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ${quoteIdent(`${n.prefix}connections_agent`)} ON ${t("connections")};
DROP POLICY IF EXISTS ${quoteIdent(`${n.prefix}connections_owner`)} ON ${t("connections")};
REVOKE ALL ON ${t("connections")} FROM PUBLIC;
REVOKE ALL ON ${t("connections")} FROM ${agent}, ${owner};
CREATE POLICY ${quoteIdent(`${n.prefix}connections_agent`)} ON ${t("connections")} FOR ALL TO ${agent}
  USING (id = ${ctxConnection} AND owner_id = ${ctxOwner} AND status = 'active')
  WITH CHECK (id = ${ctxConnection} AND owner_id = ${ctxOwner} AND status = 'active');
GRANT SELECT (id, owner_id, provider, display_name, mode, status, scopes, event_seq, settings, created_at, updated_at, last_seen_at, revoked_at) ON ${t("connections")} TO ${agent};
GRANT UPDATE (event_seq, last_seen_at, updated_at) ON ${t("connections")} TO ${agent};
CREATE POLICY ${quoteIdent(`${n.prefix}connections_owner`)} ON ${t("connections")} FOR ALL TO ${owner}
  USING (owner_id = ${ctxOwner}) WITH CHECK (owner_id = ${ctxOwner});
GRANT SELECT, INSERT, UPDATE, DELETE ON ${t("connections")} TO ${owner};

-- Credentials: agents never read credential rows; owners see metadata, never digests.
ALTER TABLE ${t("credentials")} ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${t("credentials")} FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ${quoteIdent(`${n.prefix}credentials_owner`)} ON ${t("credentials")};
REVOKE ALL ON ${t("credentials")} FROM PUBLIC;
REVOKE ALL ON ${t("credentials")} FROM ${agent}, ${owner};
CREATE POLICY ${quoteIdent(`${n.prefix}credentials_owner`)} ON ${t("credentials")} FOR ALL TO ${owner}
  USING (owner_id = ${ctxOwner}) WITH CHECK (owner_id = ${ctxOwner});
GRANT SELECT (id, owner_id, connection_id, kind, hint, scopes, resource, client_id, expires_at, used_at, last_used_at, revoked_at, created_at) ON ${t("credentials")} TO ${owner};
GRANT INSERT, DELETE ON ${t("credentials")} TO ${owner};
GRANT UPDATE (revoked_at) ON ${t("credentials")} TO ${owner};

${policies("work_items", scopedToConnection, "SELECT, INSERT, UPDATE, DELETE", "SELECT, UPDATE, DELETE")}
${policies("checkpoints", scopedToConnection, "SELECT, INSERT", "SELECT, DELETE")}
${policies("questions", scopedToConnection, "SELECT, INSERT, UPDATE (kind, prompt, details, options, allow_free_text, work_item_id, affected_action, action_digest, urgency, expires_at, revision, updated_at, status, status_reason, acknowledged_at, answer)", "SELECT, UPDATE, DELETE")}
${policies("jobs", scopedToConnection, "SELECT, INSERT, UPDATE (status, status_reason, revision, updated_at, completed_at)", "SELECT, UPDATE, DELETE")}

-- Agents may revise or withdraw their own pending question and acknowledge an
-- answer, and may cancel their own open job. Answering, approving and every
-- other transition belong to the owner; these triggers enforce that even if a
-- future query forgets to.
CREATE OR REPLACE FUNCTION ${s}.${quoteIdent(`${n.prefix}guard_agent_question`)}() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
  IF current_user = ${lit(n.agentRole)} THEN
    IF OLD.status = 'pending' THEN
      IF NEW.status NOT IN ('pending', 'cancelled')
        OR (NEW.status = 'cancelled' AND NEW.status_reason IS DISTINCT FROM 'cancelled_by_agent')
        OR NEW.answer IS NOT NULL OR NEW.acknowledged_at IS NOT NULL THEN
        RAISE EXCEPTION 'agents may only revise or withdraw a pending question' USING ERRCODE = '42501';
      END IF;
    ELSIF (to_jsonb(NEW) - 'acknowledged_at' - 'updated_at' - 'answer') IS DISTINCT FROM (to_jsonb(OLD) - 'acknowledged_at' - 'updated_at' - 'answer')
      OR (NEW.answer - 'acknowledged_at') IS DISTINCT FROM (OLD.answer - 'acknowledged_at') THEN
      RAISE EXCEPTION 'agents may only acknowledge a closed question' USING ERRCODE = '42501';
    END IF;
  END IF;
  RETURN NEW;
END
$fn$;
DROP TRIGGER IF EXISTS ${quoteIdent(`${n.prefix}questions_agent_guard`)} ON ${t("questions")};
CREATE TRIGGER ${quoteIdent(`${n.prefix}questions_agent_guard`)} BEFORE UPDATE ON ${t("questions")} FOR EACH ROW EXECUTE FUNCTION ${s}.${quoteIdent(`${n.prefix}guard_agent_question`)}();
CREATE OR REPLACE FUNCTION ${s}.${quoteIdent(`${n.prefix}guard_agent_job`)}() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
  IF current_user = ${lit(n.agentRole)} THEN
    IF OLD.status NOT IN ('needs_user', 'running', 'blocked') OR NEW.status <> 'cancelled' OR NEW.status_reason IS DISTINCT FROM 'cancelled_by_agent' THEN
      RAISE EXCEPTION 'agents may only cancel their own open job' USING ERRCODE = '42501';
    END IF;
  END IF;
  RETURN NEW;
END
$fn$;
DROP TRIGGER IF EXISTS ${quoteIdent(`${n.prefix}jobs_agent_guard`)} ON ${t("jobs")};
CREATE TRIGGER ${quoteIdent(`${n.prefix}jobs_agent_guard`)} BEFORE UPDATE ON ${t("jobs")} FOR EACH ROW EXECUTE FUNCTION ${s}.${quoteIdent(`${n.prefix}guard_agent_job`)}();
${policies("events", scopedToConnection, "SELECT, INSERT", "SELECT, INSERT, DELETE")}
${policies("destinations", scopedToConnection, "SELECT (id, owner_id, connection_id, kind, external_id, event_name, filter, url, auth_header_name, expires_at, created_at, updated_at), INSERT, UPDATE, DELETE", "SELECT (id, owner_id, connection_id, kind, external_id, event_name, filter, url, auth_header_name, expires_at, created_at, updated_at), INSERT, UPDATE, DELETE")}
${policies("deliveries", scopedToConnection, "SELECT, INSERT", "SELECT, INSERT, DELETE")}
${policies("audit", scopedToConnection, "INSERT", "SELECT, INSERT, DELETE")}

-- OAuth client registrations and authorization requests are service-only.
ALTER TABLE ${t("oauth_clients")} ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${t("oauth_clients")} FORCE ROW LEVEL SECURITY;
REVOKE ALL ON ${t("oauth_clients")} FROM PUBLIC;
ALTER TABLE ${t("oauth_requests")} ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${t("oauth_requests")} FORCE ROW LEVEL SECURITY;
REVOKE ALL ON ${t("oauth_requests")} FROM PUBLIC;
${revokeBlock}
`;
  const version = createHash("sha256").update(body).digest("hex").slice(0, 16);
  return `${body}COMMENT ON TABLE ${t("connections")} IS ${lit(`${SCHEMA_MARKER}${version}`)};
`;
}

export const SCHEMA_MARKER = "agent-aggregator-schema:";

/** The version marker the schema writes; compare with `obj_description` to skip unchanged DDL on boot. */
export function postgresSchemaVersion(opts: PostgresSchemaOptions = {}): string {
  const sql = postgresSchemaSql(opts);
  const match = new RegExp(`${SCHEMA_MARKER}([0-9a-f]{16})`).exec(sql);
  return match![1]!;
}

/** SQL that returns one row {current: boolean} telling whether the deployed schema matches these options. */
export function postgresSchemaProbeSql(opts: PostgresSchemaOptions = {}): string {
  const n = resolveSchemaNames(opts);
  const regclass = `${n.schema}.${n.prefix}connections`.replace(/'/g, "''");
  return `SELECT coalesce(obj_description(to_regclass('${regclass}'), 'pg_class'), '') = '${SCHEMA_MARKER}${postgresSchemaVersion(opts)}' AS current`;
}

/** SQLite DDL for single-owner local use. SQLite has no row-level security; the service always filters by owner and connection. */
export function sqliteSchemaSql(prefixInput = "aggregator_"): string {
  const p = assertPrefix(prefixInput);
  return `PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS ${p}owners (id TEXT PRIMARY KEY, name TEXT, secret_hash TEXT UNIQUE, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
CREATE TABLE IF NOT EXISTS ${p}connections (
  id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES ${p}owners(id) ON DELETE CASCADE,
  provider TEXT NOT NULL, display_name TEXT NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('mcp_webhook','oauth_events','cli_poll')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','revoked')),
  scopes TEXT NOT NULL DEFAULT '', event_seq INTEGER NOT NULL DEFAULT 0, settings TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_seen_at TEXT, revoked_at TEXT, UNIQUE (id, owner_id));
CREATE TABLE IF NOT EXISTS ${p}credentials (
  id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, connection_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('agent','oauth_access','oauth_refresh','claim')),
  secret_hash TEXT NOT NULL UNIQUE, hint TEXT NOT NULL, scopes TEXT NOT NULL DEFAULT '', resource TEXT, client_id TEXT, family_id TEXT,
  expires_at TEXT, used_at TEXT, last_used_at TEXT, revoked_at TEXT, created_at TEXT NOT NULL,
  FOREIGN KEY (connection_id, owner_id) REFERENCES ${p}connections(id, owner_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS ${p}work_items (
  owner_id TEXT NOT NULL, connection_id TEXT NOT NULL, id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('task','goal','project','state')), title TEXT NOT NULL, status TEXT, summary TEXT, blocker TEXT,
  next_step TEXT, due_at TEXT, parent_id TEXT, data TEXT, revision INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  PRIMARY KEY (connection_id, id), FOREIGN KEY (connection_id, owner_id) REFERENCES ${p}connections(id, owner_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS ${p}checkpoints (
  owner_id TEXT NOT NULL, connection_id TEXT NOT NULL, id TEXT NOT NULL, work_item_id TEXT, summary TEXT NOT NULL, status TEXT, data TEXT, created_at TEXT NOT NULL,
  PRIMARY KEY (connection_id, id), FOREIGN KEY (connection_id, owner_id) REFERENCES ${p}connections(id, owner_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS ${p}questions (
  key TEXT NOT NULL UNIQUE, owner_id TEXT NOT NULL, connection_id TEXT NOT NULL, id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('question','approval')), prompt TEXT NOT NULL, details TEXT, options TEXT NOT NULL DEFAULT '[]',
  allow_free_text INTEGER NOT NULL DEFAULT 1, work_item_id TEXT, affected_action TEXT, action_digest TEXT,
  urgency TEXT NOT NULL DEFAULT 'normal' CHECK (urgency IN ('low','normal','high')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','answered','cancelled','expired')), status_reason TEXT,
  revision INTEGER NOT NULL DEFAULT 1, expires_at TEXT, answer TEXT, answered_at TEXT, acknowledged_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  PRIMARY KEY (connection_id, id), FOREIGN KEY (connection_id, owner_id) REFERENCES ${p}connections(id, owner_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS ${p}jobs (
  key TEXT NOT NULL UNIQUE, owner_id TEXT NOT NULL, connection_id TEXT NOT NULL, id TEXT NOT NULL, idempotency_key TEXT,
  goal TEXT NOT NULL, context TEXT, success_criteria TEXT, work_item_id TEXT,
  status TEXT NOT NULL CHECK (status IN ('needs_user','running','blocked','done','declined','cancelled','failed')), status_reason TEXT,
  summary TEXT, result TEXT, revision INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, completed_at TEXT,
  PRIMARY KEY (connection_id, id), UNIQUE (connection_id, idempotency_key),
  FOREIGN KEY (connection_id, owner_id) REFERENCES ${p}connections(id, owner_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS ${p}events (
  owner_id TEXT NOT NULL, connection_id TEXT NOT NULL, seq INTEGER NOT NULL, id TEXT NOT NULL UNIQUE, name TEXT NOT NULL, data TEXT NOT NULL, created_at TEXT NOT NULL,
  PRIMARY KEY (connection_id, seq), FOREIGN KEY (connection_id, owner_id) REFERENCES ${p}connections(id, owner_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS ${p}destinations (
  id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, connection_id TEXT NOT NULL, kind TEXT NOT NULL CHECK (kind IN ('webhook','mcp_event')),
  external_id TEXT NOT NULL, event_name TEXT, filter TEXT, url TEXT NOT NULL, auth_header_name TEXT, auth_header_value_enc TEXT,
  signing_secret_enc TEXT NOT NULL, expires_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE (connection_id, external_id), UNIQUE (id, connection_id),
  FOREIGN KEY (connection_id, owner_id) REFERENCES ${p}connections(id, owner_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS ${p}deliveries (
  id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, connection_id TEXT NOT NULL,
  destination_id TEXT NOT NULL, event_seq INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','delivered','failed')), attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT NOT NULL, last_status INTEGER, last_error TEXT, delivered_at TEXT, created_at TEXT NOT NULL, UNIQUE (destination_id, event_seq),
  FOREIGN KEY (destination_id, connection_id) REFERENCES ${p}destinations(id, connection_id) ON DELETE CASCADE,
  FOREIGN KEY (connection_id, owner_id) REFERENCES ${p}connections(id, owner_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS ${p}audit (
  id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, connection_id TEXT, actor TEXT NOT NULL, action TEXT NOT NULL,
  target_type TEXT, target_id TEXT, detail TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ${p}oauth_clients (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, client_name TEXT, redirect_uris TEXT NOT NULL, metadata TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, refreshed_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ${p}oauth_requests (
  id TEXT PRIMARY KEY, client_id TEXT NOT NULL, client_name TEXT, redirect_uri TEXT NOT NULL, state TEXT, code_challenge TEXT NOT NULL,
  scopes TEXT NOT NULL, resource TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', owner_id TEXT, connection_id TEXT, code_hash TEXT UNIQUE,
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL, code_expires_at TEXT);
CREATE INDEX IF NOT EXISTS ${p}deliveries_due ON ${p}deliveries (status, next_attempt_at);
CREATE INDEX IF NOT EXISTS ${p}questions_owner_status ON ${p}questions (owner_id, status, created_at);
`;
}
