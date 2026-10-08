import { statSync } from "node:fs";
import { resolve } from "node:path";
import { postgresSchemaProbeSql, type Row } from "@agent-aggregator/core";
import type { StorageConfig } from "./config.js";
import { REVOKED_ROLES, TABLE_PREFIX, postgresSchemaOptions, type Storage } from "./storage.js";

export interface DoctorCheck {
  name: string;
  pass: boolean;
  detail: string;
}

/**
 * Read-only storage checks for `agg-server doctor`. On Postgres they verify
 * what the security model depends on: the API role can bypass RLS (it needs
 * to for credential lookup and delivery) without being a superuser, the
 * schema is current, every table forces RLS, and the anon, authenticated
 * and service_role roles (Supabase) have no table privileges.
 */
export async function runDoctor(config: StorageConfig, storage: Storage): Promise<DoctorCheck[]> {
  const checks: DoctorCheck[] = [];
  if (config.kind === "sqlite") {
    if (config.path === ":memory:") {
      checks.push({ name: "sqlite_file", pass: true, detail: "in-memory database" });
    } else {
      const path = resolve(config.path);
      const mode = statSync(path).mode & 0o777;
      checks.push({ name: "sqlite_file_mode", pass: (mode & 0o077) === 0, detail: `${path} mode ${mode.toString(8).padStart(4, "0")} (want 0600: no group/other access)` });
    }
    const tables = await storage.driver.privileged((db) =>
      db.query(`SELECT count(*) AS n FROM sqlite_master WHERE type = 'table' AND name LIKE '${TABLE_PREFIX}%'`),
    );
    const n = Number(tables[0]?.n ?? 0);
    checks.push({ name: "schema_tables", pass: n >= 15, detail: `${n} tables with prefix ${TABLE_PREFIX}` });
    checks.push({ name: "isolation", pass: true, detail: "SQLite has no row-level security: single owner on one machine only" });
    return checks;
  }
  const sql = storage.sql!;
  const one = async (text: string, params: readonly unknown[] = []): Promise<Row> => ((await sql.unsafe(text, params)) as readonly Row[])[0] ?? {};
  const role = await one("SELECT current_user AS name, rolsuper, rolbypassrls, rolcreaterole FROM pg_roles WHERE rolname = current_user");
  checks.push({ name: "role_bypassrls", pass: role.rolbypassrls === true || role.rolsuper === true, detail: `role ${String(role.name)}: bypassrls=${String(role.rolbypassrls)} superuser=${String(role.rolsuper)}` });
  const membership = await one(
    `SELECT count(*) AS n,
            coalesce(bool_and(pg_has_role(current_user, rolname, CASE WHEN current_setting('server_version_num')::int >= 160000 THEN 'SET' ELSE 'MEMBER' END)), false) AS settable
     FROM pg_roles WHERE rolname IN ($1, $2)`,
    [`${TABLE_PREFIX}agent`, `${TABLE_PREFIX}owner`],
  );
  const settable = Number(membership.n) === 2 && membership.settable === true;
  checks.push({
    name: "role_can_switch",
    pass: settable,
    detail: settable
      ? `${String(role.name)} can SET ROLE to ${TABLE_PREFIX}agent and ${TABLE_PREFIX}owner (createrole=${String(role.rolcreaterole)}: needed only while migrate creates those roles)`
      : `${String(role.name)} cannot SET ROLE to both scoped roles; run agg-server migrate with CREATEROLE, or have their creator run GRANT ${TABLE_PREFIX}agent, ${TABLE_PREFIX}owner TO ${String(role.name)}`,
  });
  const probe = await one(postgresSchemaProbeSql(postgresSchemaOptions(config.schema)));
  checks.push({ name: "schema_current", pass: probe.current === true, detail: probe.current === true ? "schema version marker matches this build" : "run: agg-server migrate" });
  const rls = await one(
    `SELECT count(*) AS total, count(*) FILTER (WHERE c.relrowsecurity AND c.relforcerowsecurity) AS forced
     FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relkind = 'r' AND c.relname LIKE $2`,
    [config.schema, `${TABLE_PREFIX.replace(/_/g, "\\_")}%`],
  );
  const total = Number(rls.total ?? 0);
  const forced = Number(rls.forced ?? 0);
  checks.push({ name: "rls_forced", pass: total >= 15 && forced === total, detail: `${forced}/${total} tables have row-level security enabled and forced` });
  const roles = await one(
    `SELECT count(*) AS present, coalesce(bool_or(has_table_privilege(r.rolname, c.oid, 'SELECT,INSERT,UPDATE,DELETE')), false) AS any_privilege
     FROM pg_roles r CROSS JOIN pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE r.rolname = ANY($3::text[]) AND n.nspname = $1 AND c.relkind = 'r' AND c.relname LIKE $2`,
    [config.schema, `${TABLE_PREFIX.replace(/_/g, "\\_")}%`, [...REVOKED_ROLES]],
  );
  checks.push({
    name: "public_roles_revoked",
    pass: roles.any_privilege !== true,
    detail: Number(roles.present ?? 0) === 0 ? `none of ${REVOKED_ROLES.join(", ")} has tables here` : `${REVOKED_ROLES.join("/")} table privileges: ${roles.any_privilege === true ? "PRESENT" : "none"}`,
  });
  const agentRoles = await one(
    `SELECT count(*) AS n, coalesce(bool_and(NOT rolcanlogin AND NOT rolbypassrls AND NOT rolsuper), false) AS safe FROM pg_roles WHERE rolname IN ($1, $2)`,
    [`${TABLE_PREFIX}agent`, `${TABLE_PREFIX}owner`],
  );
  checks.push({ name: "scoped_roles", pass: Number(agentRoles.n) === 2 && agentRoles.safe === true, detail: `${TABLE_PREFIX}agent and ${TABLE_PREFIX}owner exist as NOLOGIN, NOBYPASSRLS roles: ${agentRoles.safe === true ? "yes" : "no"}` });
  return checks;
}
