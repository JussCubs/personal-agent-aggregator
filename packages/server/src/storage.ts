import { closeSync, existsSync, mkdirSync, openSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { quoteIdent, type PostgresSchemaOptions, type Row, type SqlDriver } from "@agent-aggregator/core";
import { createPostgresDriver, type PostgresLike } from "@agent-aggregator/core/postgres";
import { createSqliteDriver } from "@agent-aggregator/core/sqlite";
import type { StorageConfig } from "./config.js";

/** Table prefix used by the reference server (the core default). */
export const TABLE_PREFIX = "aggregator_";

/**
 * Roles that must hold no privileges on the aggregator tables. On Supabase,
 * anon and authenticated back the Data API, and service_role bypasses RLS
 * there; revoking all three keeps the tables reachable only through this
 * server. Roles that do not exist are skipped.
 */
export const REVOKED_ROLES = ["anon", "authenticated", "service_role"] as const;

/** The exact schema options the server uses (migrate, probe and doctor must agree, or the version marker differs). */
export function postgresSchemaOptions(schema: string): PostgresSchemaOptions {
  return { schema, revokeFrom: REVOKED_ROLES };
}

export interface Storage {
  readonly kind: StorageConfig["kind"];
  readonly driver: SqlDriver;
  /** Raw postgres.js client (Postgres only), used by `agg-server doctor`. */
  readonly sql: (PostgresLike & { end(opts?: { timeout?: number }): Promise<void> }) | null;
  migrate(): Promise<void>;
  close(): Promise<void>;
}

interface PostgresModule {
  default: (url: string, options: Record<string, unknown>) => PostgresLike & { end(opts?: { timeout?: number }): Promise<void> };
}

export async function openStorage(config: StorageConfig): Promise<Storage> {
  if (config.kind === "postgres") {
    const moduleName = "postgres";
    const postgres = ((await import(moduleName)) as PostgresModule).default;
    const sql = postgres(config.url, {
      max: 10,
      onnotice: () => {},
      connection: { application_name: "agent-aggregator", search_path: config.schema },
    });
    const driver = createPostgresDriver(sql, postgresSchemaOptions(config.schema));
    return {
      kind: "postgres",
      driver,
      sql,
      async migrate() {
        if (config.schema !== "public") {
          // CREATE SCHEMA IF NOT EXISTS still needs CREATE on the database, so only issue it when the schema is missing.
          const existing = await sql.unsafe("SELECT 1 FROM pg_namespace WHERE nspname = $1", [config.schema]);
          if (existing.length === 0) await sql.unsafe(`CREATE SCHEMA ${quoteIdent(config.schema)}`);
        }
        await driver.migrate!();
      },
      async close() {
        await sql.end({ timeout: 5 });
      },
    };
  }
  const path = config.path === ":memory:" ? ":memory:" : resolve(config.path);
  if (path !== ":memory:") {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    // Create the file owner-only before SQLite opens it; SQLite gives the -wal/-shm files the same mode.
    if (!existsSync(path)) closeSync(openSync(path, "a", 0o600));
  }
  const driver = await createSqliteDriver(path);
  return {
    kind: "sqlite",
    driver,
    sql: null,
    async migrate() {
      await driver.migrate!();
    },
    async close() {
      await driver.close?.();
    },
  };
}

export async function countRows(driver: SqlDriver, query: string, params: readonly unknown[] = []): Promise<number> {
  const rows = await driver.privileged((db) => db.query<Row & { n: unknown }>(query, params));
  return Number(rows[0]?.n ?? 0);
}
