import { translateForSqlite, type AccessScope, type Db, type Row, type SqlDriver } from "../db.js";
import { sqliteSchemaSql } from "../schema.js";

/**
 * Local, single-owner storage on Node's built-in SQLite (Node >= 22.5).
 * SQLite has no row-level security: isolation relies on the service's
 * owner/connection predicates, so use it for one person's machine, not for a
 * multi-tenant deployment.
 */
interface StatementSync {
  all(...params: unknown[]): unknown[];
}
interface DatabaseSync {
  exec(sql: string): void;
  prepare(sql: string): StatementSync;
  close(): void;
}

function normalize(value: unknown): unknown {
  if (value === undefined) return null;
  if (typeof value === "boolean") return value ? 1 : 0;
  if (value instanceof Date) return value.toISOString();
  if (value !== null && typeof value === "object") return JSON.stringify(value);
  return value;
}

export async function createSqliteDriver(path: string, opts: { prefix?: string } = {}): Promise<SqlDriver> {
  const moduleName = "node:sqlite";
  const { DatabaseSync } = (await import(moduleName)) as { DatabaseSync: new (path: string) => DatabaseSync };
  const database = new DatabaseSync(path);
  database.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  let queue: Promise<unknown> = Promise.resolve();
  const db: Db = {
    dialect: "sqlite",
    async query<R extends Row = Row>(text: string, params: readonly unknown[] = []): Promise<R[]> {
      const translated = translateForSqlite(text);
      const statement = database.prepare(translated.text);
      return statement.all(...translated.order.map((index) => normalize(params[index - 1]))) as R[];
    },
  };
  // Serialize transactions: node:sqlite is synchronous, but service code awaits between statements.
  const transaction = async <T>(fn: (db: Db) => Promise<T>): Promise<T> => {
    const run = queue.then(async () => {
      database.exec("BEGIN IMMEDIATE");
      try {
        const result = await fn(db);
        database.exec("COMMIT");
        return result;
      } catch (error) {
        database.exec("ROLLBACK");
        throw error;
      }
    });
    queue = run.catch(() => undefined);
    return await run;
  };
  return {
    dialect: "sqlite",
    scoped: <T>(_scope: AccessScope, fn: (db: Db) => Promise<T>) => transaction(fn),
    privileged: <T>(fn: (db: Db) => Promise<T>) => transaction(fn),
    async migrate(): Promise<void> {
      database.exec(sqliteSchemaSql(opts.prefix));
    },
    async close(): Promise<void> {
      await queue;
      database.close();
    },
  };
}
