import { quoteIdent, translateForPostgres, type AccessScope, type Db, type Row, type SqlDriver } from "../db.js";
import { postgresSchemaProbeSql, postgresSchemaSql, resolveSchemaNames, type PostgresSchemaOptions } from "../schema.js";

/**
 * The minimal surface of a `postgres` (postgres.js) client this driver needs.
 * Pass the client you already use; the core does not import a driver.
 */
export interface PostgresLike {
  unsafe(text: string, params?: readonly unknown[]): Promise<readonly Row[]> & PromiseLike<readonly Row[]>;
  begin<T>(fn: (tx: PostgresTxLike) => Promise<T>): Promise<T>;
}
export interface PostgresTxLike {
  unsafe(text: string, params?: readonly unknown[]): Promise<readonly Row[]> & PromiseLike<readonly Row[]>;
}

export interface PostgresDriverOptions extends PostgresSchemaOptions {
  /** Applied with SET LOCAL inside every transaction. */
  statementTimeoutMs?: number;
}

function wrap(tx: PostgresTxLike): Db {
  return {
    dialect: "postgres",
    async query<R extends Row = Row>(text: string, params: readonly unknown[] = []): Promise<R[]> {
      const rows = await tx.unsafe(translateForPostgres(text), params as unknown[]);
      return [...rows] as R[];
    },
  };
}

/**
 * Scoped transactions run as a NOLOGIN role with the principal in
 * transaction-local settings, so RLS policies enforce isolation even if a
 * query forgets a predicate. The connecting role must be allowed to SET ROLE
 * to both roles (the schema grants this) and is used directly only for
 * privileged() work.
 */
export function createPostgresDriver(sql: PostgresLike, opts: PostgresDriverOptions = {}): SqlDriver {
  const names = resolveSchemaNames(opts);
  const timeout = Math.max(1000, Math.min(opts.statementTimeoutMs ?? 15_000, 120_000));
  return {
    dialect: "postgres",
    async scoped<T>(scope: AccessScope, fn: (db: Db) => Promise<T>): Promise<T> {
      const role = scope.role === "agent" ? names.agentRole : names.ownerRole;
      return await sql.begin(async (tx) => {
        await tx.unsafe(
          "SELECT set_config($1, $2, true), set_config($3, $4, true), set_config('statement_timeout', $5, true)",
          [
            `${names.settingPrefix}.owner_id`,
            scope.ownerId,
            `${names.settingPrefix}.connection_id`,
            scope.role === "agent" ? scope.connectionId : "",
            String(timeout),
          ],
        );
        await tx.unsafe(`SET LOCAL ROLE ${quoteIdent(role)}`);
        return await fn(wrap(tx));
      });
    },
    async privileged<T>(fn: (db: Db) => Promise<T>): Promise<T> {
      return await sql.begin(async (tx) => {
        await tx.unsafe("SELECT set_config('statement_timeout', $1, true)", [String(timeout)]);
        return await fn(wrap(tx));
      });
    },
    async migrate(): Promise<void> {
      const probe = await sql.unsafe(postgresSchemaProbeSql(opts));
      if (probe[0]?.current === true) return;
      await sql.begin(async (tx) => {
        await tx.unsafe("SELECT pg_advisory_xact_lock(hashtext($1))", [`${names.prefix}schema`]);
        await tx.unsafe(postgresSchemaSql(opts));
      });
    },
  };
}
