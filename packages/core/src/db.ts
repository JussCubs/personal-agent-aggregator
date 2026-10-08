/**
 * The storage seam. The service writes dialect-neutral SQL with `$1..$n`
 * placeholders and `$n::jsonb` for JSON parameters; drivers translate.
 *
 * Every agent- or owner-initiated query runs inside `scoped()`. On Postgres the
 * driver switches to a non-privileged role and sets the principal in
 * transaction-local settings, so row-level security policies — not just
 * WHERE clauses — keep tenants and connections apart. `privileged()` is used
 * only for credential lookup, OAuth code exchange, the delivery worker and
 * maintenance sweeps.
 */
export type Dialect = "postgres" | "sqlite";

export type Row = Record<string, unknown>;

export interface Db {
  readonly dialect: Dialect;
  query<R extends Row = Row>(text: string, params?: readonly unknown[]): Promise<R[]>;
}

export type AccessScope =
  | { role: "agent"; ownerId: string; connectionId: string }
  | { role: "owner"; ownerId: string };

export interface SqlDriver {
  readonly dialect: Dialect;
  scoped<T>(scope: AccessScope, fn: (db: Db) => Promise<T>): Promise<T>;
  privileged<T>(fn: (db: Db) => Promise<T>): Promise<T>;
  /** Applies the schema (idempotent). */
  migrate?(): Promise<void>;
  close?(): Promise<void>;
}

export function quoteIdent(name: string): string {
  if (!/^[a-z_][a-z0-9_]{0,62}$/.test(name)) throw new Error(`unsafe SQL identifier: ${name}`);
  return `"${name}"`;
}

export function assertPrefix(prefix: string): string {
  if (!/^[a-z][a-z0-9_]{0,30}_$/.test(prefix)) throw new Error("table prefix must be lowercase letters/digits/underscores and end with '_'");
  return prefix;
}

/** Postgres: JSON params are sent as text and cast, avoiding driver-side double encoding. */
export function translateForPostgres(text: string): string {
  return text.replace(/\$(\d+)::jsonb/g, "($$$1::text)::jsonb");
}

/**
 * SQLite: positional `?` params in occurrence order (reused `$n` are repeated),
 * no casts, no row locks (writers are serialized by the database).
 */
export function translateForSqlite(text: string): { text: string; order: number[] } {
  const order: number[] = [];
  const out = text
    .replace(/\s+FOR UPDATE( SKIP LOCKED)?/gi, "")
    .replace(/\$(\d+)(::[a-z]+(\[\])?)?/gi, (_match, index: string) => {
      order.push(Number(index));
      return "?";
    });
  return { text: out, order };
}

export function asIso(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "string") return new Date(value).toISOString();
  return null;
}

export function asJson<T>(value: unknown): T | null {
  if (value === null || value === undefined) return null;
  if (typeof value === "string") {
    try {
      return JSON.parse(value) as T;
    } catch {
      return null;
    }
  }
  return value as T;
}

export function asBool(value: unknown): boolean {
  return value === true || value === 1 || value === "1" || value === "t" || value === "true";
}

export function asNumber(value: unknown): number {
  if (typeof value === "number") return value;
  if (typeof value === "bigint") return Number(value);
  if (typeof value === "string" && value !== "") return Number(value);
  return 0;
}
