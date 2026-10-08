/**
 * Server configuration comes only from environment variables, validated once
 * at startup. Nothing here is ever logged except the non-secret summary from
 * `describeConfig()`.
 */
export type StorageConfig =
  | { kind: "sqlite"; path: string }
  | { kind: "postgres"; url: string; schema: string };

export interface ServerConfig {
  storage: StorageConfig;
  /** 64 hex characters (32 bytes). Encrypts webhook signing secrets and routine keys at rest. */
  encryptionKey: string;
  /** Base URL used for the OAuth issuer, resource and metadata. Null: derived from the bound address after listen(). */
  publicUrl: string | null;
  host: string;
  /** 0 picks a free port. */
  port: number;
  /** Development only: lets callbacks and client metadata documents use http and loopback/private addresses. */
  allowPrivateCallbacks: boolean;
  /** Use the right-most X-Forwarded-For address as the client IP (exactly one trusted proxy in front). */
  trustProxy: boolean;
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

type Env = Record<string, string | undefined>;

export const DEFAULT_SQLITE_PATH = "./data/aggregator.db";
export const DEFAULT_PORT = 8787;
export const DEFAULT_HOST = "127.0.0.1";

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);

export function isLoopbackHost(hostname: string): boolean {
  return LOOPBACK_HOSTS.has(hostname.toLowerCase()) || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);
}

function flag(value: string | undefined): boolean {
  return value === "1" || value === "true";
}

/** Storage settings only; used by `agg-owner init` and `agg-server migrate`, which do not need the encryption key. */
export function loadStorageConfig(env: Env): StorageConfig {
  const databaseUrl = env.AGG_DATABASE_URL?.trim();
  const sqlitePath = env.AGG_SQLITE_PATH?.trim();
  if (databaseUrl && sqlitePath) throw new ConfigError("set either AGG_DATABASE_URL or AGG_SQLITE_PATH, not both");
  if (databaseUrl) {
    let parsed: URL;
    try {
      parsed = new URL(databaseUrl);
    } catch {
      throw new ConfigError("AGG_DATABASE_URL must be a postgres:// or postgresql:// connection string");
    }
    if (parsed.protocol !== "postgres:" && parsed.protocol !== "postgresql:") {
      throw new ConfigError("AGG_DATABASE_URL must be a postgres:// or postgresql:// connection string");
    }
    const schema = env.AGG_DB_SCHEMA?.trim() || "public";
    if (!/^[a-z_][a-z0-9_]{0,62}$/.test(schema)) throw new ConfigError("AGG_DB_SCHEMA must be a lowercase identifier");
    return { kind: "postgres", url: databaseUrl, schema };
  }
  return { kind: "sqlite", path: sqlitePath || DEFAULT_SQLITE_PATH };
}

export function loadConfig(env: Env): ServerConfig {
  const storage = loadStorageConfig(env);
  const encryptionKey = env.AGG_ENCRYPTION_KEY?.trim() ?? "";
  if (!/^[0-9a-fA-F]{64}$/.test(encryptionKey)) {
    throw new ConfigError("AGG_ENCRYPTION_KEY must be 64 hex characters; generate one with: agg-server keygen");
  }
  const portRaw = env.AGG_PORT?.trim();
  const port = portRaw === undefined || portRaw === "" ? DEFAULT_PORT : Number(portRaw);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new ConfigError("AGG_PORT must be an integer between 0 and 65535");
  const host = env.AGG_HOST?.trim() || DEFAULT_HOST;
  const allowPrivateCallbacks = flag(env.AGG_ALLOW_PRIVATE_CALLBACKS);
  const publicUrl = env.AGG_PUBLIC_URL?.trim() ? normalizePublicUrl(env.AGG_PUBLIC_URL.trim(), allowPrivateCallbacks) : null;
  if (!publicUrl && !isLoopbackHost(host)) throw new ConfigError("AGG_PUBLIC_URL is required when AGG_HOST is not a loopback address");
  return { storage, encryptionKey: encryptionKey.toLowerCase(), publicUrl, host, port, allowPrivateCallbacks, trustProxy: flag(env.AGG_TRUST_PROXY) };
}

export function normalizePublicUrl(raw: string, allowHttp: boolean): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ConfigError("AGG_PUBLIC_URL must be an absolute URL such as https://aggregator.example.com");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new ConfigError("AGG_PUBLIC_URL must use https");
  if (url.protocol === "http:" && !isLoopbackHost(url.hostname) && !allowHttp) {
    throw new ConfigError("AGG_PUBLIC_URL must use https unless it is a loopback address (http://127.0.0.1:PORT)");
  }
  if (url.search || url.hash || url.username || url.password) throw new ConfigError("AGG_PUBLIC_URL must not contain a query, fragment or credentials");
  return url.toString().replace(/\/+$/, "");
}

/** A summary that is safe to log: no secrets, no connection strings. */
export function describeConfig(config: ServerConfig): Record<string, string | number | boolean> {
  return {
    storage: config.storage.kind,
    ...(config.storage.kind === "postgres" ? { db_schema: config.storage.schema } : { sqlite_path: config.storage.path }),
    host: config.host,
    port: config.port,
    allow_private_callbacks: config.allowPrivateCallbacks,
    trust_proxy: config.trustProxy,
  };
}
