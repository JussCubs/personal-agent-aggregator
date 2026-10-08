import { randomBytes } from "node:crypto";
import { postgresSchemaVersion } from "@agent-aggregator/core";
import { createAggregatorServer } from "../app.js";
import { ConfigError, describeConfig, loadConfig, loadStorageConfig } from "../config.js";
import { SERVER_VERSION } from "../context.js";
import { runDoctor } from "../doctor.js";
import { createJsonLogger, errorFields, redact } from "../log.js";
import { openStorage, postgresSchemaOptions } from "../storage.js";

const HELP = `Usage: agg-server [command]

Commands
  start      Run the server (default). Configuration comes from the environment.
  keygen     Print a new random AGG_ENCRYPTION_KEY (64 hex characters).
  migrate    Apply the database schema and exit (idempotent).
  doctor     Read-only storage and isolation checks; exit 0 when every check passes.
  help       Show this help.

Environment
  AGG_SQLITE_PATH              SQLite file (default ./data/aggregator.db). Single owner, one machine.
  AGG_DATABASE_URL             postgres:// connection string; enables Postgres with row-level security.
  AGG_DB_SCHEMA                Postgres schema for the tables (default public).
  AGG_ENCRYPTION_KEY           Required for start: 64 hex characters (agg-server keygen).
  AGG_PUBLIC_URL               Base URL clients use (OAuth issuer, MCP resource). Default http://AGG_HOST:AGG_PORT.
  AGG_HOST                     Bind address (default 127.0.0.1).
  AGG_PORT                     Port (default 8787; 0 picks a free port).
  AGG_TRUST_PROXY=1            Take the client IP from the right-most X-Forwarded-For entry.
  AGG_ALLOW_PRIVATE_CALLBACKS=1  Development only: allow http and private/loopback callback URLs.

Exit codes: 0 ok, 1 error or failed check, 2 configuration or usage error.
`;

function stderrJson(code: string, message: string): void {
  process.stderr.write(`${JSON.stringify({ error: { code, message } })}\n`);
}

async function start(): Promise<number> {
  const logger = createJsonLogger();
  const config = loadConfig(process.env);
  const server = await createAggregatorServer(config, { logger });
  const url = await server.listen();
  if (config.allowPrivateCallbacks) {
    logger.warn("development mode", { detail: "AGG_ALLOW_PRIVATE_CALLBACKS=1: callbacks may use http and reach loopback and private addresses. Never enable this on a reachable server." });
  }
  logger.info("listening", { url, mcp: `${url}/mcp`, agent_api: `${url}/api/v1`, owner_api: `${url}/owner`, version: SERVER_VERSION, ...describeConfig(config) });
  return await new Promise<number>((resolve) => {
    let closing = false;
    const shutdown = (signal: string) => {
      if (closing) return;
      closing = true;
      logger.info("shutting down", { signal });
      server.close().then(
        () => resolve(0),
        (error) => {
          logger.error("shutdown_error", errorFields(error));
          resolve(1);
        },
      );
    };
    process.once("SIGINT", () => shutdown("SIGINT"));
    process.once("SIGTERM", () => shutdown("SIGTERM"));
  });
}

export async function main(argv: readonly string[]): Promise<number> {
  const [command = "start", ...rest] = argv;
  try {
    if (rest.length > 0) throw new ConfigError(`unexpected arguments: ${rest.join(" ")}`);
    switch (command) {
      case "start":
        return await start();
      case "keygen":
        process.stdout.write(`${randomBytes(32).toString("hex")}\n`);
        return 0;
      case "migrate": {
        const storageConfig = loadStorageConfig(process.env);
        const storage = await openStorage(storageConfig);
        try {
          await storage.migrate();
        } finally {
          await storage.close();
        }
        process.stdout.write(`${JSON.stringify({ ok: true, storage: storageConfig.kind, ...(storageConfig.kind === "postgres" ? { schema: storageConfig.schema, schema_version: postgresSchemaVersion(postgresSchemaOptions(storageConfig.schema)) } : {}) })}\n`);
        return 0;
      }
      case "doctor": {
        const storageConfig = loadStorageConfig(process.env);
        const storage = await openStorage(storageConfig);
        try {
          const checks = await runDoctor(storageConfig, storage);
          const ok = checks.every((check) => check.pass);
          process.stdout.write(`${JSON.stringify({ ok, storage: storageConfig.kind, checks })}\n`);
          return ok ? 0 : 1;
        } finally {
          await storage.close();
        }
      }
      case "help":
      case "--help":
      case "-h":
        process.stdout.write(HELP);
        return 0;
      case "--version":
      case "version":
        process.stdout.write(`${SERVER_VERSION}\n`);
        return 0;
      default:
        process.stderr.write(`unknown command: ${command}\n${HELP}`);
        return 2;
    }
  } catch (error) {
    if (error instanceof ConfigError) {
      stderrJson("config", error.message);
      return 2;
    }
    const fields = errorFields(error);
    stderrJson("startup", redact(`${String(fields.error_name)}${fields.error_code ? ` ${String(fields.error_code)}` : ""}: ${String(fields.error_message ?? "")}`));
    return 1;
  }
}
