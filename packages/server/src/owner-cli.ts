import { chmodSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { parseArgs } from "node:util";
import { ConfigError, DEFAULT_PORT, loadStorageConfig } from "./config.js";
import { SERVER_VERSION } from "./context.js";
import { cleanOwnerName, countOwners, createOwner, listOwners, rotateOwnerCredential } from "./owners.js";
import { openStorage, type Storage } from "./storage.js";

/**
 * `agg-owner`: a deterministic CLI for the owner API. One JSON line on
 * stdout per command (setup-prompt prints Markdown), errors as JSON on
 * stderr, documented exit codes — so scripts and tests can drive it.
 *
 * Exit codes: 0 ok · 1 error · 2 usage · 3 empty list · 4 owner credential missing/invalid ·
 * 5 conflict (the question/job changed state or revision; read it again).
 */
export const OWNER_EXIT = { ok: 0, error: 1, usage: 2, empty: 3, auth: 4, conflict: 5 } as const;

export interface OwnerCliIo {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  env: Record<string, string | undefined>;
  fetch?: typeof fetch;
  /** Opens storage for init/reset-credential (tests inject one). */
  openStorage?: () => Promise<Storage>;
}

const HELP = `Usage: agg-owner <command> [options]

Bootstrap (direct database access; uses AGG_SQLITE_PATH or AGG_DATABASE_URL like agg-server)
  init [--name NAME] [--save] [--server URL] [--additional]   Create the owner; prints the owner credential once (or stores it with --save)
  reset-credential [--owner-id ID] [--save] [--server URL]    Replace a lost or leaked owner credential

Owner API (uses AGG_OWNER_URL + AGG_OWNER_TOKEN, or the file written by --save)
  whoami
  rotate-credential [--save]
  connection create --provider P --name NAME --mode mcp_webhook|oauth_events|cli_poll [--scope S ...]
  connection list | get --id ID | revoke --id ID | delete --id ID --yes
  credential issue --connection ID                    Agent credential, shown once
  claim-code --connection ID [--ttl SECONDS]          One-time setup code for an agent with a shell
  setup-prompt --connection ID                        Setup playbook (Markdown) to give the agent
  questions [--status pending|answered|cancelled|expired|all] [--connection ID] [--limit N]   Exit 3 when empty
  question get --connection ID --id QID
  answer --connection ID --id QID --revision N (--choice OPTION | --approve | --deny | --text TEXT) [--text TEXT]
  dismiss --connection ID --id QID
  jobs [--status open|all|needs_user|running|blocked|done|declined|cancelled|failed] [--connection ID] [--limit N]   Exit 3 when empty
  job get --connection ID --id JID
  job decide --connection ID --id JID (--approve | --decline) [--note TEXT]
  job progress --connection ID --id JID --status running|blocked|needs_user|done|failed [--summary TEXT] [--reason CODE] [--result JSON]
  items [--connection ID] [--kind task|goal|project|state] [--limit N]
  checkpoints [--connection ID] [--item ID] [--limit N]
  audit [--connection ID] [--limit N]
  webhook set --connection ID --url URL [--header NAME --value VALUE] | webhook clear --connection ID

Exit codes: 0 ok, 1 error, 2 usage, 3 empty list, 4 owner credential missing or invalid, 5 conflict (re-read and retry).
`;

class UsageError extends Error {}

class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: unknown;
  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

interface StoredOwnerConfig {
  server?: string;
  token?: string;
}

export function ownerConfigPath(env: Record<string, string | undefined>): string {
  const base = env.XDG_CONFIG_HOME || join(homedir(), ".config");
  return join(base, "agent-aggregator", "owner.json");
}

function readStored(env: Record<string, string | undefined>): StoredOwnerConfig {
  try {
    return JSON.parse(readFileSync(ownerConfigPath(env), "utf8")) as StoredOwnerConfig;
  } catch {
    return {};
  }
}

function writePrivate(path: string, contents: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, contents, { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, path);
}

function defaultServer(env: Record<string, string | undefined>): string {
  return (env.AGG_OWNER_URL || env.AGG_PUBLIC_URL || `http://127.0.0.1:${env.AGG_PORT || DEFAULT_PORT}`).replace(/\/+$/, "");
}

function need<T>(value: T | undefined, message: string): T {
  if (value === undefined || value === null || value === "") throw new UsageError(message);
  return value;
}

function integer(value: string | undefined, name: string): number | undefined {
  if (value === undefined) return undefined;
  if (!/^\d+$/.test(value)) throw new UsageError(`--${name} must be a non-negative integer`);
  return Number(value);
}

export async function runOwnerCli(argv: readonly string[], io: OwnerCliIo): Promise<number> {
  const [command, ...rest] = argv;
  const out = (value: unknown) => io.stdout(`${typeof value === "string" ? value : JSON.stringify(value)}\n`);
  if (!command || command === "help" || command === "--help" || command === "-h") {
    io.stdout(HELP);
    return command ? OWNER_EXIT.ok : OWNER_EXIT.usage;
  }
  if (command === "--version" || command === "version") {
    out(SERVER_VERSION);
    return OWNER_EXIT.ok;
  }
  const stored = readStored(io.env);
  const server = (io.env.AGG_OWNER_URL || stored.server || defaultServer(io.env)).replace(/\/+$/, "");
  const token = io.env.AGG_OWNER_TOKEN || stored.token;

  const api = async (method: string, path: string, body?: unknown, query: Record<string, string | number | undefined> = {}): Promise<{ status: number; json: unknown; text: string }> => {
    if (!token) throw new ApiError(401, "unauthorized", `no owner credential; run 'agg-owner init --save' or set AGG_OWNER_TOKEN`);
    const url = new URL(`${server}${path}`);
    if (url.protocol !== "https:" && !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)) throw new UsageError("the owner API URL must use https unless it is a loopback address");
    for (const [key, value] of Object.entries(query)) if (value !== undefined && value !== "") url.searchParams.set(key, String(value));
    const response = await (io.fetch ?? fetch)(url, {
      method,
      headers: { authorization: `Bearer ${token}`, "x-agg-surface": "cli", accept: "application/json", "user-agent": `agg-owner/${SERVER_VERSION}`, ...(body === undefined ? {} : { "content-type": "application/json" }) },
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: "error",
      signal: AbortSignal.timeout(20_000),
    });
    const text = await response.text();
    let json: unknown = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    if (!response.ok) {
      const error = (json as { error?: { code?: string; message?: string; details?: unknown } } | null)?.error;
      throw new ApiError(response.status, error?.code ?? `http_${response.status}`, error?.message ?? `HTTP ${response.status}`, error?.details);
    }
    return { status: response.status, json, text };
  };
  const conn = (id: string | undefined) => `/owner/connections/${encodeURIComponent(need(id, "--connection ID is required"))}`;
  const listResult = (value: unknown, key: string) => {
    out(value);
    const list = (value as Record<string, unknown[]> | null)?.[key];
    return Array.isArray(list) && list.length === 0 ? OWNER_EXIT.empty : OWNER_EXIT.ok;
  };
  const withStorage = async <T>(fn: (storage: Storage) => Promise<T>): Promise<T> => {
    const storage = io.openStorage ? await io.openStorage() : await openStorage(loadStorageConfig(io.env));
    try {
      await storage.migrate();
      return await fn(storage);
    } finally {
      await storage.close();
    }
  };
  const save = (serverUrl: string, credential: string) => {
    const path = ownerConfigPath(io.env);
    writePrivate(path, JSON.stringify({ server: serverUrl, token: credential }, null, 2));
    return path;
  };

  try {
    switch (command) {
      case "init": {
        const { values } = parseArgs({ args: [...rest], options: { name: { type: "string" }, save: { type: "boolean" }, server: { type: "string" }, additional: { type: "boolean" } }, strict: true });
        let name: string | null;
        try {
          name = cleanOwnerName(values.name);
        } catch (error) {
          throw new UsageError((error as Error).message);
        }
        return await withStorage(async (storage) => {
          const existing = await countOwners(storage.driver);
          if (existing > 0 && !values.additional) {
            io.stderr(`${JSON.stringify({ error: { code: "conflict", message: `an owner already exists (${existing}); use reset-credential to replace a lost credential, or --additional to create another owner` } })}\n`);
            return OWNER_EXIT.conflict;
          }
          const created = await createOwner(storage.driver, name);
          if (values.save) {
            const path = save((values.server ?? defaultServer(io.env)).replace(/\/+$/, ""), created.credential);
            out({ ok: true, owner_id: created.owner.id, name: created.owner.name, hint: created.hint, stored: path });
          } else {
            out({ ok: true, owner_id: created.owner.id, name: created.owner.name, credential: created.credential, note: "Shown once. Store it in a password manager; only its SHA-256 digest is kept." });
          }
          return OWNER_EXIT.ok;
        });
      }
      case "reset-credential": {
        const { values } = parseArgs({ args: [...rest], options: { "owner-id": { type: "string" }, save: { type: "boolean" }, server: { type: "string" } }, strict: true });
        return await withStorage(async (storage) => {
          let ownerId = values["owner-id"];
          if (!ownerId) {
            const owners = await listOwners(storage.driver);
            if (owners.length !== 1) throw new UsageError(`there are ${owners.length} owners; pass --owner-id`);
            ownerId = owners[0]!.id;
          }
          const rotated = await rotateOwnerCredential(storage.driver, ownerId);
          if (!rotated) throw new ApiError(404, "not_found", "owner not found");
          if (values.save) {
            const path = save((values.server ?? defaultServer(io.env)).replace(/\/+$/, ""), rotated.credential);
            out({ ok: true, owner_id: ownerId, hint: rotated.hint, stored: path });
          } else {
            out({ ok: true, owner_id: ownerId, credential: rotated.credential, note: "Shown once. The previous owner credential no longer works." });
          }
          return OWNER_EXIT.ok;
        });
      }
      case "whoami": {
        parseArgs({ args: [...rest], options: {}, strict: true });
        out((await api("GET", "/owner/me")).json);
        return OWNER_EXIT.ok;
      }
      case "rotate-credential": {
        const { values } = parseArgs({ args: [...rest], options: { save: { type: "boolean" } }, strict: true });
        const result = (await api("POST", "/owner/credential/rotate", {})).json as { credential: string; hint: string };
        if (values.save) out({ ok: true, hint: result.hint, stored: save(server, result.credential) });
        else out({ ok: true, credential: result.credential, hint: result.hint, note: "Shown once. The previous owner credential no longer works." });
        return OWNER_EXIT.ok;
      }
      case "connection": {
        const [sub, ...args] = rest;
        const { values } = parseArgs({
          args,
          options: { id: { type: "string" }, provider: { type: "string" }, name: { type: "string" }, mode: { type: "string" }, scope: { type: "string", multiple: true }, yes: { type: "boolean" } },
          strict: true,
        });
        if (sub === "create") {
          const body = { provider: need(values.provider, "--provider is required"), display_name: need(values.name, "--name is required"), mode: need(values.mode, "--mode is required"), ...(values.scope ? { scopes: values.scope } : {}) };
          out((await api("POST", "/owner/connections", body)).json);
          return OWNER_EXIT.ok;
        }
        if (sub === "list") return listResult((await api("GET", "/owner/connections")).json, "connections");
        if (sub === "get") {
          out((await api("GET", conn(values.id))).json);
          return OWNER_EXIT.ok;
        }
        if (sub === "revoke") {
          out((await api("POST", `${conn(values.id)}/revoke`, {})).json);
          return OWNER_EXIT.ok;
        }
        if (sub === "delete") {
          if (!values.yes) throw new UsageError("connection delete removes every row the connection produced; pass --yes to confirm");
          out((await api("DELETE", conn(values.id))).json);
          return OWNER_EXIT.ok;
        }
        throw new UsageError("connection needs create, list, get, revoke or delete");
      }
      case "credential": {
        const [sub, ...args] = rest;
        const { values } = parseArgs({ args, options: { connection: { type: "string" } }, strict: true });
        if (sub !== "issue") throw new UsageError("credential needs issue");
        out((await api("POST", `${conn(values.connection)}/credential`, {})).json);
        return OWNER_EXIT.ok;
      }
      case "claim-code": {
        const { values } = parseArgs({ args: [...rest], options: { connection: { type: "string" }, ttl: { type: "string" } }, strict: true });
        const ttl = integer(values.ttl, "ttl");
        out((await api("POST", `${conn(values.connection)}/claim-code`, ttl === undefined ? {} : { ttl_seconds: ttl })).json);
        return OWNER_EXIT.ok;
      }
      case "setup-prompt": {
        const { values } = parseArgs({ args: [...rest], options: { connection: { type: "string" } }, strict: true });
        io.stdout((await api("GET", `${conn(values.connection)}/setup-prompt`)).text);
        return OWNER_EXIT.ok;
      }
      case "questions": {
        const { values } = parseArgs({ args: [...rest], options: { status: { type: "string" }, connection: { type: "string" }, limit: { type: "string" } }, strict: true });
        return listResult((await api("GET", "/owner/questions", undefined, { status: values.status, connection_id: values.connection, limit: integer(values.limit, "limit") })).json, "questions");
      }
      case "question": {
        const [sub, ...args] = rest;
        const { values } = parseArgs({ args, options: { connection: { type: "string" }, id: { type: "string" } }, strict: true });
        if (sub !== "get") throw new UsageError("question needs get");
        out((await api("GET", `${conn(values.connection)}/questions/${encodeURIComponent(need(values.id, "--id is required"))}`)).json);
        return OWNER_EXIT.ok;
      }
      case "answer": {
        const { values } = parseArgs({
          args: [...rest],
          options: { connection: { type: "string" }, id: { type: "string" }, revision: { type: "string" }, choice: { type: "string" }, text: { type: "string" }, approve: { type: "boolean" }, deny: { type: "boolean" } },
          strict: true,
        });
        const revision = need(integer(values.revision, "revision"), "--revision N is required (the revision you reviewed)");
        if (values.approve && values.deny) throw new UsageError("pass --approve or --deny, not both");
        const choice = values.approve ? "approve" : values.deny ? "deny" : values.choice;
        if (!choice && values.text === undefined) throw new UsageError("answer needs --choice, --approve, --deny or --text");
        const body = { revision, ...(choice ? { choice } : {}), ...(values.text !== undefined ? { text: values.text } : {}) };
        out((await api("POST", `${conn(values.connection)}/questions/${encodeURIComponent(need(values.id, "--id is required"))}/answer`, body)).json);
        return OWNER_EXIT.ok;
      }
      case "dismiss": {
        const { values } = parseArgs({ args: [...rest], options: { connection: { type: "string" }, id: { type: "string" } }, strict: true });
        out((await api("POST", `${conn(values.connection)}/questions/${encodeURIComponent(need(values.id, "--id is required"))}/dismiss`, {})).json);
        return OWNER_EXIT.ok;
      }
      case "jobs": {
        const { values } = parseArgs({ args: [...rest], options: { status: { type: "string" }, connection: { type: "string" }, limit: { type: "string" } }, strict: true });
        return listResult((await api("GET", "/owner/jobs", undefined, { status: values.status, connection_id: values.connection, limit: integer(values.limit, "limit") })).json, "jobs");
      }
      case "job": {
        const [sub, ...args] = rest;
        const { values } = parseArgs({
          args,
          options: {
            connection: { type: "string" }, id: { type: "string" }, approve: { type: "boolean" }, decline: { type: "boolean" }, note: { type: "string" },
            status: { type: "string" }, summary: { type: "string" }, reason: { type: "string" }, result: { type: "string" },
          },
          strict: true,
        });
        const path = `${conn(values.connection)}/jobs/${encodeURIComponent(need(values.id, "--id is required"))}`;
        if (sub === "get") {
          out((await api("GET", path)).json);
          return OWNER_EXIT.ok;
        }
        if (sub === "decide") {
          if (values.approve === values.decline) throw new UsageError("job decide needs exactly one of --approve or --decline");
          out((await api("POST", `${path}/decision`, { approve: values.approve === true, ...(values.note !== undefined ? { note: values.note } : {}) })).json);
          return OWNER_EXIT.ok;
        }
        if (sub === "progress") {
          let result: unknown;
          if (values.result !== undefined) {
            result = JSON.parse(values.result);
            if (!result || typeof result !== "object" || Array.isArray(result)) throw new UsageError("--result must be a JSON object");
          }
          const body = {
            status: need(values.status, "--status is required"),
            ...(values.summary !== undefined ? { summary: values.summary } : {}),
            ...(values.reason !== undefined ? { reason: values.reason } : {}),
            ...(result !== undefined ? { result } : {}),
          };
          out((await api("POST", `${path}/progress`, body)).json);
          return OWNER_EXIT.ok;
        }
        throw new UsageError("job needs get, decide or progress");
      }
      case "items": {
        const { values } = parseArgs({ args: [...rest], options: { connection: { type: "string" }, kind: { type: "string" }, limit: { type: "string" } }, strict: true });
        return listResult((await api("GET", "/owner/work-items", undefined, { connection_id: values.connection, kind: values.kind, limit: integer(values.limit, "limit") })).json, "items");
      }
      case "checkpoints": {
        const { values } = parseArgs({ args: [...rest], options: { connection: { type: "string" }, item: { type: "string" }, limit: { type: "string" } }, strict: true });
        return listResult((await api("GET", "/owner/checkpoints", undefined, { connection_id: values.connection, work_item_id: values.item, limit: integer(values.limit, "limit") })).json, "checkpoints");
      }
      case "audit": {
        const { values } = parseArgs({ args: [...rest], options: { connection: { type: "string" }, limit: { type: "string" } }, strict: true });
        return listResult((await api("GET", "/owner/audit", undefined, { connection_id: values.connection, limit: integer(values.limit, "limit") })).json, "entries");
      }
      case "webhook": {
        const [sub, ...args] = rest;
        const { values } = parseArgs({ args, options: { connection: { type: "string" }, url: { type: "string" }, header: { type: "string" }, value: { type: "string" } }, strict: true });
        if (sub === "set") {
          const body = { url: need(values.url, "--url is required"), ...(values.header ? { auth_header_name: values.header } : {}), ...(values.value ? { auth_header_value: values.value } : {}) };
          out((await api("PUT", `${conn(values.connection)}/webhook`, body)).json);
          return OWNER_EXIT.ok;
        }
        if (sub === "clear") {
          out((await api("DELETE", `${conn(values.connection)}/webhook`)).json);
          return OWNER_EXIT.ok;
        }
        throw new UsageError("webhook needs set or clear");
      }
      default:
        throw new UsageError(`unknown command: ${command}`);
    }
  } catch (error) {
    if (error instanceof UsageError || error instanceof ConfigError || (error instanceof TypeError && "code" in error && String((error as { code?: unknown }).code).startsWith("ERR_PARSE_ARGS"))) {
      io.stderr(`${error.message}\nRun 'agg-owner help' for usage.\n`);
      return OWNER_EXIT.usage;
    }
    if (error instanceof SyntaxError) {
      io.stderr(`invalid JSON: ${error.message}\n`);
      return OWNER_EXIT.usage;
    }
    if (error instanceof ApiError) {
      const raw = error.details && typeof error.details === "object" ? (error.details as Record<string, unknown>) : {};
      const details = Object.fromEntries(Object.entries(raw).filter(([key]) => key === "status" || key === "revision" || key === "field" || key === "retry_after"));
      io.stderr(`${JSON.stringify({ error: { status: error.status, code: error.code, message: error.message, ...(Object.keys(details).length ? { details } : {}) } })}\n`);
      if (error.status === 401) return OWNER_EXIT.auth;
      if (error.status === 409) return OWNER_EXIT.conflict;
      return OWNER_EXIT.error;
    }
    io.stderr(`${error instanceof Error ? error.message : String(error)}\n`);
    return OWNER_EXIT.error;
  }
}
