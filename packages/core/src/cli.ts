import { spawn, spawnSync } from "node:child_process";
import { chmodSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { parseArgs } from "node:util";
import { AggregatorApiError, AggregatorClient } from "./client.js";

/**
 * A deterministic agent-side CLI. Every routine step — setup, health check,
 * pushing work items and checkpoints, asking, polling, picking up answers,
 * acknowledging — is a plain command with documented exit codes, so cron
 * jobs and hooks can run it without waking a language model. A model is
 * needed only when an answer actually arrives and someone has to act on it.
 *
 * Exit codes: 0 ok / something new · 1 error · 2 usage · 3 nothing new or still
 * pending · 4 credential missing/invalid · 5 question closed without an answer.
 */
export const EXIT = { ok: 0, error: 1, usage: 2, nothingNew: 3, auth: 4, closed: 5 } as const;

export interface CliDefaults {
  /** Command name shown in help, e.g. "agg" or "mytool hub". */
  command: string;
  /** Env var prefix: <PREFIX>_TOKEN and <PREFIX>_URL. */
  envPrefix: string;
  /** Directory for hub.json and cursor files. */
  configDir: string;
  /** Default API base URL (requests go to <url>/v1/...). */
  defaultServer?: string;
  userAgent: string;
  /** Marker used for idempotent crontab entries. */
  cronMarker?: string;
}

export interface CliIo {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  env: Record<string, string | undefined>;
  fetch?: typeof fetch;
  readStdin?: () => Promise<string>;
}

interface StoredConfig {
  server?: string;
  token?: string;
}

const HELP = (c: string) => `Usage: ${c} <command> [options]

Setup
  setup --claim CODE [--server URL] [--print-token]   Exchange a one-time setup code; store the credential (0600) or print it for your vault
  doctor                                              Read-only connection check (exit 0 ok, 4 bad credential)

Report
  item put --id ID --kind task|goal|project|state --title T [--status S] [--summary S] [--blocker S] [--next-step S] [--due ISO] [--parent ID] [--data JSON]
  item list [--kind K]        item rm --id ID
  checkpoint --summary S [--id ID] [--item ID] [--status S] [--data JSON]
  snapshot --file PATH|-      Push an explicit JSON snapshot (tasks, goals, projects, identity, memory_summary, connected_apps)

Ask
  ask --id ID --prompt TEXT [--option id=Label ...] [--approval] [--no-free-text] [--details TEXT] [--item ID] [--action TEXT] [--digest D] [--urgency low|normal|high] [--expires-in SECONDS]
  answer --id ID [--wait SECONDS] [--interval SECONDS]   Exit 0 answered (JSON on stdout), 3 still pending, 5 cancelled/expired
  ack --id ID [--revision N]
  cancel --id ID

Inbox
  inbox [--cursor-file PATH] [--limit N] [--exec CMD]     Exit 0 new events (JSON lines), 3 nothing new. With --exec, the cursor only advances if CMD exits 0
  install-poller [--every-minutes N] [--exec CMD] [--cursor-file PATH] [--print]   Idempotent crontab entry
  uninstall-poller

Hand off
  handoff --goal TEXT [--key K] [--context TEXT] [--criteria TEXT] [--item ID]
  job --id ID [--wait SECONDS] [--interval SECONDS]       Exit 0 when the job is terminal, 3 while open

Wake-up webhook
  webhook set --url URL [--header NAME] [--value VALUE]   webhook clear

Environment: <PREFIX>_TOKEN, <PREFIX>_URL override the stored config.
`;

function configPath(defaults: CliDefaults): string {
  return join(defaults.configDir, "hub.json");
}

function readConfig(defaults: CliDefaults): StoredConfig {
  try {
    return JSON.parse(readFileSync(configPath(defaults), "utf8")) as StoredConfig;
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

function parseJsonFlag(value: string | undefined, name: string): Record<string, unknown> | undefined {
  if (value === undefined) return undefined;
  const parsed: unknown = JSON.parse(value);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new UsageError(`--${name} must be a JSON object`);
  return parsed as Record<string, unknown>;
}

class UsageError extends Error {}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** mkdir-free exclusive lock file; stale after 10 minutes. */
function acquireLock(path: string): (() => void) | null {
  const lock = `${path}.lock`;
  try {
    if (existsSync(lock) && Date.now() - statSync(lock).mtimeMs > 600_000) rmSync(lock, { force: true });
    mkdirSync(dirname(lock), { recursive: true, mode: 0o700 });
    const fd = openSync(lock, "wx", 0o600);
    closeSync(fd);
    return () => rmSync(lock, { force: true });
  } catch {
    return null;
  }
}

function runHook(command: string, input: string, env: Record<string, string | undefined>): Promise<number> {
  return new Promise((resolve) => {
    const child = spawn("/bin/sh", ["-c", command], { stdio: ["pipe", "inherit", "inherit"], env: env as NodeJS.ProcessEnv });
    child.on("error", () => resolve(1));
    child.on("close", (code) => resolve(code ?? 1));
    // A hook may exit without reading its input; its exit code still decides.
    child.stdin.on("error", () => undefined);
    child.stdin.end(input);
  });
}

export async function runAgentCli(argv: readonly string[], defaults: CliDefaults, io: CliIo): Promise<number> {
  const [command, ...rest] = argv;
  const out = (value: unknown) => io.stdout(`${typeof value === "string" ? value : JSON.stringify(value)}\n`);
  if (!command || command === "help" || command === "--help" || command === "-h") {
    io.stdout(HELP(defaults.command).replaceAll("<PREFIX>", defaults.envPrefix));
    return command ? EXIT.ok : EXIT.usage;
  }
  const stored = readConfig(defaults);
  const server = io.env[`${defaults.envPrefix}_URL`] || stored.server || defaults.defaultServer;
  const token = io.env[`${defaults.envPrefix}_TOKEN`] || stored.token;
  const client = (needToken = true) => {
    if (!server) throw new UsageError(`no server configured; pass --server or set ${defaults.envPrefix}_URL`);
    if (needToken && !token) throw new AggregatorApiError(401, "unauthorized", `no credential; run '${defaults.command} setup --claim CODE' or set ${defaults.envPrefix}_TOKEN`);
    return new AggregatorClient({ baseUrl: server, token, fetch: io.fetch, userAgent: defaults.userAgent });
  };

  try {
    switch (command) {
      case "setup": {
        const { values } = parseArgs({ args: [...rest], options: { claim: { type: "string" }, server: { type: "string" }, "print-token": { type: "boolean" } }, strict: true });
        if (!values.claim) throw new UsageError("setup needs --claim CODE");
        const target = values.server ?? server;
        if (!target) throw new UsageError("setup needs --server URL");
        const result = await new AggregatorClient({ baseUrl: target, fetch: io.fetch, userAgent: defaults.userAgent }).claim(values.claim);
        if (values["print-token"]) {
          io.stdout(`${result.token}\n`);
        } else {
          writePrivate(configPath(defaults), JSON.stringify({ server: target, token: result.token }, null, 2));
          out({ ok: true, connection: result.connection, scopes: result.scopes, stored: configPath(defaults) });
        }
        return EXIT.ok;
      }
      case "doctor":
      case "whoami": {
        const info = await client().me();
        out({ ok: true, ...info });
        return EXIT.ok;
      }
      case "item": {
        const [sub, ...args] = rest;
        const { values } = parseArgs({
          args,
          options: {
            id: { type: "string" }, kind: { type: "string" }, title: { type: "string" }, status: { type: "string" }, summary: { type: "string" },
            blocker: { type: "string" }, "next-step": { type: "string" }, due: { type: "string" }, parent: { type: "string" }, data: { type: "string" },
          },
          strict: true,
        });
        if (sub === "put") {
          if (!values.id || !values.kind || !values.title) throw new UsageError("item put needs --id, --kind and --title");
          out(await client().upsertWorkItem({
            id: values.id, kind: values.kind, title: values.title, status: values.status, summary: values.summary, blocker: values.blocker,
            next_step: values["next-step"], due_at: values.due, parent_id: values.parent, data: parseJsonFlag(values.data, "data"),
          }));
          return EXIT.ok;
        }
        if (sub === "list") {
          out(await client().listWorkItems({ kind: values.kind }));
          return EXIT.ok;
        }
        if (sub === "rm") {
          if (!values.id) throw new UsageError("item rm needs --id");
          out(await client().deleteWorkItem(values.id));
          return EXIT.ok;
        }
        throw new UsageError("item needs put, list or rm");
      }
      case "checkpoint": {
        const { values } = parseArgs({ args: [...rest], options: { id: { type: "string" }, item: { type: "string" }, summary: { type: "string" }, status: { type: "string" }, data: { type: "string" } }, strict: true });
        if (!values.summary) throw new UsageError("checkpoint needs --summary");
        out(await client().postCheckpoint({ id: values.id, work_item_id: values.item, summary: values.summary, status: values.status, data: parseJsonFlag(values.data, "data") }));
        return EXIT.ok;
      }
      case "snapshot": {
        const { values } = parseArgs({ args: [...rest], options: { file: { type: "string" } }, strict: true });
        if (!values.file) throw new UsageError("snapshot needs --file PATH (or - for stdin)");
        const text = values.file === "-" ? await (io.readStdin?.() ?? Promise.resolve("")) : readFileSync(values.file, "utf8");
        out(await client().pushSnapshot(JSON.parse(text) as Record<string, unknown>));
        return EXIT.ok;
      }
      case "ask": {
        const { values } = parseArgs({
          args: [...rest],
          options: {
            id: { type: "string" }, prompt: { type: "string" }, option: { type: "string", multiple: true }, approval: { type: "boolean" }, "no-free-text": { type: "boolean" },
            details: { type: "string" }, item: { type: "string" }, action: { type: "string" }, digest: { type: "string" }, urgency: { type: "string" }, "expires-in": { type: "string" },
          },
          strict: true,
        });
        if (!values.id || !values.prompt) throw new UsageError("ask needs --id and --prompt");
        const options = (values.option ?? []).map((entry, index) => {
          const eq = entry.indexOf("=");
          return eq > 0 ? { id: entry.slice(0, eq), label: entry.slice(eq + 1) } : { id: `opt_${index + 1}`, label: entry };
        });
        out(await client().createQuestion({
          id: values.id, kind: values.approval ? "approval" : "question", prompt: values.prompt, details: values.details,
          options: values.approval ? undefined : options, allow_free_text: values["no-free-text"] ? false : undefined, work_item_id: values.item,
          affected_action: values.action, action_digest: values.digest, urgency: values.urgency,
          expires_in_seconds: values["expires-in"] ? Number(values["expires-in"]) : undefined,
        }));
        return EXIT.ok;
      }
      case "answer": {
        const { values } = parseArgs({ args: [...rest], options: { id: { type: "string" }, wait: { type: "string" }, interval: { type: "string" } }, strict: true });
        if (!values.id) throw new UsageError("answer needs --id");
        const deadline = Date.now() + Math.max(0, Number(values.wait ?? 0)) * 1000;
        const interval = Math.max(2, Number(values.interval ?? 5)) * 1000;
        for (;;) {
          const { question } = await client().getQuestion(values.id);
          if (question.status === "answered") {
            out(question);
            return EXIT.ok;
          }
          if (question.status === "cancelled" || question.status === "expired") {
            out(question);
            return EXIT.closed;
          }
          if (Date.now() + interval > deadline) {
            out({ id: question.id, status: question.status, revision: question.revision });
            return EXIT.nothingNew;
          }
          await sleep(interval);
        }
      }
      case "ack": {
        const { values } = parseArgs({ args: [...rest], options: { id: { type: "string" }, revision: { type: "string" } }, strict: true });
        if (!values.id) throw new UsageError("ack needs --id");
        out(await client().acknowledgeAnswer(values.id, values.revision ? Number(values.revision) : undefined));
        return EXIT.ok;
      }
      case "cancel": {
        const { values } = parseArgs({ args: [...rest], options: { id: { type: "string" } }, strict: true });
        if (!values.id) throw new UsageError("cancel needs --id");
        out(await client().cancelQuestion(values.id));
        return EXIT.ok;
      }
      case "inbox": {
        const { values } = parseArgs({ args: [...rest], options: { "cursor-file": { type: "string" }, cursor: { type: "string" }, limit: { type: "string" }, exec: { type: "string" } }, strict: true });
        const cursorFile = values["cursor-file"] ?? join(defaults.configDir, "inbox.cursor");
        const release = acquireLock(cursorFile);
        if (!release) {
          io.stderr("another inbox run holds the lock; skipping\n");
          return EXIT.nothingNew;
        }
        try {
          let cursor = values.cursor ?? (existsSync(cursorFile) ? readFileSync(cursorFile, "utf8").trim() : "");
          let total = 0;
          for (let page = 0; page < 20; page += 1) {
            const result = await client().readInbox(cursor || undefined, values.limit ? Number(values.limit) : undefined);
            if (result.events.length > 0) {
              const lines = result.events.map((event) => JSON.stringify(event)).join("\n");
              if (values.exec) {
                const code = await runHook(values.exec, `${lines}\n`, { ...io.env, HUB_EVENT_COUNT: String(result.events.length) });
                if (code !== 0) {
                  io.stderr(`hook exited ${code}; cursor not advanced\n`);
                  return EXIT.error;
                }
              } else {
                io.stdout(`${lines}\n`);
              }
              total += result.events.length;
            }
            if (result.cursor !== cursor) {
              writePrivate(cursorFile, result.cursor);
              cursor = result.cursor;
            }
            if (!result.has_more) break;
          }
          return total > 0 ? EXIT.ok : EXIT.nothingNew;
        } finally {
          release();
        }
      }
      case "install-poller":
      case "uninstall-poller": {
        const { values } = parseArgs({ args: [...rest], options: { "every-minutes": { type: "string" }, exec: { type: "string" }, "cursor-file": { type: "string" }, print: { type: "boolean" }, bin: { type: "string" } }, strict: true });
        const marker = `# ${defaults.cronMarker ?? "agent-aggregator-poller"}`;
        const minutes = Math.max(1, Math.min(Number(values["every-minutes"] ?? 1), 59));
        const bin = values.bin ?? defaults.command;
        const cursorFile = values["cursor-file"] ?? join(defaults.configDir, "inbox.cursor");
        const log = join(defaults.configDir, "poller.log");
        const quote = (value: string) => `'${value.replace(/'/g, `'\\''`)}'`;
        const line = `${minutes === 1 ? "*" : `*/${minutes}`} * * * * ${bin} inbox --cursor-file ${quote(cursorFile)}${values.exec ? ` --exec ${quote(values.exec)}` : ""} >> ${quote(log)} 2>&1 ${marker}`;
        if (values.print) {
          out(line);
          return EXIT.ok;
        }
        const current = spawnSync("crontab", ["-l"], { encoding: "utf8" });
        const existing = current.status === 0 ? current.stdout : "";
        const kept = existing.split("\n").filter((entry) => entry.trim() && !entry.includes(marker));
        const next = command === "install-poller" ? [...kept, line] : kept;
        const write = spawnSync("crontab", ["-"], { input: `${next.join("\n")}\n`, encoding: "utf8" });
        if (write.status !== 0) {
          io.stderr(`crontab failed: ${write.stderr || "not available"}\nAdd this line with your scheduler instead:\n${line}\n`);
          return EXIT.error;
        }
        out({ ok: true, installed: command === "install-poller", entry: command === "install-poller" ? line : null });
        return EXIT.ok;
      }
      case "handoff": {
        const { values } = parseArgs({ args: [...rest], options: { goal: { type: "string" }, key: { type: "string" }, context: { type: "string" }, criteria: { type: "string" }, item: { type: "string" } }, strict: true });
        if (!values.goal) throw new UsageError("handoff needs --goal");
        out(await client().handoffGoal({ goal: values.goal, idempotency_key: values.key, context: values.context, success_criteria: values.criteria, work_item_id: values.item }));
        return EXIT.ok;
      }
      case "job": {
        const { values } = parseArgs({ args: [...rest], options: { id: { type: "string" }, wait: { type: "string" }, interval: { type: "string" } }, strict: true });
        if (!values.id) throw new UsageError("job needs --id");
        const deadline = Date.now() + Math.max(0, Number(values.wait ?? 0)) * 1000;
        const interval = Math.max(2, Number(values.interval ?? 5)) * 1000;
        for (;;) {
          const { job } = await client().getJob(values.id);
          if (["done", "declined", "cancelled", "failed"].includes(job.status)) {
            out(job);
            return EXIT.ok;
          }
          if (Date.now() + interval > deadline) {
            out(job);
            return EXIT.nothingNew;
          }
          await sleep(interval);
        }
      }
      case "webhook": {
        const [sub, ...args] = rest;
        const { values } = parseArgs({ args, options: { url: { type: "string" }, header: { type: "string" }, value: { type: "string" } }, strict: true });
        if (sub === "set") {
          if (!values.url) throw new UsageError("webhook set needs --url");
          out(await client().setWebhook({ url: values.url, auth_header_name: values.header, auth_header_value: values.value }));
          return EXIT.ok;
        }
        if (sub === "clear") {
          out(await client().clearWebhook());
          return EXIT.ok;
        }
        throw new UsageError("webhook needs set or clear");
      }
      default:
        throw new UsageError(`unknown command: ${command}`);
    }
  } catch (error) {
    if (error instanceof UsageError || (error instanceof TypeError && /parseArgs|Unknown option|option/i.test(error.message))) {
      io.stderr(`${error.message}\nRun '${defaults.command} help' for usage.\n`);
      return EXIT.usage;
    }
    if (error instanceof AggregatorApiError) {
      io.stderr(`${JSON.stringify({ error: { status: error.status, code: error.code, message: error.message } })}\n`);
      return error.status === 401 ? EXIT.auth : EXIT.error;
    }
    if (error instanceof SyntaxError) {
      io.stderr(`invalid JSON: ${error.message}\n`);
      return EXIT.usage;
    }
    io.stderr(`${error instanceof Error ? error.message : String(error)}\n`);
    return EXIT.error;
  }
}

export function defaultConfigDir(appName: string): string {
  const base = process.env.XDG_CONFIG_HOME || join(homedir(), ".config");
  return join(base, appName);
}
