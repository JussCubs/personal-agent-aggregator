// Shared plumbing for the wake-mode examples: start a reference server on a
// fresh SQLite file, run the agg-owner / agg executables, receive signed
// deliveries, call MCP, and record PASS/FAIL steps. No language model is
// involved anywhere: every "agent" here is a deterministic script.
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath, pathToFileURL } from "node:url";
import { verifyWebhook } from "@agent-aggregator/core";

export const ROOT = fileURLToPath(new URL("../..", import.meta.url));
export const BIN = {
  server: join(ROOT, "packages/server/bin/agg-server.js"),
  owner: join(ROOT, "packages/server/bin/agg-owner.js"),
  agg: join(ROOT, "packages/agent-cli/bin/agg.js"),
};

export class StepFailed extends Error {}

/** Records each step as PASS or FAIL with its duration. The first failure stops the example. */
export class Checklist {
  constructor(example) {
    this.example = example;
    this.rows = [];
  }

  async step(name, fn) {
    const started = performance.now();
    try {
      const value = await fn();
      this.rows.push({ example: this.example, step: name, result: "PASS", ms: Math.round(performance.now() - started) });
      return value;
    } catch (error) {
      this.rows.push({ example: this.example, step: name, result: "FAIL", ms: Math.round(performance.now() - started), detail: error instanceof Error ? error.message : String(error) });
      throw new StepFailed(name);
    }
  }
}

export function expect(condition, message) {
  if (!condition) throw new Error(message);
}

export function expectEqual(actual, expected, what) {
  if (actual !== expected) throw new Error(`${what}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

/** Runs a Node executable and collects its output. */
export function run(bin, args, env, { input } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [bin, ...args], { env, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("error", reject);
    child.on("close", (code) => {
      const lines = stdout.trim().split("\n").filter(Boolean);
      let json = null;
      try {
        json = lines.length ? JSON.parse(lines.at(-1)) : null;
      } catch {
        json = null;
      }
      resolve({ code, stdout, stderr, json });
    });
    child.stdin.end(input ?? "");
  });
}

/** Runs a command and requires a specific exit code. */
export async function runExpect(bin, args, env, code, opts) {
  const result = await run(bin, args, env, opts);
  if (result.code !== code) throw new Error(`${args.slice(0, 2).join(" ")} exited ${result.code}, expected ${code}: ${(result.stderr || result.stdout).trim().slice(0, 300)}`);
  return result;
}

function baseEnv(dir) {
  const env = {};
  // Start from a clean environment so a developer's own AGG_* settings never leak into the demo.
  for (const [key, value] of Object.entries(process.env)) if (!key.startsWith("AGG_") && key !== "XDG_CONFIG_HOME") env[key] = value;
  return {
    ...env,
    AGG_SQLITE_PATH: join(dir, "aggregator.db"),
    AGG_ENCRYPTION_KEY: randomBytes(32).toString("hex"),
    AGG_HOST: "127.0.0.1",
    AGG_PORT: "0",
    AGG_ALLOW_PRIVATE_CALLBACKS: "1",
    XDG_CONFIG_HOME: join(dir, "config"),
  };
}

/**
 * Starts `agg-server` on a fresh SQLite file and a free loopback port, then
 * bootstraps the owner with `agg-owner init --save`.
 */
export async function startStack(name) {
  const dir = mkdtempSync(join(tmpdir(), `agg-example-${name}-`));
  const env = baseEnv(dir);
  const logs = [];
  const child = spawn(process.execPath, [BIN.server], { env, stdio: ["ignore", "pipe", "pipe"] });
  const url = await new Promise((resolve, reject) => {
    let buffer = "";
    const timer = setTimeout(() => reject(new Error(`agg-server did not start: ${buffer.slice(0, 500)}`)), 15_000);
    child.stdout.on("data", (chunk) => {
      buffer += chunk;
      let index;
      while ((index = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 1);
        logs.push(line);
        try {
          const entry = JSON.parse(line);
          if (entry.msg === "listening") {
            clearTimeout(timer);
            resolve(entry.url);
          }
        } catch {
          // non-JSON output is kept in logs for the secrets check
        }
      }
    });
    child.stderr.on("data", (chunk) => logs.push(String(chunk)));
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`agg-server exited with ${code}: ${logs.join("").slice(0, 500)}`));
    });
  });
  const ownerEnv = { ...env, AGG_OWNER_URL: url };
  const init = await runExpect(BIN.owner, ["init", "--name", "Example owner", "--save", "--server", url], ownerEnv, 0);
  const ownerFile = init.json.stored;
  const ownerCredential = JSON.parse(readFileSync(ownerFile, "utf8")).token;
  return {
    dir,
    env,
    url,
    logs,
    ownerCredential,
    owner: (args, code = 0) => runExpect(BIN.owner, args, ownerEnv, code),
    agg: (args, code = 0, opts) => runExpect(BIN.agg, args, env, code, opts),
    async stop() {
      if (child.exitCode === null) {
        const exited = new Promise((resolve) => child.once("exit", resolve));
        child.kill("SIGTERM");
        await exited;
      }
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

/** Polls `fn` until it returns a truthy value (returned) or the timeout passes. */
export async function eventually(fn, what, timeoutMs = 10_000, intervalMs = 200) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await fn();
    if (value) return value;
    if (Date.now() > deadline) throw new Error(`timed out after ${timeoutMs} ms waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}

/** The owner's view of one thread (`agg-owner thread`): the message with this id, or undefined. */
export async function ownerMessage(stack, connectionId, ref, messageId) {
  const res = await stack.owner(["thread", connectionId, ref]);
  return res.json.messages.find((m) => m.id === messageId);
}

/**
 * Checks what the server logged about a conversation: the status changes of
 * the owner's message, in order, and one message_posted line per agent post,
 * and that none of the given texts appear anywhere in the logs.
 */
export function assertConversationLogged(stack, messageId, statuses, texts) {
  const entries = stack.logs.flatMap((line) => {
    try {
      return [JSON.parse(line)];
    } catch {
      return [];
    }
  });
  const seen = entries.filter((e) => (e.msg === "message_status" || e.msg === "message_failed") && e.message_id === messageId).map((e) => e.status);
  expectEqual(seen.join(","), statuses.join(","), "logged status changes");
  const posts = entries.filter((e) => e.msg === "message_posted" && e.reply_to === messageId);
  expect(posts.length >= 1, "the agent's posts are logged");
  const all = stack.logs.join("\n");
  for (const text of texts) expect(!all.includes(text), `logs contain message text "${text.slice(0, 20)}"`);
  return `${seen.length} status lines, ${posts.length} posts, no message text`;
}

/** Fails if the server's logs contain any of the given secrets. */
export function assertLogsClean(stack, secrets) {
  const all = stack.logs.join("\n");
  expect(stack.logs.length > 0, "server produced no logs");
  for (const secret of secrets.filter(Boolean)) {
    expect(!all.includes(secret), `server logs contain a secret starting ${secret.slice(0, 8)}`);
  }
  expect(!/Bearer [A-Za-z0-9]/.test(all), "server logs contain an Authorization value");
  return `${stack.logs.length} log lines checked`;
}

/**
 * A local HTTPS-less receiver for the wake-up webhook / MCP event deliveries.
 * Every request must carry a valid Standard Webhooks signature for the
 * current secret; MCP verification challenges are echoed back.
 */
export async function startReceiver() {
  const state = { secret: null, received: [], rejected: 0, verifications: 0 };
  const waiters = new Set();
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      if (!state.secret || !verifyWebhook(state.secret, req.headers, body)) {
        state.rejected += 1;
        res.writeHead(401).end();
        return;
      }
      const json = JSON.parse(body);
      if (json.type === "verification") {
        state.verifications += 1;
        res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ challenge: json.challenge }));
        return;
      }
      // Deliveries are at-least-once: keep the first copy of each event id.
      if (!state.received.some((entry) => entry.json.eventId === json.eventId)) state.received.push({ path: req.url, headers: req.headers, body, json });
      res.writeHead(204).end();
      for (const wake of waiters) wake();
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}`;
  return {
    url,
    state,
    async waitFor(predicate, what, timeoutMs = 15_000) {
      const deadline = Date.now() + timeoutMs;
      for (;;) {
        const hit = state.received.find(predicate);
        if (hit) return hit;
        if (Date.now() > deadline) throw new Error(`timed out after ${timeoutMs} ms waiting for ${what}`);
        await new Promise((resolve) => {
          const wake = () => {
            waiters.delete(wake);
            resolve();
          };
          waiters.add(wake);
          setTimeout(wake, 250);
        });
      }
    },
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

/** One JSON-RPC request to the MCP endpoint, legacy (no headers) or 2026-07-28 (headers + _meta). */
export async function mcp(baseUrl, token, method, params = {}, { modern = false, id = Math.floor(Math.random() * 1e9) } = {}) {
  const headers = { "content-type": "application/json", accept: "application/json, text/event-stream" };
  if (token) headers.authorization = `Bearer ${token}`;
  let body = { jsonrpc: "2.0", id, method, params };
  if (modern) {
    headers["mcp-protocol-version"] = "2026-07-28";
    headers["mcp-method"] = method;
    if (typeof params.name === "string" && method === "tools/call") headers["mcp-name"] = params.name;
    body = { ...body, params: { ...params, _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientInfo": { name: "example-agent", version: "0.1.0" } } } };
  }
  const response = await fetch(`${baseUrl}/mcp`, { method: "POST", headers, body: JSON.stringify(body) });
  const text = await response.text();
  return { status: response.status, headers: response.headers, json: text ? JSON.parse(text) : null };
}

/** tools/call that must succeed; returns structuredContent. */
export async function tool(baseUrl, token, name, args = {}, opts = {}) {
  const res = await mcp(baseUrl, token, "tools/call", { name, arguments: args }, opts);
  expectEqual(res.status, 200, `${name} HTTP status`);
  const result = res.json.result;
  expect(result && result.isError === false, `${name} failed: ${JSON.stringify(res.json.result?.structuredContent ?? res.json.error)}`);
  return result.structuredContent;
}

/** A digest that binds an approval to the exact action (canonical JSON, SHA-256). */
export function actionDigest(action) {
  const canonical = JSON.stringify(Object.fromEntries(Object.entries(action).sort(([a], [b]) => (a < b ? -1 : 1))));
  return `sha256:${createHash("sha256").update(canonical).digest("hex")}`;
}

export function printTable(rows) {
  const headers = ["Wake mode", "Step", "Result", "ms"];
  const data = rows.map((r) => [r.example, r.step, r.result, String(r.ms)]);
  const widths = headers.map((h, i) => Math.max(h.length, ...data.map((row) => row[i].length)));
  const line = (cells) => cells.map((cell, i) => (i === 3 ? cell.padStart(widths[i]) : cell.padEnd(widths[i]))).join("  ");
  const out = [line(headers), widths.map((w) => "-".repeat(w)).join("  "), ...data.map(line)];
  for (const row of rows) if (row.result === "FAIL" && row.detail) out.push(`FAIL ${row.example} / ${row.step}: ${row.detail}`);
  return out.join("\n");
}

/** Lets each example run on its own: `node examples/<mode>/run.mjs`. */
export async function runStandalone(name, fn) {
  const check = new Checklist(name);
  let ok = true;
  try {
    await fn(check);
  } catch (error) {
    ok = false;
    if (!(error instanceof StepFailed)) check.rows.push({ example: name, step: "unexpected error", result: "FAIL", ms: 0, detail: error instanceof Error ? error.stack ?? error.message : String(error) });
  }
  console.log(printTable(check.rows));
  const failed = check.rows.filter((r) => r.result === "FAIL").length;
  console.log(`\n${check.rows.length} checks: ${check.rows.length - failed} passed, ${failed} failed`);
  process.exitCode = ok && failed === 0 ? 0 : 1;
}

/** True when the module is the entry point (`node examples/<mode>/run.mjs`). */
export function isMain(moduleUrl) {
  return Boolean(process.argv[1]) && pathToFileURL(process.argv[1]).href === moduleUrl;
}
