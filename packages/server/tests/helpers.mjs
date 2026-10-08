import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { verifyWebhook } from "@agent-aggregator/core";
import { createAggregatorServer, createJsonLogger, createOwner, loadConfig } from "../dist/index.js";

/** Starts an in-process reference server on a free loopback port with a fresh SQLite file (or the given env). */
export async function startServer(extraEnv = {}, opts = {}) {
  const dir = mkdtempSync(join(tmpdir(), "agg-server-test-"));
  const env = {
    AGG_SQLITE_PATH: join(dir, "agg.db"),
    AGG_ENCRYPTION_KEY: randomBytes(32).toString("hex"),
    AGG_PORT: "0",
    AGG_ALLOW_PRIVATE_CALLBACKS: "1",
    ...extraEnv,
  };
  const logs = [];
  const logger = createJsonLogger((line) => logs.push(line));
  const server = await createAggregatorServer(loadConfig(env), { logger, worker: opts.worker ?? { deliverEveryMs: 100, sweepEveryMs: 60_000 }, ...(opts.hooks ? { hooks: opts.hooks } : {}), ...(opts.now ? { now: opts.now } : {}) });
  const url = await server.listen();
  const owner = await createOwner(server.storage.driver, "Test owner");
  const ownerApi = (method, path, body) => request(url, method, path, { token: owner.credential, body });
  return { dir, env, url, server, logs, owner, ownerApi, close: () => server.close() };
}

/** JSON request helper. Returns { status, headers, json, text }. */
export async function request(base, method, path, { token, body, headers = {}, form, redirect = "manual" } = {}) {
  const init = { method, headers: { ...headers }, redirect };
  if (token) init.headers.authorization = `Bearer ${token}`;
  if (form) {
    init.headers["content-type"] = "application/x-www-form-urlencoded";
    init.body = new URLSearchParams(form).toString();
  } else if (body !== undefined) {
    init.headers["content-type"] = "application/json";
    init.body = typeof body === "string" ? body : JSON.stringify(body);
  }
  const response = await fetch(`${base}${path}`, init);
  const text = await response.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: response.status, headers: response.headers, json, text };
}

export async function mcp(base, token, method, params = {}, { modern = false, id = 1 } = {}) {
  const meta = modern ? { _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" } } : {};
  const headers = modern ? { "mcp-protocol-version": "2026-07-28", "mcp-method": method } : {};
  return await request(base, "POST", "/mcp", { token, headers, body: { jsonrpc: "2.0", id, method, params: { ...params, ...meta } } });
}

/** A local receiver that verifies Standard Webhooks signatures and answers MCP verification challenges. */
export async function startReceiver(secretRef) {
  const received = [];
  const waiters = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      const secret = secretRef.current;
      const valid = Boolean(secret) && verifyWebhook(secret, req.headers, body);
      if (!valid) {
        res.writeHead(401).end();
        return;
      }
      const json = JSON.parse(body);
      if (json.type === "verification") {
        res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ challenge: json.challenge }));
        return;
      }
      received.push({ headers: req.headers, json });
      res.writeHead(204).end();
      for (const waiter of waiters.splice(0)) waiter();
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}`;
  return {
    url,
    received,
    async waitFor(predicate, timeoutMs = 10_000) {
      const deadline = Date.now() + timeoutMs;
      for (;;) {
        const hit = received.find(predicate);
        if (hit) return hit;
        if (Date.now() > deadline) throw new Error("timed out waiting for a delivery");
        await new Promise((resolve) => {
          waiters.push(resolve);
          setTimeout(resolve, 200);
        });
      }
    },
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

export function pkcePair() {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}

/** Runs the whole OAuth dance through the HTML consent form. Returns the redirect target URL. */
export async function consentFlow(base, { clientId, redirectUri, challenge, state, ownerCredential, scope }) {
  const query = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: redirectUri, code_challenge: challenge, code_challenge_method: "S256", state, ...(scope ? { scope } : {}) });
  const start = await request(base, "GET", `/oauth/authorize?${query}`);
  if (start.status !== 303) throw new Error(`authorize returned ${start.status}: ${start.text.slice(0, 200)}`);
  const page = await request(base, "GET", start.headers.get("location"));
  const cookie = page.headers.get("set-cookie").split(";")[0];
  const field = (name) => new RegExp(`name="${name}" value="([^"]+)"`).exec(page.text)?.[1];
  const post = await request(base, "POST", "/oauth/authorize", {
    headers: { cookie },
    form: { request_id: field("request_id"), csrf: field("csrf"), action: "approve", owner_credential: ownerCredential },
  });
  return { page, post, location: post.headers.get("location") };
}
