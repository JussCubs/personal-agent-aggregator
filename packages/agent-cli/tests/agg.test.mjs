import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const BIN = fileURLToPath(new URL("../bin/agg.js", import.meta.url));
const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

function agg(args, env = {}) {
  return new Promise((resolve) => {
    const clean = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("AGG_")));
    const child = spawn(process.execPath, [BIN, ...args], { env: { ...clean, ...env }, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c) => (stdout += c));
    child.stderr.on("data", (c) => (stderr += c));
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

test("agg: help, usage errors and neutral defaults", async () => {
  const home = mkdtempSync(join(tmpdir(), "agg-cli-"));
  const help = await agg(["help"], { XDG_CONFIG_HOME: home });
  assert.equal(help.code, 0);
  assert.match(help.stdout, /^Usage: agg <command>/);
  assert.match(help.stdout, /AGG_TOKEN, AGG_URL override the stored config/);
  assert.equal((await agg([], { XDG_CONFIG_HOME: home })).code, 2, "no command is a usage error");
  assert.equal((await agg(["bogus"], { XDG_CONFIG_HOME: home })).code, 2);
  assert.equal((await agg(["doctor"], { XDG_CONFIG_HOME: home })).code, 2, "no server configured");
  const noToken = await agg(["doctor"], { XDG_CONFIG_HOME: home, AGG_URL: "http://127.0.0.1:9/api" });
  assert.equal(noToken.code, 4, "no credential");
  assert.match(noToken.stderr, /agg setup --claim CODE/);
});

test("agg: setup stores the credential under $XDG_CONFIG_HOME/agent-aggregator and sends its user agent", async (t) => {
  const seen = [];
  const server = createServer((req, res) => {
    seen.push({ method: req.method, url: req.url, ua: req.headers["user-agent"], auth: req.headers.authorization });
    res.setHeader("content-type", "application/json");
    if (req.url === "/api/v1/claim") {
      res.end(JSON.stringify({ token: `agg_${"t".repeat(43)}`, connection: { id: "c", provider: "p", display_name: "d", mode: "cli_poll" }, scopes: ["hub:read"] }));
      return;
    }
    if (req.url === "/api/v1/me") {
      res.end(JSON.stringify({ connection_id: "c", mode: "cli_poll", scopes: ["hub:read"] }));
      return;
    }
    res.statusCode = 404;
    res.end("{}");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}/api`;
  const home = mkdtempSync(join(tmpdir(), "agg-cli-"));
  const setup = await agg(["setup", "--claim", "ABCDE-FGHJK-MNPQR-STVWX", "--server", base], { XDG_CONFIG_HOME: home });
  assert.equal(setup.code, 0, setup.stderr);
  const file = join(home, "agent-aggregator", "hub.json");
  assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.equal(JSON.parse(readFileSync(file, "utf8")).server, base);
  assert.ok(!setup.stdout.includes("tttt"), "the credential is stored, not printed");
  const doctor = await agg(["doctor"], { XDG_CONFIG_HOME: home });
  assert.equal(doctor.code, 0);
  assert.equal(seen.at(-1).auth, `Bearer agg_${"t".repeat(43)}`);
  assert.ok(seen.every((r) => r.ua === `agent-aggregator-cli/${version}`), "every request sends the CLI user agent");
  const printed = await agg(["setup", "--claim", "ABCDE-FGHJK-MNPQR-STVWX", "--server", base, "--print-token"], { XDG_CONFIG_HOME: mkdtempSync(join(tmpdir(), "agg-cli-")) });
  assert.equal(printed.stdout.trim(), `agg_${"t".repeat(43)}`, "--print-token prints only the credential");
  const poller = await agg(["install-poller", "--print"], { XDG_CONFIG_HOME: home });
  assert.match(poller.stdout, /^\* \* \* \* \* agg inbox --cursor-file '.*agent-aggregator\/inbox\.cursor' >> '.*poller\.log' 2>&1 # agent-aggregator-poller$/m);
});

test("agg: messages, working, reply, say and ask --thread speak the conversation API with documented exit codes", async (t) => {
  const seen = [];
  let open = [{ id: "11111111-1111-4111-8111-111111111111", thread_id: "22222222-2222-4222-8222-222222222222", direction: "to_agent", status: "delivered", text: "Rebook the 9:05" }];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : null;
      const url = new URL(req.url, "http://x");
      seen.push({ method: req.method, path: url.pathname, query: Object.fromEntries(url.searchParams), body });
      res.setHeader("content-type", "application/json");
      if (req.method === "GET" && url.pathname === "/api/v1/messages") return res.end(JSON.stringify({ messages: open }));
      if (req.method === "POST" && /^\/api\/v1\/messages\/[0-9a-f-]{36}\/ack$/.test(url.pathname)) return res.end(JSON.stringify({ message: { ...open[0], status: "working" } }));
      if (req.method === "POST" && url.pathname === "/api/v1/messages") {
        open = [];
        res.statusCode = 201;
        return res.end(JSON.stringify({ message: { id: "33333333-3333-4333-8333-333333333333", ...body }, thread: { id: "22222222-2222-4222-8222-222222222222" }, created: true }));
      }
      if (req.method === "POST" && url.pathname === "/api/v1/questions") return res.end(JSON.stringify({ question: { id: body.id, thread_id: body.thread_id }, created: true, revised: false }));
      res.statusCode = 404;
      res.end("{}");
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const env = { XDG_CONFIG_HOME: mkdtempSync(join(tmpdir(), "agg-cli-")), AGG_URL: `http://127.0.0.1:${server.address().port}/api`, AGG_TOKEN: `agg_${"t".repeat(43)}` };
  const id = open[0].id;
  const thread = open[0].thread_id;

  const help = await agg(["help"], env);
  for (const line of [/messages \[--thread ID\]/, /working --id MESSAGE_ID/, /reply --to MESSAGE_ID --text TEXT/, /say --text TEXT \[--thread ID\]/, /ask .*\[--thread ID\]/]) assert.match(help.stdout, line);

  const listed = await agg(["messages", "--thread", thread], env);
  assert.equal(listed.code, 0, "open messages exit 0");
  assert.equal(JSON.parse(listed.stdout.trim()).text, "Rebook the 9:05");
  assert.deepEqual(seen.at(-1).query, { thread_id: thread });
  assert.equal((await agg(["working", "--id", id], env)).code, 0);
  assert.deepEqual([seen.at(-1).method, seen.at(-1).path], ["POST", `/api/v1/messages/${id}/ack`]);
  assert.equal((await agg(["reply", "--to", id, "--text", "Comparing fares", "--progress"], env)).code, 0);
  assert.deepEqual(seen.at(-1).body, { text: "Comparing fares", reply_to: id, kind: "progress" });
  assert.equal((await agg(["reply", "--to", id, "--text", "Rebooked on the 11:40", "--id", "reply-1"], env)).code, 0);
  assert.deepEqual(seen.at(-1).body, { text: "Rebooked on the 11:40", id: "reply-1", reply_to: id, kind: "reply" });
  assert.equal((await agg(["messages"], env)).code, 3, "nothing open exits 3");
  assert.equal((await agg(["say", "--text", "Heads up: fares dropped", "--thread", thread], env)).code, 0);
  assert.deepEqual(seen.at(-1).body, { text: "Heads up: fares dropped", thread_id: thread });
  assert.equal((await agg(["ask", "--id", "q-seat", "--prompt", "Window or aisle?", "--option", "w=Window", "--thread", thread], env)).code, 0);
  assert.equal(seen.at(-1).body.thread_id, thread);
  assert.equal((await agg(["reply", "--text", "no target"], env)).code, 2, "reply needs --to");
  assert.equal((await agg(["working"], env)).code, 2, "working needs --id");
  assert.equal((await agg(["say"], env)).code, 2, "say needs --text");
});
