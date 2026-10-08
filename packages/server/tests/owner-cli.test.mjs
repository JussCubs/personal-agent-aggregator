import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { OWNER_EXIT, runOwnerCli } from "../dist/index.js";
import { startServer } from "./helpers.mjs";

function cli(env) {
  const stdout = [];
  const stderr = [];
  const run = async (...args) => {
    stdout.length = 0;
    stderr.length = 0;
    return await runOwnerCli(args, { stdout: (t) => stdout.push(t), stderr: (t) => stderr.push(t), env });
  };
  const json = () => JSON.parse(stdout.join("").trim().split("\n").at(-1));
  return { run, stdout, stderr, json };
}

test("agg-owner: bootstrap on SQLite, credential file, exit codes", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "agg-owner-"));
  const env = { AGG_SQLITE_PATH: join(dir, "agg.db"), XDG_CONFIG_HOME: join(dir, "config") };
  const c = cli(env);
  assert.equal(await c.run(), OWNER_EXIT.usage);
  assert.equal(await c.run("help"), OWNER_EXIT.ok);
  assert.equal(await c.run("bogus"), OWNER_EXIT.usage);
  assert.equal(await c.run("whoami"), OWNER_EXIT.auth, "no credential yet");

  assert.equal(await c.run("init", "--name", "Sam"), OWNER_EXIT.ok);
  const printed = c.json();
  assert.match(printed.credential, /^aggown_[A-Za-z0-9_-]{43}$/);
  assert.equal(await c.run("init", "--name", "Sam"), OWNER_EXIT.conflict, "a second owner needs --additional");
  assert.equal(await c.run("reset-credential", "--save", "--server", "http://127.0.0.1:1"), OWNER_EXIT.ok);
  const stored = JSON.parse(readFileSync(join(dir, "config", "agent-aggregator", "owner.json"), "utf8"));
  assert.match(stored.token, /^aggown_/);
  assert.notEqual(stored.token, printed.credential, "reset replaced the credential");
  assert.equal(statSync(join(dir, "config", "agent-aggregator", "owner.json")).mode & 0o777, 0o600);
  assert.ok(!c.stdout.join("").includes(stored.token), "--save does not print the credential");
  t.diagnostic(`owner ${printed.owner_id}`);
});

test("agg-owner against a live server: connect, answer, decide, conflicts", async (t) => {
  const ctx = await startServer();
  t.after(() => ctx.close());
  const c = cli({ AGG_OWNER_URL: ctx.url, AGG_OWNER_TOKEN: ctx.owner.credential, XDG_CONFIG_HOME: mkdtempSync(join(tmpdir(), "agg-owner-cfg-")) });
  assert.equal(await c.run("whoami"), OWNER_EXIT.ok);
  assert.equal(await c.run("connection", "create", "--provider", "shell_agent", "--name", "Shell agent", "--mode", "cli_poll"), OWNER_EXIT.ok);
  const connection = c.json().connection;
  assert.equal(await c.run("connection", "create", "--provider", "x"), OWNER_EXIT.usage);
  assert.equal(await c.run("questions"), OWNER_EXIT.empty);
  assert.equal(await c.run("credential", "issue", "--connection", connection.id), OWNER_EXIT.ok);
  const token = c.json().token;
  const api = (method, path, body) => fetch(`${ctx.url}/api/v1${path}`, { method, headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: body && JSON.stringify(body) }).then((r) => r.json());
  await api("POST", "/questions", { id: "q1", kind: "approval", prompt: "Send the invoice?", affected_action: "Email invoice 42", action_digest: "sha256:abc" });
  assert.equal(await c.run("questions"), OWNER_EXIT.ok);
  assert.equal(c.json().questions[0].question.id, "q1");
  await api("POST", "/questions", { id: "q1", kind: "approval", prompt: "Send the corrected invoice?", affected_action: "Email invoice 42b", action_digest: "sha256:def" });
  assert.equal(await c.run("answer", "--connection", connection.id, "--id", "q1", "--revision", "1", "--approve"), OWNER_EXIT.conflict, "stale revision exits 5");
  assert.match(c.stderr.join(""), /"code":"stale_revision"/);
  assert.equal(await c.run("answer", "--connection", connection.id, "--id", "q1", "--revision", "2", "--approve"), OWNER_EXIT.ok);
  assert.equal(c.json().question.answer.decision, "approved");
  assert.equal(await c.run("answer", "--connection", connection.id, "--id", "q1", "--revision", "2", "--deny"), OWNER_EXIT.conflict, "already answered exits 5");
  assert.equal(await c.run("answer", "--connection", connection.id, "--id", "q1"), OWNER_EXIT.usage);

  const { job } = await api("POST", "/jobs", { goal: "Draft the report", idempotency_key: "report-1" });
  assert.equal(await c.run("jobs"), OWNER_EXIT.ok);
  assert.equal(await c.run("job", "progress", "--connection", connection.id, "--id", job.id, "--status", "done"), OWNER_EXIT.conflict, "not approved yet");
  assert.equal(await c.run("job", "decide", "--connection", connection.id, "--id", job.id, "--approve"), OWNER_EXIT.ok);
  assert.equal(c.json().job.status, "running");
  assert.equal(await c.run("job", "progress", "--connection", connection.id, "--id", job.id, "--status", "done", "--summary", "Report drafted", "--result", '{"pages":3}'), OWNER_EXIT.ok);
  assert.equal(c.json().job.status, "done");
  assert.equal(await c.run("jobs"), OWNER_EXIT.empty, "no open jobs remain");
  assert.equal(await c.run("setup-prompt", "--connection", connection.id), OWNER_EXIT.ok);
  assert.match(c.stdout.join(""), /agg setup --claim/);
  assert.ok(!c.stdout.join("").includes(token), "the setup prompt never contains a credential");
  assert.equal(await c.run("audit", "--connection", connection.id), OWNER_EXIT.ok);
  assert.ok(c.json().entries.some((e) => e.action === "question.answer"));
  assert.equal(await c.run("connection", "delete", "--id", connection.id), OWNER_EXIT.usage, "delete needs --yes");
  assert.equal(await c.run("connection", "revoke", "--id", connection.id), OWNER_EXIT.ok);
  assert.equal((await fetch(`${ctx.url}/api/v1/me`, { headers: { authorization: `Bearer ${token}` } })).status, 401);
  assert.equal(await c.run("connection", "delete", "--id", connection.id, "--yes"), OWNER_EXIT.ok);
  assert.equal(c.json().deleted.questions, 1);

  const bad = cli({ AGG_OWNER_URL: ctx.url, AGG_OWNER_TOKEN: `aggown_${randomBytes(32).toString("base64url")}` });
  assert.equal(await bad.run("whoami"), OWNER_EXIT.auth);
});

test("agg-owner say and thread: message an agent, follow the thread, exit codes", async (t) => {
  const ctx = await startServer();
  t.after(() => ctx.close());
  const c = cli({ AGG_OWNER_URL: ctx.url, AGG_OWNER_TOKEN: ctx.owner.credential, XDG_CONFIG_HOME: mkdtempSync(join(tmpdir(), "agg-owner-cfg-")) });
  assert.equal(await c.run("connection", "create", "--provider", "shell_agent", "--name", "Shell agent", "--mode", "cli_poll"), OWNER_EXIT.ok);
  const connection = c.json().connection;
  assert.equal(await c.run("credential", "issue", "--connection", connection.id), OWNER_EXIT.ok);
  const token = c.json().token;
  const api = (method, path, body) => fetch(`${ctx.url}/api/v1${path}`, { method, headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: body && JSON.stringify(body) }).then((r) => r.json());

  assert.equal(await c.run("thread", connection.id, "trip"), OWNER_EXIT.empty, "an empty thread exits 3");
  assert.equal(await c.run("say", connection.id, "Find a hotel near the venue", "--thread", "trip", "--title", "Trip", "--key", "host-1"), OWNER_EXIT.ok);
  const sent = c.json();
  assert.equal(sent.created, true);
  assert.deepEqual([sent.message.status, sent.thread.ref, sent.thread.title], ["queued", "trip", "Trip"]);
  assert.equal(await c.run("say", "--connection", connection.id, "--text", "Find a hotel near the venue", "--thread", "trip", "--key", "host-1"), OWNER_EXIT.ok);
  assert.equal(c.json().created, false, "--key makes a retried say safe");
  assert.equal(await c.run("thread", connection.id, "trip", "--wait", "1", "--interval", "1"), OWNER_EXIT.empty, "--wait exits 3 while the agent has not answered");

  const { messages } = await api("GET", "/messages");
  await api("POST", "/messages", { reply_to: messages[0].id, text: "Booked the Lakeside, 2 nights" });
  assert.equal(await c.run("thread", "--connection", connection.id, "--thread", "trip", "--wait", "5"), OWNER_EXIT.ok);
  assert.deepEqual(c.json().messages.map((m) => [m.direction, m.status, m.text]), [
    ["to_agent", "replied", "Find a hotel near the venue"],
    ["from_agent", "posted", "Booked the Lakeside, 2 nights"],
  ]);
  assert.equal(await c.run("say", connection.id, "Default thread works too"), OWNER_EXIT.ok);
  assert.equal(c.json().thread.ref, "default");
  assert.equal(await c.run("thread", connection.id), OWNER_EXIT.ok);
  assert.equal(c.json().messages.length, 1);

  assert.equal(await c.run("say", connection.id), OWNER_EXIT.usage, "say needs text");
  assert.equal(await c.run("say", connection.id, "two", "texts"), OWNER_EXIT.usage, "unquoted text is refused");
  assert.equal(await c.run("say", connection.id, "x", "--connection", connection.id), OWNER_EXIT.usage, "connection given twice");
  assert.equal(await c.run("thread", connection.id, "trip", "--thread", "trip"), OWNER_EXIT.usage);

  assert.equal(await c.run("connection", "create", "--provider", "narrow_agent", "--name", "Narrow", "--mode", "cli_poll", "--scope", "hub:read"), OWNER_EXIT.ok);
  const narrow = c.json().connection;
  await c.run("credential", "issue", "--connection", narrow.id);
  assert.equal(await c.run("say", narrow.id, "hi"), OWNER_EXIT.conflict, "a connection without hub:chat exits 5");
});
