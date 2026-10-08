import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createAggregatorServer, createOwner, loadConfig, silentLogger } from "@agent-aggregator/server";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const POLL = join(ROOT, "scripts/poll-inbox.sh");
const INSTALL = join(ROOT, "scripts/install-poller.sh");

function sh(script, args, env) {
  return new Promise((resolve) => {
    const clean = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("AGG_")));
    const child = spawn("sh", [script, ...args], { env: { ...clean, ...env }, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c) => (stdout += c));
    child.stderr.on("data", (c) => (stderr += c));
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

async function stack(t) {
  const dir = mkdtempSync(join(tmpdir(), "agg-scripts-"));
  const config = loadConfig({ AGG_SQLITE_PATH: join(dir, "agg.db"), AGG_ENCRYPTION_KEY: randomBytes(32).toString("hex"), AGG_PORT: "0" });
  const server = await createAggregatorServer(config, { logger: silentLogger, worker: false });
  const url = await server.listen();
  t.after(() => server.close());
  const { credential } = await createOwner(server.storage.driver, "Owner");
  const owner = async (method, path, body) => {
    const res = await fetch(`${url}${path}`, { method, headers: { authorization: `Bearer ${credential}`, "content-type": "application/json" }, body: body && JSON.stringify(body) });
    return await res.json();
  };
  const { connection } = await owner("POST", "/owner/connections", { provider: "shell_agent", display_name: "Shell", mode: "cli_poll" });
  const { token } = await owner("POST", `/owner/connections/${connection.id}/credential`, {});
  const agent = async (method, path, body) => {
    const res = await fetch(`${url}/api/v1${path}`, { method, headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: body && JSON.stringify(body) });
    return await res.json();
  };
  return { dir, url, api: `${url}/api`, token, owner, agent, connection };
}

test("poll-inbox.sh: exit codes, cursor, hook semantics, paging, lock", async (t) => {
  const s = await stack(t);
  const env = { AGG_URL: s.api, AGG_TOKEN: s.token, XDG_CONFIG_HOME: join(s.dir, "cfg") };
  assert.equal((await sh(POLL, [], { ...env, AGG_URL: "" })).code, 1, "AGG_URL missing");
  assert.equal((await sh(POLL, [], { ...env, AGG_TOKEN: "" })).code, 4, "token missing");
  assert.equal((await sh(POLL, [], { ...env, AGG_TOKEN: `agg_${"z".repeat(43)}` })).code, 4, "token rejected");
  assert.equal((await sh(POLL, [], { ...env, AGG_POLL_LIMIT: "500" })).code, 1, "limit out of range");
  const first = await sh(POLL, [], env);
  assert.equal(first.code, 3, `nothing new yet: ${first.stderr}`);
  assert.ok(existsSync(join(s.dir, "cfg/agent-aggregator/inbox-sh.cursor")), "default cursor file");

  for (const id of ["q1", "q2", "q3"]) await s.agent("POST", "/questions", { id, prompt: `Question ${id}?`, options: ["yes"] });
  for (const id of ["q1", "q2", "q3"]) await s.owner("POST", `/owner/connections/${s.connection.id}/questions/${id}/answer`, { revision: 1, choice: "opt_1" });

  const cursor = join(s.dir, "custom.cursor");
  const failing = await sh(POLL, [cursor], { ...env, AGG_POLL_EXEC: "cat >/dev/null; exit 9" });
  assert.equal(failing.code, 1);
  assert.match(failing.stderr, /hook exited 9; cursor not advanced/);
  assert.ok(!existsSync(cursor), "cursor not written when the hook fails");

  const out = join(s.dir, "pages.jsonl");
  const paged = await sh(POLL, [cursor], { ...env, AGG_POLL_LIMIT: "1", AGG_POLL_EXEC: `cat >> '${out}'` });
  assert.equal(paged.code, 0, paged.stderr);
  const pages = readFileSync(out, "utf8").trim().split("\n").map((line) => JSON.parse(line));
  assert.equal(pages.length, 3, "one page per event with AGG_POLL_LIMIT=1");
  assert.deepEqual(pages.map((p) => p.events[0].data.question_id), ["q1", "q2", "q3"]);
  assert.equal(readFileSync(cursor, "utf8"), pages.at(-1).cursor, "cursor file holds the last page cursor");
  assert.equal((await sh(POLL, [cursor], env)).code, 3, "nothing new after the cursor");

  writeFileSync(cursor, "not-a-cursor");
  assert.equal((await sh(POLL, [cursor], env)).code, 1, "corrupt cursor file");
  writeFileSync(cursor, pages[0].cursor);
  const printed = await sh(POLL, [cursor], env);
  assert.equal(printed.code, 0);
  assert.deepEqual(JSON.parse(printed.stdout.trim()).events.map((e) => e.data.question_id), ["q2", "q3"], "without a hook, pages print to stdout");

  mkdirSync(`${cursor}.lock`);
  const locked = await sh(POLL, [cursor], env);
  assert.equal(locked.code, 3);
  assert.match(locked.stderr, /another run holds/);

  const envFile = join(s.dir, "poller.env");
  writeFileSync(envFile, `AGG_URL='${s.api}'\nAGG_TOKEN='${s.token}'\n`, { mode: 0o600 });
  assert.equal((await sh(POLL, [join(s.dir, "from-env-file.cursor")], { AGG_ENV_FILE: envFile, XDG_CONFIG_HOME: join(s.dir, "cfg") })).code, 0, "AGG_ENV_FILE supplies URL and token");
});

test("install-poller.sh: idempotent marked entry, permissions, uninstall, print", async () => {
  const dir = mkdtempSync(join(tmpdir(), "agg-cron-"));
  const tab = join(dir, "tab");
  const fake = join(dir, "crontab");
  writeFileSync(fake, `#!/bin/sh\nif [ "$1" = "-l" ]; then [ -f '${tab}' ] && cat '${tab}' || exit 1; else cat > '${tab}'; fi\n`);
  chmodSync(fake, 0o700);
  const env = { AGG_CRONTAB: fake, XDG_CONFIG_HOME: join(dir, "cfg") };
  const envFile = join(dir, "cfg/agent-aggregator/poller.env");
  assert.equal((await sh(INSTALL, [], env)).code, 1, "env file missing");
  mkdirSync(join(dir, "cfg/agent-aggregator"), { recursive: true });
  writeFileSync(envFile, "AGG_URL=x\nAGG_TOKEN=y\n", { mode: 0o644 });
  chmodSync(envFile, 0o644);
  const loose = await sh(INSTALL, [], env);
  assert.equal(loose.code, 1);
  assert.match(loose.stderr, /readable by other users/);
  chmodSync(envFile, 0o600);
  writeFileSync(tab, "0 3 * * * /usr/local/bin/nightly\n");
  assert.equal((await sh(INSTALL, ["--every-minutes", "5", "--exec", "wake 'worker'"], env)).code, 0);
  assert.equal((await sh(INSTALL, ["--every-minutes", "2"], env)).code, 0);
  const lines = readFileSync(tab, "utf8").trim().split("\n");
  assert.equal(lines.length, 2, "re-running replaces the entry");
  assert.equal(lines[0], "0 3 * * * /usr/local/bin/nightly");
  assert.match(lines[1], /^\*\/2 \* \* \* \* AGG_ENV_FILE='.*poller\.env' '.*\/scripts\/poll-inbox\.sh' >> '.*poll-inbox\.log' 2>&1 # agent-aggregator-poll-inbox$/);
  const printed = await sh(INSTALL, ["--print", "--exec", "it's"], env);
  assert.match(printed.stdout, /AGG_POLL_EXEC='it'\\''s'/, "single quotes are escaped for sh");
  assert.equal((await sh(INSTALL, ["--exec", "100%"], env)).code, 2, "% is refused (cron newline)");
  assert.equal((await sh(INSTALL, ["--every-minutes", "60"], env)).code, 2);
  assert.equal((await sh(INSTALL, ["--uninstall"], env)).code, 0);
  assert.equal(readFileSync(tab, "utf8").trim(), "0 3 * * * /usr/local/bin/nightly");
  assert.equal((await sh(INSTALL, [], { ...env, AGG_CRONTAB: join(dir, "missing-crontab") })).code, 1, "no crontab available");
});
