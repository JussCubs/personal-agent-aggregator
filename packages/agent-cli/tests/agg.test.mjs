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
