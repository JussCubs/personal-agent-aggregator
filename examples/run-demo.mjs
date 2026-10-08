// npm run demo: runs the three wake-mode examples against fresh local
// reference servers (SQLite, AGG_ALLOW_PRIVATE_CALLBACKS=1) and prints one
// PASS/FAIL table. Exit code 0 only if every step passed. No network access
// beyond 127.0.0.1 and no language-model calls.
import { run as cliPoll, NAME as CLI_POLL } from "./cli-poll/run.mjs";
import { Checklist, StepFailed, printTable } from "./lib/harness.mjs";
import { run as mcpWebhook, NAME as MCP_WEBHOOK } from "./mcp-webhook/run.mjs";
import { run as oauthEvents, NAME as OAUTH_EVENTS } from "./oauth-events/run.mjs";

const examples = [
  [MCP_WEBHOOK, mcpWebhook],
  [OAUTH_EVENTS, oauthEvents],
  [CLI_POLL, cliPoll],
];

const rows = [];
const summary = [];
for (const [name, fn] of examples) {
  const check = new Checklist(name);
  let ok = true;
  try {
    await fn(check);
  } catch (error) {
    ok = false;
    if (!(error instanceof StepFailed)) check.rows.push({ example: name, step: "unexpected error", result: "FAIL", ms: 0, detail: error instanceof Error ? error.stack ?? error.message : String(error) });
  }
  const failed = check.rows.filter((row) => row.result === "FAIL").length;
  rows.push(...check.rows);
  summary.push({ name, ok: ok && failed === 0, passed: check.rows.length - failed, failed });
}

console.log(printTable(rows));
console.log("");
for (const entry of summary) console.log(`${entry.ok ? "PASS" : "FAIL"}  ${entry.name}: ${entry.passed} passed, ${entry.failed} failed`);
const failed = rows.filter((row) => row.result === "FAIL").length;
const allOk = summary.every((entry) => entry.ok);
console.log(`\n${allOk ? "PASS" : "FAIL"}: ${rows.length} checks, ${rows.length - failed} passed, ${failed} failed`);
process.exitCode = allOk ? 0 : 1;
