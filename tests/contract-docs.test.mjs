import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { EVENT_NAMES, TOOL_DEFINITIONS } from "@agent-aggregator/core";
import { OWNER_ROUTES } from "@agent-aggregator/server";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

test("docs/contract.md generated blocks match the code (run npm run docs:contract to update)", () => {
  const result = spawnSync(process.execPath, ["--experimental-sqlite", "scripts/gen-contract-docs.mjs", "--check"], { cwd: ROOT, encoding: "utf8" });
  assert.equal(result.status, 0, `${result.stderr}${result.stdout}`);
});

test("docs/contract.md names every MCP tool, event and owner route exactly once in its tables", () => {
  const doc = readFileSync(`${ROOT}docs/contract.md`, "utf8");
  for (const tool of TOOL_DEFINITIONS) assert.equal(doc.split(`| \`${tool.name}\` |`).length - 1, 1, tool.name);
  for (const name of EVENT_NAMES) assert.equal(doc.split(`| \`${name}\` |`).length - 1, 1, name);
  for (const route of OWNER_ROUTES) assert.ok(doc.includes(`| \`${route.method}\` | \`${route.path}\` |`), `${route.method} ${route.path}`);
});
