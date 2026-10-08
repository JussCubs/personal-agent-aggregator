import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";
import postgres from "postgres";
import { createAggregatorServer, createOwner, loadConfig, silentLogger } from "@agent-aggregator/server";

/**
 * Runs scripts/verify-rls.sql (the script the playbooks tell operators to run)
 * against a freshly migrated database with two owners' data in it, and
 * requires every check to read PASS. Requires AGG_TEST_DATABASE_URL.
 */
const url = process.env.AGG_TEST_DATABASE_URL;
const SCRIPT = readFileSync(fileURLToPath(new URL("../scripts/verify-rls.sql", import.meta.url)), "utf8");

test("scripts/verify-rls.sql passes on a migrated database with data", { skip: !url }, async (t) => {
  const database = `agg_verify_${randomBytes(4).toString("hex")}`;
  const admin = postgres(url, { max: 1, onnotice: () => {} });
  await admin.unsafe(`CREATE DATABASE ${database}`);
  t.after(async () => {
    await admin.unsafe(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    await admin.end({ timeout: 5 });
  });
  const target = new URL(url);
  target.pathname = `/${database}`;

  const server = await createAggregatorServer(loadConfig({ AGG_DATABASE_URL: target.toString(), AGG_ENCRYPTION_KEY: randomBytes(32).toString("hex"), AGG_PORT: "0", AGG_ALLOW_PRIVATE_CALLBACKS: "1" }), { logger: silentLogger, worker: false });
  try {
    for (const name of ["Owner A", "Owner B"]) {
      const { owner } = await createOwner(server.storage.driver, name);
      const principal = { kind: "owner", ownerId: owner.id, name, surface: "test" };
      const connection = await server.service.createConnection(principal, { provider: "test_agent", display_name: `${name} agent`, mode: "cli_poll" });
      const { token } = await server.service.issueAgentCredential(principal, connection.id);
      const agent = await server.service.authenticate(token);
      await server.service.upsertWorkItem(agent, { id: "t1", kind: "task", title: `${name} task` });
      await server.service.createQuestion(agent, { id: "q1", prompt: "Proceed?", options: ["yes"] });
      await server.service.handoffJob(agent, { goal: "Do the thing" });
      await server.service.setWebhook(agent, { url: "http://127.0.0.1:9/hook", auth_header_value: "k" });
    }
  } finally {
    await server.close();
  }

  const sql = postgres(target.toString(), { max: 1, onnotice: () => {} });
  try {
    const results = await sql.unsafe(SCRIPT);
    const checks = results.flat().filter((row) => row && typeof row.result === "string");
    assert.equal(checks.length, 9, "nine checks");
    for (const row of checks) assert.equal(row.result, "PASS", `${row.check_name}: ${row.detail}`);
    t.diagnostic(checks.map((row) => `${row.check_name}: ${row.detail}`).join(" | "));
  } finally {
    await sql.end({ timeout: 5 });
  }
});
