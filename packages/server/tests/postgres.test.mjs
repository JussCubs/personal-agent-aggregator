import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import postgres from "postgres";
import { loadStorageConfig, openStorage, runDoctor } from "../dist/index.js";
import { request, startServer } from "./helpers.mjs";

/**
 * The reference server on Postgres: migrate, owner bootstrap (owners table
 * under FORCE RLS, reached through privileged()), a full agent round trip,
 * and the doctor checks the deployment playbooks rely on. Runs in a fresh
 * schema; requires AGG_TEST_DATABASE_URL.
 */
const url = process.env.AGG_TEST_DATABASE_URL;

test("reference server on Postgres", { skip: !url }, async (t) => {
  const schema = `agg_srv_${randomBytes(4).toString("hex")}`;
  const admin = postgres(url, { max: 1, onnotice: () => {} });
  t.after(async () => {
    await admin.unsafe(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await admin.end({ timeout: 5 });
  });
  const ctx = await startServer({ AGG_SQLITE_PATH: undefined, AGG_DATABASE_URL: url, AGG_DB_SCHEMA: schema });
  t.after(() => ctx.close());

  const created = await ctx.ownerApi("POST", "/owner/connections", { provider: "shell_agent", display_name: "Shell agent", mode: "cli_poll" });
  assert.equal(created.status, 201);
  const id = created.json.connection.id;
  const code = (await ctx.ownerApi("POST", `/owner/connections/${id}/claim-code`, {})).json.code;
  const token = (await request(ctx.url, "POST", "/api/v1/claim", { body: { code } })).json.token;
  assert.equal((await request(ctx.url, "PUT", "/api/v1/work-items/task-1", { token, body: { kind: "task", title: "Pay invoice" } })).status, 200);
  assert.equal((await request(ctx.url, "POST", "/api/v1/checkpoints", { token, body: { id: "cp-1", work_item_id: "task-1", summary: "Invoice found" } })).status, 201);
  assert.equal((await request(ctx.url, "POST", "/api/v1/questions", { token, body: { id: "q-1", prompt: "Pay now?", options: ["yes", "no"] } })).status, 201);
  assert.equal((await ctx.ownerApi("POST", `/owner/connections/${id}/questions/q-1/answer`, { revision: 1, choice: "opt_1" })).status, 200);
  const inbox = await request(ctx.url, "GET", "/api/v1/inbox", { token });
  assert.equal(inbox.json.events[0].name, "answer.created");
  assert.equal((await request(ctx.url, "POST", "/api/v1/questions/q-1/ack", { token, body: { revision: 1 } })).status, 200);
  const items = await ctx.ownerApi("GET", "/owner/work-items");
  assert.equal(items.json.items.length, 1);

  const storageConfig = loadStorageConfig({ AGG_DATABASE_URL: url, AGG_DB_SCHEMA: schema });
  const storage = await openStorage(storageConfig);
  try {
    const checks = await runDoctor(storageConfig, storage);
    for (const check of checks) assert.equal(check.pass, true, `${check.name}: ${check.detail}`);
    t.diagnostic(checks.map((c) => `${c.name}: ${c.detail}`).join(" | "));
  } finally {
    await storage.close();
  }
});

test("reference server as a non-superuser role with BYPASSRLS and CREATEROLE (managed-Postgres shape)", { skip: !url }, async (t) => {
  const tag = randomBytes(4).toString("hex");
  const schema = `agg_srv_${tag}`;
  const role = `agg_api_${tag}`;
  const password = randomBytes(16).toString("hex");
  const admin = postgres(url, { max: 1, onnotice: () => {} });
  await admin.unsafe(`CREATE ROLE ${role} LOGIN BYPASSRLS CREATEROLE PASSWORD '${password}'`);
  await admin.unsafe(`CREATE SCHEMA ${schema} AUTHORIZATION ${role}`);
  // Supabase-style roles and a default that grants every new table to them; migrate must revoke these grants.
  for (const exposed of ["anon", "authenticated", "service_role"]) {
    await admin.unsafe(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${exposed}') THEN CREATE ROLE ${exposed} NOLOGIN; END IF; END $$`);
    await admin.unsafe(`GRANT USAGE ON SCHEMA ${schema} TO ${exposed}`);
  }
  await admin.unsafe(`ALTER DEFAULT PRIVILEGES FOR ROLE ${role} IN SCHEMA ${schema} GRANT ALL ON TABLES TO anon, authenticated, service_role`);
  // The NOLOGIN roles are cluster-wide; when another role created them earlier, that role (here the superuser) grants SET on them.
  for (const scoped of ["aggregator_agent", "aggregator_owner"]) {
    await admin.unsafe(`DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${scoped}') THEN EXECUTE 'GRANT ${scoped} TO ${role}'; END IF; END $$`);
  }
  t.after(async () => {
    await admin.unsafe(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await admin.unsafe(`DROP OWNED BY ${role}`).catch(() => {});
    await admin.unsafe(`DROP ROLE IF EXISTS ${role}`).catch(() => {});
    await admin.end({ timeout: 5 });
  });
  const appUrl = new URL(url);
  appUrl.username = role;
  appUrl.password = password;
  const ctx = await startServer({ AGG_SQLITE_PATH: undefined, AGG_DATABASE_URL: appUrl.toString(), AGG_DB_SCHEMA: schema });
  t.after(() => ctx.close());
  const created = await ctx.ownerApi("POST", "/owner/connections", { provider: "shell_agent", display_name: "Shell agent", mode: "cli_poll" });
  const token = (await ctx.ownerApi("POST", `/owner/connections/${created.json.connection.id}/credential`, {})).json.token;
  assert.equal((await request(ctx.url, "GET", "/api/v1/me", { token })).status, 200);
  const storageConfig = loadStorageConfig({ AGG_DATABASE_URL: appUrl.toString(), AGG_DB_SCHEMA: schema });
  const storage = await openStorage(storageConfig);
  try {
    const checks = await runDoctor(storageConfig, storage);
    for (const check of checks) assert.equal(check.pass, true, `${check.name}: ${check.detail}`);
    assert.match(checks.find((c) => c.name === "role_bypassrls").detail, /bypassrls=true superuser=false/);
    assert.match(checks.find((c) => c.name === "public_roles_revoked").detail, /privileges: none/);
  } finally {
    await storage.close();
  }
});
