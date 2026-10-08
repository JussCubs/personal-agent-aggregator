import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import test from "node:test";
import postgres from "postgres";
import { AggregatorService, createAesGcmSecretBox, postgresSchemaSql } from "../dist/index.js";
import { createPostgresDriver } from "../dist/stores/postgres.js";

/**
 * Row-level security, proven against a real Postgres. The application role is
 * a non-superuser with BYPASSRLS and CREATEROLE (the shape of a managed
 * Postgres admin role). Scoped transactions switch to the NOLOGIN agent/owner
 * roles, where the policies — not the service's WHERE clauses — decide.
 */
const url = process.env.AGG_TEST_DATABASE_URL;

test("RLS isolates owners and connections in Postgres", { skip: !url }, async (t) => {
  const tag = randomBytes(4).toString("hex");
  const schema = `agg_rls_${tag}`;
  const prefix = `t${tag}_`;
  const appRole = `agg_app_${tag}`;
  const password = randomBytes(12).toString("hex");
  const admin = postgres(url, { max: 1, onnotice: () => {} });
  const counts = { checks: 0 };
  const check = (fn) => {
    counts.checks += 1;
    return fn();
  };
  await admin.unsafe(`CREATE ROLE ${appRole} LOGIN BYPASSRLS CREATEROLE PASSWORD '${password}'`);
  await admin.unsafe(`CREATE SCHEMA ${schema} AUTHORIZATION ${appRole}`);
  for (const role of ["anon", "authenticated"]) {
    await admin.unsafe(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${role}') THEN CREATE ROLE ${role} NOLOGIN; END IF; END $$`);
    await admin.unsafe(`GRANT USAGE ON SCHEMA ${schema} TO ${role}`);
  }
  // A managed-Postgres default that would otherwise expose new tables.
  await admin.unsafe(`ALTER DEFAULT PRIVILEGES FOR ROLE ${appRole} IN SCHEMA ${schema} GRANT ALL ON TABLES TO anon, authenticated`);
  const appUrl = new URL(url);
  appUrl.username = appRole;
  appUrl.password = password;
  const sql = postgres(appUrl.toString(), { max: 4, onnotice: () => {}, connection: { search_path: schema } });
  const schemaOpts = { prefix, schema };
  const driver = createPostgresDriver(sql, schemaOpts);
  const t_ = (name) => `${schema}.${prefix}${name}`;
  try {
    await driver.migrate();
    await driver.migrate(); // idempotent; second run is skipped by the version marker
    const service = new AggregatorService({ driver, prefix, secretBox: createAesGcmSecretBox(randomBytes(32).toString("hex")), outbound: { allowPrivateNetwork: true }, send: async () => ({ status: 200, body: "" }) });

    const ownerA = { kind: "owner", ownerId: randomUUID(), name: "A", surface: "test" };
    const ownerB = { kind: "owner", ownerId: randomUUID(), name: "B", surface: "test" };
    for (const o of [ownerA, ownerB]) await sql.unsafe(`INSERT INTO ${t_("owners")} (id, name) VALUES ($1, $2)`, [o.ownerId, o.name]);
    const make = async (o, name) => {
      const c = await service.createConnection(o, { provider: "test_agent", display_name: name, mode: "mcp_webhook" });
      const { token } = await service.issueAgentCredential(o, c.id);
      return { c, token, p: await service.authenticate(token) };
    };
    const a1 = await make(ownerA, "A1");
    const a2 = await make(ownerA, "A2");
    const b1 = await make(ownerB, "B1");
    await service.upsertWorkItem(a1.p, { id: "secret-task", kind: "task", title: "A1 private task" });
    await service.postCheckpoint(a1.p, { id: "cp", summary: "A1 progress" });
    await service.createQuestion(a1.p, { id: "q", prompt: "A1 private question", options: ["yes"] });
    await service.handoffJob(a1.p, { goal: "A1 goal" });
    await service.setWebhook(a1.p, { url: "http://127.0.0.1:9/h", auth_header_value: "k" });
    // Agent-initiated events fan out to the webhook inside the agent-scoped transaction.
    await service.handoffJob(a1.p, { goal: "A1 second goal" });

    const tables = ["work_items", "checkpoints", "questions", "jobs", "events", "destinations", "audit"];

    await t.test("another integration of the same owner cannot read or write", async () => {
      for (const table of tables) {
        const visible = await check(() =>
          driver.scoped({ role: "agent", ownerId: ownerA.ownerId, connectionId: a2.c.id }, (db) => db.query(`SELECT count(*) AS n FROM ${t_(table)} WHERE connection_id = $1`, [a1.c.id])),
        ).catch((error) => (/permission denied/.test(String(error)) ? [{ n: 0 }] : Promise.reject(error)));
        assert.equal(Number(visible[0].n), 0, `${table}: A2 sees none of A1's rows`);
      }
      await assert.rejects(
        check(() => driver.scoped({ role: "agent", ownerId: ownerA.ownerId, connectionId: a2.c.id }, (db) =>
          db.query(`INSERT INTO ${t_("work_items")} (owner_id, connection_id, id, kind, title, created_at, updated_at) VALUES ($1, $2, 'x', 'task', 'x', now(), now())`, [ownerA.ownerId, a1.c.id]))),
        /row-level security/,
      );
      const updated = await check(() => driver.scoped({ role: "agent", ownerId: ownerA.ownerId, connectionId: a2.c.id }, (db) =>
        db.query(`UPDATE ${t_("work_items")} SET title = 'pwned' WHERE connection_id = $1 RETURNING id`, [a1.c.id])));
      assert.equal(updated.length, 0);
      await assert.rejects(
        check(() => driver.scoped({ role: "agent", ownerId: ownerA.ownerId, connectionId: a2.c.id }, (db) => db.query(`DELETE FROM ${t_("questions")} WHERE connection_id = $1`, [a1.c.id]))),
        /permission denied/,
        "agents cannot delete questions at all",
      );
      const deletedItems = await check(() => driver.scoped({ role: "agent", ownerId: ownerA.ownerId, connectionId: a2.c.id }, (db) =>
        db.query(`DELETE FROM ${t_("work_items")} WHERE connection_id = $1 RETURNING id`, [a1.c.id])));
      assert.equal(deletedItems.length, 0, "A2 cannot delete A1's work items");
      const conn = await check(() => driver.scoped({ role: "agent", ownerId: ownerA.ownerId, connectionId: a2.c.id }, (db) => db.query(`SELECT id FROM ${t_("connections")}`)));
      assert.deepEqual(conn.map((r) => r.id), [a2.c.id], "an agent sees only its own connection row");
      await assert.rejects(check(() => service.getQuestion(a2.p, "q")), /not found/);
      await assert.rejects(check(() => service.getWorkItem(a2.p, "secret-task")), /not found/);
    });

    await t.test("another owner cannot read or write", async () => {
      for (const table of tables) {
        const asAgent = await check(() => driver.scoped({ role: "agent", ownerId: ownerB.ownerId, connectionId: b1.c.id }, (db) => db.query(`SELECT count(*) AS n FROM ${t_(table)} WHERE owner_id = $1`, [ownerA.ownerId])))
          .catch((error) => (/permission denied/.test(String(error)) ? [{ n: 0 }] : Promise.reject(error)));
        assert.equal(Number(asAgent[0].n), 0, `${table}: another owner's agent sees none of owner A's rows`);
        const leaked = await check(() => driver.scoped({ role: "owner", ownerId: ownerB.ownerId }, (db) => db.query(`SELECT count(*) AS n FROM ${t_(table)} WHERE owner_id = $1`, [ownerA.ownerId])));
        assert.equal(Number(leaked[0].n), 0, `${table}: owner B sees none of owner A's rows`);
      }
      const answer = await check(() => driver.scoped({ role: "owner", ownerId: ownerB.ownerId }, (db) =>
        db.query(`UPDATE ${t_("questions")} SET status = 'answered' WHERE owner_id = $1 RETURNING id`, [ownerA.ownerId])));
      assert.equal(answer.length, 0, "owner B cannot answer owner A's questions");
      await assert.rejects(
        check(() => driver.scoped({ role: "owner", ownerId: ownerB.ownerId }, (db) =>
          db.query(`INSERT INTO ${t_("connections")} (id, owner_id, provider, display_name, mode, status, created_at, updated_at) VALUES ($1, $2, 'x_y', 'x', 'cli_poll', 'active', now(), now())`, [randomUUID(), ownerA.ownerId]))),
        /row-level security/,
      );
      // Mixing owner B with owner A's connection id is rejected by the composite foreign key even where a policy would allow it.
      await assert.rejects(
        check(() => driver.scoped({ role: "owner", ownerId: ownerB.ownerId }, (db) =>
          db.query(`INSERT INTO ${t_("events")} (owner_id, connection_id, seq, id, name, data, created_at) VALUES ($1, $2, 999, 'evt_x', 'job.updated', '{}', now())`, [ownerB.ownerId, a1.c.id]))),
        /foreign key/,
      );
      await assert.rejects(check(() => service.getOwnerQuestion(ownerB, a1.c.id, "q")), /not found/);
      await assert.rejects(check(() => service.answerQuestion(ownerB, { connection_id: a1.c.id, question_id: "q", revision: 1, choice: "opt_1" })), /not found/);
    });

    await t.test("credentials and escalation paths are closed", async () => {
      await assert.rejects(check(() => driver.scoped({ role: "agent", ownerId: ownerA.ownerId, connectionId: a1.c.id }, (db) => db.query(`SELECT * FROM ${t_("credentials")}`))), /permission denied/);
      await assert.rejects(check(() => driver.scoped({ role: "owner", ownerId: ownerA.ownerId }, (db) => db.query(`SELECT secret_hash FROM ${t_("credentials")}`))), /permission denied/);
      await assert.rejects(check(() => driver.scoped({ role: "agent", ownerId: ownerA.ownerId, connectionId: a1.c.id }, (db) => db.query(`UPDATE ${t_("connections")} SET scopes = 'hub:read hub:write hub:ask hub:handoff', status = 'active' WHERE id = $1`, [a1.c.id]))), /permission denied/);
      await assert.rejects(check(() => driver.scoped({ role: "agent", ownerId: ownerA.ownerId, connectionId: a1.c.id }, (db) => db.query(`SELECT auth_header_value_enc FROM ${t_("destinations")}`))), /permission denied/);
      await assert.rejects(check(() => driver.scoped({ role: "agent", ownerId: ownerA.ownerId, connectionId: a1.c.id }, (db) => db.query(`SELECT * FROM ${t_("oauth_requests")}`))), /permission denied/);
      // Owner-only transitions cannot be forged by an agent even with raw SQL in its own scope.
      await assert.rejects(
        check(() => driver.scoped({ role: "agent", ownerId: ownerA.ownerId, connectionId: a1.c.id }, (db) => db.query(`UPDATE ${t_("jobs")} SET status = 'running', status_reason = 'approved_by_owner'`))),
        /may only cancel/,
      );
      await assert.rejects(
        check(() => driver.scoped({ role: "agent", ownerId: ownerA.ownerId, connectionId: a1.c.id }, (db) => db.query(`UPDATE ${t_("questions")} SET status = 'answered', answer = '{"decision":"approved"}'::jsonb`))),
        /may only revise or withdraw/,
      );
      const a1Destination = await admin.unsafe(`SELECT id FROM ${t_("destinations")} WHERE connection_id = $1 LIMIT 1`, [a1.c.id]);
      await assert.rejects(
        check(() => driver.scoped({ role: "agent", ownerId: ownerA.ownerId, connectionId: a2.c.id }, (db) =>
          db.query(`INSERT INTO ${t_("deliveries")} (id, owner_id, connection_id, destination_id, event_seq, status, attempts, next_attempt_at, created_at) VALUES ($1, $2, $3, $4, 1, 'pending', 0, now(), now())`, [randomUUID(), ownerA.ownerId, a2.c.id, a1Destination[0].id]))),
        /foreign key/,
        "a delivery cannot target a sibling connection's webhook",
      );
      // Conversation bridge: an agent cannot read a sibling's thread, forge the owner's side, or edit the owner's text.
      const toA1 = await service.sendMessage(ownerA, { connection_id: a1.c.id, thread_ref: "room-a", text: "private note for A1" });
      await assert.rejects(check(() => service.checkMessages(a2.p, { thread_id: toA1.thread.id }).then((r) => { if (r.messages.length) throw new Error("leak"); throw new Error("not found"); })), /not found/);
      await assert.rejects(
        check(() => driver.scoped({ role: "agent", ownerId: ownerA.ownerId, connectionId: a1.c.id }, (db) =>
          db.query(`INSERT INTO ${t_("messages")} (id, owner_id, connection_id, thread_id, direction, kind, body_enc, status, created_at, updated_at) VALUES ($1, $2, $3, $4, 'to_agent', 'message', 'x', 'queued', now(), now())`, [randomUUID(), ownerA.ownerId, a1.c.id, toA1.thread.id]))),
        /may only post their own messages/,
      );
      await assert.rejects(
        check(() => driver.scoped({ role: "agent", ownerId: ownerA.ownerId, connectionId: a1.c.id }, (db) => db.query(`UPDATE ${t_("messages")} SET body_enc = 'tampered' WHERE id = $1`, [toA1.message.id]))),
        /permission denied/,
      );
      const siblingView = await check(() => driver.scoped({ role: "agent", ownerId: ownerA.ownerId, connectionId: a2.c.id }, (db) => db.query(`SELECT count(*) AS n FROM ${t_("messages")}`)));
      assert.equal(Number(siblingView[0].n), 0, "a sibling connection sees none of A1's messages");
      const siblingThreads = await check(() => driver.scoped({ role: "agent", ownerId: ownerA.ownerId, connectionId: a2.c.id }, (db) => db.query(`SELECT count(*) AS n FROM ${t_("threads")}`)));
      assert.equal(Number(siblingThreads[0].n), 0, "a sibling connection sees none of A1's threads");
      const atRest = await check(() => admin.unsafe(`SELECT (SELECT string_agg(data::text, '') FROM ${t_("events")} WHERE connection_id = $1) AS events, (SELECT string_agg(body_enc, '') FROM ${t_("messages")} WHERE connection_id = $1) AS bodies`, [a1.c.id]));
      assert.ok(!String(atRest[0].events).includes("private note") && !String(atRest[0].bodies).includes("private note"), "message text is encrypted in messages and in the inbox");
      assert.equal((await service.readInbox(a1.p, {})).events.find((e) => e.name === "message.created").data.text, "private note for A1");
      const noContext = await check(() => sql.begin(async (tx) => {
        await tx.unsafe(`SET LOCAL ROLE ${prefix}agent`);
        return tx.unsafe(`SELECT count(*) AS n FROM ${t_("work_items")}`);
      }));
      assert.equal(Number(noContext[0].n), 0, "without a principal the agent role sees nothing");
      for (const role of ["anon", "authenticated"]) {
        const rows = await check(() => admin.unsafe(`SELECT bool_or(has_table_privilege('${role}', c.oid, 'SELECT')) AS any FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relname LIKE $2`, [schema, `${prefix}%`]));
        assert.equal(rows[0].any, false, `${role} has no table privileges`);
      }
      const rls = await check(() => admin.unsafe(`SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relkind = 'r'`, [schema]));
      assert.ok(rls.length >= 13);
      for (const row of rls) {
        assert.equal(row.relrowsecurity, true, `${row.relname} has RLS enabled`);
        assert.equal(row.relforcerowsecurity, true, `${row.relname} forces RLS`);
      }
    });

    await t.test("revoke kills the token at once; delete removes the rows", async () => {
      assert.ok(await check(() => service.authenticate(a1.token)));
      await check(() => service.revokeConnection(ownerA, a1.c.id));
      assert.equal(await check(() => service.authenticate(a1.token)), null);
      assert.ok(await check(() => service.authenticate(a2.token)), "a sibling connection keeps working");
      const removed = await check(() => service.deleteConnection(ownerA, a1.c.id));
      assert.ok(removed.deleted.work_items >= 1);
      assert.ok(removed.deleted.messages >= 1 && removed.deleted.threads >= 1, "delete counts the conversation rows");
      for (const table of ["work_items", "checkpoints", "questions", "jobs", "events", "destinations", "deliveries", "credentials", "threads", "messages"]) {
        const rows = await admin.unsafe(`SELECT count(*) AS n FROM ${t_(table)} WHERE connection_id = $1`, [a1.c.id]);
        assert.equal(Number(rows[0].n), 0, `${table} cleared`);
      }
    });

    console.log(`[rls] ${counts.checks} cross-tenant and privilege checks passed`);
    assert.ok(postgresSchemaSql(schemaOpts).includes("FORCE ROW LEVEL SECURITY"));
  } finally {
    await sql.end({ timeout: 5 });
    await admin.unsafe(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    for (const role of [`${prefix}agent`, `${prefix}owner`, appRole]) {
      await admin.unsafe(`DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${role}') THEN EXECUTE 'DROP OWNED BY ${role}'; EXECUTE 'DROP ROLE ${role}'; END IF; END $$`).catch(() => {});
    }
    await admin.end({ timeout: 5 });
  }
});

test("migrating a 0.1.0 Postgres schema adds the columns and tables introduced since", { skip: !url }, async () => {
  const tag = randomBytes(4).toString("hex");
  const schema = `agg_upg_${tag}`;
  const prefix = `u${tag}_`;
  const admin = postgres(url, { max: 1, onnotice: () => {} });
  await admin.unsafe(`CREATE SCHEMA ${schema}`);
  const sql = postgres(url, { max: 2, onnotice: () => {}, connection: { search_path: schema } });
  const driver = createPostgresDriver(sql, { prefix, schema });
  const t_ = (name) => `${schema}.${prefix}${name}`;
  try {
    await driver.migrate();
    // Back to the 0.1.0 shape: no conversation tables, no questions.thread_id, and an older version marker.
    await admin.unsafe(`DROP TABLE ${t_("messages")}, ${t_("threads")}`);
    await admin.unsafe(`ALTER TABLE ${t_("questions")} DROP COLUMN thread_id`);
    await admin.unsafe(`COMMENT ON TABLE ${t_("connections")} IS 'agent-aggregator-schema:0000000000000000'`);
    await driver.migrate();
    const columns = await admin.unsafe(`SELECT column_name FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2 AND column_name = 'thread_id'`, [schema, `${prefix}questions`]);
    assert.equal(columns.length, 1, "questions.thread_id was added");
    const service = new AggregatorService({ driver, prefix, secretBox: createAesGcmSecretBox(randomBytes(32).toString("hex")) });
    const owner = { kind: "owner", ownerId: randomUUID(), name: "U", surface: "test" };
    await sql.unsafe(`INSERT INTO ${t_("owners")} (id, name) VALUES ($1, $2)`, [owner.ownerId, owner.name]);
    const connection = await service.createConnection(owner, { provider: "test_agent", display_name: "Upgraded", mode: "cli_poll" });
    const agent = await service.authenticate((await service.issueAgentCredential(owner, connection.id)).token);
    const sent = await service.sendMessage(owner, { connection_id: connection.id, thread_ref: "room", text: "Which seat?" });
    const asked = await service.createQuestion(agent, { id: "q-seat", prompt: "Window or aisle?", options: ["window", "aisle"], thread_id: sent.thread.id });
    assert.equal(asked.question.thread_id, sent.thread.id);
  } finally {
    await sql.end({ timeout: 5 });
    await admin.unsafe(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    for (const role of [`${prefix}agent`, `${prefix}owner`]) {
      await admin.unsafe(`DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${role}') THEN EXECUTE 'DROP OWNED BY ${role}'; EXECUTE 'DROP ROLE ${role}'; END IF; END $$`).catch(() => {});
    }
    await admin.end({ timeout: 5 });
  }
});
