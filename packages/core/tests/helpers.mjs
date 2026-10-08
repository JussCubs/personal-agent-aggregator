import { randomBytes, randomUUID } from "node:crypto";
import { after } from "node:test";
import { AggregatorService, createAesGcmSecretBox } from "../dist/index.js";
import { createSqliteDriver } from "../dist/stores/sqlite.js";
import { createPostgresDriver } from "../dist/stores/postgres.js";

const pgUrl = process.env.AGG_TEST_DRIVER === "postgres" ? process.env.AGG_TEST_DATABASE_URL : undefined;
const pgClients = [];
let postgresModule;

async function makeDriver() {
  if (!pgUrl) return createSqliteDriver(":memory:");
  postgresModule ??= (await import("postgres")).default;
  const tag = randomBytes(4).toString("hex");
  const schema = `agg_svc_${tag}`;
  const admin = postgresModule(pgUrl, { max: 1, onnotice: () => {} });
  await admin.unsafe(`CREATE SCHEMA ${schema}`);
  await admin.end();
  const sql = postgresModule(pgUrl, { max: 3, onnotice: () => {}, connection: { search_path: schema } });
  if (pgClients.length === 0) after(() => closeAll());
  pgClients.push(sql);
  return createPostgresDriver(sql, { schema, agentRole: "agg_test_agent", ownerRole: "agg_test_owner", settingPrefix: "aggtest" });
}

export async function closeAll() {
  for (const sql of pgClients.splice(0)) await sql.end({ timeout: 5 });
}

export const TEST_KEY = randomBytes(32).toString("hex");

export async function sqliteService(opts = {}) {
  const driver = await makeDriver();
  await driver.migrate();
  const sent = [];
  const service = new AggregatorService({
    driver,
    secretBox: createAesGcmSecretBox(TEST_KEY),
    outbound: { allowPrivateNetwork: true },
    send: opts.send ?? (async (request) => {
      sent.push(request);
      const body = JSON.parse(request.body);
      if (body.type === "verification") return { status: 200, body: JSON.stringify({ challenge: body.challenge }) };
      return { status: opts.status ?? 200, body: "" };
    }),
    hooks: opts.hooks,
    now: opts.now,
  });
  const owners = {};
  async function owner(name) {
    const id = randomUUID();
    await driver.privileged((db) => db.query("INSERT INTO aggregator_owners (id, name) VALUES ($1, $2)", [id, name]));
    owners[name] = { kind: "owner", ownerId: id, name, surface: "test" };
    return owners[name];
  }
  return { service, driver, sent, owner };
}

/** Creates an active connection and returns its principal + token. */
export async function connect(service, owner, input = {}) {
  const connection = await service.createConnection(owner, {
    provider: input.provider ?? "test_agent",
    display_name: input.display_name ?? "Test agent",
    mode: input.mode ?? "mcp_webhook",
    scopes: input.scopes,
  });
  const { token } = await service.issueAgentCredential(owner, connection.id);
  const principal = await service.authenticate(token);
  return { connection, token, principal };
}
