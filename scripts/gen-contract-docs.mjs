// Generates the reference tables in docs/contract.md from the code itself and
// fails (with --check) when the document has drifted.
//
//   node scripts/gen-contract-docs.mjs          rewrite the generated blocks in place
//   node scripts/gen-contract-docs.mjs --check  exit 1 if any generated block is stale
//
// Requires a build (npm run build). Scopes are not copied from comments: they
// are measured by calling every REST route and MCP tool with a credential that
// has no scopes and reading the insufficient_scope error. Event fields are
// measured from events the service actually emits.
import { randomBytes, randomUUID } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  AggregatorError,
  AggregatorService,
  CONTRACT_VERSION,
  DEFAULT_RATE_LIMITS,
  EVENT_DEFINITIONS,
  LEGACY_PROTOCOL_VERSIONS,
  LIMITS,
  MODERN_PROTOCOL_VERSIONS,
  SCOPE_DESCRIPTIONS,
  TOOL_DEFINITIONS,
  callTool,
  createAesGcmSecretBox,
  handleAgentRest,
  rateBucket,
} from "../packages/core/dist/index.js";
import { EXIT, runAgentCli } from "../packages/core/dist/cli.js";
import { createSqliteDriver } from "../packages/core/dist/stores/sqlite.js";
import { OWNER_EXIT, OWNER_ROUTES, SERVER_RATE_LIMITS, runOwnerCli } from "../packages/server/dist/index.js";

// node:sqlite prints an ExperimentalWarning on first use; keep every other warning.
const warningListeners = process.listeners("warning");
process.removeAllListeners("warning");
process.on("warning", (warning) => {
  if (!(warning.name === "ExperimentalWarning" && /SQLite/i.test(warning.message))) for (const listener of warningListeners) listener(warning);
});

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const DOC = `${ROOT}docs/contract.md`;
const read = (path) => readFileSync(`${ROOT}${path}`, "utf8");

/** Descriptions for every JSON-RPC error code the MCP handler can return. A code in the source without a description fails generation. */
const JSONRPC_CODES = {
  "-32700": ["400", "Parse error: the body is not JSON"],
  "-32600": ["400 / 413", "Invalid request: not a single JSON-RPC 2.0 object (batches are refused), or the body exceeds requestBodyBytes (413)"],
  "-32001": ["401", "Unauthorized: missing, invalid, revoked or wrong-audience credential (with WWW-Authenticate)"],
  "-32020": ["400", "Header mismatch: MCP-Protocol-Version, Mcp-Method or Mcp-Name disagree with the body (2026-07-28 requests)"],
  "-32022": ["400", "Unsupported protocol version; error.data.supported lists the versions"],
  "-32601": ["200 (legacy) / 404 (2026-07-28)", "Method not found"],
  "-32602": ["200", "Invalid params: unknown tool, invalid subscription request, insufficient scope or not found outside tools/call; error.data carries the core error"],
  "-32015": ["200", "Callback endpoint error: events/subscribe could not verify the delivery URL; error.data.reason is challenge_failed, http_error, timeout or unreachable"],
  "-32000": ["403 / 405 / 429", "Origin not allowed (403), method not allowed: use POST (405), or rate limited (429, with Retry-After)"],
  "-32603": ["200 / 503", "Internal error (details are logged server-side without arguments); 503 \"Temporarily unavailable\" when the credential could not be checked"],
};

const table = (headers, rows) =>
  [`| ${headers.join(" | ")} |`, `| ${headers.map(() => "---").join(" | ")} |`, ...rows.map((row) => `| ${row.map((cell) => String(cell).replace(/\|/g, "\\|")).join(" | ")} |`)].join("\n");
const code = (value) => `\`${value}\``;

async function probeService() {
  const driver = await createSqliteDriver(":memory:");
  await driver.migrate();
  let now = new Date("2026-10-01T00:00:00.000Z");
  const service = new AggregatorService({ driver, secretBox: createAesGcmSecretBox(randomBytes(32).toString("hex")), now: () => now, send: async () => ({ status: 200, body: "" }), outbound: { allowPrivateNetwork: true } });
  const ownerId = randomUUID();
  await driver.privileged((db) => db.query("INSERT INTO aggregator_owners (id, name, created_at) VALUES ($1, $2, $3)", [ownerId, "probe", now.toISOString()]));
  const owner = { kind: "owner", ownerId, name: "probe", surface: "probe" };
  const connection = await service.createConnection(owner, { provider: "probe_agent", display_name: "Probe", mode: "cli_poll" });
  const { token } = await service.issueAgentCredential(owner, connection.id);
  const full = await service.authenticate(token);
  const none = { ...full, scopes: [] };
  return { service, owner, connection, full, none, advance: (seconds) => (now = new Date(now.getTime() + seconds * 1000)) };
}

async function requiredScopes(fn) {
  try {
    await fn();
    return [];
  } catch (error) {
    if (error instanceof AggregatorError && error.code === "insufficient_scope") return error.details.required;
    return [];
  }
}

function restRoutes() {
  const source = read("packages/core/src/rest.ts");
  const routes = [];
  const pattern = /\{ method: "(\w+)", pattern: (?:\/\^(.+?)\$\/|new RegExp\(`\^(.+?)\$`\)), key: "([\w.]+)"/g;
  for (const match of source.matchAll(pattern)) {
    const routePattern = (match[2] ?? match[3]).replace(/\\\//g, "/");
    // ${SEGMENT} is an id; ([0-9a-f-]{36}) is a UUID (message ids).
    const uuid = routePattern.includes("([0-9a-f-]{36})");
    const raw = routePattern.replace(/\$\{SEGMENT\}/g, "{id}").replace("([0-9a-f-]{36})", "{id}");
    routes.push({ method: match[1], path: raw, key: match[4], uuid });
  }
  if (routes.length < 20) throw new Error(`parsed only ${routes.length} routes from rest.ts`);
  return routes;
}

async function sections() {
  const probe = await probeService();
  const out = {};

  out.version = `Contract version ${code(CONTRACT_VERSION)} (\`CONTRACT_VERSION\`, returned by \`whoami\` / \`GET /v1/me\` as \`contract_version\`). MCP protocol versions: ${MODERN_PROTOCOL_VERSIONS.map(code).join(", ")} (modern) and ${LEGACY_PROTOCOL_VERSIONS.map(code).join(", ")} (legacy \`initialize\`).`;

  out.scopes = table(["Scope", "Grants"], Object.entries(SCOPE_DESCRIPTIONS).map(([scope, text]) => [code(scope), text]));

  const rows = [[code("POST"), code("/v1/claim"), "none (one-time setup code in the body)", code("claim"), "per IP"]];
  for (const route of restRoutes()) {
    const path = route.path.replace("{id}", route.uuid ? randomUUID() : "x");
    const res = await handleAgentRest({ method: route.method, path, query: {}, body: {}, authorization: "Bearer probe" }, { service: probe.service, authenticate: async () => probe.none, challenge: () => "Bearer" });
    const unauth = await handleAgentRest({ method: route.method, path, query: {}, body: {}, authorization: undefined }, { service: probe.service, authenticate: async () => null, challenge: () => "Bearer" });
    if (unauth.status !== 401) throw new Error(`${route.method} ${route.path} did not require authentication`);
    const required = res.status === 403 && res.body.error.code === "insufficient_scope" ? res.body.error.details.required : [];
    rows.push([code(route.method), code(route.path), required.length ? required.map(code).join(" or ") : "any", code(route.key), rateBucket(route.key)]);
  }
  out["rest-routes"] = table(["Method", "Path (below the API base)", "Scope (any of)", "Route key", "Rate bucket"], rows);

  const toolRows = [];
  for (const def of TOOL_DEFINITIONS) {
    const enforced = await requiredScopes(() => callTool(probe.service, probe.none, def.name, {}));
    const advertised = def.scopes;
    if (enforced.join(" ") !== advertised.join(" ")) throw new Error(`${def.name}: TOOL_DEFINITIONS scopes ${advertised.join(" ")} differ from enforced ${enforced.join(" ")}`);
    const a = def.annotations;
    toolRows.push([code(def.name), def.title, (def.inputSchema.required ?? []).map(code).join(", ") || "none", advertised.length ? advertised.map(code).join(" or ") : "any", a.readOnlyHint, a.destructiveHint, a.idempotentHint, a.openWorldHint, rateBucket(def.name)]);
  }
  out["mcp-tools"] = table(["Tool", "Title", "Required arguments", "Scope (any of)", "readOnly", "destructive", "idempotent", "openWorld", "Rate bucket"], toolRows);

  out["jsonrpc-codes"] = (() => {
    const found = [...new Set(read("packages/core/src/mcp.ts").match(/-32\d{3}/g))].sort();
    const documented = Object.keys(JSONRPC_CODES).sort();
    if (found.join() !== documented.join()) throw new Error(`JSON-RPC codes in mcp.ts (${found.join(", ")}) differ from the documented set (${documented.join(", ")})`);
    return table(["Code", "HTTP status", "Meaning"], Object.entries(JSONRPC_CODES).map(([c, [status, meaning]]) => [code(c), status, meaning]));
  })();

  // Emit every event the service can produce and record the payload fields it actually sends.
  const { service, owner, connection, full } = probe;
  await service.createQuestion(full, { id: "q-answer", prompt: "Answer me?", options: ["yes"] });
  await service.answerQuestion(owner, { connection_id: connection.id, question_id: "q-answer", revision: 1, choice: "opt_1" });
  await service.createQuestion(full, { id: "q-dismiss", prompt: "Dismiss me?", options: ["yes"] });
  await service.dismissQuestion(owner, connection.id, "q-dismiss");
  await service.createQuestion(full, { id: "q-expire", prompt: "Expire me?", options: ["yes"], expires_in_seconds: 60 });
  probe.advance(120);
  await service.sweep();
  const { job } = await service.handoffJob(full, { goal: "Do it" });
  await service.decideJob(owner, { connection_id: connection.id, job_id: job.id, approve: true });
  await service.sendMessage(owner, { connection_id: connection.id, thread_ref: "probe-thread", text: "Hello agent" });
  const inbox = await service.readInbox(full, {});
  const emitted = {};
  for (const event of inbox.events) emitted[event.name] = new Set([...(emitted[event.name] ?? []), ...Object.keys(event.data)]);
  const envelopeKeys = Object.keys(inbox.events[0]);
  const answerKeys = Object.keys(inbox.events.find((e) => e.name === "answer.created").data.answer);
  out.events = [
    `Envelope (inbox entry, webhook body and MCP event body): ${envelopeKeys.map(code).join(", ")}.`,
    "",
    table(
      ["Event", "When", "Payload fields (data)", "Required in events/list payloadSchema"],
      EVENT_DEFINITIONS.map((def) => [code(def.name), def.description, [...(emitted[def.name] ?? [])].map(code).join(", "), def.payloadSchema.required.map(code).join(", ")]),
    ),
    "",
    `\`answer.created\` \`data.answer\` fields: ${answerKeys.map(code).join(", ")}.`,
  ].join("\n");

  out.errors = (() => {
    const source = read("packages/core/src/errors.ts");
    const block = /const STATUS[^{]*\{([\s\S]*?)\};/.exec(source)[1];
    const codes = [...block.matchAll(/(\w+): (\d{3})/g)].map((m) => [m[1], Number(m[2])]);
    for (const [name, status] of codes) {
      const actual = new AggregatorError(name, "x").status;
      if (actual !== status) throw new Error(`${name}: parsed ${status}, runtime ${actual}`);
    }
    return table(["Code", "HTTP status"], codes.map(([name, status]) => [code(name), status]));
  })();

  out.limits = table(["Limit", "Value"], Object.entries(LIMITS).map(([name, value]) => [code(name), value]));
  out["rate-limits"] = table(
    ["Budget", "Value", "Applies to"],
    [
      ...Object.entries(DEFAULT_RATE_LIMITS).map(([name, value]) => [code(name), value, name.endsWith("PerIp") ? "per client IP" : "per connection, by rate bucket"]),
      ...Object.entries(SERVER_RATE_LIMITS).map(([name, value]) => [code(name), value, "per client IP (reference server)"]),
    ],
  );

  out["owner-routes"] = table(["Method", "Path", "Purpose"], OWNER_ROUTES.map((route) => [code(route.method), code(route.path), route.summary]));

  const capture = async (fn) => {
    let text = "";
    await fn((t) => (text += t));
    return text;
  };
  const aggHelp = await capture((write) => runAgentCli(["help"], { command: "agg", envPrefix: "AGG", configDir: "~/.config/agent-aggregator", userAgent: "x" }, { stdout: write, stderr: () => {}, env: {} }));
  const ownerHelp = await capture((write) => runOwnerCli(["help"], { stdout: write, stderr: () => {}, env: {} }));
  out["agent-cli"] = ["```text", aggHelp.trimEnd(), "```", "", table(["Exit code", "Name", "Meaning"], [
    [EXIT.ok, "ok", "Success, or something new (inbox events, an answer, a terminal job)"],
    [EXIT.error, "error", "Network, server or hook failure; the inbox cursor did not advance"],
    [EXIT.usage, "usage", "Bad arguments, invalid JSON input, or no server configured"],
    [EXIT.nothingNew, "nothingNew", "Nothing new, question still pending, job still open, or another inbox run holds the lock"],
    [EXIT.auth, "auth", "Credential missing, invalid, revoked or expired (HTTP 401)"],
    [EXIT.closed, "closed", "The question was cancelled or expired without an answer"],
  ])].join("\n");
  if (Object.keys(EXIT).length !== 6) throw new Error("agent CLI EXIT codes changed");
  out["owner-cli"] = ["```text", ownerHelp.trimEnd(), "```", "", table(["Exit code", "Name", "Meaning"], [
    [OWNER_EXIT.ok, "ok", "Success"],
    [OWNER_EXIT.error, "error", "Network or server error"],
    [OWNER_EXIT.usage, "usage", "Bad arguments or configuration"],
    [OWNER_EXIT.empty, "empty", "A list command returned no entries (questions, jobs, items, checkpoints, audit, connection list)"],
    [OWNER_EXIT.auth, "auth", "Owner credential missing or invalid (HTTP 401)"],
    [OWNER_EXIT.conflict, "conflict", "HTTP 409: stale revision, already answered/decided, or init found an existing owner"],
  ])].join("\n");
  if (Object.keys(OWNER_EXIT).length !== 6) throw new Error("agg-owner exit codes changed");
  return out;
}

const check = process.argv.includes("--check");
const generated = await sections();
let doc = readFileSync(DOC, "utf8");
const stale = [];
for (const [name, body] of Object.entries(generated)) {
  const re = new RegExp(`(<!-- BEGIN GENERATED: ${name} -->\\n)([\\s\\S]*?)(<!-- END GENERATED: ${name} -->)`);
  const match = re.exec(doc);
  if (!match) {
    stale.push(`${name} (markers missing)`);
    continue;
  }
  if (match[2] !== `${body}\n`) stale.push(name);
  doc = doc.replace(re, (_m, start, _old, end) => `${start}${body}\n${end}`);
}
const unknown = [...doc.matchAll(/<!-- BEGIN GENERATED: ([\w-]+) -->/g)].map((m) => m[1]).filter((name) => !(name in generated));
if (unknown.length) stale.push(...unknown.map((name) => `${name} (no generator)`));
if (check) {
  if (stale.length) {
    console.error(`docs/contract.md is out of date: ${stale.join(", ")}\nRun: npm run docs:contract`);
    process.exit(1);
  }
  console.log(`docs/contract.md matches the code (${Object.keys(generated).length} generated sections)`);
} else {
  if (unknown.length || stale.some((s) => s.includes("markers missing"))) {
    console.error(`cannot update: ${stale.join(", ")}`);
    process.exit(1);
  }
  writeFileSync(DOC, doc);
  console.log(`updated docs/contract.md (${stale.length ? stale.join(", ") : "no changes"})`);
}
