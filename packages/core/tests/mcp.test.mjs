import assert from "node:assert/strict";
import test from "node:test";
import { handleMcpHttp, TOOL_DEFINITIONS } from "../dist/index.js";
import { connect, sqliteService } from "./helpers.mjs";

async function setup() {
  const ctx = await sqliteService();
  const alice = await ctx.owner("alice");
  const { token, principal } = await connect(ctx.service, alice);
  const opts = {
    service: ctx.service,
    serverInfo: { name: "test-aggregator", version: "0.0.0" },
    instructions: "test",
    authenticate: async (authorization) => (authorization === `Bearer ${token}` ? ctx.service.authenticate(token) : null),
    challenge: (error) => `Bearer resource_metadata="https://example.test/.well-known/oauth-protected-resource", error="${error ?? "invalid_token"}"`,
  };
  const call = (body, headers = {}) =>
    handleMcpHttp({ method: "POST", headers: { authorization: `Bearer ${token}`, ...headers }, body: JSON.stringify(body) }, opts);
  return { ...ctx, alice, token, principal, opts, call };
}

test("legacy initialize handshake and tool calls", async () => {
  const { call, alice, service, principal } = await setup();
  const init = await call({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "c", version: "1" } } });
  assert.equal(init.status, 200);
  const result = JSON.parse(init.body).result;
  assert.equal(result.protocolVersion, "2025-06-18");
  assert.ok(result.capabilities.tools);
  assert.equal(result.resultType, undefined, "legacy results carry no resultType");
  const note = await call({ jsonrpc: "2.0", method: "notifications/initialized" });
  assert.equal(note.status, 202);
  const list = JSON.parse((await call({ jsonrpc: "2.0", id: 2, method: "tools/list" }, { "mcp-protocol-version": "2025-06-18" })).body).result;
  assert.equal(list.tools.length, TOOL_DEFINITIONS.length);
  assert.ok(list.tools.every((tool) => typeof tool.annotations.readOnlyHint === "boolean"));
  const ask = JSON.parse((await call({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "create_question", arguments: { id: "q1", prompt: "Ship?", options: [{ id: "y", label: "Yes" }] } } })).body).result;
  assert.equal(ask.isError, false);
  assert.equal(ask.structuredContent.question.id, "q1");
  await service.answerQuestion(alice, { connection_id: principal.connectionId, question_id: "q1", revision: 1, choice: "y" });
  const got = JSON.parse((await call({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "get_answer", arguments: { question_id: "q1" } } })).body).result;
  assert.equal(got.structuredContent.status, "answered");
  assert.equal(got.structuredContent.answer.choice, "y");
  const bad = JSON.parse((await call({ jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "get_answer", arguments: { question_id: "nope" } } })).body).result;
  assert.equal(bad.isError, true);
  assert.equal(bad.structuredContent.error.code, "not_found");
});

test("modern 2026-07-28 requests: discover, headers, resultType, events", async () => {
  const { call } = await setup();
  const meta = { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientInfo": { name: "c", version: "1" }, "io.modelcontextprotocol/clientCapabilities": {} };
  const headers = { "mcp-protocol-version": "2026-07-28" };
  const discover = await call({ jsonrpc: "2.0", id: "d", method: "server/discover", params: { _meta: meta } }, { ...headers, "mcp-method": "server/discover" });
  const d = JSON.parse(discover.body).result;
  assert.equal(d.resultType, "complete");
  assert.ok(d.supportedVersions.includes("2026-07-28"));
  assert.ok(d.capabilities.events);
  assert.equal(d._meta["io.modelcontextprotocol/serverInfo"].name, "test-aggregator");
  const tools = JSON.parse((await call({ jsonrpc: "2.0", id: 2, method: "tools/list", params: { _meta: meta } }, { ...headers, "mcp-method": "tools/list" })).body).result;
  assert.equal(tools.cacheScope, "private");
  const who = await call({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "whoami", arguments: {}, _meta: meta } }, { ...headers, "mcp-method": "tools/call", "mcp-name": "whoami" });
  assert.equal(JSON.parse(who.body).result.structuredContent.contract_version.length > 0, true);
  const mismatch = await call({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "whoami", arguments: {}, _meta: meta } }, { ...headers, "mcp-method": "tools/call", "mcp-name": "get_job" });
  assert.equal(mismatch.status, 400);
  assert.equal(JSON.parse(mismatch.body).error.code, -32020);
  const unsupported = await call({ jsonrpc: "2.0", id: 5, method: "tools/list", params: { _meta: { ...meta, "io.modelcontextprotocol/protocolVersion": "2099-01-01" } } }, { "mcp-protocol-version": "2099-01-01" });
  assert.equal(unsupported.status, 400);
  assert.equal(JSON.parse(unsupported.body).error.code, -32022);
  assert.ok(JSON.parse(unsupported.body).error.data.supported.includes("2026-07-28"));
  const unknown = await call({ jsonrpc: "2.0", id: 6, method: "nope/nope", params: { _meta: meta } }, headers);
  assert.equal(unknown.status, 404);
  assert.equal(JSON.parse(unknown.body).error.code, -32601);
  const events = JSON.parse((await call({ jsonrpc: "2.0", id: 7, method: "events/list", params: { _meta: meta } }, headers)).body).result;
  assert.deepEqual(events.events.map((e) => e.name), ["answer.created", "question.updated", "job.updated"]);
  const sub = JSON.parse((await call({
    jsonrpc: "2.0", id: 8, method: "events/subscribe",
    params: { _meta: meta, name: "answer.created", arguments: {}, delivery: { mode: "webhook", url: "http://127.0.0.1:9/e", secret: `whsec_${Buffer.alloc(32, 3).toString("base64")}` }, cursor: null },
  }, headers)).body).result;
  assert.match(sub.id, /^sub_/);
  assert.equal(sub.resultType, "complete");
});

test("authentication, origin and method guards", async () => {
  const { opts, token } = await setup();
  const unauth = await handleMcpHttp({ method: "POST", headers: {}, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }) }, opts);
  assert.equal(unauth.status, 401);
  assert.match(unauth.headers["www-authenticate"], /resource_metadata=/);
  const get = await handleMcpHttp({ method: "GET", headers: { authorization: `Bearer ${token}` }, body: "" }, opts);
  assert.equal(get.status, 405);
  const origin = await handleMcpHttp({ method: "POST", headers: { authorization: `Bearer ${token}`, origin: "https://evil.example" }, body: "{}" }, opts);
  assert.equal(origin.status, 403);
  const batch = await handleMcpHttp({ method: "POST", headers: { authorization: `Bearer ${token}` }, body: "[]" }, opts);
  assert.equal(batch.status, 400);
});

test("failed callback verification maps to CallbackEndpointError", async () => {
  const ctx = await sqliteService({ send: async () => ({ status: 500, body: "" }) });
  const alice = await ctx.owner("alice");
  const { token } = await connect(ctx.service, alice);
  const opts = { service: ctx.service, serverInfo: { name: "t", version: "0" }, instructions: "t", authenticate: async () => ctx.service.authenticate(token), challenge: () => "Bearer" };
  const res = await handleMcpHttp({ method: "POST", headers: {}, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "events/subscribe", params: { name: "job.updated", delivery: { mode: "webhook", url: "http://127.0.0.1:9/x", secret: `whsec_${Buffer.alloc(32, 9).toString("base64")}` } } }) }, opts);
  const error = JSON.parse(res.body).error;
  assert.equal(error.code, -32015);
  assert.equal(error.data.reason, "http_error");
});
