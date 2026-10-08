import assert from "node:assert/strict";
import test from "node:test";
import { generateWebhookSecret } from "@agent-aggregator/core";
import { consentFlow, mcp, pkcePair, request, startReceiver, startServer } from "./helpers.mjs";

async function agentConnection(ctx, mode = "mcp_webhook", extra = {}) {
  const created = await ctx.ownerApi("POST", "/owner/connections", { provider: "test_agent", display_name: "Test agent", mode, ...extra });
  assert.equal(created.status, 201);
  const issued = await ctx.ownerApi("POST", `/owner/connections/${created.json.connection.id}/credential`, {});
  assert.equal(issued.status, 200);
  return { id: created.json.connection.id, token: issued.json.token };
}

test("owner API authenticates, routes and reports errors in the core error shape", async (t) => {
  const ctx = await startServer();
  t.after(() => ctx.close());
  assert.equal((await request(ctx.url, "GET", "/owner/me")).status, 401);
  const bad = await request(ctx.url, "GET", "/owner/me", { token: "aggown_not-a-real-credential-0000000000000" });
  assert.equal(bad.status, 401);
  assert.equal(bad.json.error.code, "unauthorized");
  const me = await ctx.ownerApi("GET", "/owner/me");
  assert.deepEqual(me.json, { owner: { id: ctx.owner.owner.id, name: "Test owner" } });
  const unknown = await ctx.ownerApi("GET", "/owner/nope");
  assert.equal(unknown.status, 404);
  const wrongMethod = await ctx.ownerApi("PUT", "/owner/questions");
  assert.equal(wrongMethod.status, 404);
  assert.equal(wrongMethod.headers.get("allow"), "GET");
  const invalid = await ctx.ownerApi("POST", "/owner/connections", { provider: "Bad Provider", display_name: "x", mode: "cli_poll" });
  assert.equal(invalid.status, 400);
  assert.equal(invalid.json.error.code, "invalid_request");
  const notJson = await ctx.ownerApi("POST", "/owner/connections", "{not json");
  assert.equal(notJson.status, 400);
  const badId = await ctx.ownerApi("GET", "/owner/connections/not-a-uuid");
  assert.equal(badId.status, 404);

  const rotated = await ctx.ownerApi("POST", "/owner/credential/rotate", {});
  assert.match(rotated.json.credential, /^aggown_/);
  assert.equal((await ctx.ownerApi("GET", "/owner/me")).status, 401, "the old owner credential stops working at once");
  assert.equal((await request(ctx.url, "GET", "/owner/me", { token: rotated.json.credential })).status, 200);
});

test("agent REST under /api/v1: claim, scopes, audience, limits, bodies", async (t) => {
  const ctx = await startServer();
  t.after(() => ctx.close());
  const created = await ctx.ownerApi("POST", "/owner/connections", { provider: "shell_agent", display_name: "Shell agent", mode: "cli_poll", scopes: ["hub:read", "hub:ask"] });
  const connectionId = created.json.connection.id;
  const code = (await ctx.ownerApi("POST", `/owner/connections/${connectionId}/claim-code`, { ttl_seconds: 600 })).json.code;
  assert.match(code, /^[A-Z2-9]{5}(-[A-Z2-9]{5}){3}$/);
  const claimed = await request(ctx.url, "POST", "/api/v1/claim", { body: { code } });
  assert.equal(claimed.status, 200);
  const token = claimed.json.token;
  assert.match(token, /^agg_/);
  assert.equal((await request(ctx.url, "POST", "/api/v1/claim", { body: { code } })).status, 401, "setup codes are single-use");

  const me = await request(ctx.url, "GET", "/api/v1/me", { token });
  assert.equal(me.status, 200);
  assert.deepEqual(me.json.scopes, ["hub:read", "hub:ask"]);
  const denied = await request(ctx.url, "PUT", "/api/v1/work-items/t1", { token, body: { kind: "task", title: "x" } });
  assert.equal(denied.status, 403);
  assert.equal(denied.json.error.code, "insufficient_scope");
  assert.match(denied.headers.get("www-authenticate"), /insufficient_scope/);
  const unauth = await request(ctx.url, "GET", "/api/v1/me");
  assert.equal(unauth.status, 401);
  assert.equal(unauth.headers.get("www-authenticate"), 'Bearer realm="agent-aggregator"');
  const malformed = await request(ctx.url, "POST", "/api/v1/questions", { token, body: "{nope" });
  assert.equal(malformed.status, 400);
  const huge = await request(ctx.url, "POST", "/api/v1/questions", { token, body: JSON.stringify({ prompt: "x".repeat(300_000) }) });
  assert.equal(huge.status, 413);
  assert.equal(huge.json.error.code, "payload_too_large");

  // Per-IP claim budget: 10 per minute (DEFAULT_RATE_LIMITS.claimsPerMinutePerIp); two were used above.
  let last;
  for (let i = 0; i < 9; i += 1) last = await request(ctx.url, "POST", "/api/v1/claim", { body: { code: "AAAAA-AAAAA-AAAAA-AAAAA" } });
  assert.equal(last.status, 429);
  assert.ok(Number(last.headers.get("retry-after")) >= 1);
});

test("failed authentications from one IP are blocked after 30 per minute", async (t) => {
  const ctx = await startServer();
  t.after(() => ctx.close());
  for (let i = 0; i < 30; i += 1) {
    const res = await request(ctx.url, "GET", "/api/v1/me", { token: `agg_${"x".repeat(43)}` });
    assert.equal(res.status, 401);
  }
  const blocked = await request(ctx.url, "GET", "/api/v1/me", { token: `agg_${"x".repeat(43)}` });
  assert.equal(blocked.status, 429);
  assert.equal((await ctx.ownerApi("GET", "/owner/me")).status, 429, "the block covers every credential-bearing endpoint");
});

test("MCP endpoint: challenges, origins, both protocol eras", async (t) => {
  const ctx = await startServer();
  t.after(() => ctx.close());
  const { token } = await agentConnection(ctx);
  const anonymous = await request(ctx.url, "POST", "/mcp", { body: { jsonrpc: "2.0", id: 1, method: "initialize", params: {} } });
  assert.equal(anonymous.status, 401);
  assert.equal(anonymous.headers.get("www-authenticate"), `Bearer resource_metadata="${ctx.url}/.well-known/oauth-protected-resource/mcp", scope="hub:read hub:write hub:ask hub:handoff"`);
  const wrong = await request(ctx.url, "POST", "/mcp", { token: `agg_${"y".repeat(43)}`, body: { jsonrpc: "2.0", id: 1, method: "ping" } });
  assert.match(wrong.headers.get("www-authenticate"), /error="invalid_token"/);
  const init = await mcp(ctx.url, token, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } });
  assert.equal(init.json.result.protocolVersion, "2025-06-18");
  assert.equal(init.json.result.serverInfo.name, "agent-aggregator");
  const discover = await mcp(ctx.url, token, "server/discover", {}, { modern: true });
  assert.equal(discover.json.result.resultType, "complete");
  const evil = await request(ctx.url, "POST", "/mcp", { token, headers: { origin: "https://attacker.example" }, body: { jsonrpc: "2.0", id: 1, method: "ping" } });
  assert.equal(evil.status, 403);
  const own = await request(ctx.url, "POST", "/mcp", { token, headers: { origin: new URL(ctx.url).origin }, body: { jsonrpc: "2.0", id: 1, method: "ping" } });
  assert.equal(own.status, 200);
  assert.equal((await request(ctx.url, "GET", "/mcp", { token })).status, 405);
});

test("OAuth: metadata, DCR, consent page (escaping, CSRF, credential), PRG, tokens, audience, revocation", async (t) => {
  const ctx = await startServer();
  t.after(() => ctx.close());
  const prm = await request(ctx.url, "GET", "/.well-known/oauth-protected-resource/mcp");
  assert.deepEqual(prm.json.authorization_servers, [ctx.url]);
  assert.equal(prm.json.resource, `${ctx.url}/mcp`);
  assert.equal((await request(ctx.url, "GET", "/.well-known/oauth-protected-resource")).json.resource, `${ctx.url}/mcp`);
  const asm = await request(ctx.url, "GET", "/.well-known/oauth-authorization-server");
  assert.equal(asm.json.issuer, ctx.url);
  assert.deepEqual(asm.json.code_challenge_methods_supported, ["S256"]);

  const redirectUri = "http://127.0.0.1:9/callback";
  const reg = await request(ctx.url, "POST", "/oauth/register", { body: { client_name: "<script>alert(1)</script> Helper", redirect_uris: [redirectUri] } });
  assert.equal(reg.status, 201);
  assert.match(reg.json.client_id, /^dcr_/);
  assert.equal(reg.json.token_endpoint_auth_method, "none");
  const badReg = await request(ctx.url, "POST", "/oauth/register", { body: { redirect_uris: ["http://attacker.example/cb"] } });
  assert.equal(badReg.status, 400);
  assert.equal(badReg.json.error, "invalid_redirect_uri");

  const { verifier, challenge } = pkcePair();
  const query = new URLSearchParams({ response_type: "code", client_id: reg.json.client_id, redirect_uri: redirectUri, code_challenge: challenge, code_challenge_method: "S256", state: "s-123", scope: "hub:read hub:ask" });
  const unregistered = await request(ctx.url, "GET", `/oauth/authorize?${new URLSearchParams({ ...Object.fromEntries(query), redirect_uri: "http://127.0.0.1:9/other" })}`);
  assert.equal(unregistered.status, 400, "an unregistered redirect URI is shown an error, never redirected to");
  const plain = await request(ctx.url, "GET", `/oauth/authorize?${new URLSearchParams({ ...Object.fromEntries(query), code_challenge_method: "plain" })}`);
  assert.equal(plain.status, 302);
  assert.match(plain.headers.get("location"), /error=invalid_request/);
  assert.match(plain.headers.get("location"), /iss=/);

  const start = await request(ctx.url, "GET", `/oauth/authorize?${query}`);
  assert.equal(start.status, 303);
  const page = await request(ctx.url, "GET", start.headers.get("location"));
  assert.equal(page.status, 200);
  assert.ok(!page.text.includes("<script>alert(1)</script>"), "client name is escaped");
  assert.ok(page.text.includes("&lt;script&gt;alert(1)&lt;/script&gt; Helper"));
  assert.ok(page.text.includes("127.0.0.1:9"), "page shows the redirect host");
  assert.ok(page.text.includes("hub:ask") && !page.text.includes("<code>hub:write</code>"), "page shows exactly the requested scopes");
  assert.match(page.headers.get("content-security-policy"), /default-src 'none'.*form-action 'self' http:\/\/127\.0\.0\.1:9.*frame-ancestors 'none'/);
  assert.equal(page.headers.get("x-frame-options"), "DENY");
  const cookie = page.headers.get("set-cookie");
  assert.match(cookie, /HttpOnly; SameSite=Strict/);
  const field = (name) => new RegExp(`name="${name}" value="([^"]+)"`).exec(page.text)[1];
  const requestId = field("request_id");

  const noCookie = await request(ctx.url, "POST", "/oauth/authorize", { form: { request_id: requestId, csrf: field("csrf"), action: "approve", owner_credential: ctx.owner.credential } });
  assert.equal(noCookie.status, 303);
  assert.match(noCookie.headers.get("location"), /error=csrf$/);
  const wrongCredential = await request(ctx.url, "POST", "/oauth/authorize", { headers: { cookie: cookie.split(";")[0] }, form: { request_id: requestId, csrf: field("csrf"), action: "approve", owner_credential: "aggown_wrong-wrong-wrong-wrong-wrong-wrong-wrong" } });
  assert.match(wrongCredential.headers.get("location"), /error=credential$/);
  const retry = await request(ctx.url, "GET", wrongCredential.headers.get("location"));
  assert.ok(retry.text.includes("That owner credential is not valid"));

  const approved = await request(ctx.url, "POST", "/oauth/authorize", { headers: { cookie: cookie.split(";")[0] }, form: { request_id: requestId, csrf: field("csrf"), action: "approve", owner_credential: ctx.owner.credential } });
  assert.equal(approved.status, 303);
  const location = new URL(approved.headers.get("location"));
  assert.equal(`${location.origin}${location.pathname}`, redirectUri);
  assert.equal(location.searchParams.get("state"), "s-123");
  assert.equal(location.searchParams.get("iss"), ctx.url);
  const code = location.searchParams.get("code");
  assert.match(code, /^aggc_/);
  const again = await request(ctx.url, "POST", "/oauth/authorize", { headers: { cookie: cookie.split(";")[0] }, form: { request_id: requestId, csrf: field("csrf"), action: "approve", owner_credential: ctx.owner.credential } });
  assert.equal(again.status, 410, "a handled request cannot be approved twice");

  assert.equal((await request(ctx.url, "POST", "/oauth/token", { body: { grant_type: "authorization_code" } })).status, 400, "token endpoint takes form bodies only");
  const exchange = await request(ctx.url, "POST", "/oauth/token", { form: { grant_type: "authorization_code", code, code_verifier: verifier, client_id: reg.json.client_id, redirect_uri: redirectUri } });
  assert.equal(exchange.status, 200);
  assert.equal(exchange.json.scope, "hub:read hub:ask");
  assert.equal(exchange.headers.get("cache-control"), "no-store");
  const replay = await request(ctx.url, "POST", "/oauth/token", { form: { grant_type: "authorization_code", code, code_verifier: verifier, client_id: reg.json.client_id, redirect_uri: redirectUri } });
  assert.equal(replay.json.error, "invalid_grant");
  assert.equal((await mcp(ctx.url, exchange.json.access_token, "ping")).status, 401, "replaying the code revoked what it issued");

  const second = await consentFlow(ctx.url, { clientId: reg.json.client_id, redirectUri, challenge, state: "s-2", ownerCredential: ctx.owner.credential });
  const tokens = (await request(ctx.url, "POST", "/oauth/token", { form: { grant_type: "authorization_code", code: new URL(second.location).searchParams.get("code"), code_verifier: verifier, client_id: reg.json.client_id, redirect_uri: redirectUri } })).json;
  const who = await mcp(ctx.url, tokens.access_token, "tools/call", { name: "whoami", arguments: {} });
  assert.equal(who.json.result.structuredContent.mode, "oauth_events");
  assert.equal((await request(ctx.url, "GET", "/api/v1/me", { token: tokens.access_token })).status, 401, "OAuth tokens are audience-bound to /mcp");
  const refreshed = await request(ctx.url, "POST", "/oauth/token", { form: { grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: reg.json.client_id } });
  assert.equal(refreshed.status, 200);
  assert.notEqual(refreshed.json.refresh_token, tokens.refresh_token);
  const reuse = await request(ctx.url, "POST", "/oauth/token", { form: { grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: reg.json.client_id } });
  assert.equal(reuse.json.error, "invalid_grant");
  assert.equal((await mcp(ctx.url, refreshed.json.access_token, "ping")).status, 401, "refresh reuse revoked the family");

  const third = await consentFlow(ctx.url, { clientId: reg.json.client_id, redirectUri, challenge, state: "s-3", ownerCredential: ctx.owner.credential });
  const pair = (await request(ctx.url, "POST", "/oauth/token", { form: { grant_type: "authorization_code", code: new URL(third.location).searchParams.get("code"), code_verifier: verifier, client_id: reg.json.client_id, redirect_uri: redirectUri } })).json;
  assert.equal((await request(ctx.url, "POST", "/oauth/revoke", { form: { token: pair.refresh_token } })).status, 200);
  assert.equal((await mcp(ctx.url, pair.access_token, "ping")).status, 401);
  assert.equal((await request(ctx.url, "POST", "/oauth/revoke", { form: { token: "unknown" } })).status, 200, "unknown tokens are not an error");

  const denyStart = await request(ctx.url, "GET", `/oauth/authorize?${new URLSearchParams({ ...Object.fromEntries(query), state: "s-4" })}`);
  const denyPage = await request(ctx.url, "GET", denyStart.headers.get("location"));
  const denyField = (name) => new RegExp(`name="${name}" value="([^"]+)"`).exec(denyPage.text)[1];
  const denied = await request(ctx.url, "POST", "/oauth/authorize", { headers: { cookie: denyPage.headers.get("set-cookie").split(";")[0] }, form: { request_id: denyField("request_id"), csrf: denyField("csrf"), action: "deny" } });
  const deniedTo = new URL(denied.headers.get("location"));
  assert.equal(deniedTo.searchParams.get("error"), "access_denied");
  assert.equal(deniedTo.searchParams.get("state"), "s-4");
});

test("DCR is rate limited per IP (20 per hour)", async (t) => {
  const ctx = await startServer();
  t.after(() => ctx.close());
  let last;
  for (let i = 0; i < 21; i += 1) last = await request(ctx.url, "POST", "/oauth/register", { body: { client_name: `c${i}`, redirect_uris: ["https://client.example.com/cb"] } });
  assert.equal(last.status, 429);
  assert.ok(last.headers.get("retry-after"));
});

test("webhook deliveries leave the server signed, with the routine key, within seconds", async (t) => {
  const ctx = await startServer();
  const secretRef = { current: null };
  const receiver = await startReceiver(secretRef);
  t.after(async () => {
    await ctx.close();
    await receiver.close();
  });
  const { id, token } = await agentConnection(ctx);
  const set = await request(ctx.url, "PUT", "/api/v1/webhook", { token, body: { url: `${receiver.url}/hook`, auth_header_value: "routine-key-1" } });
  assert.equal(set.status, 200);
  secretRef.current = set.json.signing_secret;
  await request(ctx.url, "POST", "/api/v1/questions", { token, body: { id: "q1", prompt: "Proceed?", options: [{ id: "yes", label: "Yes" }] } });
  const answered = await ctx.ownerApi("POST", `/owner/connections/${id}/questions/q1/answer`, { revision: 1, choice: "yes" });
  assert.equal(answered.status, 200);
  const delivery = await receiver.waitFor((d) => d.json.name === "answer.created");
  assert.equal(delivery.headers.authorization, "Bearer routine-key-1");
  assert.equal(delivery.json.data.answer.choice, "yes");
  const stale = await ctx.ownerApi("POST", `/owner/connections/${id}/questions/q1/answer`, { revision: 1, choice: "yes" });
  assert.equal(stale.status, 409);

  // MCP event subscription against the same receiver, with a secret the agent chose.
  const subSecret = generateWebhookSecret();
  secretRef.current = subSecret;
  const sub = await mcp(ctx.url, token, "events/subscribe", { name: "job.updated", delivery: { mode: "webhook", url: `${receiver.url}/events`, secret: subSecret } }, { modern: true });
  assert.match(sub.json.result.id, /^sub_/);
  const job = await request(ctx.url, "POST", "/api/v1/jobs", { token, body: { goal: "Summarize the week", idempotency_key: "week-1" } });
  assert.equal(job.status, 201);
  const event = await receiver.waitFor((d) => d.json.name === "job.updated" && d.headers["x-mcp-subscription-id"] === sub.json.result.id);
  assert.equal(event.json.data.status, "needs_user");
});

test("logs never contain credentials, codes, request bodies or authorization headers", async (t) => {
  const ctx = await startServer();
  t.after(() => ctx.close());
  const { id, token } = await agentConnection(ctx);
  const marker = "BODY-MARKER-7f3a";
  await request(ctx.url, "POST", "/api/v1/questions", { token, body: { id: "q-log", prompt: `Contains ${marker}`, options: ["yes"] } });
  const code = (await ctx.ownerApi("POST", `/owner/connections/${id}/claim-code`, {})).json.code;
  await request(ctx.url, "POST", "/api/v1/claim", { body: { code } });
  await request(ctx.url, "GET", `/api/v1/inbox?cursor=c1.${marker}`, { token });
  await request(ctx.url, "POST", "/api/v1/claim", { body: `{"code":"${marker}"` });
  const all = ctx.logs.join("");
  assert.ok(ctx.logs.length >= 5);
  for (const secret of [token, ctx.owner.credential, code, marker, "Bearer ", ctx.env.AGG_ENCRYPTION_KEY]) {
    assert.ok(!all.includes(secret), `log must not contain ${secret.slice(0, 12)}`);
  }
  for (const line of ctx.logs) assert.doesNotThrow(() => JSON.parse(line), "every log line is JSON");
  assert.ok(ctx.logs.some((line) => JSON.parse(line).path === "/api/v1/inbox"), "paths are logged without the query string");
});
