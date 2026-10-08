import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { AggregatorError, handleAgentRest, pkceChallengeS256 } from "../dist/index.js";
import { EXIT, runAgentCli } from "../dist/cli.js";
import { connect, sqliteService } from "./helpers.mjs";

test("OAuth authorization code + PKCE, refresh rotation, reuse detection, revoke", async () => {
  const { service, owner } = await sqliteService();
  const alice = await owner("alice");
  const resource = "https://api.example.com/mcp";
  const redirect = "https://client.example.com/oauth/callback";
  const { client_id } = await service.registerOAuthClient({ client_name: "Example MCP client", redirect_uris: [redirect], metadata: {} });
  const verifier = randomBytes(32).toString("base64url");
  const request = await service.createAuthorizationRequest({ client_id, client_name: "Example MCP client", redirect_uri: redirect, state: "st", code_challenge: pkceChallengeS256(verifier), scopes: ["hub:read", "hub:ask"], resource });
  const approved = await service.approveAuthorizationRequest(alice, request.id, { provider: "oauth_client", display_name: "Example MCP client" });
  assert.equal(approved.redirect_uri, redirect);
  assert.equal(approved.state, "st");
  await assert.rejects(service.exchangeAuthorizationCode({ code: approved.code, code_verifier: randomBytes(32).toString("base64url"), client_id, redirect_uri: redirect }), AggregatorError, "wrong verifier");
  const tokens = await service.exchangeAuthorizationCode({ code: approved.code, code_verifier: verifier, client_id, redirect_uri: redirect, resource });
  assert.equal(tokens.token_type, "Bearer");
  assert.equal(tokens.scope, "hub:read hub:ask");
  const principal = await service.authenticate(tokens.access_token);
  assert.equal(principal.credentialKind, "oauth_access");
  assert.equal(principal.resource, resource);
  assert.deepEqual(principal.scopes, ["hub:read", "hub:ask"]);
  await assert.rejects(service.exchangeAuthorizationCode({ code: approved.code, code_verifier: verifier, client_id, redirect_uri: redirect }), AggregatorError, "codes are single-use");
  assert.equal(await service.authenticate(tokens.access_token), null, "replaying a code revokes what it issued");

  const second = await service.createAuthorizationRequest({ client_id, client_name: "Example MCP client", redirect_uri: redirect, state: null, code_challenge: pkceChallengeS256(verifier), scopes: ["hub:read"], resource });
  const ok = await service.approveAuthorizationRequest(alice, second.id, { connection_id: approved.connection.id });
  const pair = await service.exchangeAuthorizationCode({ code: ok.code, code_verifier: verifier, client_id, redirect_uri: redirect });
  const rotated = await service.refreshAccessToken({ refresh_token: pair.refresh_token, client_id });
  assert.ok(await service.authenticate(rotated.access_token));
  await assert.rejects(service.refreshAccessToken({ refresh_token: pair.refresh_token, client_id }), AggregatorError, "refresh tokens rotate");
  assert.equal(await service.authenticate(rotated.access_token), null, "refresh reuse revokes the family");

  const third = await service.createAuthorizationRequest({ client_id, client_name: "Example MCP client", redirect_uri: redirect, state: null, code_challenge: pkceChallengeS256(verifier), scopes: ["hub:read"], resource });
  const ok3 = await service.approveAuthorizationRequest(alice, third.id, { connection_id: approved.connection.id });
  const pair3 = await service.exchangeAuthorizationCode({ code: ok3.code, code_verifier: verifier, client_id, redirect_uri: redirect });
  await service.revokeOAuthToken(pair3.refresh_token);
  assert.equal(await service.authenticate(pair3.access_token), null, "RFC 7009 revocation kills the pair");
  const fourth = await service.createAuthorizationRequest({ client_id, client_name: "Example MCP client", redirect_uri: redirect, state: null, code_challenge: pkceChallengeS256(verifier), scopes: ["hub:read"], resource });
  const ok4 = await service.approveAuthorizationRequest(alice, fourth.id, { connection_id: approved.connection.id });
  const pair4 = await service.exchangeAuthorizationCode({ code: ok4.code, code_verifier: verifier, client_id, redirect_uri: redirect });
  await service.revokeConnection(alice, approved.connection.id);
  assert.equal(await service.authenticate(pair4.access_token), null, "disconnect kills OAuth tokens");
  await assert.rejects(service.refreshAccessToken({ refresh_token: pair4.refresh_token, client_id }), AggregatorError);
});

/** A fetch that routes to the in-process REST handler. */
function restFetch(service) {
  return async (input, init = {}) => {
    const url = new URL(input);
    const body = init.body ? JSON.parse(init.body) : null;
    const res = await handleAgentRest(
      { method: init.method ?? "GET", path: url.pathname.replace(/^\/hub/, ""), query: Object.fromEntries(url.searchParams), body, authorization: init.headers?.authorization },
      { service, authenticate: async (auth) => (auth?.startsWith("Bearer ") ? service.authenticate(auth.slice(7)) : null), challenge: () => "Bearer" },
    );
    return new Response(JSON.stringify(res.body), { status: res.status, headers: res.headers });
  };
}

test("deterministic CLI: claim, doctor, ask, answer exit codes, inbox hook semantics", async () => {
  const { service, owner } = await sqliteService();
  const alice = await owner("alice");
  const connection = await service.createConnection(alice, { provider: "shell_agent", display_name: "Shell agent", mode: "cli_poll" });
  const { code } = await service.issueClaimCode(alice, connection.id);
  const dir = mkdtempSync(join(tmpdir(), "agg-cli-"));
  const lines = [];
  const errors = [];
  const defaults = { command: "agg", envPrefix: "AGG", configDir: dir, userAgent: "agg-test/1" };
  const io = { stdout: (t) => lines.push(t), stderr: (t) => errors.push(t), env: {}, fetch: restFetch(service) };
  const run = (...args) => runAgentCli(args, defaults, io);

  assert.equal(await run("doctor"), EXIT.usage, "no server configured yet");
  assert.equal(await run("setup", "--claim", code, "--server", "http://localhost/hub"), EXIT.ok);
  const stored = JSON.parse(readFileSync(join(dir, "hub.json"), "utf8"));
  assert.match(stored.token, /^agg_/);
  assert.equal(statSync(join(dir, "hub.json")).mode & 0o777, 0o600, "credential file is private");
  assert.equal(await run("setup", "--claim", code, "--server", "http://localhost/hub"), EXIT.auth, "setup codes are single-use");
  assert.equal(await run("doctor"), EXIT.ok);
  assert.equal(await run("item", "put", "--id", "t1", "--kind", "task", "--title", "Do it", "--status", "in_progress"), EXIT.ok);
  assert.equal(await run("checkpoint", "--item", "t1", "--id", "cp1", "--summary", "half done"), EXIT.ok);
  assert.equal(await run("ask", "--id", "q1", "--prompt", "Proceed?", "--option", "yes=Yes", "--option", "no=No"), EXIT.ok);
  assert.equal(await run("answer", "--id", "q1"), EXIT.nothingNew, "pending answer exits 3");
  assert.equal(await run("inbox"), EXIT.nothingNew);
  const p = await service.listOwnerQuestions(alice);
  await service.answerQuestion(alice, { connection_id: connection.id, question_id: "q1", revision: p[0].question.revision, choice: "yes" });
  assert.equal(await run("inbox", "--exec", "exit 7"), EXIT.error, "failing hook does not advance the cursor");
  const hookOut = join(dir, "hook.out");
  assert.equal(await run("inbox", "--exec", `cat > '${hookOut}'`), EXIT.ok);
  assert.match(readFileSync(hookOut, "utf8"), /answer\.created/);
  assert.equal(await run("inbox", "--exec", "exit 9"), EXIT.nothingNew, "nothing new: the hook is not even started");
  lines.length = 0;
  assert.equal(await run("answer", "--id", "q1"), EXIT.ok);
  const answer = JSON.parse(lines.at(-1));
  assert.equal(answer.answer.choice, "yes");
  assert.equal(await run("ack", "--id", "q1", "--revision", String(answer.revision)), EXIT.ok);
  assert.equal(await run("handoff", "--goal", "Write the summary", "--key", "k1"), EXIT.ok);
  const job = JSON.parse(lines.at(-1)).job;
  assert.equal(await run("job", "--id", job.id), EXIT.nothingNew, "open job exits 3");
  assert.equal(await run("install-poller", "--print", "--exec", "wake-worker"), EXIT.ok);
  assert.match(lines.at(-1), /^\* \* \* \* \* agg inbox --cursor-file .* --exec 'wake-worker' >> .* # agent-aggregator-poller/);
  assert.equal(await run("bogus"), EXIT.usage);
  await service.revokeConnection(alice, connection.id);
  assert.equal(await run("doctor"), EXIT.auth, "revoked credential exits 4");
});

test("REST: unauthenticated and unknown routes", async () => {
  const { service, owner } = await sqliteService();
  const alice = await owner("alice");
  const { token } = await connect(service, alice);
  const opts = { service, authenticate: async (a) => (a === `Bearer ${token}` ? service.authenticate(token) : null), challenge: () => "Bearer realm=test" };
  const unauth = await handleAgentRest({ method: "GET", path: "/v1/me", query: {}, body: null }, opts);
  assert.equal(unauth.status, 401);
  assert.equal(unauth.headers["www-authenticate"], "Bearer realm=test");
  const missing = await handleAgentRest({ method: "GET", path: "/v1/nope", query: {}, body: null, authorization: `Bearer ${token}` }, opts);
  assert.equal(missing.status, 404);
  const created = await handleAgentRest({ method: "POST", path: "/v1/questions", query: {}, body: { id: "q", prompt: "ok?", options: ["y"] }, authorization: `Bearer ${token}` }, opts);
  assert.equal(created.status, 201);
  const again = await handleAgentRest({ method: "POST", path: "/v1/questions", query: {}, body: { id: "q", prompt: "ok?", options: ["y"] }, authorization: `Bearer ${token}` }, opts);
  assert.equal(again.status, 200);
  const limited = await handleAgentRest({ method: "GET", path: "/v1/me", query: {}, body: null, authorization: `Bearer ${token}` }, { ...opts, beforeCall: async () => { throw new AggregatorError("rate_limited", "slow down", { retry_after: 7 }); } });
  assert.equal(limited.status, 429);
  assert.equal(limited.headers["retry-after"], "7");
});
