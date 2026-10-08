// Wake mode 2: an OAuth-protected MCP plugin, woken by signed MCP Events.
//
// The "agent" is this script acting as an MCP client with no pre-shared
// credential. It discovers the authorization server from the 401 challenge,
// registers itself (dynamic client registration, and separately with a
// client ID metadata document it serves on localhost), runs authorization
// code + PKCE through the server's HTML consent page with the owner's
// credential typed into the form, exchanges the code, subscribes to MCP
// events (answering the signed verification challenge), and reacts to signed
// event deliveries. No language model is called.
import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { generateWebhookSecret } from "@agent-aggregator/core";
import { assertLogsClean, expect, expectEqual, isMain, mcp, runStandalone, startReceiver, startStack, tool } from "../lib/harness.mjs";

export const NAME = "oauth-events";

function pkce() {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}

async function get(url, init = {}) {
  const response = await fetch(url, { redirect: "manual", ...init });
  const text = await response.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: response.status, headers: response.headers, text, json };
}

function form(fields) {
  return { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(fields).toString() };
}

/** Authorization request → consent page → owner approves in the form → redirect with code. */
async function authorize(base, metadata, { clientId, redirectUri, scope, ownerCredential, expectPage }) {
  const { verifier, challenge } = pkce();
  const state = randomBytes(12).toString("base64url");
  const query = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: redirectUri, scope, state, code_challenge: challenge, code_challenge_method: "S256", resource: `${base}/mcp` });
  const start = await get(`${metadata.authorization_endpoint}?${query}`);
  expectEqual(start.status, 303, "authorize redirects to the consent page");
  const page = await get(new URL(start.headers.get("location"), base).toString());
  expectEqual(page.status, 200, "consent page status");
  expectPage?.(page.text);
  const field = (name) => new RegExp(`name="${name}" value="([^"]+)"`).exec(page.text)?.[1];
  const cookie = page.headers.get("set-cookie").split(";")[0];
  const post = await get(`${base}/oauth/authorize`, { ...form({ request_id: field("request_id"), csrf: field("csrf"), action: "approve", owner_credential: ownerCredential }), headers: { "content-type": "application/x-www-form-urlencoded", cookie } });
  expectEqual(post.status, 303, "approval redirects back to the client");
  const target = new URL(post.headers.get("location"));
  expectEqual(`${target.origin}${target.pathname}`, redirectUri, "redirect target");
  expectEqual(target.searchParams.get("state"), state, "state round-trips");
  expectEqual(target.searchParams.get("iss"), metadata.issuer, "RFC 9207 iss");
  const code = target.searchParams.get("code");
  expect(code, "authorization code present");
  const tokens = await get(metadata.token_endpoint, form({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: clientId, redirect_uri: redirectUri, resource: `${base}/mcp` }));
  expectEqual(tokens.status, 200, `token exchange (${tokens.text.slice(0, 120)})`);
  expectEqual(tokens.json.token_type, "Bearer", "token_type");
  return tokens.json;
}

export async function run(check) {
  let stack;
  let receiver;
  let cimdServer;
  try {
    stack = await check.step("agg-server starts on SQLite; agg-owner init creates the owner", async () => startStack(NAME));
    const { url } = stack;
    const redirectUri = "http://127.0.0.1:53682/callback";

    const metadata = await check.step("discovery: 401 challenge → protected resource metadata → authorization server metadata", async () => {
      const challenge = await mcp(url, null, "server/discover", {}, { modern: true });
      expectEqual(challenge.status, 401, "unauthenticated MCP status");
      const resourceMetadataUrl = /resource_metadata="([^"]+)"/.exec(challenge.headers.get("www-authenticate"))?.[1];
      const prm = await get(resourceMetadataUrl);
      expectEqual(prm.json.resource, `${url}/mcp`, "resource");
      const asm = await get(`${prm.json.authorization_servers[0]}/.well-known/oauth-authorization-server`);
      expectEqual(asm.json.issuer, url, "issuer");
      expect(asm.json.code_challenge_methods_supported.includes("S256"), "S256 supported");
      expectEqual(asm.json.client_id_metadata_document_supported, true, "CIMD supported");
      return asm.json;
    });

    const client = await check.step("dynamic client registration (RFC 7591), public client", async () => {
      const res = await get(metadata.registration_endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "Example events agent", redirect_uris: [redirectUri], grant_types: ["authorization_code", "refresh_token"], token_endpoint_auth_method: "none" }) });
      expectEqual(res.status, 201, "registration status");
      expect(/^dcr_/.test(res.json.client_id), "client_id issued");
      return res.json;
    });

    const tokens = await check.step("authorization code + PKCE via the consent page (owner credential typed into the form)", async () =>
      authorize(url, metadata, {
        clientId: client.client_id, redirectUri, scope: "hub:read hub:write hub:ask hub:handoff", ownerCredential: stack.ownerCredential,
        expectPage: (html) => {
          expect(html.includes("Example events agent"), "page shows the client name");
          expect(html.includes("127.0.0.1:53682"), "page shows the redirect host");
          for (const scope of ["hub:read", "hub:write", "hub:ask", "hub:handoff"]) expect(html.includes(`<code>${scope}</code>`), `page lists ${scope}`);
        },
      }),
    );

    await check.step("MCP with the access token: server/discover, whoami (mode oauth_events), events/list", async () => {
      const discover = await mcp(url, tokens.access_token, "server/discover", {}, { modern: true });
      expectEqual(discover.json.result.resultType, "complete", "resultType");
      const who = await tool(url, tokens.access_token, "whoami", {}, { modern: true });
      expectEqual(who.mode, "oauth_events", "mode");
      const events = await mcp(url, tokens.access_token, "events/list", {}, { modern: true });
      expectEqual(events.json.result.events.map((e) => e.name).join(","), "answer.created,question.updated,job.updated,message.created", "event catalog");
    });

    receiver = await startReceiver();
    const subscriptionSecret = generateWebhookSecret();
    receiver.state.secret = subscriptionSecret;
    const subscriptions = await check.step("events/subscribe answer.created + job.updated; signed verification challenge answered", async () => {
      const out = {};
      for (const name of ["answer.created", "job.updated"]) {
        const res = await mcp(url, tokens.access_token, "events/subscribe", { name, arguments: {}, delivery: { mode: "webhook", url: `${receiver.url}/mcp-events`, secret: subscriptionSecret } }, { modern: true });
        expect(res.json.result, `subscribe ${name}: ${JSON.stringify(res.json.error)}`);
        expect(/^sub_[0-9a-f]{32}$/.test(res.json.result.id), "subscription id");
        expect(res.json.result.refreshBefore, "refreshBefore");
        out[name] = res.json.result.id;
      }
      expectEqual(receiver.state.verifications, 2, "verification challenges answered");
      return out;
    });

    await check.step("a callback that cannot prove it holds the secret is refused (-32015)", async () => {
      const res = await mcp(url, tokens.access_token, "events/subscribe", { name: "question.updated", delivery: { mode: "webhook", url: `${receiver.url}/mcp-events`, secret: generateWebhookSecret() } }, { modern: true });
      expectEqual(res.json.error?.code, -32015, "CallbackEndpointError");
    });

    await check.step("upsert_work_item + post_checkpoint + create_question", async () => {
      await tool(url, tokens.access_token, "upsert_work_item", { id: "goal-q4-trip", kind: "goal", title: "Plan the Q4 offsite", status: "in_progress" });
      await tool(url, tokens.access_token, "post_checkpoint", { id: "cp-q4-trip-1", work_item_id: "goal-q4-trip", summary: "Shortlisted two venues" });
      const asked = await tool(url, tokens.access_token, "create_question", { id: "q-q4-venue", prompt: "Which venue should I book?", options: [{ id: "lake", label: "Lake lodge" }, { id: "city", label: "City loft" }], work_item_id: "goal-q4-trip" });
      expectEqual(asked.question.status, "pending", "status");
    });

    const connectionId = await check.step("owner answers with agg-owner (choice lake)", async () => {
      const pending = await stack.owner(["questions"]);
      const entry = pending.json.questions.find((q) => q.question.id === "q-q4-venue");
      await stack.owner(["answer", "--connection", entry.connection.id, "--id", "q-q4-venue", "--revision", String(entry.question.revision), "--choice", "lake", "--text", "Book Friday to Sunday"]);
      return entry.connection.id;
    });

    await check.step("signed answer.created event arrives with x-mcp-subscription-id", async () => {
      const hit = await receiver.waitFor((d) => d.json.name === "answer.created", "answer.created event");
      expectEqual(hit.headers["x-mcp-subscription-id"], subscriptions["answer.created"], "subscription id header");
      expectEqual(hit.json.data.answer.choice, "lake", "choice in payload");
      expect(typeof hit.json.cursor === "string" && hit.json.cursor.startsWith("c1."), "event carries an inbox cursor");
    });

    await check.step("get_answer + acknowledge_answer", async () => {
      const q = await tool(url, tokens.access_token, "get_answer", { question_id: "q-q4-venue" });
      expectEqual(q.answer.choice_label, "Lake lodge", "choice label");
      expectEqual(q.answer.text, "Book Friday to Sunday", "free text");
      const acked = await tool(url, tokens.access_token, "acknowledge_answer", { question_id: "q-q4-venue", revision: q.revision });
      expect(acked.answer.acknowledged_at, "acknowledged");
    });

    await check.step("handoff_goal → needs_user → owner approves → owner reports done; job.updated events arrive", async () => {
      const { job } = await tool(url, tokens.access_token, "handoff_goal", { goal: "Book the lake lodge for Friday to Sunday", idempotency_key: "q4-booking", work_item_id: "goal-q4-trip" });
      await receiver.waitFor((d) => d.json.name === "job.updated" && d.json.data.job_id === job.id && d.json.data.status === "needs_user", "job.updated needs_user");
      await stack.owner(["job", "decide", "--connection", connectionId, "--id", job.id, "--approve"]);
      await receiver.waitFor((d) => d.json.name === "job.updated" && d.json.data.status === "running", "job.updated running");
      await stack.owner(["job", "progress", "--connection", connectionId, "--id", job.id, "--status", "done", "--summary", "Booked; confirmation sent"]);
      const done = await receiver.waitFor((d) => d.json.name === "job.updated" && d.json.data.status === "done", "job.updated done");
      expectEqual(done.headers["x-mcp-subscription-id"], subscriptions["job.updated"], "subscription id header");
    });

    const rotated = await check.step("refresh token rotates; reusing the old refresh token revokes the family", async () => {
      const refreshed = await get(metadata.token_endpoint, form({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: client.client_id }));
      expectEqual(refreshed.status, 200, "refresh status");
      expect(refreshed.json.refresh_token !== tokens.refresh_token, "new refresh token");
      const who = await tool(url, refreshed.json.access_token, "whoami");
      expectEqual(who.mode, "oauth_events", "new access token works");
      const reuse = await get(metadata.token_endpoint, form({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: client.client_id }));
      expectEqual(reuse.json.error, "invalid_grant", "reuse rejected");
      const after = await mcp(url, refreshed.json.access_token, "ping");
      expectEqual(after.status, 401, "family revoked after reuse");
      return refreshed.json;
    });

    // A client identified by a metadata document it publishes (CIMD). In development the server accepts http on loopback.
    let documentFetches = 0;
    const cimdRedirect = "http://127.0.0.1:53683/callback";
    cimdServer = createServer((req, res) => {
      if (req.url !== "/oauth/client-metadata.json") {
        res.writeHead(404).end();
        return;
      }
      documentFetches += 1;
      const clientId = `http://127.0.0.1:${cimdServer.address().port}/oauth/client-metadata.json`;
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ client_id: clientId, client_name: "Example CIMD agent", redirect_uris: [cimdRedirect], grant_types: ["authorization_code", "refresh_token"], token_endpoint_auth_method: "none" }));
    });
    await new Promise((resolve) => cimdServer.listen(0, "127.0.0.1", resolve));
    const cimdClientId = `http://127.0.0.1:${cimdServer.address().port}/oauth/client-metadata.json`;

    const cimdTokens = await check.step("client ID metadata document: server fetches it, consent shows its host, tokens issued", async () => {
      const out = await authorize(url, metadata, {
        clientId: cimdClientId, redirectUri: cimdRedirect, scope: "hub:read hub:ask", ownerCredential: stack.ownerCredential,
        expectPage: (html) => {
          expect(html.includes("Example CIMD agent"), "page shows the document's client name");
          expect(html.includes(`Metadata document published at <code>127.0.0.1:${cimdServer.address().port}</code>`), "page shows the document host");
        },
      });
      expectEqual(documentFetches, 1, "document fetched once (then cached)");
      expectEqual(out.scope, "hub:read hub:ask", "granted scopes");
      const who = await tool(url, out.access_token, "whoami");
      expectEqual(who.scopes.join(" "), "hub:read hub:ask", "token scopes");
      return out;
    });

    await check.step("RFC 7009 revocation: revoked access token gets 401", async () => {
      const res = await get(metadata.revocation_endpoint, form({ token: cimdTokens.access_token }));
      expectEqual(res.status, 200, "revoke status");
      expectEqual((await mcp(url, cimdTokens.access_token, "ping")).status, 401, "revoked token");
    });

    await check.step("server logs contain no tokens, codes, secrets or Authorization values", async () =>
      assertLogsClean(stack, [tokens.access_token, tokens.refresh_token, rotated.access_token, rotated.refresh_token, cimdTokens.access_token, stack.ownerCredential, subscriptionSecret, stack.env.AGG_ENCRYPTION_KEY]),
    );
  } finally {
    await receiver?.close();
    if (cimdServer) await new Promise((resolve) => cimdServer.close(resolve));
    await stack?.stop();
  }
}

if (isMain(import.meta.url)) await runStandalone(NAME, run);
