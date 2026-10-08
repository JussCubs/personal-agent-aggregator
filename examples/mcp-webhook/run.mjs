// Wake mode 1: MCP + bearer credential, woken by a signed webhook.
//
// The "agent" is this script. It talks MCP over Streamable HTTP with a bearer
// credential the owner issued (both the legacy initialize handshake and the
// 2026-07-28 server/discover flow), registers a wake-up webhook pointing at a
// local receiver, and reacts to signed deliveries. The owner acts through
// agg-owner. No language model is called.
import { createHash } from "node:crypto";
import {
  actionDigest,
  assertLogsClean,
  expect,
  expectEqual,
  isMain,
  mcp,
  runStandalone,
  startReceiver,
  startStack,
  tool,
} from "../lib/harness.mjs";

export const NAME = "mcp-webhook";

export async function run(check) {
  let stack;
  let receiver;
  try {
    stack = await check.step("agg-server starts on SQLite; agg-owner init creates the owner", async () => startStack(NAME));
    const { url } = stack;

    const connection = await check.step("owner creates an mcp_webhook connection", async () => {
      const res = await stack.owner(["connection", "create", "--provider", "example_mcp_agent", "--name", "Example MCP agent", "--mode", "mcp_webhook"]);
      expectEqual(res.json.connection.mode, "mcp_webhook", "mode");
      expectEqual(res.json.connection.status, "pending", "status before a credential exists");
      return res.json.connection;
    });

    const token = await check.step("owner issues the agent credential (shown once)", async () => {
      const res = await stack.owner(["credential", "issue", "--connection", connection.id]);
      expect(/^agg_[A-Za-z0-9_-]{43}$/.test(res.json.token), "credential has the agg_ prefix");
      expectEqual(res.json.connection.status, "active", "status after issuing");
      return res.json.token;
    });

    await check.step("MCP without a credential gets 401 + WWW-Authenticate resource_metadata", async () => {
      const res = await mcp(url, null, "initialize", {});
      expectEqual(res.status, 401, "status");
      expect(res.headers.get("www-authenticate").includes(`resource_metadata="${url}/.well-known/oauth-protected-resource/mcp"`), "challenge names the resource metadata");
    });

    await check.step("legacy MCP: initialize, notifications/initialized, tools/list", async () => {
      const init = await mcp(url, token, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "example-agent", version: "0.1.0" } });
      expectEqual(init.json.result.protocolVersion, "2025-06-18", "negotiated version");
      const note = await fetch(`${url}/mcp`, { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) });
      expectEqual(note.status, 202, "notification status");
      const list = await mcp(url, token, "tools/list", {});
      const names = list.json.result.tools.map((t) => t.name);
      expectEqual(names.length, 18, "tool count");
      expect(names.includes("set_callback_webhook") && names.includes("create_question"), "expected tools present");
      expect(["check_messages", "acknowledge_message", "post_message"].every((n) => names.includes(n)), "conversation tools present");
      expect(list.json.result.tools.every((t) => typeof t.annotations.readOnlyHint === "boolean"), "every tool has annotations");
    });

    await check.step("2026-07-28 MCP: server/discover with protocol headers and _meta", async () => {
      const res = await mcp(url, token, "server/discover", {}, { modern: true });
      expectEqual(res.json.result.resultType, "complete", "resultType");
      expect(res.json.result.supportedVersions.includes("2026-07-28"), "supports 2026-07-28");
      expect(res.json.result.capabilities.events, "advertises events");
    });

    await check.step("whoami (modern): callback not configured yet", async () => {
      const who = await tool(url, token, "whoami", {}, { modern: true });
      expectEqual(who.connection_id, connection.id, "connection id");
      expectEqual(who.callback.configured, false, "callback.configured");
    });

    receiver = await startReceiver();
    const routineKey = "example-routine-key-1";
    await check.step("set_callback_webhook to a local receiver; signing secret returned once", async () => {
      const result = await tool(url, token, "set_callback_webhook", { url: `${receiver.url}/wake`, auth_header_value: routineKey });
      expect(/^whsec_/.test(result.signing_secret), "whsec_ signing secret");
      receiver.state.secret = result.signing_secret;
      const who = await tool(url, token, "whoami");
      expectEqual(who.callback.configured, true, "callback.configured");
      expectEqual(who.callback.url_host, new URL(receiver.url).host, "callback host");
    });

    await check.step("upsert_work_item + post_checkpoint (idempotent by id)", async () => {
      const first = await tool(url, token, "upsert_work_item", { id: "task-invoice-42", kind: "task", title: "Pay invoice 42", status: "in_progress", next_step: "Get approval" });
      expectEqual(first.changed, true, "first upsert changes");
      const again = await tool(url, token, "upsert_work_item", { id: "task-invoice-42", kind: "task", title: "Pay invoice 42", status: "in_progress", next_step: "Get approval" });
      expectEqual(again.changed, false, "identical upsert is a no-op");
      const cp = await tool(url, token, "post_checkpoint", { id: "cp-invoice-42-1", work_item_id: "task-invoice-42", summary: "Invoice matched to purchase order" });
      expectEqual(cp.created, true, "checkpoint created");
      const cpAgain = await tool(url, token, "post_checkpoint", { id: "cp-invoice-42-1", work_item_id: "task-invoice-42", summary: "Invoice matched to purchase order" });
      expectEqual(cpAgain.created, false, "checkpoint retry recorded once");
    });

    const action = { type: "payment", invoice: "42", amount: "412.00", currency: "USD" };
    const digest = actionDigest(action);
    await check.step("create_question: approval with affected_action and action_digest", async () => {
      const asked = await tool(url, token, "create_question", {
        id: "q-invoice-42-pay", kind: "approval", prompt: "Pay invoice 42 for 412.00 USD?", affected_action: "Pay 412.00 USD to the vendor on invoice 42", action_digest: digest, work_item_id: "task-invoice-42", urgency: "high",
      });
      expectEqual(asked.created, true, "created");
      expectEqual(asked.question.revision, 1, "revision");
      expectEqual(asked.question.options.map((o) => o.id).join(","), "approve,deny", "fixed approval options");
    });

    await check.step("owner lists pending questions and approves revision 1 (agg-owner answer --approve)", async () => {
      const pending = await stack.owner(["questions"]);
      const entry = pending.json.questions.find((q) => q.question.id === "q-invoice-42-pay");
      expect(entry, "question visible to the owner");
      expectEqual(entry.question.action_digest, digest, "owner sees the digest");
      const answered = await stack.owner(["answer", "--connection", connection.id, "--id", "q-invoice-42-pay", "--revision", String(entry.question.revision), "--approve"]);
      expectEqual(answered.json.question.status, "answered", "status");
    });

    const delivery = await check.step("answer.created webhook arrives signed (Standard Webhooks) with the routine key", async () => {
      const hit = await receiver.waitFor((d) => d.json.name === "answer.created", "answer.created");
      expectEqual(hit.headers.authorization, `Bearer ${routineKey}`, "routine key header");
      expectEqual(hit.headers["webhook-id"], hit.json.eventId, "webhook-id is the event id");
      expectEqual(hit.json.data.question_id, "q-invoice-42-pay", "question id");
      return hit;
    });

    await check.step("receiver rejects a forged signature and a tampered body", async () => {
      const before = receiver.state.rejected;
      const forged = await fetch(`${receiver.url}/wake`, { method: "POST", headers: { "webhook-id": "evt_forged", "webhook-timestamp": String(Math.floor(Date.now() / 1000)), "webhook-signature": `v1,${createHash("sha256").update("x").digest("base64")}`, "content-type": "application/json" }, body: delivery.body });
      expectEqual(forged.status, 401, "forged signature");
      const tampered = await fetch(`${receiver.url}/wake`, { method: "POST", headers: { "webhook-id": delivery.headers["webhook-id"], "webhook-timestamp": delivery.headers["webhook-timestamp"], "webhook-signature": delivery.headers["webhook-signature"], "content-type": "application/json" }, body: delivery.body.replace("approved", "denied") });
      expectEqual(tampered.status, 401, "tampered body");
      expectEqual(receiver.state.rejected, before + 2, "both rejected");
    });

    await check.step("get_answer: approved, question_revision and action_digest match what was asked", async () => {
      const q = await tool(url, token, "get_answer", { question_id: "q-invoice-42-pay" });
      expectEqual(q.answer.decision, "approved", "decision");
      expectEqual(q.answer.question_revision, 1, "question_revision");
      expectEqual(q.answer.action_digest, digest, "action_digest");
      expectEqual(q.answer.author.verified, true, "verified author");
      expectEqual(q.answer.author.surface, "cli", "answered from agg-owner");
    });

    await check.step("acknowledge_answer with the revision; answer is marked acknowledged", async () => {
      const acked = await tool(url, token, "acknowledge_answer", { question_id: "q-invoice-42-pay", revision: 1 });
      expect(acked.answer.acknowledged_at, "acknowledged_at set");
      const inbox = await tool(url, token, "check_inbox", {});
      expect(inbox.events.some((e) => e.name === "answer.created"), "the same event is also in the inbox");
    });

    const job = await check.step("handoff_goal: job starts needs_user; job.updated webhook arrives", async () => {
      const out = await tool(url, token, "handoff_goal", { goal: "Reconcile the vendor ledger for invoice 42", idempotency_key: "ledger-42", work_item_id: "task-invoice-42" });
      expectEqual(out.created, true, "created");
      expectEqual(out.job.status, "needs_user", "initial status");
      const retry = await tool(url, token, "handoff_goal", { goal: "Reconcile the vendor ledger for invoice 42", idempotency_key: "ledger-42" });
      expectEqual(retry.job.id, out.job.id, "idempotency_key returns the same job");
      await receiver.waitFor((d) => d.json.name === "job.updated" && d.json.data.job_id === out.job.id && d.json.data.status === "needs_user", "job.updated needs_user");
      return out.job;
    });

    await check.step("owner approves the job (agg-owner job decide); job.updated running arrives", async () => {
      const res = await stack.owner(["job", "decide", "--connection", connection.id, "--id", job.id, "--approve", "--note", "Go ahead"]);
      expectEqual(res.json.job.status, "running", "status");
      await receiver.waitFor((d) => d.json.name === "job.updated" && d.json.data.status === "running", "job.updated running");
    });

    await check.step("owner reports done (agg-owner job progress); job.updated done arrives; get_job is done", async () => {
      await stack.owner(["job", "progress", "--connection", connection.id, "--id", job.id, "--status", "done", "--summary", "Ledger reconciled", "--result", '{"adjustments":0}']);
      const done = await receiver.waitFor((d) => d.json.name === "job.updated" && d.json.data.status === "done", "job.updated done");
      expectEqual(done.json.data.result.adjustments, 0, "result delivered");
      const got = await tool(url, token, "get_job", { job_id: job.id });
      expectEqual(got.status, "done", "get_job status");
    });

    await check.step("server logs contain no credentials, secrets or Authorization values", async () => assertLogsClean(stack, [token, stack.ownerCredential, receiver.state.secret, routineKey, stack.env.AGG_ENCRYPTION_KEY]));
  } finally {
    await receiver?.close();
    await stack?.stop();
  }
}

if (isMain(import.meta.url)) await runStandalone(NAME, run);
