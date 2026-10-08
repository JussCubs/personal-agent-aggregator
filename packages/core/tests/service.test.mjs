import assert from "node:assert/strict";
import test from "node:test";
import { verifyWebhook, AggregatorError } from "../dist/index.js";
import { connect, sqliteService } from "./helpers.mjs";

const rejects = async (promise, code) => {
  await assert.rejects(promise, (error) => error instanceof AggregatorError && error.code === code);
};

test("checkpoint -> question -> answer -> inbox -> ack round trip", async () => {
  const { service, owner } = await sqliteService();
  const alice = await owner("alice");
  const { principal } = await connect(service, alice);

  const item = await service.upsertWorkItem(principal, { id: "task-1", kind: "task", title: "Book flights", status: "in_progress" });
  assert.equal(item.changed, true);
  assert.equal(item.item.revision, 1);
  const same = await service.upsertWorkItem(principal, { id: "task-1", kind: "task", title: "Book flights", status: "in_progress" });
  assert.equal(same.changed, false, "identical upsert is a no-op");
  const bumped = await service.upsertWorkItem(principal, { id: "task-1", kind: "task", title: "Book flights", status: "blocked" });
  assert.equal(bumped.item.revision, 2);

  const cp1 = await service.postCheckpoint(principal, { id: "cp-1", work_item_id: "task-1", summary: "Found options" });
  const cp2 = await service.postCheckpoint(principal, { id: "cp-1", work_item_id: "task-1", summary: "Found options" });
  assert.equal(cp1.created, true);
  assert.equal(cp2.created, false, "checkpoint ids make retries safe");

  const asked = await service.createQuestion(principal, {
    id: "q-1", kind: "approval", prompt: "Book the 9:05 for $412?", affected_action: "Charge $412", action_digest: "sha256:abc", work_item_id: "task-1",
  });
  assert.equal(asked.created, true);
  assert.equal(asked.question.status, "pending");
  assert.deepEqual(asked.question.options.map((o) => o.id), ["approve", "deny"]);
  const again = await service.createQuestion(principal, {
    id: "q-1", kind: "approval", prompt: "Book the 9:05 for $412?", affected_action: "Charge $412", action_digest: "sha256:abc", work_item_id: "task-1",
  });
  assert.equal(again.created, false);
  assert.equal(again.revised, false);
  const revised = await service.createQuestion(principal, {
    id: "q-1", kind: "approval", prompt: "Book the 9:05 for $398?", affected_action: "Charge $398", action_digest: "sha256:def", work_item_id: "task-1",
  });
  assert.equal(revised.revised, true);
  assert.equal(revised.question.revision, 2);

  const pending = await service.listOwnerQuestions(alice);
  assert.equal(pending.length, 1);
  assert.equal(pending[0].question.prompt, "Book the 9:05 for $398?");

  await rejects(service.answerQuestion(alice, { connection_id: principal.connectionId, question_id: "q-1", revision: 1, choice: "approve" }), "stale_revision");
  const answered = await service.answerQuestion(alice, { connection_id: principal.connectionId, question_id: "q-1", revision: 2, choice: "approve" });
  assert.equal(answered.status, "answered");
  assert.equal(answered.answer.decision, "approved");
  assert.equal(answered.answer.question_revision, 2);
  assert.equal(answered.answer.action_digest, "sha256:def");
  assert.equal(answered.answer.author.verified, true);
  await rejects(service.answerQuestion(alice, { connection_id: principal.connectionId, question_id: "q-1", revision: 2, choice: "deny" }), "conflict");

  const inbox = await service.readInbox(principal, {});
  assert.equal(inbox.events.length, 1);
  assert.equal(inbox.events[0].name, "answer.created");
  assert.equal(inbox.events[0].data.question_id, "q-1");
  const empty = await service.readInbox(principal, { cursor: inbox.cursor });
  assert.equal(empty.events.length, 0, "cursor resumes after the last event");
  assert.equal(empty.cursor, inbox.cursor);

  await rejects(service.acknowledgeAnswer(principal, "q-1", 1), "stale_revision");
  const acked = await service.acknowledgeAnswer(principal, "q-1", 2);
  assert.ok(acked.answer.acknowledged_at);
  const unacked = await service.listQuestions(principal, { unacknowledged: true });
  assert.equal(unacked.length, 0);
});

test("handoff produces needs_user, running, then done/blocked events", async () => {
  const { service, owner } = await sqliteService();
  const alice = await owner("alice");
  const { principal } = await connect(service, alice);
  const { job, created } = await service.handoffJob(principal, { goal: "Draft the itinerary", idempotency_key: "trip-1" });
  assert.equal(created, true);
  assert.match(job.id, /^job_/);
  assert.equal(job.status, "needs_user");
  assert.equal(job.status_reason, "awaiting_owner_approval");
  const dup = await service.handoffJob(principal, { goal: "Draft the itinerary", idempotency_key: "trip-1" });
  assert.equal(dup.created, false);
  assert.equal(dup.job.id, job.id);

  await rejects(service.reportJobProgress(alice, { connection_id: principal.connectionId, job_id: job.id, status: "done" }), "conflict");
  const running = await service.decideJob(alice, { connection_id: principal.connectionId, job_id: job.id, approve: true });
  assert.equal(running.status, "running");
  const blocked = await service.reportJobProgress(alice, { connection_id: principal.connectionId, job_id: job.id, status: "blocked", summary: "Needs dates" });
  assert.equal(blocked.status, "blocked");
  const done = await service.reportJobProgress(alice, { connection_id: principal.connectionId, job_id: job.id, status: "done", summary: "Itinerary ready", result: { url: "https://example.com/i" } });
  assert.equal(done.status, "done");
  assert.ok(done.completed_at);
  const inbox = await service.readInbox(principal, {});
  assert.deepEqual(inbox.events.map((e) => e.data.status), ["needs_user", "running", "blocked", "done"]);

  const second = await service.handoffJob(principal, { goal: "Book a hotel" });
  const declined = await service.decideJob(alice, { connection_id: principal.connectionId, job_id: second.job.id, approve: false });
  assert.equal(declined.status, "declined");
});

test("revocation kills credentials immediately and delete removes every row", async () => {
  const { service, owner, driver } = await sqliteService();
  const alice = await owner("alice");
  const { principal, token, connection } = await connect(service, alice);
  await service.upsertWorkItem(principal, { id: "t", kind: "task", title: "x" });
  await service.createQuestion(principal, { id: "q", prompt: "ok?", options: ["yes", "no"] });
  await service.handoffJob(principal, { goal: "g" });
  assert.ok(await service.authenticate(token));
  const revoked = await service.revokeConnection(alice, connection.id);
  assert.equal(revoked.status, "revoked");
  assert.equal(await service.authenticate(token), null, "token is dead right after revoke");
  const closed = await service.listOwnerQuestions(alice, { status: "cancelled" });
  assert.equal(closed[0].question.status_reason ?? "connection_revoked", "connection_revoked");
  const deleted = await service.deleteConnection(alice, connection.id);
  assert.equal(deleted.deleted.work_items, 1);
  assert.equal(deleted.deleted.questions, 1);
  assert.equal(deleted.deleted.jobs, 1);
  for (const table of ["connections", "work_items", "checkpoints", "questions", "jobs", "events", "credentials", "destinations", "deliveries"]) {
    const rows = await driver.privileged((db) => db.query(`SELECT count(*) AS n FROM aggregator_${table} WHERE ${table === "connections" ? "id" : "connection_id"} = $1`, [connection.id]));
    assert.equal(Number(rows[0].n), 0, `${table} rows removed`);
  }
  const audit = await service.listAudit(alice, { connection_id: connection.id });
  assert.deepEqual(audit.map((a) => a.action), ["connection.delete"], "only the deletion record remains");
});

test("claim codes work once and expire", async () => {
  let now = new Date("2026-10-01T00:00:00Z");
  const { service, owner } = await sqliteService({ now: () => now });
  const alice = await owner("alice");
  const connection = await service.createConnection(alice, { provider: "shell_agent", display_name: "Shell agent", mode: "cli_poll" });
  const { code } = await service.issueClaimCode(alice, connection.id);
  const claimed = await service.claim(code.toLowerCase());
  assert.ok(claimed.token);
  assert.ok(await service.authenticate(claimed.token));
  await rejects(service.claim(code), "unauthorized");
  const second = await service.issueClaimCode(alice, connection.id, 120);
  now = new Date(now.getTime() + 121_000);
  await rejects(service.claim(second.code), "unauthorized");
  assert.ok(await service.authenticate(claimed.token), "existing credential still works");
});

test("scopes are enforced per credential", async () => {
  const { service, owner } = await sqliteService();
  const alice = await owner("alice");
  const { principal } = await connect(service, alice, { scopes: ["hub:read"] });
  await rejects(service.upsertWorkItem(principal, { id: "a", kind: "task", title: "x" }), "insufficient_scope");
  await rejects(service.createQuestion(principal, { id: "q", prompt: "x", options: ["a"] }), "insufficient_scope");
  await rejects(service.handoffJob(principal, { goal: "x" }), "insufficient_scope");
  const info = await service.getConnectionInfo(principal);
  assert.deepEqual(info.scopes, ["hub:read"]);
});

test("webhook deliveries are signed, carry the routine key, and retry", async () => {
  const requests = [];
  let status = 500;
  const { service, owner } = await sqliteService({
    send: async (request) => {
      requests.push(request);
      return { status, body: "" };
    },
  });
  const alice = await owner("alice");
  const { principal } = await connect(service, alice);
  const hook = await service.setWebhook(principal, { url: "http://127.0.0.1:9/hook", auth_header_value: "test-key" });
  assert.match(hook.signing_secret, /^whsec_/);
  await service.createQuestion(principal, { id: "q", prompt: "ok?", options: ["yes", "no"] });
  const [{ question }] = await service.listOwnerQuestions(alice);
  await service.answerQuestion(alice, { connection_id: principal.connectionId, question_id: "q", revision: question.revision, choice: "opt_1" });
  const first = await service.deliverDue();
  assert.equal(first.retried, 1);
  assert.equal(requests.length, 1);
  const sentOnce = requests[0];
  assert.equal(sentOnce.headers.authorization, "Bearer test-key");
  assert.ok(verifyWebhook(hook.signing_secret, sentOnce.headers, sentOnce.body));
  const envelope = JSON.parse(sentOnce.body);
  assert.equal(envelope.name, "answer.created");
  assert.equal(envelope.data.answer.choice, "opt_1");
  assert.equal(sentOnce.headers["webhook-id"], envelope.eventId);
  status = 200;
  const notYet = await service.deliverDue();
  assert.equal(notYet.delivered, 0, "retry waits for its backoff");
});

test("MCP event subscriptions verify the callback and deliver with the subscription id", async () => {
  const { service, owner, sent } = await sqliteService();
  const alice = await owner("alice");
  const { principal } = await connect(service, alice, { mode: "oauth_events" });
  const secret = `whsec_${Buffer.alloc(32, 7).toString("base64")}`;
  const sub = await service.subscribeEvent(principal, { name: "answer.created", arguments: {}, delivery: { mode: "webhook", url: "http://127.0.0.1:9/events", secret }, cursor: null });
  assert.match(sub.id, /^sub_[0-9a-f]{32}$/);
  assert.ok(sub.refreshBefore);
  const again = await service.subscribeEvent(principal, { name: "answer.created", arguments: {}, delivery: { mode: "webhook", url: "http://127.0.0.1:9/events", secret }, cursor: null });
  assert.equal(again.id, sub.id, "deterministic subscription id");
  const verification = JSON.parse(sent[0].body);
  assert.equal(verification.type, "verification");
  assert.ok(verifyWebhook(secret, sent[0].headers, sent[0].body));
  await service.createQuestion(principal, { id: "q", prompt: "ok?", options: ["yes"] });
  await service.answerQuestion(alice, { connection_id: principal.connectionId, question_id: "q", revision: 1, choice: "opt_1" });
  const result = await service.deliverDue();
  assert.equal(result.delivered, 1);
  const delivery = sent.at(-1);
  assert.equal(delivery.headers["x-mcp-subscription-id"], sub.id);
  assert.ok(verifyWebhook(secret, delivery.headers, delivery.body));
  await service.unsubscribeEvent(principal, { name: "answer.created", arguments: {}, delivery: { mode: "webhook", url: "http://127.0.0.1:9/events" } });
  const overview = await service.getConnection(alice, principal.connectionId);
  assert.equal(overview.subscriptions, 0);
});

test("a callback that fails verification is rejected", async () => {
  const { service, owner } = await sqliteService({ send: async () => ({ status: 200, body: JSON.stringify({ challenge: "wrong" }) }) });
  const alice = await owner("alice");
  const { principal } = await connect(service, alice);
  await assert.rejects(
    service.subscribeEvent(principal, { name: "job.updated", delivery: { mode: "webhook", url: "http://127.0.0.1:9/e", secret: `whsec_${Buffer.alloc(32, 1).toString("base64")}` } }),
    (error) => error instanceof AggregatorError && error.details?.callback_error === true,
  );
});

test("untrusted text is normalized and bounded", async () => {
  const { service, owner } = await sqliteService();
  const alice = await owner("alice");
  const { principal } = await connect(service, alice);
  const { question } = await service.createQuestion(principal, { id: "q", prompt: "Pay‮ $100\u0007 now?", options: ["yes"] });
  assert.equal(question.prompt, "Pay $100 now?");
  await rejects(service.createQuestion(principal, { id: "q2", prompt: "x".repeat(1001) }), "invalid_request");
  await rejects(service.upsertWorkItem(principal, { id: "bad id!", kind: "task", title: "x" }), "invalid_request");
  await rejects(service.upsertWorkItem(principal, { id: "big", kind: "task", title: "x", data: { blob: "y".repeat(20000) } }), "payload_too_large");
});

test("questions expire on sweep and notify the agent", async () => {
  let now = new Date("2026-10-01T00:00:00Z");
  const { service, owner } = await sqliteService({ now: () => now });
  const alice = await owner("alice");
  const { principal } = await connect(service, alice);
  await service.createQuestion(principal, { id: "q", prompt: "Soon?", options: ["yes"], expires_in_seconds: 120 });
  now = new Date(now.getTime() + 200_000);
  const swept = await service.sweep();
  assert.equal(swept.expired, 1);
  const q = await service.getQuestion(principal, "q");
  assert.equal(q.status, "expired");
  const inbox = await service.readInbox(principal, {});
  assert.equal(inbox.events[0].name, "question.updated");
  assert.equal(inbox.events[0].data.status, "expired");
});

test("re-sending a question with a relative expiry is a no-op", async () => {
  let now = new Date("2026-10-01T00:00:00Z");
  const { service, owner } = await sqliteService({ now: () => now });
  const alice = await owner("alice");
  const { principal } = await connect(service, alice);
  const first = await service.createQuestion(principal, { id: "q", prompt: "Ship?", options: ["yes"], expires_in_seconds: 3600 });
  now = new Date(now.getTime() + 5000);
  const retry = await service.createQuestion(principal, { id: "q", prompt: "Ship?", options: ["yes"], expires_in_seconds: 3600 });
  assert.equal(retry.created, false);
  assert.equal(retry.revised, false, "a retry does not revise the question");
  assert.equal(retry.question.revision, first.question.revision);
  assert.equal(retry.question.expires_at, first.question.expires_at, "the deadline set on first ask is kept");
});

test("a DNS failure is retried, not final", async () => {
  const { service, owner } = await sqliteService({
    send: async () => {
      throw new AggregatorError("unavailable", "destination host did not resolve", { field: "url", reason: "dns" });
    },
  });
  const alice = await owner("alice");
  const { principal } = await connect(service, alice);
  await service.setWebhook(principal, { url: "http://127.0.0.1:9/hook" });
  await service.handoffJob(principal, { goal: "g" });
  const result = await service.deliverDue();
  assert.equal(result.retried, 1);
  assert.equal(result.failed, 0);
});
