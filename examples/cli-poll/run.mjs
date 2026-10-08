// Wake mode 3: an agent with a shell, woken by polling the inbox.
//
// The "agent" is the `agg` CLI plus scripts/poll-inbox.sh, driven exactly as
// a cron job would drive them. The credential arrives through a one-time
// setup code the agent exchanges itself, so it never passes through a chat.
// Every step is a command with a documented exit code, including answering
// the owner's messages (agg messages / working / reply, agg ask --thread). No
// language model is called.
import { spawn } from "node:child_process";
import { chmodSync, existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ROOT, assertConversationLogged, assertLogsClean, expect, expectEqual, isMain, ownerMessage, runStandalone, startStack } from "../lib/harness.mjs";

export const NAME = "cli-poll";

function sh(script, args, env) {
  return new Promise((resolve, reject) => {
    const child = spawn("sh", [script, ...args], { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c) => (stdout += c));
    child.stderr.on("data", (c) => (stderr += c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

const lines = (text) => text.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));

export async function run(check) {
  let stack;
  try {
    stack = await check.step("agg-server starts on SQLite; agg-owner init creates the owner", async () => startStack(NAME));
    const apiBase = `${stack.url}/api`;
    const configDir = join(stack.env.XDG_CONFIG_HOME, "agent-aggregator");

    const connection = await check.step("owner creates a cli_poll connection and a one-time setup code", async () => {
      const created = await stack.owner(["connection", "create", "--provider", "example_shell_agent", "--name", "Example shell agent", "--mode", "cli_poll"]);
      const code = await stack.owner(["claim-code", "--connection", created.json.connection.id, "--ttl", "900"]);
      expect(/^[A-Z2-9]{5}(-[A-Z2-9]{5}){3}$/.test(code.json.code), "setup code format");
      return { id: created.json.connection.id, code: code.json.code };
    });

    const token = await check.step("agg setup --claim stores the credential in a 0600 file (exit 0); the code is single-use (exit 4)", async () => {
      const res = await stack.agg(["setup", "--claim", connection.code, "--server", apiBase]);
      expectEqual(res.json.ok, true, "setup ok");
      const file = join(configDir, "hub.json");
      expectEqual(statSync(file).mode & 0o777, 0o600, "credential file mode");
      await stack.agg(["setup", "--claim", connection.code, "--server", apiBase], 4);
      return JSON.parse(readFileSync(file, "utf8")).token;
    });

    await check.step("agg doctor: read-only check (exit 0, mode cli_poll)", async () => {
      const res = await stack.agg(["doctor"]);
      expectEqual(res.json.ok, true, "ok");
      expectEqual(res.json.mode, "cli_poll", "mode");
    });

    await check.step("agg item put + agg checkpoint (exit 0)", async () => {
      const item = await stack.agg(["item", "put", "--id", "task-backup", "--kind", "task", "--title", "Rotate the backup drive", "--status", "in_progress", "--next-step", "Confirm the swap date"]);
      expectEqual(item.json.item.revision, 1, "revision");
      const cp = await stack.agg(["checkpoint", "--item", "task-backup", "--id", "cp-backup-1", "--summary", "New drive formatted and verified"]);
      expectEqual(cp.json.created, true, "checkpoint created");
    });

    await check.step("agg ask with two options (exit 0); agg answer while pending (exit 3); agg inbox with nothing new (exit 3)", async () => {
      const asked = await stack.agg(["ask", "--id", "q-backup-swap", "--prompt", "Swap the backup drive on Saturday?", "--option", "yes=Yes, Saturday", "--option", "no=No, wait", "--item", "task-backup"]);
      expectEqual(asked.json.created, true, "created");
      await stack.agg(["answer", "--id", "q-backup-swap"], 3);
      await stack.agg(["inbox"], 3);
    });

    await check.step("owner answers with agg-owner (choice yes)", async () => {
      const pending = await stack.owner(["questions", "--connection", connection.id]);
      const entry = pending.json.questions.find((q) => q.question.id === "q-backup-swap");
      expect(entry, "pending question visible");
      await stack.owner(["answer", "--connection", connection.id, "--id", "q-backup-swap", "--revision", String(entry.question.revision), "--choice", "yes"]);
    });

    const eventsFile = join(stack.dir, "events.jsonl");
    await check.step("agg inbox --exec: a failing hook keeps the cursor (exit 1); a working hook gets answer.created (exit 0)", async () => {
      await stack.agg(["inbox", "--exec", "exit 7"], 1);
      await stack.agg(["inbox", "--exec", `cat >> '${eventsFile}'`]);
      const events = lines(readFileSync(eventsFile, "utf8"));
      expect(events.some((e) => e.name === "answer.created" && e.data.question_id === "q-backup-swap"), "answer.created delivered to the hook");
      await stack.agg(["inbox"], 3);
    });

    await check.step("agg answer (exit 0, JSON) + agg ack --revision (exit 0)", async () => {
      const res = await stack.agg(["answer", "--id", "q-backup-swap"]);
      expectEqual(res.json.answer.choice, "yes", "choice");
      expectEqual(res.json.answer.choice_label, "Yes, Saturday", "label");
      const acked = await stack.agg(["ack", "--id", "q-backup-swap", "--revision", String(res.json.revision)]);
      expect(acked.json.question.answer.acknowledged_at, "acknowledged");
    });

    const job = await check.step("agg handoff (exit 0, needs_user); agg job while open (exit 3)", async () => {
      const res = await stack.agg(["handoff", "--goal", "Order a spare backup drive", "--key", "spare-drive", "--item", "task-backup"]);
      expectEqual(res.json.job.status, "needs_user", "status");
      await stack.agg(["job", "--id", res.json.job.id], 3);
      return res.json.job;
    });

    await check.step("scripts/poll-inbox.sh (sh + curl, own cursor): new events (exit 0), then nothing new (exit 3)", async () => {
      const envFile = join(configDir, "poller.env");
      writeFileSync(envFile, `AGG_URL='${apiBase}'\nAGG_TOKEN='${token}'\n`, { mode: 0o600 });
      const env = { ...stack.env, AGG_ENV_FILE: envFile };
      const cursorFile = join(stack.dir, "sh.cursor");
      const first = await sh(join(ROOT, "scripts/poll-inbox.sh"), [cursorFile], env);
      expectEqual(first.code, 0, `first poll (${first.stderr.trim()})`);
      const names = lines(first.stdout).flatMap((page) => page.events.map((e) => e.name));
      expect(names.includes("answer.created") && names.includes("job.updated"), `events seen: ${names.join(",")}`);
      expectEqual(statSync(cursorFile).mode & 0o777, 0o600, "cursor file mode");
      const second = await sh(join(ROOT, "scripts/poll-inbox.sh"), [cursorFile], env);
      expectEqual(second.code, 3, "second poll");
      const bad = await sh(join(ROOT, "scripts/poll-inbox.sh"), [cursorFile], { ...stack.env, AGG_URL: apiBase, AGG_TOKEN: `agg_${"0".repeat(43)}` });
      expectEqual(bad.code, 4, "rejected credential");
    });

    await check.step("owner approves, then reports done; agg inbox --exec gets job.updated running + done; agg job (exit 0)", async () => {
      await stack.owner(["job", "decide", "--connection", connection.id, "--id", job.id, "--approve"]);
      await stack.owner(["job", "progress", "--connection", connection.id, "--id", job.id, "--status", "done", "--summary", "Spare drive ordered"]);
      writeFileSync(eventsFile, "");
      await stack.agg(["inbox", "--exec", `cat >> '${eventsFile}'`]);
      const statuses = lines(readFileSync(eventsFile, "utf8")).filter((e) => e.name === "job.updated").map((e) => e.data.status);
      expectEqual(statuses.join(","), "needs_user,running,done", "job.updated statuses since the last cursor");
      const done = await stack.agg(["job", "--id", job.id]);
      expectEqual(done.json.status, "done", "job status");
    });

    // Conversation bridge from a shell: the poller sees message.created and only then wakes the worker.
    const ownerText = "Also check the spare drive's SMART status";
    const message = await check.step("owner messages the agent (agg-owner say); agg inbox --exec gets message.created; reading it is the delivery receipt", async () => {
      const res = await stack.owner(["say", connection.id, ownerText, "--thread", "conv-backup", "--key", "host-msg-3"]);
      expectEqual(res.json.message.status, "queued", "queued until the agent reads it");
      writeFileSync(eventsFile, "");
      await stack.agg(["inbox", "--exec", `cat >> '${eventsFile}'`]);
      const event = lines(readFileSync(eventsFile, "utf8")).find((e) => e.name === "message.created");
      expect(event, "message.created handed to the hook");
      expectEqual(event.data.text, ownerText, "text");
      expectEqual(event.data.message_id, res.json.message.id, "message id");
      expectEqual((await ownerMessage(stack, connection.id, "conv-backup", res.json.message.id)).status, "delivered", "owner's view");
      return { id: res.json.message.id, threadId: res.json.thread.id };
    });

    await check.step("agg messages (exit 0, one JSON line) + agg working --id; the owner sees working", async () => {
      const open = await stack.agg(["messages"]);
      expectEqual(open.json.id, message.id, "open message");
      expectEqual(open.json.text, ownerText, "text");
      await stack.agg(["working", "--id", message.id]);
      expectEqual((await ownerMessage(stack, connection.id, "conv-backup", message.id)).status, "working", "owner's view");
    });

    await check.step("agg ask --thread (exit 0); owner answers in that conversation; agg inbox gets answer.created; agg answer + ack", async () => {
      const asked = await stack.agg(["ask", "--id", "q-backup-smart", "--prompt", "Drive 2 reports 3 reallocated sectors. Replace it now?", "--option", "now=Replace now", "--option", "later=Next month", "--item", "task-backup", "--thread", message.threadId]);
      expectEqual(asked.json.question.thread_id, message.threadId, "question carries the thread");
      const pending = await stack.owner(["questions", "--connection", connection.id]);
      const entry = pending.json.questions.find((q) => q.question.id === "q-backup-smart");
      expectEqual(entry.question.thread_id, message.threadId, "owner sees the thread");
      await stack.owner(["answer", "--connection", connection.id, "--id", "q-backup-smart", "--revision", "1", "--choice", "now"]);
      writeFileSync(eventsFile, "");
      await stack.agg(["inbox", "--exec", `cat >> '${eventsFile}'`]);
      expect(lines(readFileSync(eventsFile, "utf8")).some((e) => e.name === "answer.created" && e.data.question_id === "q-backup-smart"), "answer.created delivered to the hook");
      const answer = await stack.agg(["answer", "--id", "q-backup-smart"]);
      expectEqual(answer.json.answer.choice, "now", "choice");
      await stack.agg(["ack", "--id", "q-backup-smart", "--revision", String(answer.json.revision)]);
    });

    const replyText = "Drive 2 replaced; SMART is clean on the spare.";
    await check.step("agg reply --to (exit 0); agg messages has nothing open (exit 3); the owner's thread shows replied", async () => {
      const reply = await stack.agg(["reply", "--to", message.id, "--text", replyText, "--id", "reply-backup-smart"]);
      expectEqual(reply.json.created, true, "created");
      await stack.agg(["messages"], 3);
      const thread = await stack.owner(["thread", connection.id, "conv-backup"]);
      expectEqual(thread.json.messages.map((m) => `${m.direction}:${m.status}`).join(","), "to_agent:replied,from_agent:posted", "thread");
      expectEqual(thread.json.messages[1].text, replyText, "the agent's words");
    });

    await check.step("server logged delivered → working → replied, never the text", async () => assertConversationLogged(stack, message.id, ["delivered", "working", "replied"], [ownerText, replyText]));

    await check.step("pollers install idempotently: agg install-poller --print, scripts/install-poller.sh twice → one entry", async () => {
      const printed = await stack.agg(["install-poller", "--print", "--exec", "wake-my-worker"]);
      expect(printed.stdout.includes("# agent-aggregator-poller"), "agg prints a marked crontab line");
      const tab = join(stack.dir, "crontab.txt");
      const fake = join(stack.dir, "fake-crontab");
      writeFileSync(tab, "0 3 * * * /usr/local/bin/nightly-backup\n");
      writeFileSync(fake, `#!/bin/sh\nif [ "$1" = "-l" ]; then cat '${tab}'; else cat > '${tab}'; fi\n`);
      chmodSync(fake, 0o700);
      const env = { ...stack.env, AGG_CRONTAB: fake };
      for (let i = 0; i < 2; i += 1) {
        const res = await sh(join(ROOT, "scripts/install-poller.sh"), ["--every-minutes", "2", "--env-file", join(configDir, "poller.env")], env);
        expectEqual(res.code, 0, `install run ${i + 1} (${res.stderr.trim()})`);
      }
      const content = readFileSync(tab, "utf8");
      expectEqual(content.split("\n").filter((l) => l.includes("# agent-aggregator-poll-inbox")).length, 1, "marked entries");
      expect(content.includes("nightly-backup"), "other entries kept");
      expect(existsSync(join(ROOT, "scripts/poll-inbox.sh")), "poller script present");
    });

    await check.step("owner revokes the connection: an unanswered message fails visibly (connection_revoked); agg doctor exits 4", async () => {
      const pending = await stack.owner(["say", connection.id, "One more thing before you go", "--thread", "conv-backup"]);
      await stack.owner(["connection", "revoke", "--id", connection.id]);
      const lost = await ownerMessage(stack, connection.id, "conv-backup", pending.json.message.id);
      expectEqual(`${lost.status}:${lost.status_reason}`, "failed:connection_revoked", "status");
      await stack.owner(["say", connection.id, "Are you there?"], 5);
      await stack.agg(["doctor"], 4);
    });

    await check.step("server logs contain no credentials, setup codes or Authorization values", async () => assertLogsClean(stack, [token, connection.code, stack.ownerCredential, stack.env.AGG_ENCRYPTION_KEY]));
  } finally {
    await stack?.stop();
  }
}

if (isMain(import.meta.url)) await runStandalone(NAME, run);
