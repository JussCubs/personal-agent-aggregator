import { EVENT_NAMES, LIMITS, SCOPES, WORK_ITEM_KINDS, type Scope } from "./contract.js";
import { AggregatorError, toAggregatorError } from "./errors.js";
import type { AgentPrincipal, AggregatorService } from "./service.js";

/**
 * A dual-era MCP server over Streamable HTTP (JSON responses):
 * - modern clients (2026-07-28): per-request `_meta`, `server/discover`,
 *   `resultType`, header/body validation, MCP Events (`events/*`);
 * - legacy clients (2024-11-05 … 2025-11-25): `initialize` handshake.
 * Stateless: no sessions, no GET stream. Every request is authenticated.
 */
export const MODERN_PROTOCOL_VERSIONS = ["2026-07-28"] as const;
export const LEGACY_PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"] as const;
const META_VERSION = "io.modelcontextprotocol/protocolVersion";

interface JsonSchema {
  type: "object";
  properties: Record<string, unknown>;
  required?: string[];
  additionalProperties?: boolean;
}

export interface ToolDefinition {
  name: string;
  title: string;
  description: string;
  inputSchema: JsonSchema;
  annotations: { readOnlyHint: boolean; destructiveHint: boolean; idempotentHint: boolean; openWorldHint: boolean; title?: string };
  scopes: Scope[];
}

const str = (description: string, extra: Record<string, unknown> = {}) => ({ type: "string", description, ...extra });
const idProp = (description: string) => str(description, { maxLength: LIMITS.idLength, pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$" });

const WORK_ITEM_PROPS = {
  id: idProp("Your stable id for this item. Re-sending the same id updates it."),
  kind: { type: "string", enum: [...WORK_ITEM_KINDS], description: "task, goal, project or state" },
  title: str("Short title", { maxLength: LIMITS.titleLength }),
  status: str("Free-form status, e.g. todo, in_progress, blocked, done", { maxLength: LIMITS.statusLength }),
  summary: str("What this is and where it stands", { maxLength: LIMITS.summaryLength }),
  blocker: str("What is blocking it, if anything", { maxLength: LIMITS.summaryLength }),
  next_step: str("The next concrete step", { maxLength: LIMITS.summaryLength }),
  due_at: str("ISO 8601 due time", { format: "date-time" }),
  parent_id: idProp("Id of the goal or project this belongs to"),
  data: { type: "object", description: "Extra structured fields (JSON, at most 16 KB). Stored as data only." },
  expected_revision: { type: "integer", minimum: 1, description: "Optional optimistic-concurrency guard" },
};

export const TOOL_DEFINITIONS: readonly ToolDefinition[] = [
  {
    name: "whoami",
    title: "Check connection",
    description: "Use this first to verify the connection works. Returns this connection's id, provider, granted scopes and whether a wake-up webhook is configured. Read-only.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    scopes: [],
  },
  {
    name: "upsert_work_item",
    title: "Save a task, goal, project or state",
    description: "Use this when you create or change a task, goal, project or state the owner should see in one place. Idempotent by id: send the full current item each time.",
    inputSchema: { type: "object", properties: WORK_ITEM_PROPS, required: ["kind", "title"], additionalProperties: false },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    scopes: [SCOPES.write],
  },
  {
    name: "list_work_items",
    title: "List saved work items",
    description: "Use this to read back the work items this connection saved. Read-only. Page with `after` = the last id you received.",
    inputSchema: {
      type: "object",
      properties: { kind: { type: "string", enum: [...WORK_ITEM_KINDS] }, after: idProp("Return items with ids after this one"), limit: { type: "integer", minimum: 1, maximum: LIMITS.pageSize } },
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    scopes: [SCOPES.read, SCOPES.write],
  },
  {
    name: "post_checkpoint",
    title: "Post a checkpoint",
    description: "Use this to record progress on a task (what happened, current status). Append-only; passing the same id twice records it once.",
    inputSchema: {
      type: "object",
      properties: {
        id: idProp("Your stable id for this checkpoint (makes retries safe)"),
        work_item_id: idProp("The task or project this checkpoint belongs to"),
        summary: str("What happened", { maxLength: LIMITS.summaryLength }),
        status: str("Status after this checkpoint", { maxLength: LIMITS.statusLength }),
        data: { type: "object", description: "Extra structured fields (JSON)" },
      },
      required: ["summary"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    scopes: [SCOPES.write],
  },
  {
    name: "push_snapshot",
    title: "Push a full snapshot",
    description: "Use this to share an explicit snapshot: tasks, goals and projects (upserted by id) plus identity, a memory summary you choose to share, and connected apps. Never include raw internal state or secrets. Does not ask the owner anything.",
    inputSchema: {
      type: "object",
      properties: {
        identity: { type: "object", description: "Who you are (name, app, version)" },
        tasks: { type: "array", maxItems: LIMITS.snapshotItems, items: { type: "object", properties: WORK_ITEM_PROPS, required: ["id", "title"] } },
        goals: { type: "array", maxItems: LIMITS.snapshotItems, items: { type: "object", properties: WORK_ITEM_PROPS, required: ["id", "title"] } },
        projects: { type: "array", maxItems: LIMITS.snapshotItems, items: { type: "object", properties: WORK_ITEM_PROPS, required: ["id", "title"] } },
        memory_summary: str("A summary the owner chose to share", { maxLength: LIMITS.detailsLength }),
        connected_apps: { type: "array", maxItems: LIMITS.connectedApps, items: { type: "string" } },
      },
      additionalProperties: false,
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    scopes: [SCOPES.write],
  },
  {
    name: "create_question",
    title: "Ask the owner",
    description:
      "Use this when you need the owner's answer or approval before continuing. Give it a stable id; re-sending the same id is safe. The owner is notified and answers in their aggregator app; then fetch the answer with get_answer (or wait for the answer.created event). For approvals, set kind=approval, describe affected_action, and pass action_digest (a hash of the exact action) so you can check the answer applies to that exact action. Still apply your own app's confirmation rules for sensitive actions.",
    inputSchema: {
      type: "object",
      properties: {
        id: idProp("Your stable id for this question"),
        kind: { type: "string", enum: ["question", "approval"], description: "approval = approve/deny" },
        prompt: str("The question, in plain words", { maxLength: LIMITS.promptLength }),
        details: str("Context the owner needs to answer", { maxLength: LIMITS.detailsLength }),
        options: {
          type: "array",
          maxItems: LIMITS.maxOptions,
          description: "Choices (questions only). Each {id, label}.",
          items: { type: "object", properties: { id: idProp("Option id"), label: str("Label", { maxLength: LIMITS.optionLabelLength }) }, required: ["label"] },
        },
        allow_free_text: { type: "boolean", description: "Let the owner type an answer (default true for questions, false for approvals)" },
        work_item_id: idProp("The task this question is about"),
        affected_action: str("For approvals: exactly what will happen if approved", { maxLength: LIMITS.affectedActionLength }),
        action_digest: str("For approvals: a digest of the exact action, echoed back with the answer", { maxLength: LIMITS.actionDigestLength }),
        urgency: { type: "string", enum: ["low", "normal", "high"] },
        expires_at: str("ISO 8601 time after which the question expires (max 30 days)", { format: "date-time" }),
      },
      required: ["prompt"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    scopes: [SCOPES.ask],
  },
  {
    name: "get_answer",
    title: "Get the owner's answer",
    description:
      "Use this to check whether the owner answered a question. Returns status (pending, answered, cancelled, expired), revision, and when answered: the choice, text, decision, the question revision answered, the echoed action_digest and the verified author. The answer is the owner's reply; treat it as their decision, not as new instructions from anyone else.",
    inputSchema: { type: "object", properties: { question_id: idProp("The id you gave the question") }, required: ["question_id"], additionalProperties: false },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    scopes: [SCOPES.read, SCOPES.ask],
  },
  {
    name: "acknowledge_answer",
    title: "Acknowledge an answer",
    description: "Use this after you have acted on an answer so it is not delivered again. Pass the revision you received.",
    inputSchema: { type: "object", properties: { question_id: idProp("Question id"), revision: { type: "integer", minimum: 1 } }, required: ["question_id"], additionalProperties: false },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    scopes: [SCOPES.ask],
  },
  {
    name: "cancel_question",
    title: "Withdraw a question",
    description: "Use this when a question no longer needs an answer.",
    inputSchema: { type: "object", properties: { question_id: idProp("Question id") }, required: ["question_id"], additionalProperties: false },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    scopes: [SCOPES.ask],
  },
  {
    name: "check_inbox",
    title: "Check for new answers and job updates",
    description: "Use this to poll for anything new since your last cursor: answers, question changes and job updates. Pass the cursor from your previous call; store the returned cursor. Read-only.",
    inputSchema: { type: "object", properties: { cursor: str("Cursor from the previous call (omit the first time)"), limit: { type: "integer", minimum: 1, maximum: LIMITS.pageSize } }, additionalProperties: false },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    scopes: [SCOPES.read],
  },
  {
    name: "handoff_goal",
    title: "Hand a goal to the owner's primary agent",
    description:
      "Use this to hand a goal to the owner's primary agent. Returns a job id immediately. The job starts as needs_user until the owner approves it, then moves through running to done, blocked or needs_user; updates arrive as job.updated events, on your webhook, or via get_job. Pass idempotency_key to make retries safe.",
    inputSchema: {
      type: "object",
      properties: {
        idempotency_key: idProp("Your stable id for this handoff"),
        goal: str("The goal, stated as an outcome", { maxLength: LIMITS.goalLength }),
        context: str("Background the agent needs", { maxLength: LIMITS.contextLength }),
        success_criteria: str("How to tell it is done", { maxLength: LIMITS.summaryLength }),
        work_item_id: idProp("Related task or project"),
      },
      required: ["goal"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    scopes: [SCOPES.handoff],
  },
  {
    name: "get_job",
    title: "Get a handed-off job",
    description: "Use this to check a job's status, summary and result. Read-only.",
    inputSchema: { type: "object", properties: { job_id: idProp("Job id from handoff_goal") }, required: ["job_id"], additionalProperties: false },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    scopes: [SCOPES.read, SCOPES.handoff],
  },
  {
    name: "cancel_job",
    title: "Cancel a handed-off job",
    description: "Use this when a handed-off goal is no longer needed.",
    inputSchema: { type: "object", properties: { job_id: idProp("Job id") }, required: ["job_id"], additionalProperties: false },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    scopes: [SCOPES.handoff],
  },
  {
    name: "set_callback_webhook",
    title: "Set the wake-up webhook",
    description:
      "Use this once during setup if your platform can be woken by an HTTPS webhook (for example a routine URL). Every new answer and job update is POSTed there, signed with Standard Webhooks headers. If your routine needs a key, pass it as auth_header_value (and auth_header_name if it is not Authorization). Returns the signing secret once.",
    inputSchema: {
      type: "object",
      properties: {
        url: str("Public https URL to POST events to", { format: "uri" }),
        auth_header_name: str("Header your endpoint expects, default Authorization"),
        auth_header_value: str("Value for that header, e.g. your routine key"),
      },
      required: ["url"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    scopes: [SCOPES.read],
  },
  {
    name: "clear_callback_webhook",
    title: "Remove the wake-up webhook",
    description: "Use this to stop webhook deliveries.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    scopes: [SCOPES.read],
  },
];

export const EVENT_DEFINITIONS = [
  {
    name: "answer.created",
    description: "The owner answered one of this connection's questions.",
    delivery: ["webhook"],
    inputSchema: { type: "object", properties: { question_id: { type: "string", description: "Only this question (optional)" } }, additionalProperties: false },
    payloadSchema: {
      type: "object",
      properties: {
        question_id: { type: "string" },
        kind: { type: "string" },
        revision: { type: "integer" },
        status: { type: "string" },
        work_item_id: { type: ["string", "null"] },
        answer: { type: "object" },
      },
      required: ["question_id", "revision", "status", "answer"],
    },
  },
  {
    name: "question.updated",
    description: "A question was dismissed by the owner or expired.",
    delivery: ["webhook"],
    inputSchema: { type: "object", properties: { question_id: { type: "string" } }, additionalProperties: false },
    payloadSchema: {
      type: "object",
      properties: { question_id: { type: "string" }, status: { type: "string" }, reason: { type: "string" }, revision: { type: "integer" } },
      required: ["question_id", "status"],
    },
  },
  {
    name: "job.updated",
    description: "A handed-off job changed status (needs_user, running, blocked, done, declined, cancelled, failed).",
    delivery: ["webhook"],
    inputSchema: { type: "object", properties: { job_id: { type: "string" } }, additionalProperties: false },
    payloadSchema: {
      type: "object",
      properties: {
        job_id: { type: "string" },
        status: { type: "string" },
        status_reason: { type: ["string", "null"] },
        summary: { type: ["string", "null"] },
        result: { type: ["object", "null"] },
        revision: { type: "integer" },
      },
      required: ["job_id", "status", "revision"],
    },
  },
] as const;

if (EVENT_DEFINITIONS.length !== EVENT_NAMES.length) throw new Error("event catalog out of sync");

type Args = Record<string, unknown>;

/** Runs one tool against the service. Shared by the HTTP server and stdio servers. */
export async function callTool(service: AggregatorService, principal: AgentPrincipal, name: string, args: Args): Promise<unknown> {
  switch (name) {
    case "whoami":
      return await service.getConnectionInfo(principal);
    case "upsert_work_item":
      return await service.upsertWorkItem(principal, args);
    case "list_work_items":
      return await service.listWorkItems(principal, args);
    case "post_checkpoint":
      return await service.postCheckpoint(principal, args);
    case "push_snapshot":
      return await service.pushSnapshot(principal, args);
    case "create_question":
      return await service.createQuestion(principal, args);
    case "get_answer":
      return await service.getQuestion(principal, String(args.question_id ?? ""));
    case "acknowledge_answer":
      return await service.acknowledgeAnswer(principal, String(args.question_id ?? ""), args.revision);
    case "cancel_question":
      return await service.cancelQuestion(principal, String(args.question_id ?? ""));
    case "check_inbox":
      return await service.readInbox(principal, args);
    case "handoff_goal":
      return await service.handoffJob(principal, args);
    case "get_job":
      return await service.getJob(principal, String(args.job_id ?? ""));
    case "cancel_job":
      return await service.cancelJob(principal, String(args.job_id ?? ""));
    case "set_callback_webhook":
      return await service.setWebhook(principal, args);
    case "clear_callback_webhook":
      return await service.clearWebhook(principal);
    default:
      throw new AggregatorError("not_found", `unknown tool ${name}`);
  }
}

export interface McpHttpRequest {
  method: string;
  headers: Record<string, string | undefined>;
  body: string;
}

export interface McpHttpResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

export interface McpServerOptions {
  service: AggregatorService;
  serverInfo: { name: string; version: string; title?: string };
  instructions: string;
  /** Resolves the bearer credential (and enforces audience) — null means 401. */
  authenticate(authorization: string | undefined): Promise<AgentPrincipal | null>;
  /** WWW-Authenticate value for 401s and insufficient scope. */
  challenge(error?: "invalid_token" | "insufficient_scope", scopes?: readonly Scope[]): string;
  /** Browser origins allowed to call (DNS-rebinding protection). Requests without Origin are allowed. */
  allowedOrigins?: readonly string[];
  /** Called before each tool call / subscription; throw AggregatorError("rate_limited") to refuse. */
  beforeCall?(principal: AgentPrincipal, method: string, name?: string): Promise<void>;
  /** Logged with method and tool name only; never with arguments. */
  onError?(error: unknown, context: { method: string; tool?: string }): void;
}

function json(status: number, body: unknown, headers: Record<string, string> = {}): McpHttpResponse {
  return { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...headers }, body: JSON.stringify(body) };
}

function rpcError(id: unknown, code: number, message: string, data?: unknown) {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message, ...(data === undefined ? {} : { data }) } };
}

function header(headers: Record<string, string | undefined>, name: string): string | undefined {
  const key = Object.keys(headers).find((candidate) => candidate.toLowerCase() === name);
  return key ? headers[key] : undefined;
}

function decodeHeaderValue(value: string): string {
  const match = /^=\?base64\?(.*)\?=$/.exec(value);
  return match ? Buffer.from(match[1]!, "base64").toString("utf8") : value;
}

function toolList(): Array<Record<string, unknown>> {
  return TOOL_DEFINITIONS.map((tool) => ({
    name: tool.name,
    title: tool.title,
    description: tool.description,
    inputSchema: tool.inputSchema,
    annotations: { ...tool.annotations, title: tool.title },
    securitySchemes: [{ type: "oauth2", scopes: tool.scopes.length ? [tool.scopes[0]] : [] }],
  }));
}

/** Handles one Streamable HTTP request to the MCP endpoint. */
export async function handleMcpHttp(req: McpHttpRequest, opts: McpServerOptions): Promise<McpHttpResponse> {
  if (req.method !== "POST") return { status: 405, headers: { allow: "POST", "content-type": "application/json" }, body: JSON.stringify(rpcError(null, -32000, "Method not allowed: use POST")) };
  const origin = header(req.headers, "origin");
  if (origin && !(opts.allowedOrigins ?? []).includes(origin)) return json(403, rpcError(null, -32000, "Origin not allowed"));
  if (Buffer.byteLength(req.body, "utf8") > LIMITS.requestBodyBytes) return json(413, rpcError(null, -32600, "Request too large"));

  let principal: AgentPrincipal | null;
  try {
    principal = await opts.authenticate(header(req.headers, "authorization"));
  } catch (error) {
    const safe = toAggregatorError(error);
    if (safe.code === "rate_limited") return json(429, rpcError(null, -32000, safe.message), { "retry-after": String(safe.details?.retry_after ?? 60) });
    opts.onError?.(error, { method: "authenticate" });
    return json(503, rpcError(null, -32603, "Temporarily unavailable"));
  }
  if (!principal) {
    return json(401, rpcError(null, -32001, "Unauthorized: connect this agent to obtain a credential"), { "www-authenticate": opts.challenge("invalid_token") });
  }

  let message: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(req.body);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return json(400, rpcError(null, -32600, "Send one JSON-RPC message per request"));
    message = parsed as Record<string, unknown>;
  } catch {
    return json(400, rpcError(null, -32700, "Parse error"));
  }
  if (message.jsonrpc !== "2.0" || typeof message.method !== "string") return json(400, rpcError(message.id, -32600, "Invalid request"));
  const method = message.method;
  const isNotification = message.id === undefined || message.id === null;
  if (isNotification) return { status: 202, headers: {}, body: "" };

  const params = (message.params && typeof message.params === "object" && !Array.isArray(message.params) ? message.params : {}) as Args;
  const meta = (params._meta && typeof params._meta === "object" ? params._meta : {}) as Args;
  const headerVersion = header(req.headers, "mcp-protocol-version");
  const bodyVersion = typeof meta[META_VERSION] === "string" ? (meta[META_VERSION] as string) : undefined;
  const modern = method !== "initialize" && (bodyVersion !== undefined || (headerVersion !== undefined && !(LEGACY_PROTOCOL_VERSIONS as readonly string[]).includes(headerVersion)));

  if (modern) {
    const requested = bodyVersion ?? headerVersion!;
    if (headerVersion && bodyVersion && headerVersion !== bodyVersion) return json(400, rpcError(message.id, -32020, "Header mismatch: MCP-Protocol-Version does not match _meta"));
    if (!(MODERN_PROTOCOL_VERSIONS as readonly string[]).includes(requested)) {
      return json(400, rpcError(message.id, -32022, "Unsupported protocol version", { supported: [...MODERN_PROTOCOL_VERSIONS, ...LEGACY_PROTOCOL_VERSIONS], requested }));
    }
    const methodHeader = header(req.headers, "mcp-method");
    if (methodHeader !== undefined && methodHeader !== method) return json(400, rpcError(message.id, -32020, "Header mismatch: Mcp-Method does not match the body"));
    const nameHeader = header(req.headers, "mcp-name");
    if (nameHeader !== undefined && typeof params.name === "string" && decodeHeaderValue(nameHeader) !== params.name) {
      return json(400, rpcError(message.id, -32020, "Header mismatch: Mcp-Name does not match the body"));
    }
  }

  const complete = (result: Record<string, unknown>) => json(200, { jsonrpc: "2.0", id: message.id, result: modern ? { resultType: "complete", ...result } : result });
  const fail = (code: number, text: string, data?: unknown, status = 200) => json(modern && status === 200 && code === -32601 ? 404 : status, rpcError(message.id, code, text, data));

  try {
    switch (method) {
      case "initialize": {
        const requested = typeof params.protocolVersion === "string" ? params.protocolVersion : LEGACY_PROTOCOL_VERSIONS[1];
        const protocolVersion = (LEGACY_PROTOCOL_VERSIONS as readonly string[]).includes(requested) ? requested : LEGACY_PROTOCOL_VERSIONS[0];
        return complete({ protocolVersion, capabilities: { tools: { listChanged: false } }, serverInfo: opts.serverInfo, instructions: opts.instructions });
      }
      case "server/discover":
        return complete({
          supportedVersions: [...MODERN_PROTOCOL_VERSIONS, ...LEGACY_PROTOCOL_VERSIONS],
          capabilities: { tools: {}, events: {} },
          _meta: { "io.modelcontextprotocol/serverInfo": opts.serverInfo },
          instructions: opts.instructions,
          ttlMs: 3_600_000,
          cacheScope: "private",
        });
      case "ping":
        return complete({});
      case "tools/list":
        return complete(modern ? { tools: toolList(), ttlMs: 3_600_000, cacheScope: "private" } : { tools: toolList() });
      case "resources/list":
        return complete({ resources: [] });
      case "prompts/list":
        return complete({ prompts: [] });
      case "tools/call": {
        const name = typeof params.name === "string" ? params.name : "";
        const tool = TOOL_DEFINITIONS.find((candidate) => candidate.name === name);
        if (!tool) return fail(-32602, `Unknown tool: ${name}`);
        const args = (params.arguments && typeof params.arguments === "object" && !Array.isArray(params.arguments) ? params.arguments : {}) as Args;
        try {
          await opts.beforeCall?.(principal, method, name);
          const result = await callTool(opts.service, principal, name, args);
          return complete({ content: [{ type: "text", text: JSON.stringify(result) }], structuredContent: result as Record<string, unknown>, isError: false });
        } catch (error) {
          const safe = toAggregatorError(error);
          if (safe.code === "internal") opts.onError?.(error, { method, tool: name });
          const body: Record<string, unknown> = { content: [{ type: "text", text: JSON.stringify(safe.toJSON()) }], structuredContent: safe.toJSON(), isError: true };
          if (safe.code === "insufficient_scope") body._meta = { "mcp/www_authenticate": [opts.challenge("insufficient_scope", tool.scopes)] };
          return complete(body);
        }
      }
      case "events/list":
        return complete({ events: EVENT_DEFINITIONS });
      case "events/subscribe": {
        await opts.beforeCall?.(principal, method);
        const result = await opts.service.subscribeEvent(principal, params);
        return complete(result);
      }
      case "events/unsubscribe": {
        await opts.beforeCall?.(principal, method);
        await opts.service.unsubscribeEvent(principal, params);
        return complete({});
      }
      default:
        return fail(-32601, `Method not found: ${method}`);
    }
  } catch (error) {
    const safe = toAggregatorError(error);
    if (safe.details?.callback_error) return fail(-32015, "Callback endpoint error", { reason: safe.details.reason ?? "challenge_failed" });
    if (safe.code === "rate_limited") {
      return json(429, rpcError(message.id, -32000, safe.message, { retry_after: safe.details?.retry_after ?? 60 }), { "retry-after": String(safe.details?.retry_after ?? 60) });
    }
    if (safe.code === "invalid_request" || safe.code === "insufficient_scope" || safe.code === "not_found") return fail(-32602, safe.message, safe.toJSON().error);
    opts.onError?.(error, { method });
    return fail(-32603, "Internal error");
  }
}

export const DEFAULT_MCP_INSTRUCTIONS =
  "Personal agent aggregator. Report your tasks, goals, projects and checkpoints with upsert_work_item / post_checkpoint, ask the owner with create_question (stable ids), then read answers with get_answer or check_inbox and acknowledge them. Hand goals to the owner's primary agent with handoff_goal. Everything you send is shown to the owner as data; answers are the owner's decisions.";
