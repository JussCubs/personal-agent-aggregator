import { AggregatorError, toAggregatorError } from "./errors.js";
import type { AgentPrincipal, AggregatorService } from "./service.js";

/**
 * The agent-facing REST API, independent of any HTTP framework. Mount it at
 * any base path and pass the path below that base (e.g. "/v1/questions").
 *
 *   GET    /v1/me                         connection info (use as the read-only setup check)
 *   POST   /v1/claim                      exchange a one-time setup code for a credential (no auth)
 *   GET    /v1/work-items                 ?kind=&after=&limit=
 *   PUT    /v1/work-items/{id}            upsert
 *   GET    /v1/work-items/{id}
 *   DELETE /v1/work-items/{id}
 *   POST   /v1/checkpoints                append (idempotent by id)
 *   GET    /v1/checkpoints                ?work_item_id=&limit=
 *   PUT    /v1/snapshot                   explicit snapshot
 *   POST   /v1/questions                  ask (idempotent by id)
 *   GET    /v1/questions                  ?status=&unacknowledged=true
 *   GET    /v1/questions/{id}             status + answer
 *   POST   /v1/questions/{id}/ack         {revision}
 *   POST   /v1/questions/{id}/cancel
 *   GET    /v1/inbox                      ?cursor=&limit= → {events, cursor, has_more}
 *   POST   /v1/jobs                       hand off a goal → {job}
 *   GET    /v1/jobs                       ?status=
 *   GET    /v1/jobs/{id}
 *   POST   /v1/jobs/{id}/cancel
 *   GET    /v1/messages                   owner messages to this agent not yet replied to
 *   POST   /v1/messages                   {text, reply_to? | thread_id?, kind?, id?} → posted into the owner's thread
 *   POST   /v1/messages/{id}/ack          mark one of the owner's messages as being worked on
 *   PUT    /v1/webhook                    {url, auth_header_name?, auth_header_value?} → signing secret (once)
 *   DELETE /v1/webhook
 */
export interface RestRequest {
  method: string;
  path: string;
  query: Record<string, string | undefined>;
  body: unknown;
  authorization?: string | undefined;
}

export interface RestResponse {
  status: number;
  headers: Record<string, string>;
  body: unknown;
}

export interface RestOptions {
  service: AggregatorService;
  authenticate(authorization: string | undefined): Promise<AgentPrincipal | null>;
  challenge(error?: "invalid_token" | "insufficient_scope"): string;
  /** Rate limiting / plan checks. `principal` is null only for /v1/claim. Throw AggregatorError to refuse. */
  beforeCall?(principal: AgentPrincipal | null, route: string): Promise<void>;
  onError?(error: unknown, route: string): void;
}

type Handler = (p: AgentPrincipal, params: string[], req: RestRequest, svc: AggregatorService) => Promise<{ status?: number; body: unknown }>;

const SEGMENT = "([A-Za-z0-9][A-Za-z0-9._:-]{0,127})";

const ROUTES: Array<{ method: string; pattern: RegExp; key: string; handler: Handler }> = [
  { method: "GET", pattern: /^\/v1\/me$/, key: "me", handler: async (p, _a, _r, s) => ({ body: await s.getConnectionInfo(p) }) },
  { method: "GET", pattern: /^\/v1\/work-items$/, key: "work_items.list", handler: async (p, _a, r, s) => ({ body: await s.listWorkItems(p, r.query) }) },
  { method: "POST", pattern: /^\/v1\/work-items$/, key: "work_items.upsert", handler: async (p, _a, r, s) => ({ body: await s.upsertWorkItem(p, r.body) }) },
  { method: "PUT", pattern: new RegExp(`^/v1/work-items/${SEGMENT}$`), key: "work_items.upsert", handler: async (p, a, r, s) => ({ body: await s.upsertWorkItem(p, r.body, a[0]) }) },
  { method: "GET", pattern: new RegExp(`^/v1/work-items/${SEGMENT}$`), key: "work_items.get", handler: async (p, a, _r, s) => ({ body: { item: await s.getWorkItem(p, a[0]!) } }) },
  { method: "DELETE", pattern: new RegExp(`^/v1/work-items/${SEGMENT}$`), key: "work_items.delete", handler: async (p, a, _r, s) => ({ body: await s.deleteWorkItem(p, a[0]!) }) },
  { method: "POST", pattern: /^\/v1\/checkpoints$/, key: "checkpoints.create", handler: async (p, _a, r, s) => { const out = await s.postCheckpoint(p, r.body); return { status: out.created ? 201 : 200, body: out }; } },
  { method: "GET", pattern: /^\/v1\/checkpoints$/, key: "checkpoints.list", handler: async (p, _a, r, s) => ({ body: { checkpoints: await s.listCheckpoints(p, r.query) } }) },
  { method: "PUT", pattern: /^\/v1\/snapshot$/, key: "snapshot.push", handler: async (p, _a, r, s) => ({ body: await s.pushSnapshot(p, r.body) }) },
  { method: "POST", pattern: /^\/v1\/questions$/, key: "questions.create", handler: async (p, _a, r, s) => { const out = await s.createQuestion(p, r.body); return { status: out.created ? 201 : 200, body: out }; } },
  { method: "GET", pattern: /^\/v1\/questions$/, key: "questions.list", handler: async (p, _a, r, s) => ({ body: { questions: await s.listQuestions(p, r.query) } }) },
  { method: "GET", pattern: new RegExp(`^/v1/questions/${SEGMENT}$`), key: "questions.get", handler: async (p, a, _r, s) => ({ body: { question: await s.getQuestion(p, a[0]!) } }) },
  { method: "POST", pattern: new RegExp(`^/v1/questions/${SEGMENT}/ack$`), key: "questions.ack", handler: async (p, a, r, s) => ({ body: { question: await s.acknowledgeAnswer(p, a[0]!, (r.body as { revision?: unknown } | null)?.revision) } }) },
  { method: "POST", pattern: new RegExp(`^/v1/questions/${SEGMENT}/cancel$`), key: "questions.cancel", handler: async (p, a, _r, s) => ({ body: { question: await s.cancelQuestion(p, a[0]!) } }) },
  { method: "GET", pattern: /^\/v1\/inbox$/, key: "inbox.read", handler: async (p, _a, r, s) => ({ body: await s.readInbox(p, r.query) }) },
  { method: "POST", pattern: /^\/v1\/jobs$/, key: "jobs.create", handler: async (p, _a, r, s) => { const out = await s.handoffJob(p, r.body); return { status: out.created ? 201 : 200, body: out }; } },
  { method: "GET", pattern: /^\/v1\/jobs$/, key: "jobs.list", handler: async (p, _a, r, s) => ({ body: { jobs: await s.listJobs(p, r.query) } }) },
  { method: "GET", pattern: new RegExp(`^/v1/jobs/${SEGMENT}$`), key: "jobs.get", handler: async (p, a, _r, s) => ({ body: { job: await s.getJob(p, a[0]!) } }) },
  { method: "POST", pattern: new RegExp(`^/v1/jobs/${SEGMENT}/cancel$`), key: "jobs.cancel", handler: async (p, a, _r, s) => ({ body: { job: await s.cancelJob(p, a[0]!) } }) },
  { method: "GET", pattern: /^\/v1\/messages$/, key: "messages.check", handler: async (p, _a, r, s) => ({ body: await s.checkMessages(p, r.query) }) },
  { method: "POST", pattern: /^\/v1\/messages$/, key: "messages.post", handler: async (p, _a, r, s) => { const out = await s.postMessage(p, r.body); return { status: out.created ? 201 : 200, body: out }; } },
  { method: "POST", pattern: /^\/v1\/messages\/([0-9a-f-]{36})\/ack$/, key: "messages.ack", handler: async (p, a, _r, s) => ({ body: await s.acknowledgeMessage(p, { message_id: a[0] }) }) },
  { method: "PUT", pattern: /^\/v1\/webhook$/, key: "webhook.set", handler: async (p, _a, r, s) => ({ body: await s.setWebhook(p, r.body) }) },
  { method: "DELETE", pattern: /^\/v1\/webhook$/, key: "webhook.clear", handler: async (p, _a, _r, s) => ({ body: await s.clearWebhook(p) }) },
];

function errorResponse(error: AggregatorError, headers: Record<string, string> = {}): RestResponse {
  return { status: error.status, headers: { "content-type": "application/json", "cache-control": "no-store", ...headers }, body: error.toJSON() };
}

export async function handleAgentRest(req: RestRequest, opts: RestOptions): Promise<RestResponse> {
  const ok = (status: number, body: unknown): RestResponse => ({ status, headers: { "content-type": "application/json", "cache-control": "no-store" }, body });
  const method = req.method.toUpperCase();
  const path = req.path.replace(/\/+$/, "") || "/";
  try {
    if (path === "/v1/claim") {
      if (method !== "POST") return errorResponse(new AggregatorError("not_found", "use POST /v1/claim"), { allow: "POST" });
      await opts.beforeCall?.(null, "claim");
      const body = (req.body ?? {}) as { code?: unknown };
      return ok(200, await opts.service.claim(body.code));
    }
    const matches = ROUTES.filter((route) => route.pattern.test(path));
    if (matches.length === 0) return errorResponse(new AggregatorError("not_found", "unknown endpoint"));
    const route = matches.find((candidate) => candidate.method === method);
    if (!route) return errorResponse(new AggregatorError("not_found", "method not supported for this endpoint"), { allow: matches.map((m) => m.method).join(", ") });
    const principal = await opts.authenticate(req.authorization);
    if (!principal) return errorResponse(new AggregatorError("unauthorized", "missing or invalid credential"), { "www-authenticate": opts.challenge("invalid_token") });
    await opts.beforeCall?.(principal, route.key);
    const params = route.pattern.exec(path)!.slice(1);
    const out = await route.handler(principal, params, req, opts.service);
    return ok(out.status ?? 200, out.body);
  } catch (error) {
    const safe = toAggregatorError(error);
    if (safe.code === "internal") opts.onError?.(error, path);
    const headers: Record<string, string> = {};
    if (safe.code === "insufficient_scope") headers["www-authenticate"] = opts.challenge("insufficient_scope");
    if (safe.code === "rate_limited" && typeof safe.details?.retry_after === "number") headers["retry-after"] = String(safe.details.retry_after);
    return errorResponse(safe, headers);
  }
}
