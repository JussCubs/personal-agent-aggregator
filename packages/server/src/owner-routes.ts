import type { IncomingMessage, ServerResponse } from "node:http";
import {
  AggregatorError,
  LIMITS,
  asObject,
  invalid,
  isUuid,
  renderSetupMarkdown,
  toAggregatorError,
  type OwnerPrincipal,
} from "@agent-aggregator/core";
import { PRODUCT_NAME, SERVER_VERSION, urls, type AppContext } from "./context.js";
import { bearerToken, headerValue, readBody, send, sendError, sendJson } from "./http.js";
import { errorFields } from "./log.js";
import { authenticateOwner, rotateOwnerCredential } from "./owners.js";

/**
 * The owner API: everything a person does with their agents — connect,
 * issue credentials, answer, approve, read the shared state. Authenticated
 * with the owner bearer credential (`agg-owner init`). JSON in, JSON out.
 */
type Params = Record<string, string>;
type Body = Record<string, unknown>;
type Handler = (ctx: AppContext, owner: OwnerPrincipal, params: Params, body: Body, query: Record<string, string>) => Promise<{ status?: number; body: unknown; text?: string }>;

export interface OwnerRoute {
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  path: string;
  summary: string;
  handler: Handler;
}

const ID_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export const OWNER_ROUTES: readonly OwnerRoute[] = [
  {
    method: "GET", path: "/owner/me", summary: "The authenticated owner",
    handler: async (_c, o) => ({ body: { owner: { id: o.ownerId, name: o.name ?? null } } }),
  },
  {
    method: "POST", path: "/owner/credential/rotate", summary: "Replace the owner credential (shown once); the old one stops working",
    handler: async (c, o) => {
      const rotated = await rotateOwnerCredential(c.storage.driver, o.ownerId);
      if (!rotated) throw new AggregatorError("not_found", "owner not found");
      return { body: { credential: rotated.credential, hint: rotated.hint } };
    },
  },
  {
    method: "GET", path: "/owner/connections", summary: "List connections with counts, webhook host and credential hints",
    handler: async (c, o) => ({ body: { connections: await c.service.listConnections(o) } }),
  },
  {
    method: "POST", path: "/owner/connections", summary: "Create a connection {provider, display_name, mode, scopes?, settings?}",
    handler: async (c, o, _p, b) => ({ status: 201, body: { connection: await c.service.createConnection(o, b) } }),
  },
  {
    method: "GET", path: "/owner/connections/{connection_id}", summary: "One connection with counts",
    handler: async (c, o, p) => ({ body: { connection: await c.service.getConnection(o, p.connection_id!) } }),
  },
  {
    method: "PATCH", path: "/owner/connections/{connection_id}", summary: "Rename, change scopes or settings {display_name?, scopes?, settings?}",
    handler: async (c, o, p, b) => ({ body: { connection: await c.service.updateConnection(o, p.connection_id!, b) } }),
  },
  {
    method: "DELETE", path: "/owner/connections/{connection_id}", summary: "Disconnect and delete every row the connection produced",
    handler: async (c, o, p) => ({ body: await c.service.deleteConnection(o, p.connection_id!) }),
  },
  {
    method: "POST", path: "/owner/connections/{connection_id}/revoke", summary: "Disconnect: credentials die, deliveries stop, open questions and jobs close",
    handler: async (c, o, p) => ({ body: { connection: await c.service.revokeConnection(o, p.connection_id!) } }),
  },
  {
    method: "POST", path: "/owner/connections/{connection_id}/credential", summary: "Issue an agent credential (shown once); earlier agent credentials are revoked",
    handler: async (c, o, p) => ({ body: await c.service.issueAgentCredential(o, p.connection_id!) }),
  },
  {
    method: "POST", path: "/owner/connections/{connection_id}/claim-code", summary: "Issue a one-time setup code {ttl_seconds?}",
    handler: async (c, o, p, b) => {
      const ttl = b.ttl_seconds === undefined || b.ttl_seconds === null ? undefined : Number(b.ttl_seconds);
      if (ttl !== undefined && (!Number.isInteger(ttl) || ttl < 60 || ttl > 86_400)) throw invalid("ttl_seconds must be an integer between 60 and 86400", "ttl_seconds");
      return { body: await c.service.issueClaimCode(o, p.connection_id!, ttl) };
    },
  },
  {
    method: "GET", path: "/owner/connections/{connection_id}/setup-prompt", summary: "Setup playbook for the agent (Markdown, contains no secrets)",
    handler: async (c, o, p) => {
      const connection = await c.service.getConnection(o, p.connection_id!);
      const u = urls(c);
      const text = renderSetupMarkdown({
        productName: PRODUCT_NAME,
        agentName: connection.display_name,
        mode: connection.mode,
        mcpUrl: u.mcp,
        apiBaseUrl: u.api,
        userAgent: `agent-aggregator-cli/${SERVER_VERSION}`,
        cli: { install: "npm install -g @agent-aggregator/agent-cli", command: "agg", envPrefix: "AGG", cronMarker: "agent-aggregator-poller" },
      });
      return { body: null, text };
    },
  },
  {
    method: "PUT", path: "/owner/connections/{connection_id}/webhook", summary: "Set the connection's wake-up webhook {url, auth_header_name?, auth_header_value?}; returns the signing secret once",
    handler: async (c, o, p, b) => ({ body: await c.service.ownerSetWebhook(o, p.connection_id!, b) }),
  },
  {
    method: "DELETE", path: "/owner/connections/{connection_id}/webhook", summary: "Remove the connection's webhook",
    handler: async (c, o, p) => ({ body: await c.service.ownerClearWebhook(o, p.connection_id!) }),
  },
  {
    method: "GET", path: "/owner/questions", summary: "Questions across connections ?status=pending|answered|cancelled|expired|all&connection_id=&limit=",
    handler: async (c, o, _p, _b, q) => ({ body: { questions: await c.service.listOwnerQuestions(o, q) } }),
  },
  {
    method: "GET", path: "/owner/connections/{connection_id}/questions/{question_id}", summary: "One question",
    handler: async (c, o, p) => ({ body: await c.service.getOwnerQuestion(o, p.connection_id!, p.question_id!) }),
  },
  {
    method: "POST", path: "/owner/connections/{connection_id}/questions/{question_id}/answer", summary: "Answer {revision, choice?, text?, decision?}",
    handler: async (c, o, p, b) => ({ body: { question: await c.service.answerQuestion(o, { ...b, connection_id: p.connection_id, question_id: p.question_id }) } }),
  },
  {
    method: "POST", path: "/owner/connections/{connection_id}/questions/{question_id}/dismiss", summary: "Dismiss without answering (the agent gets question.updated)",
    handler: async (c, o, p) => ({ body: { question: await c.service.dismissQuestion(o, p.connection_id!, p.question_id!) } }),
  },
  {
    method: "GET", path: "/owner/jobs", summary: "Handed-off jobs ?status=open|all|<status>&connection_id=&limit=",
    handler: async (c, o, _p, _b, q) => ({ body: { jobs: await c.service.listOwnerJobs(o, q) } }),
  },
  {
    method: "GET", path: "/owner/connections/{connection_id}/jobs/{job_id}", summary: "One job",
    handler: async (c, o, p) => ({ body: await c.service.getOwnerJob(o, p.connection_id!, p.job_id!) }),
  },
  {
    method: "POST", path: "/owner/connections/{connection_id}/jobs/{job_id}/decision", summary: "Approve or decline a job waiting for the owner {approve, note?}",
    handler: async (c, o, p, b) => ({ body: { job: await c.service.decideJob(o, { ...b, connection_id: p.connection_id, job_id: p.job_id }) } }),
  },
  {
    method: "POST", path: "/owner/connections/{connection_id}/jobs/{job_id}/progress", summary: "Report progress on an approved job {status, summary?, reason?, result?}",
    handler: async (c, o, p, b) => ({ body: { job: await c.service.reportJobProgress(o, { ...b, connection_id: p.connection_id, job_id: p.job_id }) } }),
  },
  {
    method: "POST", path: "/owner/connections/{connection_id}/messages", summary: "Send the agent a message {text, thread_ref?, thread_title?, idempotency_key?}; 201 when new, 200 for a known idempotency_key",
    handler: async (c, o, p, b) => {
      const out = await c.service.sendMessage(o, { ...b, connection_id: p.connection_id });
      return { status: out.created ? 201 : 200, body: out };
    },
  },
  {
    method: "GET", path: "/owner/connections/{connection_id}/messages", summary: "One thread with statuses, oldest first ?thread_ref=&limit= (default thread \"default\", the latest 50)",
    handler: async (c, o, p, _b, q) => ({ body: { messages: await c.service.listThreadMessages(o, { ...q, connection_id: p.connection_id }) } }),
  },
  {
    method: "GET", path: "/owner/work-items", summary: "Tasks, goals, projects and states across connections ?connection_id=&kind=&limit=",
    handler: async (c, o, _p, _b, q) => ({ body: { items: await c.service.listOwnerWorkItems(o, q) } }),
  },
  {
    method: "GET", path: "/owner/checkpoints", summary: "Checkpoints across connections ?connection_id=&work_item_id=&limit=",
    handler: async (c, o, _p, _b, q) => ({ body: { checkpoints: await c.service.listOwnerCheckpoints(o, q) } }),
  },
  {
    method: "GET", path: "/owner/audit", summary: "Audit log ?connection_id=&limit= (max 200)",
    handler: async (c, o, _p, _b, q) => ({ body: { entries: await c.service.listAudit(o, q) } }),
  },
];

interface CompiledRoute extends OwnerRoute {
  pattern: RegExp;
  names: string[];
}

const COMPILED: CompiledRoute[] = OWNER_ROUTES.map((route) => {
  const names: string[] = [];
  const source = route.path.replace(/\{([a-z_]+)\}/g, (_m, name: string) => {
    names.push(name);
    return "([^/]+)";
  });
  return { ...route, pattern: new RegExp(`^${source}$`), names };
});

function decodeParams(route: CompiledRoute, match: RegExpExecArray): Params | null {
  const params: Params = {};
  for (let i = 0; i < route.names.length; i += 1) {
    let value: string;
    try {
      value = decodeURIComponent(match[i + 1]!);
    } catch {
      return null;
    }
    const name = route.names[i]!;
    if (name === "connection_id" ? !isUuid(value) : !ID_SEGMENT.test(value)) return null;
    params[name] = value;
  }
  return params;
}

export async function handleOwner(ctx: AppContext, req: IncomingMessage, res: ServerResponse, url: URL, ip: string): Promise<void> {
  const method = (req.method ?? "GET").toUpperCase();
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const candidates = COMPILED.filter((route) => route.pattern.test(path));
  if (candidates.length === 0) {
    sendError(res, new AggregatorError("not_found", "unknown endpoint"));
    return;
  }
  const route = candidates.find((candidate) => candidate.method === method);
  if (!route) {
    sendError(res, new AggregatorError("not_found", "method not supported for this endpoint"), { allow: candidates.map((c) => c.method).join(", ") });
    return;
  }
  const params = decodeParams(route, route.pattern.exec(path)!);
  if (!params) {
    sendError(res, new AggregatorError("not_found", "not found"));
    return;
  }
  const blocked = ctx.limits.blockedFor(ip);
  if (blocked > 0) {
    sendError(res, new AggregatorError("rate_limited", `too many failed authentications from this address; retry after ${blocked} seconds`, { retry_after: blocked }), { "retry-after": String(blocked) });
    return;
  }
  const surfaceHeader = headerValue(req, "x-agg-surface");
  const surface = surfaceHeader && /^[a-z][a-z0-9_-]{0,19}$/.test(surfaceHeader) ? surfaceHeader : "api";
  const owner = await authenticateOwner(ctx.storage.driver, bearerToken(headerValue(req, "authorization")), surface);
  if (!owner) {
    if (headerValue(req, "authorization")) await ctx.limits.authFailed(ip);
    sendError(res, new AggregatorError("unauthorized", "missing or invalid owner credential"), { "www-authenticate": 'Bearer realm="owner"' });
    return;
  }
  try {
    let body: Body = {};
    if (method !== "GET" && method !== "DELETE") {
      const text = await readBody(req, LIMITS.requestBodyBytes);
      if (text.trim() !== "") {
        let parsed: unknown;
        try {
          parsed = JSON.parse(text);
        } catch {
          throw invalid("body must be valid JSON");
        }
        body = asObject(parsed);
      }
    }
    const out = await route.handler(ctx, owner, params, body, Object.fromEntries(url.searchParams));
    if (out.text !== undefined) send(res, out.status ?? 200, out.text, { "content-type": "text/markdown; charset=utf-8" });
    else sendJson(res, out.status ?? 200, out.body);
  } catch (error) {
    const safe = toAggregatorError(error);
    if (safe.code === "internal") ctx.logger.error("owner_error", { route: `${route.method} ${route.path}`, ...errorFields(error) });
    sendError(res, safe);
  }
}
