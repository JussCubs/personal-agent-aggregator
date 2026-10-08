import type { IncomingMessage, ServerResponse } from "node:http";
import {
  ALL_SCOPES,
  AggregatorError,
  DEFAULT_MCP_INSTRUCTIONS,
  LIMITS,
  handleAgentRest,
  handleMcpHttp,
  invalid,
  wwwAuthenticate,
  type AgentPrincipal,
} from "@agent-aggregator/core";
import { PRODUCT_NAME, SERVER_NAME, SERVER_VERSION, urls, type AppContext } from "./context.js";
import { bearerToken, flatHeaders, headerValue, readBody, send, sendError, sendJson } from "./http.js";
import { errorFields } from "./log.js";

/**
 * Resolves an agent bearer credential for one audience:
 * - REST (/api/v1) accepts only long-lived agent credentials;
 * - MCP (/mcp) accepts agent credentials and OAuth access tokens issued for this MCP resource.
 * Every rejected credential counts toward the per-IP failed-authentication limit.
 */
export async function authenticateAgent(ctx: AppContext, authorization: string | undefined, ip: string, audience: "rest" | "mcp"): Promise<AgentPrincipal | null> {
  const token = bearerToken(authorization);
  if (!token) return null;
  const principal = await ctx.service.authenticate(token);
  const accepted =
    principal !== null &&
    (principal.credentialKind === "agent" || (audience === "mcp" && principal.credentialKind === "oauth_access" && principal.resource === urls(ctx).mcp));
  if (!accepted) {
    await ctx.limits.authFailed(ip);
    return null;
  }
  return principal;
}

/** Agent REST API: /api/v1/* is passed to the core handler as /v1/*. */
export async function handleRest(ctx: AppContext, req: IncomingMessage, res: ServerResponse, url: URL, ip: string): Promise<void> {
  const blocked = ctx.limits.blockedFor(ip);
  if (blocked > 0) {
    sendError(res, new AggregatorError("rate_limited", `too many failed authentications from this address; retry after ${blocked} seconds`, { retry_after: blocked }), { "retry-after": String(blocked) });
    return;
  }
  const method = (req.method ?? "GET").toUpperCase();
  let body: unknown = null;
  if (method !== "GET" && method !== "HEAD") {
    const text = await readBody(req, LIMITS.requestBodyBytes);
    if (text.trim() !== "") {
      try {
        body = JSON.parse(text);
      } catch {
        sendError(res, invalid("body must be valid JSON"));
        return;
      }
    }
  }
  const authorization = headerValue(req, "authorization");
  const response = await handleAgentRest(
    { method, path: url.pathname.slice("/api".length), query: Object.fromEntries(url.searchParams), body, authorization },
    {
      service: ctx.service,
      authenticate: (value) => authenticateAgent(ctx, value, ip, "rest"),
      challenge: (error) => `Bearer realm="${SERVER_NAME}"${error && authorization ? `, error="${error}"` : ""}`,
      beforeCall: async (principal, route) => {
        if (principal) await ctx.limits.agentCall(principal, route);
        else await ctx.limits.perIp("claim", ip);
      },
      onError: (error, route) => ctx.logger.error("rest_error", { route, ...errorFields(error) }),
    },
  );
  sendJson(res, response.status, response.body, response.headers);
}

function rpcFailure(status: number, code: number, message: string, headers: Record<string, string> = {}): { status: number; body: string; headers: Record<string, string> } {
  return { status, body: JSON.stringify({ jsonrpc: "2.0", id: null, error: { code, message } }), headers: { "content-type": "application/json", ...headers } };
}

/** MCP over Streamable HTTP (JSON responses, stateless). */
export async function handleMcp(ctx: AppContext, req: IncomingMessage, res: ServerResponse, ip: string): Promise<void> {
  const blocked = ctx.limits.blockedFor(ip);
  if (blocked > 0) {
    const out = rpcFailure(429, -32000, `Too many failed authentications from this address; retry after ${blocked} seconds`, { "retry-after": String(blocked) });
    send(res, out.status, out.body, out.headers);
    return;
  }
  const method = (req.method ?? "GET").toUpperCase();
  let body = "";
  if (method === "POST") {
    try {
      body = await readBody(req, LIMITS.requestBodyBytes);
    } catch (error) {
      if (error instanceof AggregatorError && error.code === "payload_too_large") {
        const out = rpcFailure(413, -32600, "Request too large");
        send(res, out.status, out.body, out.headers);
        return;
      }
      throw error;
    }
  }
  const headers = flatHeaders(req);
  const presented = Boolean(headers.authorization);
  const u = urls(ctx);
  const response = await handleMcpHttp(
    { method, headers, body },
    {
      service: ctx.service,
      serverInfo: { name: SERVER_NAME, version: SERVER_VERSION, title: PRODUCT_NAME },
      instructions: DEFAULT_MCP_INSTRUCTIONS,
      authenticate: (value) => authenticateAgent(ctx, value, ip, "mcp"),
      challenge: (error, scopes) =>
        wwwAuthenticate({
          resourceMetadataUrl: u.resourceMetadata,
          scope: scopes && scopes.length > 0 ? scopes : ALL_SCOPES,
          ...(error && (presented || error === "insufficient_scope") ? { error } : {}),
        }),
      allowedOrigins: [new URL(ctx.publicUrl).origin],
      beforeCall: (principal, rpcMethod, name) => ctx.limits.agentCall(principal, name ?? rpcMethod),
      onError: (error, context) => ctx.logger.error("mcp_error", { rpc_method: context.method, tool: context.tool, ...errorFields(error) }),
    },
  );
  send(res, response.status, response.body, response.headers);
}
