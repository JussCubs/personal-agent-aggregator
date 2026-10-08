import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { performance } from "node:perf_hooks";
import {
  AggregatorError,
  AggregatorService,
  CONTRACT_VERSION,
  createAesGcmSecretBox,
  type AggregatorServiceOptions,
} from "@agent-aggregator/core";
import { handleMcp, handleRest } from "./agent-routes.js";
import type { ServerConfig } from "./config.js";
import { SERVER_NAME, SERVER_VERSION, urls, type AppContext } from "./context.js";
import { clientIp, sendError, sendJson } from "./http.js";
import { Limits } from "./limits.js";
import { createJsonLogger, errorFields, type Logger } from "./log.js";
import {
  deriveCsrfKey,
  handleAuthorizationServerMetadata,
  handleAuthorize,
  handleProtectedResourceMetadata,
  handleRegister,
  handleRevoke,
  handleToken,
} from "./oauth-routes.js";
import { handleOwner } from "./owner-routes.js";
import { openStorage, type Storage } from "./storage.js";
import { startWorker, type Worker, type WorkerOptions } from "./worker.js";

export interface CreateServerOptions {
  logger?: Logger;
  /** A storage opened by the caller (closed by close()). Default: opened from config.storage. */
  storage?: Storage;
  /** Delivery transport override for tests. Default: the core's SSRF-guarded HTTP client. */
  send?: AggregatorServiceOptions["send"];
  /** Delivery loop timing; false disables the loop (tests drive deliverDue() themselves). */
  worker?: WorkerOptions | false;
  now?: () => Date;
}

export interface AggregatorServer {
  readonly service: AggregatorService;
  readonly storage: Storage;
  readonly http: Server;
  /** Starts listening and the delivery loop. Resolves to the public base URL. */
  listen(): Promise<string>;
  /** Stops accepting requests, finishes the current delivery pass and closes storage. */
  close(): Promise<void>;
  url(): string;
}

type RouteLabel = string;

async function route(ctx: AppContext, req: IncomingMessage, res: ServerResponse, url: URL, ip: string): Promise<RouteLabel> {
  const path = url.pathname;
  const method = (req.method ?? "GET").toUpperCase();
  if (path === "/mcp") {
    await handleMcp(ctx, req, res, ip);
    return "mcp";
  }
  if (path === "/api/v1" || path.startsWith("/api/v1/")) {
    await handleRest(ctx, req, res, url, ip);
    return "agent_api";
  }
  if (path === "/owner" || path.startsWith("/owner/")) {
    await handleOwner(ctx, req, res, url, ip);
    return "owner_api";
  }
  if (path === "/oauth/authorize") {
    await handleAuthorize(ctx, req, res, url, ip);
    return "oauth.authorize";
  }
  if (path === "/oauth/token") {
    await handleToken(ctx, req, res, ip);
    return "oauth.token";
  }
  if (path === "/oauth/register") {
    await handleRegister(ctx, req, res, ip);
    return "oauth.register";
  }
  if (path === "/oauth/revoke") {
    await handleRevoke(ctx, req, res, ip);
    return "oauth.revoke";
  }
  if (method === "GET" && (path === "/.well-known/oauth-protected-resource" || path === "/.well-known/oauth-protected-resource/mcp")) {
    handleProtectedResourceMetadata(ctx, res);
    return "oauth.resource_metadata";
  }
  if (method === "GET" && path === "/.well-known/oauth-authorization-server") {
    handleAuthorizationServerMetadata(ctx, res);
    return "oauth.server_metadata";
  }
  if (method === "GET" && path === "/healthz") {
    await ctx.storage.driver.privileged((db) => db.query("SELECT 1 AS ok"));
    sendJson(res, 200, { ok: true });
    return "health";
  }
  if (method === "GET" && path === "/") {
    const u = urls(ctx);
    sendJson(res, 200, {
      name: SERVER_NAME,
      version: SERVER_VERSION,
      contract_version: CONTRACT_VERSION,
      endpoints: {
        mcp: u.mcp,
        agent_api: `${u.api}/v1`,
        owner_api: `${u.base}/owner`,
        oauth_authorization_server: `${u.base}/.well-known/oauth-authorization-server`,
        oauth_protected_resource: u.resourceMetadata,
      },
    });
    return "index";
  }
  sendError(res, new AggregatorError("not_found", "unknown endpoint"));
  return "not_found";
}

export async function createAggregatorServer(config: ServerConfig, opts: CreateServerOptions = {}): Promise<AggregatorServer> {
  const logger = opts.logger ?? createJsonLogger();
  const storage = opts.storage ?? (await openStorage(config.storage));
  try {
    await storage.migrate();
  } catch (error) {
    if (!opts.storage) await storage.close().catch(() => undefined);
    throw error;
  }
  let worker: Worker | null = null;
  const service = new AggregatorService({
    driver: storage.driver,
    secretBox: createAesGcmSecretBox(config.encryptionKey),
    outbound: { allowPrivateNetwork: config.allowPrivateCallbacks },
    ...(opts.send ? { send: opts.send } : {}),
    ...(opts.now ? { now: opts.now } : {}),
    hooks: {
      deliveriesQueued: () => worker?.kick(),
      hookError: (error, hook) => logger.error("hook_error", { hook, ...errorFields(error) }),
    },
  });
  const limits = new Limits();
  const ctx: AppContext = {
    config,
    service,
    storage,
    limits,
    logger,
    csrfKey: deriveCsrfKey(config.encryptionKey),
    publicUrl: config.publicUrl ?? `http://${config.host}:${config.port}`,
  };

  const http = createServer(async (req, res) => {
    const started = performance.now();
    const ip = clientIp(req, config.trustProxy);
    const rawUrl = req.url ?? "/";
    let label = "invalid";
    let path = "-";
    res.on("finish", () => {
      logger.info("request", { method: req.method ?? "-", path: path.slice(0, 200), route: label, status: res.statusCode, ms: Math.round(performance.now() - started), ip });
    });
    try {
      if (!rawUrl.startsWith("/")) {
        sendError(res, new AggregatorError("invalid_request", "request target must be a path"));
        return;
      }
      const url = new URL(`http://localhost${rawUrl}`);
      path = url.pathname;
      label = await route(ctx, req, res, url, ip);
    } catch (error) {
      if (error instanceof AggregatorError) {
        sendError(res, error, error.code === "rate_limited" && typeof error.details?.retry_after === "number" ? { "retry-after": String(error.details.retry_after) } : {});
        return;
      }
      logger.error("unhandled_error", { route: label, ...errorFields(error) });
      if (!res.headersSent) sendError(res, new AggregatorError("internal", "Internal error"));
      else res.end();
    }
  });
  http.requestTimeout = 30_000;
  http.headersTimeout = 15_000;
  http.keepAliveTimeout = 5_000;

  let listening = false;
  return {
    service,
    storage,
    http,
    url: () => ctx.publicUrl,
    async listen() {
      await new Promise<void>((resolve, reject) => {
        http.once("error", reject);
        http.listen(config.port, config.host, () => {
          http.off("error", reject);
          resolve();
        });
      });
      listening = true;
      if (!config.publicUrl) {
        const address = http.address() as AddressInfo;
        const host = address.family === "IPv6" ? `[${address.address}]` : address.address;
        ctx.publicUrl = `http://${host}:${address.port}`;
      }
      if (opts.worker !== false) worker = startWorker(service, logger, { ...(opts.worker ?? {}), onSweep: () => limits.prune() });
      return ctx.publicUrl;
    },
    async close() {
      if (listening) {
        await new Promise<void>((resolve) => {
          http.close(() => resolve());
          http.closeIdleConnections();
        });
      }
      await worker?.stop();
      await storage.close();
    },
  };
}
