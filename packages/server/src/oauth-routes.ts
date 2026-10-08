import { createHmac, randomBytes } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import {
  AggregatorError,
  authorizationResponseUrl,
  authorizationServerMetadata,
  cleanText,
  guardedRequest,
  isClientIdMetadataUrl,
  parseAuthorizeRequest,
  protectedResourceMetadata,
  safeEqual,
  validateClientMetadataDocument,
  validateRegistrationRequest,
  type OwnerPrincipal,
} from "@agent-aggregator/core";
import { CONSENT_ERRORS, cspNonce, htmlHeaders, renderConsentPage, renderMessagePage } from "./consent.js";
import { PRODUCT_NAME, urls, type AppContext } from "./context.js";
import { headerValue, isFormRequest, parseCookies, parseForm, readBody, redirect, send, sendJson, singleQuery } from "./http.js";
import { errorFields } from "./log.js";
import { authenticateOwner } from "./owners.js";

/**
 * OAuth 2.1 authorization server for the MCP endpoint: RFC 9728 protected
 * resource metadata, RFC 8414 server metadata, authorization code + PKCE
 * (S256) with a server-rendered consent page, refresh-token rotation,
 * RFC 7591 dynamic registration, client ID metadata documents, RFC 7009
 * revocation and RFC 9207 `iss` in every authorization response.
 */
const CONSENT_COOKIE = "agg_consent";
const CIMD_CACHE_MS = 3_600_000;
const FORM_BYTES = 16_384;

export function deriveCsrfKey(encryptionKeyHex: string): Buffer {
  return createHmac("sha256", Buffer.from(encryptionKeyHex, "hex")).update("agent-aggregator/consent-csrf/v1").digest();
}

function csrfToken(ctx: AppContext, requestId: string, nonce: string): string {
  return createHmac("sha256", ctx.csrfKey).update(`${requestId}.${nonce}`).digest("base64url");
}

function oauthJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  sendJson(res, status, body, { pragma: "no-cache", ...headers });
}

function oauthError(res: ServerResponse, status: number, error: string, description: string, headers: Record<string, string> = {}): void {
  oauthJson(res, status, { error, error_description: description }, headers);
}

function messagePage(res: ServerResponse, status: number, title: string, message: string): void {
  const nonce = cspNonce();
  send(res, status, renderMessagePage(title, message, nonce), htmlHeaders(nonce));
}

function hostOf(value: string): string {
  try {
    return new URL(value).host;
  } catch {
    return "(invalid)";
  }
}

function originOf(value: string): string | null {
  try {
    return new URL(value).origin;
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------ metadata

export function handleProtectedResourceMetadata(ctx: AppContext, res: ServerResponse): void {
  const u = urls(ctx);
  sendJson(res, 200, protectedResourceMetadata({ resource: u.mcp, authorizationServers: [u.issuer], name: PRODUCT_NAME }), { "cache-control": "public, max-age=300" });
}

export function handleAuthorizationServerMetadata(ctx: AppContext, res: ServerResponse): void {
  const u = urls(ctx);
  sendJson(
    res,
    200,
    authorizationServerMetadata({ issuer: u.issuer, authorizationEndpoint: u.authorize, tokenEndpoint: u.token, registrationEndpoint: u.register, revocationEndpoint: u.revoke }),
    { "cache-control": "public, max-age=300" },
  );
}

// ------------------------------------------------------------------- clients

/** In development (AGG_ALLOW_PRIVATE_CALLBACKS=1) a metadata document may also be served over http from a loopback address. */
export function isMetadataDocumentClientId(ctx: AppContext, clientId: string): boolean {
  if (isClientIdMetadataUrl(clientId)) return true;
  if (!ctx.config.allowPrivateCallbacks) return false;
  try {
    const url = new URL(clientId);
    return url.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) && url.pathname !== "/" && !url.hash && !url.username && !url.password;
  } catch {
    return false;
  }
}

interface ResolvedClient {
  kind: "dcr" | "cimd";
  client_name: string | null;
  redirect_uris: string[];
}

async function resolveClient(ctx: AppContext, clientId: string | undefined): Promise<ResolvedClient | null> {
  if (!clientId || clientId.length > 2000) return null;
  if (isMetadataDocumentClientId(ctx, clientId)) {
    const cached = await ctx.service.getOAuthClient(clientId);
    if (cached && cached.kind === "cimd" && Date.now() - Date.parse(cached.refreshed_at) < CIMD_CACHE_MS) {
      return { kind: "cimd", client_name: cached.client_name, redirect_uris: cached.redirect_uris };
    }
    try {
      const response = await guardedRequest({
        url: clientId,
        method: "GET",
        headers: { accept: "application/json" },
        timeoutMs: 5000,
        maxResponseBytes: 16_384,
        allowPrivateNetwork: ctx.config.allowPrivateCallbacks,
      });
      if (response.status !== 200) return null;
      const meta = validateClientMetadataDocument(clientId, JSON.parse(response.body));
      if (!meta) return null;
      await ctx.service.cacheCimdClient(clientId, { client_name: meta.client_name, redirect_uris: meta.redirect_uris, metadata: { client_uri: meta.client_uri, logo_uri: meta.logo_uri } });
      return { kind: "cimd", client_name: meta.client_name, redirect_uris: meta.redirect_uris };
    } catch {
      return null;
    }
  }
  const client = await ctx.service.getOAuthClient(clientId);
  return client && client.kind === "dcr" ? { kind: "dcr", client_name: client.client_name, redirect_uris: client.redirect_uris } : null;
}

// ----------------------------------------------------------------- authorize

export async function handleAuthorize(ctx: AppContext, req: IncomingMessage, res: ServerResponse, url: URL, ip: string): Promise<void> {
  const method = (req.method ?? "GET").toUpperCase();
  if (method === "POST") return await handleConsentPost(ctx, req, res, ip);
  if (method !== "GET") {
    send(res, 405, "", { allow: "GET, POST" });
    return;
  }
  try {
    await ctx.limits.perIp("authorize", ip);
  } catch {
    messagePage(res, 429, "Too many requests", "Too many authorization requests from this address. Wait a minute and try again.");
    return;
  }
  const query = singleQuery(url);
  if (!query) {
    messagePage(res, 400, "Invalid request", "A parameter was repeated. Start the connection again from the application.");
    return;
  }
  if (query.request_id !== undefined) return await renderConsent(ctx, res, query.request_id, query.error ?? null);

  const client = await resolveClient(ctx, query.client_id);
  const parsed = parseAuthorizeRequest(query, client, urls(ctx).mcp);
  if (!parsed.ok) {
    if (parsed.error.fatal) {
      messagePage(res, 400, "This connection request cannot be used", parsed.error.description);
      return;
    }
    redirect(res, authorizationResponseUrl(parsed.error.redirectUri, { error: parsed.error.error, error_description: parsed.error.description, state: parsed.error.state, iss: urls(ctx).issuer }), 302);
    return;
  }
  const created = await ctx.service.createAuthorizationRequest({
    client_id: parsed.value.client_id,
    client_name: client!.client_name,
    redirect_uri: parsed.value.redirect_uri,
    state: parsed.value.state,
    code_challenge: parsed.value.code_challenge,
    scopes: parsed.value.scopes,
    resource: parsed.value.resource,
  });
  // Post/redirect/get: reloading the consent page never creates another request.
  redirect(res, `/oauth/authorize?request_id=${encodeURIComponent(created.id)}`, 303);
}

async function renderConsent(ctx: AppContext, res: ServerResponse, requestId: string, errorKey: string | null): Promise<void> {
  const request = await ctx.service.getAuthorizationRequest(requestId);
  if (!request) {
    messagePage(res, 404, "Request not found", "This authorization request does not exist. Start the connection again from the application.");
    return;
  }
  if (request.status !== "pending") {
    messagePage(res, 410, "Request already handled", `This authorization request is ${request.status}. Start the connection again from the application if you still want to connect.`);
    return;
  }
  const client = await ctx.service.getOAuthClient(request.client_id);
  const nonce = randomBytes(32).toString("base64url");
  const secure = ctx.publicUrl.startsWith("https://");
  const cookie = `${CONSENT_COOKIE}=${nonce}; Path=/oauth; HttpOnly; SameSite=Strict; Max-Age=900${secure ? "; Secure" : ""}`;
  const cspValue = cspNonce();
  const html = renderConsentPage(
    {
      requestId: request.id,
      csrf: csrfToken(ctx, request.id, nonce),
      clientName: request.client_name,
      clientKind: client?.kind ?? "dcr",
      clientIdHost: client?.kind === "cimd" ? hostOf(request.client_id) : null,
      redirectHost: hostOf(request.redirect_uri),
      scopes: request.scopes,
      expiresAt: request.expires_at,
      error: errorKey ? CONSENT_ERRORS[errorKey] ?? null : null,
    },
    cspValue,
  );
  const target = originOf(request.redirect_uri);
  send(res, 200, html, { ...htmlHeaders(cspValue, target ? [target] : []), "set-cookie": cookie });
}

function connectionName(clientName: string | null, redirectUri: string): string {
  try {
    const cleaned = cleanText(clientName, "display_name", 200, { multiline: false });
    if (cleaned) return [...cleaned].slice(0, 80).join("");
  } catch {
    // fall through to the host name
  }
  return `OAuth client at ${hostOf(redirectUri)}`.slice(0, 80);
}

async function handleConsentPost(ctx: AppContext, req: IncomingMessage, res: ServerResponse, ip: string): Promise<void> {
  if (!isFormRequest(req)) {
    messagePage(res, 415, "Unsupported form", "Submit the consent form from the consent page.");
    return;
  }
  const form = parseForm(await readBody(req, FORM_BYTES));
  if (!form || !form.request_id) {
    messagePage(res, 400, "Invalid form", "Submit the consent form from the consent page.");
    return;
  }
  const back = (error: string) => redirect(res, `/oauth/authorize?request_id=${encodeURIComponent(form.request_id!)}&error=${error}`, 303);
  const request = await ctx.service.getAuthorizationRequest(form.request_id);
  if (!request || request.status !== "pending") {
    messagePage(res, 410, "Request already handled", "This authorization request is no longer pending. Start the connection again from the application.");
    return;
  }
  const nonce = parseCookies(headerValue(req, "cookie"))[CONSENT_COOKIE];
  if (!nonce || typeof form.csrf !== "string" || !safeEqual(form.csrf, csrfToken(ctx, request.id, nonce))) {
    back("csrf");
    return;
  }
  const issuer = urls(ctx).issuer;
  if (form.action === "deny") {
    const denied = await ctx.service.denyAuthorizationRequest(request.id);
    if (!denied) {
      messagePage(res, 410, "Request already handled", "This authorization request is no longer pending.");
      return;
    }
    redirect(res, authorizationResponseUrl(denied.redirect_uri, { error: "access_denied", error_description: "The owner denied the request.", state: denied.state, iss: issuer }), 303);
    return;
  }
  if (form.action !== "approve") {
    messagePage(res, 400, "Invalid form", "Choose Approve or Deny.");
    return;
  }
  if (ctx.limits.blockedFor(ip) > 0) {
    back("blocked");
    return;
  }
  const owner = await authenticateOwner(ctx.storage.driver, form.owner_credential, "web");
  if (!owner) {
    await ctx.limits.authFailed(ip);
    back("credential");
    return;
  }
  const target = form.connection_id?.trim()
    ? { connection_id: form.connection_id.trim() }
    : { provider: "oauth_client", display_name: connectionName(request.client_name, request.redirect_uri) };
  let approved: Awaited<ReturnType<typeof ctx.service.approveAuthorizationRequest>>;
  try {
    approved = await ctx.service.approveAuthorizationRequest(owner as OwnerPrincipal, request.id, target);
  } catch (error) {
    if (error instanceof AggregatorError && "connection_id" in target && (error.code === "not_found" || error.code === "conflict")) {
      back("connection");
      return;
    }
    throw error;
  }
  redirect(res, authorizationResponseUrl(approved.redirect_uri, { code: approved.code, state: approved.state, iss: issuer }), 303);
}

// --------------------------------------------------------------------- token

export async function handleToken(ctx: AppContext, req: IncomingMessage, res: ServerResponse, ip: string): Promise<void> {
  if ((req.method ?? "GET").toUpperCase() !== "POST") {
    send(res, 405, "", { allow: "POST" });
    return;
  }
  try {
    await ctx.limits.perIp("token", ip);
  } catch (error) {
    const retry = error instanceof AggregatorError && typeof error.details?.retry_after === "number" ? error.details.retry_after : 60;
    oauthError(res, 429, "invalid_request", "too many token requests from this address", { "retry-after": String(retry) });
    return;
  }
  if (!isFormRequest(req)) {
    oauthError(res, 400, "invalid_request", "use application/x-www-form-urlencoded");
    return;
  }
  const form = parseForm(await readBody(req, FORM_BYTES));
  if (!form) {
    oauthError(res, 400, "invalid_request", "parameters must not repeat");
    return;
  }
  try {
    if (form.grant_type === "authorization_code") {
      if (!form.code || !form.code_verifier || !form.client_id || !form.redirect_uri) {
        oauthError(res, 400, "invalid_request", "code, code_verifier, client_id and redirect_uri are required");
        return;
      }
      const tokens = await ctx.service.exchangeAuthorizationCode({ code: form.code, code_verifier: form.code_verifier, client_id: form.client_id, redirect_uri: form.redirect_uri, resource: form.resource ?? null });
      oauthJson(res, 200, tokens);
      return;
    }
    if (form.grant_type === "refresh_token") {
      if (!form.refresh_token || !form.client_id) {
        oauthError(res, 400, "invalid_request", "refresh_token and client_id are required");
        return;
      }
      const tokens = await ctx.service.refreshAccessToken({ refresh_token: form.refresh_token, client_id: form.client_id, resource: form.resource ?? null });
      oauthJson(res, 200, tokens);
      return;
    }
    oauthError(res, 400, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token");
  } catch (error) {
    if (error instanceof AggregatorError && error.code !== "internal") {
      // The service reports every grant failure as invalid_grant (or invalid_target for a resource mismatch) without saying which check failed.
      if (error.message === "invalid_target") oauthError(res, 400, "invalid_target", "resource does not match the authorization");
      else oauthError(res, 400, "invalid_grant", "the code or refresh token is invalid, expired, already used, or was issued to another client");
      return;
    }
    ctx.logger.error("token_error", errorFields(error));
    oauthError(res, 500, "server_error", "internal error");
  }
}

// -------------------------------------------------------------- registration

export async function handleRegister(ctx: AppContext, req: IncomingMessage, res: ServerResponse, ip: string): Promise<void> {
  if ((req.method ?? "GET").toUpperCase() !== "POST") {
    send(res, 405, "", { allow: "POST" });
    return;
  }
  try {
    await ctx.limits.perIp("register", ip);
  } catch (error) {
    const retry = error instanceof AggregatorError && typeof error.details?.retry_after === "number" ? error.details.retry_after : 3600;
    oauthError(res, 429, "rate_limited", "too many registrations from this address", { "retry-after": String(retry) });
    return;
  }
  let body: unknown;
  try {
    body = JSON.parse(await readBody(req, FORM_BYTES));
  } catch (error) {
    if (error instanceof AggregatorError) throw error;
    oauthError(res, 400, "invalid_client_metadata", "body must be a JSON object");
    return;
  }
  const checked = validateRegistrationRequest(body);
  if (!checked.ok) {
    oauthError(res, 400, checked.error, checked.description);
    return;
  }
  const registered = await ctx.service.registerOAuthClient({ client_name: checked.client_name, redirect_uris: checked.redirect_uris, metadata: checked.metadata });
  oauthJson(res, 201, {
    client_id: registered.client_id,
    client_id_issued_at: registered.issued_at,
    client_name: checked.client_name,
    redirect_uris: checked.redirect_uris,
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
    ...(checked.metadata.client_uri ? { client_uri: checked.metadata.client_uri } : {}),
  });
}

// ---------------------------------------------------------------- revocation

export async function handleRevoke(ctx: AppContext, req: IncomingMessage, res: ServerResponse, ip: string): Promise<void> {
  if ((req.method ?? "GET").toUpperCase() !== "POST") {
    send(res, 405, "", { allow: "POST" });
    return;
  }
  try {
    await ctx.limits.perIp("token", ip);
  } catch {
    oauthError(res, 429, "invalid_request", "too many requests from this address", { "retry-after": "60" });
    return;
  }
  if (!isFormRequest(req)) {
    oauthError(res, 400, "invalid_request", "use application/x-www-form-urlencoded");
    return;
  }
  const form = parseForm(await readBody(req, FORM_BYTES));
  if (!form || !form.token) {
    oauthError(res, 400, "invalid_request", "token is required");
    return;
  }
  await ctx.service.revokeOAuthToken(form.token);
  // RFC 7009 §2.2: unknown tokens are not an error.
  send(res, 200, "");
}
