import { createHash } from "node:crypto";
import { ALL_SCOPES, parseScopes, type Scope } from "./contract.js";
import { cleanText } from "./validate.js";

/** Client-chosen display names are untrusted: strip control/bidi characters and bound the length. */
function displayName(value: unknown): string | null {
  if (typeof value !== "string") return null;
  try {
    return cleanText(value, "client_name", 100, { multiline: false });
  } catch {
    return cleanText(value.slice(0, 100), "client_name", 100, { multiline: false });
  }
}

/**
 * OAuth 2.1 helpers for an MCP authorization server: PKCE (S256 only),
 * RFC 8414 / RFC 9728 metadata, RFC 9207 issuer identification, client ID
 * metadata documents (CIMD) and RFC 7591 dynamic registration. Clients are
 * public (token_endpoint_auth_method "none"); PKCE binds the code to the client.
 */

export function pkceChallengeS256(verifier: string): string {
  return createHash("sha256").update(verifier, "ascii").digest("base64url");
}

export function verifyPkceS256(verifier: unknown, challenge: string): boolean {
  if (typeof verifier !== "string" || !/^[A-Za-z0-9\-._~]{43,128}$/.test(verifier)) return false;
  const expected = pkceChallengeS256(verifier);
  if (expected.length !== challenge.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i += 1) diff |= expected.charCodeAt(i) ^ challenge.charCodeAt(i);
  return diff === 0;
}

export interface AuthorizationServerMetadataInput {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  registrationEndpoint?: string;
  revocationEndpoint?: string;
  scopes?: readonly string[];
  serviceDocumentation?: string;
}

export function authorizationServerMetadata(input: AuthorizationServerMetadataInput): Record<string, unknown> {
  return {
    issuer: input.issuer,
    authorization_endpoint: input.authorizationEndpoint,
    token_endpoint: input.tokenEndpoint,
    ...(input.registrationEndpoint ? { registration_endpoint: input.registrationEndpoint } : {}),
    ...(input.revocationEndpoint ? { revocation_endpoint: input.revocationEndpoint, revocation_endpoint_auth_methods_supported: ["none"] } : {}),
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: [...(input.scopes ?? ALL_SCOPES)],
    client_id_metadata_document_supported: true,
    authorization_response_iss_parameter_supported: true,
    ...(input.serviceDocumentation ? { service_documentation: input.serviceDocumentation } : {}),
  };
}

export function protectedResourceMetadata(input: { resource: string; authorizationServers: readonly string[]; scopes?: readonly string[]; documentation?: string; name?: string }): Record<string, unknown> {
  return {
    resource: input.resource,
    authorization_servers: [...input.authorizationServers],
    scopes_supported: [...(input.scopes ?? ALL_SCOPES)],
    bearer_methods_supported: ["header"],
    ...(input.name ? { resource_name: input.name } : {}),
    ...(input.documentation ? { resource_documentation: input.documentation } : {}),
  };
}

function quoteParam(value: string): string {
  return `"${value.replace(/[\\"]/g, "\\$&")}"`;
}

/** RFC 6750 / RFC 9728 challenge. */
export function wwwAuthenticate(input: { resourceMetadataUrl: string; scope?: readonly string[]; error?: "invalid_token" | "insufficient_scope" | "invalid_request"; description?: string }): string {
  const parts = [`resource_metadata=${quoteParam(input.resourceMetadataUrl)}`];
  if (input.scope?.length) parts.push(`scope=${quoteParam(input.scope.join(" "))}`);
  if (input.error) parts.push(`error=${quoteParam(input.error)}`);
  if (input.description) parts.push(`error_description=${quoteParam(input.description)}`);
  return `Bearer ${parts.join(", ")}`;
}

/** Redirect URIs must be https, or http on a loopback host for native/dev clients. No fragments. */
export function isAllowedRedirectUri(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 2000) return false;
  try {
    const url = new URL(value);
    if (url.hash || url.username || url.password) return false;
    if (url.protocol === "https:") return true;
    return url.protocol === "http:" && (url.hostname === "127.0.0.1" || url.hostname === "localhost" || url.hostname === "[::1]");
  } catch {
    return false;
  }
}

export type AuthorizeError = { fatal: true; error: string; description: string } | { fatal: false; error: string; description: string; redirectUri: string; state: string | null };

export interface AuthorizeParams {
  client_id: string;
  redirect_uri: string;
  state: string | null;
  code_challenge: string;
  scopes: Scope[];
  resource: string;
}

/**
 * Validates an authorization request. Client and redirect problems are fatal
 * (shown to the user, never redirected, per RFC 6749 §4.1.2.1); everything
 * else is returned to the client's redirect URI.
 */
export function parseAuthorizeRequest(
  query: Record<string, string | undefined>,
  client: { redirect_uris: readonly string[] } | null,
  expectedResource: string,
): { ok: true; value: AuthorizeParams } | { ok: false; error: AuthorizeError } {
  const clientId = query.client_id;
  if (!clientId || !client) return { ok: false, error: { fatal: true, error: "invalid_client", description: "Unknown client." } };
  const redirectUri = query.redirect_uri ?? (client.redirect_uris.length === 1 ? client.redirect_uris[0] : undefined);
  if (!redirectUri || !client.redirect_uris.includes(redirectUri) || !isAllowedRedirectUri(redirectUri)) {
    return { ok: false, error: { fatal: true, error: "invalid_request", description: "The redirect URI is not registered for this client." } };
  }
  const state = query.state ?? null;
  const fail = (error: string, description: string) => ({ ok: false as const, error: { fatal: false as const, error, description, redirectUri, state } });
  if (state !== null && state.length > 1000) return fail("invalid_request", "state is too long");
  if (query.response_type !== "code") return fail("unsupported_response_type", "Only response_type=code is supported.");
  if (!query.code_challenge || query.code_challenge_method !== "S256" || !/^[A-Za-z0-9_-]{43}$/.test(query.code_challenge)) {
    return fail("invalid_request", "PKCE with code_challenge_method=S256 is required.");
  }
  const resource = query.resource ?? expectedResource;
  if (resource !== expectedResource) return fail("invalid_target", "Unknown resource.");
  const requested = query.scope === undefined || query.scope.trim() === "" ? [...ALL_SCOPES] : parseScopes(query.scope);
  if (requested.length === 0) return fail("invalid_scope", "No supported scope was requested.");
  return { ok: true, value: { client_id: clientId, redirect_uri: redirectUri, state, code_challenge: query.code_challenge, scopes: requested, resource } };
}

export function authorizationResponseUrl(redirectUri: string, params: Record<string, string | null | undefined>): string {
  const url = new URL(redirectUri);
  for (const [key, value] of Object.entries(params)) if (value !== null && value !== undefined) url.searchParams.set(key, value);
  return url.toString();
}

/** Client ID Metadata Document validation: the document must name itself as client_id. */
export function validateClientMetadataDocument(clientIdUrl: string, doc: unknown): { client_name: string | null; redirect_uris: string[]; client_uri: string | null; logo_uri: string | null } | null {
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return null;
  const raw = doc as Record<string, unknown>;
  if (raw.client_id !== clientIdUrl) return null;
  const redirects = Array.isArray(raw.redirect_uris) ? raw.redirect_uris.filter(isAllowedRedirectUri).slice(0, 20) : [];
  if (redirects.length === 0) return null;
  const httpsUrl = (value: unknown) => (typeof value === "string" && /^https:\/\//.test(value) && value.length < 2000 ? value : null);
  return { client_name: displayName(raw.client_name), redirect_uris: redirects, client_uri: httpsUrl(raw.client_uri), logo_uri: httpsUrl(raw.logo_uri) };
}

export function isClientIdMetadataUrl(clientId: string): boolean {
  try {
    const url = new URL(clientId);
    return url.protocol === "https:" && url.pathname !== "/" && !url.hash && !url.username && !url.password;
  } catch {
    return false;
  }
}

/** RFC 7591 registration request → stored metadata, or an error code. */
export function validateRegistrationRequest(body: unknown): { ok: true; client_name: string | null; redirect_uris: string[]; metadata: Record<string, string | null> } | { ok: false; error: string; description: string } {
  if (!body || typeof body !== "object" || Array.isArray(body)) return { ok: false, error: "invalid_client_metadata", description: "Body must be a JSON object." };
  const raw = body as Record<string, unknown>;
  const redirects = Array.isArray(raw.redirect_uris) ? raw.redirect_uris : [];
  if (redirects.length === 0 || redirects.length > 10 || !redirects.every(isAllowedRedirectUri)) {
    return { ok: false, error: "invalid_redirect_uri", description: "redirect_uris must be 1-10 https (or loopback http) URIs." };
  }
  const method = raw.token_endpoint_auth_method ?? "none";
  if (method !== "none") return { ok: false, error: "invalid_client_metadata", description: "Only public clients (token_endpoint_auth_method none) with PKCE are supported." };
  const grants = Array.isArray(raw.grant_types) ? raw.grant_types : ["authorization_code"];
  if (!grants.every((grant) => grant === "authorization_code" || grant === "refresh_token")) {
    return { ok: false, error: "invalid_client_metadata", description: "Only authorization_code and refresh_token grants are supported." };
  }
  const name = displayName(raw.client_name);
  const uri = typeof raw.client_uri === "string" && /^https:\/\//.test(raw.client_uri) ? raw.client_uri.slice(0, 2000) : null;
  return { ok: true, client_name: name, redirect_uris: redirects as string[], metadata: { client_uri: uri } };
}
