import type { IncomingMessage, ServerResponse } from "node:http";
import { isIP } from "node:net";
import { AggregatorError } from "@agent-aggregator/core";

/** Headers sent on every response. */
export const BASE_HEADERS: Record<string, string> = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "cache-control": "no-store",
};

export class HttpError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** Reads the request body as UTF-8, refusing anything larger than `maxBytes`. */
export async function readBody(req: IncomingMessage, maxBytes: number): Promise<string> {
  const declared = Number(req.headers["content-length"] ?? "0");
  if (Number.isFinite(declared) && declared > maxBytes) {
    req.resume();
    throw new AggregatorError("payload_too_large", `request body must be at most ${maxBytes} bytes`);
  }
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buffer = chunk as Buffer;
    size += buffer.length;
    if (size > maxBytes) {
      req.resume();
      throw new AggregatorError("payload_too_large", `request body must be at most ${maxBytes} bytes`);
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export function send(res: ServerResponse, status: number, body: string, headers: Record<string, string> = {}): void {
  if (res.headersSent) return;
  res.writeHead(status, { ...BASE_HEADERS, ...headers, "content-length": String(Buffer.byteLength(body, "utf8")) });
  res.end(body);
}

export function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  send(res, status, JSON.stringify(body), { "content-type": "application/json; charset=utf-8", ...headers });
}

export function sendError(res: ServerResponse, error: AggregatorError, headers: Record<string, string> = {}): void {
  sendJson(res, error.status, error.toJSON(), headers);
}

export function redirect(res: ServerResponse, location: string, status = 303, headers: Record<string, string> = {}): void {
  send(res, status, "", { location, ...headers });
}

/** Flattens Node's header object (arrays joined) for the framework-free core handlers. */
export function flatHeaders(req: IncomingMessage): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(req.headers)) out[key] = Array.isArray(value) ? value.join(", ") : value;
  return out;
}

export function headerValue(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

export function bearerToken(authorization: string | undefined): string | null {
  if (!authorization) return null;
  const match = /^Bearer\s+([^\s]+)\s*$/i.exec(authorization);
  return match ? match[1]! : null;
}

/** Client address for per-IP limits. With trustProxy, the right-most X-Forwarded-For entry (added by the one trusted proxy). */
export function clientIp(req: IncomingMessage, trustProxy: boolean): string {
  if (trustProxy) {
    const forwarded = headerValue(req, "x-forwarded-for");
    const last = forwarded?.split(",").map((part) => part.trim()).filter(Boolean).at(-1);
    if (last && isIP(last) !== 0) return last;
  }
  return req.socket.remoteAddress ?? "unknown";
}

export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq <= 0) continue;
    const name = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (name && !(name in out)) out[name] = value;
  }
  return out;
}

/** application/x-www-form-urlencoded → record. Repeated keys are refused (OAuth parameters must not repeat). */
export function parseForm(body: string): Record<string, string> | null {
  const params = new URLSearchParams(body);
  const out: Record<string, string> = {};
  for (const [key, value] of params) {
    if (key in out) return null;
    out[key] = value;
  }
  return out;
}

export function isFormRequest(req: IncomingMessage): boolean {
  return /^application\/x-www-form-urlencoded\b/i.test(headerValue(req, "content-type") ?? "");
}

/** Query parameters as a record; null when a parameter repeats. */
export function singleQuery(url: URL): Record<string, string> | null {
  const out: Record<string, string> = {};
  for (const [key, value] of url.searchParams) {
    if (key in out) return null;
    out[key] = value;
  }
  return out;
}

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]!);
}
