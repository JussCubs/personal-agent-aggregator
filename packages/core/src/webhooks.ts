import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Standard Webhooks (https://www.standardwebhooks.com) signing.
 * Signed content: `${webhook-id}.${webhook-timestamp}.${body}`, HMAC-SHA256,
 * key = base64-decoded secret after the `whsec_` prefix, header `v1,<base64>`.
 * Multiple signatures (key rotation) are space separated.
 */
export const WEBHOOK_SECRET_PREFIX = "whsec_";

export function generateWebhookSecret(bytes = 32): string {
  return `${WEBHOOK_SECRET_PREFIX}${randomBytes(bytes).toString("base64")}`;
}

/** Decodes and validates a `whsec_` secret. MCP event subscriptions require 24-64 key bytes. */
export function decodeWebhookSecret(secret: string, opts: { minBytes?: number; maxBytes?: number } = {}): Buffer {
  const min = opts.minBytes ?? 24;
  const max = opts.maxBytes ?? 64;
  if (typeof secret !== "string" || !secret.startsWith(WEBHOOK_SECRET_PREFIX)) throw new Error("webhook secret must start with whsec_");
  const encoded = secret.slice(WEBHOOK_SECRET_PREFIX.length);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) throw new Error("webhook secret must be base64 after whsec_");
  const key = Buffer.from(encoded, "base64");
  if (key.length < min || key.length > max) throw new Error(`webhook secret must decode to ${min}-${max} bytes`);
  return key;
}

export function signWebhook(secret: string, messageId: string, timestampSeconds: number, body: string): string {
  const key = decodeWebhookSecret(secret, { minBytes: 1, maxBytes: 1024 });
  const mac = createHmac("sha256", key).update(`${messageId}.${timestampSeconds}.${body}`, "utf8").digest("base64");
  return `v1,${mac}`;
}

export interface WebhookHeaders {
  "webhook-id": string;
  "webhook-timestamp": string;
  "webhook-signature": string;
}

/** Signs `body` with every secret in `secrets` (current first, previous during rotation). */
export function webhookHeaders(secrets: string | readonly string[], messageId: string, body: string, now: Date = new Date()): WebhookHeaders {
  const list = typeof secrets === "string" ? [secrets] : [...secrets];
  if (list.length === 0) throw new Error("at least one webhook secret is required");
  const timestamp = Math.floor(now.getTime() / 1000);
  return {
    "webhook-id": messageId,
    "webhook-timestamp": String(timestamp),
    "webhook-signature": list.map((secret) => signWebhook(secret, messageId, timestamp, body)).join(" "),
  };
}

/** Verifies a received webhook. Rejects stale timestamps to limit replay. */
export function verifyWebhook(
  secret: string,
  headers: Record<string, string | string[] | undefined>,
  body: string,
  opts: { toleranceSeconds?: number; now?: Date } = {},
): boolean {
  const read = (name: string): string | undefined => {
    const direct = headers[name] ?? headers[name.toLowerCase()];
    if (direct !== undefined) return Array.isArray(direct) ? direct[0] : direct;
    const key = Object.keys(headers).find((candidate) => candidate.toLowerCase() === name);
    const value = key ? headers[key] : undefined;
    return Array.isArray(value) ? value[0] : value;
  };
  const id = read("webhook-id");
  const timestampRaw = read("webhook-timestamp");
  const signatures = read("webhook-signature");
  if (!id || !timestampRaw || !signatures || !/^\d{1,12}$/.test(timestampRaw)) return false;
  const timestamp = Number(timestampRaw);
  const nowSeconds = Math.floor((opts.now ?? new Date()).getTime() / 1000);
  if (Math.abs(nowSeconds - timestamp) > (opts.toleranceSeconds ?? 300)) return false;
  let expected: Buffer;
  try {
    expected = Buffer.from(signWebhook(secret, id, timestamp, body).slice(3), "base64");
  } catch {
    return false;
  }
  return signatures.split(" ").some((entry) => {
    const [version, value] = entry.split(",", 2);
    if (version !== "v1" || !value) return false;
    const candidate = Buffer.from(value, "base64");
    return candidate.length === expected.length && timingSafeEqual(candidate, expected);
  });
}
