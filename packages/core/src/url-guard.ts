import { lookup as dnsLookup } from "node:dns/promises";
import { request as httpRequest, type IncomingHttpHeaders } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP, type LookupFunction } from "node:net";
import { AggregatorError } from "./errors.js";

/**
 * Outbound calls go to URLs that agents or owners supply, so every call is
 * guarded against server-side request forgery: HTTPS only, no credentials in
 * the URL, no private/loopback/link-local/metadata destinations (checked on the
 * resolved address, then pinned so DNS cannot change between check and
 * connect), no redirects, bounded time and bounded response size.
 */
export interface UrlGuardOptions {
  /** Development/testing only: permits http:, loopback and private addresses. Never enable in production. */
  allowPrivateNetwork?: boolean;
  allowedPorts?: readonly number[];
}

const BLOCKED_SUFFIXES = [".localhost", ".local", ".internal", ".intranet", ".lan", ".home.arpa", ".corp"];

export function validateOutboundUrl(raw: unknown, opts: UrlGuardOptions = {}): URL {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 2048) {
    throw new AggregatorError("invalid_request", "url must be an absolute https URL of at most 2048 characters", { field: "url" });
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new AggregatorError("invalid_request", "url must be an absolute https URL", { field: "url" });
  }
  const allowPrivate = opts.allowPrivateNetwork === true;
  if (url.protocol !== "https:" && !(allowPrivate && url.protocol === "http:")) {
    throw new AggregatorError("invalid_request", "url must use https", { field: "url" });
  }
  if (url.username || url.password) throw new AggregatorError("invalid_request", "url must not contain credentials", { field: "url" });
  if (url.hash) url.hash = "";
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (!allowPrivate) {
    if (host === "localhost" || BLOCKED_SUFFIXES.some((suffix) => host.endsWith(suffix)) || !host.includes(".") && isIP(host) === 0) {
      throw new AggregatorError("invalid_request", "url host must be a public internet hostname", { field: "url" });
    }
    if (isIP(host) !== 0 && !isPublicAddress(host)) {
      throw new AggregatorError("invalid_request", "url must not point at a private or reserved address", { field: "url" });
    }
    const ports = opts.allowedPorts ?? [443, 8443];
    const port = url.port ? Number(url.port) : 443;
    if (!ports.includes(port)) throw new AggregatorError("invalid_request", `url port must be one of ${ports.join(", ")}`, { field: "url" });
  }
  return url;
}

function ipv4ToInt(ip: string): number {
  return ip.split(".").reduce((acc, part) => (acc << 8) + Number(part), 0) >>> 0;
}

const V4_BLOCKED: Array<[string, number]> = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
];

function isPublicV4(ip: string): boolean {
  const value = ipv4ToInt(ip);
  return !V4_BLOCKED.some(([base, bits]) => {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (value & mask) === (ipv4ToInt(base) & mask);
  });
}

function expandV6(ip: string): number[] | null {
  let text = ip.toLowerCase().split("%")[0] ?? "";
  let tail: number[] = [];
  if (text.includes(".")) {
    const idx = text.lastIndexOf(":");
    const v4 = text.slice(idx + 1);
    if (idx < 0 || isIP(v4) !== 4) return null;
    const n = ipv4ToInt(v4);
    tail = [(n >>> 16) & 0xffff, n & 0xffff];
    text = text.slice(0, idx + 1);
    if (!text.endsWith("::")) text = text.slice(0, -1);
  }
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const parse = (part: string): number[] => (part ? part.split(":").map((h) => parseInt(h, 16)) : []);
  const head = parse(halves[0] ?? "");
  const rest = halves.length === 2 ? parse(halves[1] ?? "") : [];
  const fill = 8 - tail.length - head.length - rest.length;
  if (halves.length === 1 && fill !== 0) return null;
  if (fill < 0) return null;
  const groups = [...head, ...new Array(halves.length === 2 ? fill : 0).fill(0), ...rest, ...tail];
  if (groups.length !== 8 || groups.some((g) => !Number.isInteger(g) || g < 0 || g > 0xffff)) return null;
  return groups;
}

function isPublicV6(ip: string): boolean {
  const g = expandV6(ip);
  if (!g) return false;
  const [a, b] = [g[0]!, g[1]!];
  if (g.every((x) => x === 0)) return false; // ::
  if (g.slice(0, 7).every((x) => x === 0) && g[7] === 1) return false; // ::1
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) {
    return isPublicV4(`${g[6]! >> 8}.${g[6]! & 0xff}.${g[7]! >> 8}.${g[7]! & 0xff}`); // ::ffff:a.b.c.d
  }
  if (g.slice(0, 6).every((x) => x === 0)) return false; // deprecated IPv4-compatible
  if (a === 0x64 && b === 0xff9b) return false; // NAT64
  if (a === 0x100 && g[1] === 0 && g[2] === 0 && g[3] === 0) return false; // discard prefix
  if (a === 0x2001 && b < 0x200) return false; // IETF protocol assignments, Teredo, ORCHID
  if (a === 0x2001 && b === 0xdb8) return false; // documentation
  if (a === 0x2002) return false; // 6to4 (embeds arbitrary IPv4)
  if ((a & 0xfe00) === 0xfc00) return false; // unique local
  if ((a & 0xffc0) === 0xfe80) return false; // link local
  if ((a & 0xff00) === 0xff00) return false; // multicast
  return (a & 0xe000) === 0x2000; // only global unicast 2000::/3
}

export function isPublicAddress(ip: string): boolean {
  const family = isIP(ip);
  if (family === 4) return isPublicV4(ip);
  if (family === 6) return isPublicV6(ip);
  return false;
}

export type Resolver = (hostname: string) => Promise<Array<{ address: string; family: number }>>;

const defaultResolver: Resolver = async (hostname) => dnsLookup(hostname, { all: true, verbatim: true });

/** Resolves once; every answer must be public. Returns the address to pin. */
export async function resolvePublicDestination(url: URL, opts: UrlGuardOptions & { resolver?: Resolver } = {}): Promise<{ address: string; family: number }> {
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (isIP(host) !== 0) {
    if (!opts.allowPrivateNetwork && !isPublicAddress(host)) throw new AggregatorError("invalid_request", "destination address is not public", { field: "url" });
    return { address: host, family: isIP(host) };
  }
  let answers: Array<{ address: string; family: number }>;
  try {
    answers = (await (opts.resolver ?? defaultResolver)(host)).slice(0, 32);
  } catch {
    throw new AggregatorError("invalid_request", "destination host did not resolve", { field: "url" });
  }
  if (answers.length === 0) throw new AggregatorError("invalid_request", "destination host did not resolve", { field: "url" });
  if (!opts.allowPrivateNetwork && answers.some((answer) => !isPublicAddress(answer.address))) {
    throw new AggregatorError("invalid_request", "destination resolves to a private or reserved address", { field: "url" });
  }
  return answers[0]!;
}

export interface GuardedResponse {
  status: number;
  headers: IncomingHttpHeaders;
  body: string;
}

export interface GuardedRequestInput extends UrlGuardOptions {
  url: string;
  method?: "POST" | "GET";
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  maxResponseBytes?: number;
  resolver?: Resolver;
}

/** One HTTP request to an untrusted URL: pinned DNS, no redirects, bounded time and size. */
export async function guardedRequest(input: GuardedRequestInput): Promise<GuardedResponse> {
  const url = validateOutboundUrl(input.url, input);
  const destination = await resolvePublicDestination(url, input);
  const timeoutMs = input.timeoutMs ?? 10_000;
  const maxBytes = input.maxResponseBytes ?? 65_536;
  const isHttps = url.protocol === "https:";
  const send = isHttps ? httpsRequest : httpRequest;
  const headers: Record<string, string> = {
    "user-agent": "agent-aggregator/0.1",
    ...(input.body !== undefined ? { "content-length": String(Buffer.byteLength(input.body, "utf8")) } : {}),
    ...input.headers,
  };
  return await new Promise<GuardedResponse>((resolve, reject) => {
    let settled = false;
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };
    const req = send(
      {
        protocol: url.protocol,
        hostname: url.hostname.replace(/^\[|\]$/g, ""),
        port: url.port ? Number(url.port) : isHttps ? 443 : 80,
        path: `${url.pathname}${url.search}`,
        method: input.method ?? "POST",
        headers,
        agent: false,
        lookup: ((_hostname: string, options: unknown, callback: (...args: unknown[]) => void) => {
          const all = typeof options === "object" && options !== null && (options as { all?: boolean }).all;
          if (all) callback(null, [{ address: destination.address, family: destination.family }]);
          else callback(null, destination.address, destination.family);
        }) as unknown as LookupFunction,
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > maxBytes) {
            res.destroy();
            finish(() => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", () => finish(() => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") })));
        res.on("error", (error) => finish(() => reject(error)));
      },
    );
    const timer = setTimeout(() => {
      req.destroy(new Error("timeout"));
      finish(() => reject(new AggregatorError("unavailable", "destination timed out")));
    }, timeoutMs);
    req.on("error", (error) => finish(() => reject(error)));
    if (input.body !== undefined) req.write(input.body);
    req.end();
  });
}
