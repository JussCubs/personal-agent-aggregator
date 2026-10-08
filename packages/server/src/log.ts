/**
 * Structured, one-line JSON logs. Callers pass only primitive fields; every
 * string is passed through `redact()` and truncated. Request logs carry the
 * method, path (never the query string), status, duration and client IP —
 * never headers, bodies, credentials or OAuth codes.
 */
export type LogValue = string | number | boolean | null | undefined;
export type LogFields = Record<string, LogValue>;

export interface Logger {
  info(msg: string, fields?: LogFields): void;
  warn(msg: string, fields?: LogFields): void;
  error(msg: string, fields?: LogFields): void;
}

const REDACTIONS: Array<[RegExp, string]> = [
  // Bearer credentials in any header-like text.
  [/\b(Bearer|Basic)\s+[^\s"',;]+/gi, "$1 [redacted]"],
  // Prefixed credentials: agent, OAuth access/refresh/code, owner, challenge.
  [/\b(agg|aggo|aggr|aggc|aggown|chal)_[A-Za-z0-9_-]{8,}/g, "$1_[redacted]"],
  // Standard Webhooks secrets.
  [/\bwhsec_[A-Za-z0-9+/=]{8,}/g, "whsec_[redacted]"],
  // One-time setup codes (XXXXX-XXXXX-XXXXX-XXXXX).
  [/\b[A-HJ-NP-Z2-9]{5}(?:-[A-HJ-NP-Z2-9]{5}){3}\b/g, "[redacted-code]"],
  // Long hex strings: keys and digests.
  [/\b[0-9a-fA-F]{40,}\b/g, "[redacted-hex]"],
  // Credentials embedded in URLs (postgres://user:password@host).
  [/(\b[a-z][a-z0-9+.-]*:\/\/)[^\s/:@]+:[^\s/@]+@/gi, "$1[redacted]@"],
];

export function redact(text: string): string {
  let out = text;
  for (const [pattern, replacement] of REDACTIONS) out = out.replace(pattern, replacement);
  return out;
}

function clean(fields: LogFields | undefined): Record<string, string | number | boolean | null> {
  const out: Record<string, string | number | boolean | null> = {};
  if (!fields) return out;
  for (const [key, value] of Object.entries(fields)) {
    if (value === undefined) continue;
    out[key] = typeof value === "string" ? redact(value).slice(0, 300) : value;
  }
  return out;
}

export function createJsonLogger(write: (line: string) => void = (line) => process.stdout.write(line)): Logger {
  const emit = (level: "info" | "warn" | "error", msg: string, fields?: LogFields) => {
    write(`${JSON.stringify({ ts: new Date().toISOString(), level, msg: redact(msg), ...clean(fields) })}\n`);
  };
  return {
    info: (msg, fields) => emit("info", msg, fields),
    warn: (msg, fields) => emit("warn", msg, fields),
    error: (msg, fields) => emit("error", msg, fields),
  };
}

export const silentLogger: Logger = { info() {}, warn() {}, error() {} };

/** Fields that describe an error without leaking its payload (driver errors can carry row values in `detail`). */
export function errorFields(error: unknown): LogFields {
  if (error instanceof Error) {
    const code = (error as { code?: unknown }).code;
    return { error_name: error.name, error_code: typeof code === "string" ? code : undefined, error_message: error.message.slice(0, 200) };
  }
  return { error_name: typeof error };
}
