import { invalid, AggregatorError } from "./errors.js";
import {
  LIMITS,
  WORK_ITEM_KINDS,
  type JsonObject,
  type JsonValue,
  type QuestionKind,
  type QuestionOption,
  type Urgency,
  type WorkItemKind,
} from "./contract.js";

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
// C0 controls except tab/newline/carriage return, DEL, C1 controls.
const CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;
// Bidirectional overrides and isolates can make displayed text differ from stored text.
const BIDI_CONTROLS = /[‪-‮⁦-⁩‎‏؜]/g;

export type Raw = Record<string, unknown>;

export function asObject(value: unknown, field = "body"): Raw {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw invalid(`${field} must be a JSON object`, field);
  }
  return value as Raw;
}

/** Normalizes untrusted text: NFC, strips control and bidi characters, trims, enforces a length. */
export function cleanText(value: unknown, field: string, max: number, opts: { required?: boolean; multiline?: boolean } = {}): string | null {
  if (value === undefined || value === null) {
    if (opts.required) throw invalid(`${field} is required`, field);
    return null;
  }
  if (typeof value !== "string") throw invalid(`${field} must be a string`, field);
  let text = value.normalize("NFC").replace(CONTROL_CHARS, "").replace(BIDI_CONTROLS, "");
  text = opts.multiline === false ? text.replace(/[\r\n\t]+/g, " ") : text.replace(/\r\n?/g, "\n");
  text = text.trim();
  if (!text) {
    if (opts.required) throw invalid(`${field} must not be empty`, field);
    return null;
  }
  if ([...text].length > max) throw invalid(`${field} must be at most ${max} characters`, field);
  return text;
}

export function requiredText(value: unknown, field: string, max: number, multiline = true): string {
  return cleanText(value, field, max, { required: true, multiline }) as string;
}

export function cleanId(value: unknown, field: string, opts: { required?: boolean } = {}): string | null {
  if (value === undefined || value === null || value === "") {
    if (opts.required) throw invalid(`${field} is required`, field);
    return null;
  }
  if (typeof value !== "string" || !ID_PATTERN.test(value)) {
    throw invalid(`${field} must be 1-128 characters of letters, digits, '.', '_', ':' or '-' and start with a letter or digit`, field);
  }
  return value;
}

export function requiredId(value: unknown, field: string): string {
  return cleanId(value, field, { required: true }) as string;
}

export function cleanTimestamp(value: unknown, field: string): string | null {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string" || value.length > 40) throw invalid(`${field} must be an ISO 8601 timestamp`, field);
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) throw invalid(`${field} must be an ISO 8601 timestamp`, field);
  return new Date(ms).toISOString();
}

export function cleanBoolean(value: unknown, field: string, fallback: boolean): boolean {
  if (value === undefined || value === null) return fallback;
  if (typeof value !== "boolean") throw invalid(`${field} must be a boolean`, field);
  return value;
}

export function cleanInteger(value: unknown, field: string, opts: { min: number; max: number; fallback?: number }): number {
  if (value === undefined || value === null || value === "") {
    if (opts.fallback !== undefined) return opts.fallback;
    throw invalid(`${field} is required`, field);
  }
  const n = typeof value === "string" && /^-?\d+$/.test(value) ? Number(value) : value;
  if (typeof n !== "number" || !Number.isInteger(n) || n < opts.min || n > opts.max) {
    throw invalid(`${field} must be an integer between ${opts.min} and ${opts.max}`, field);
  }
  return n;
}

function checkJson(value: unknown, field: string, depth: number): JsonValue {
  if (depth > LIMITS.dataDepth) throw invalid(`${field} is nested too deeply`, field);
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw invalid(`${field} contains a non-finite number`, field);
    return value;
  }
  if (typeof value === "string") return value.replace(CONTROL_CHARS, "").replace(BIDI_CONTROLS, "");
  if (Array.isArray(value)) return value.map((item) => checkJson(item, field, depth + 1));
  if (typeof value === "object") {
    const out: Record<string, JsonValue> = {};
    for (const [key, item] of Object.entries(value as Raw)) {
      if (key === "__proto__" || key === "constructor" || key === "prototype") continue;
      if (item === undefined) continue;
      out[key.slice(0, 200)] = checkJson(item, field, depth + 1);
    }
    return out;
  }
  throw invalid(`${field} must contain only JSON values`, field);
}

/** Structured, opaque agent data. Stored and shown as data only. */
export function cleanData(value: unknown, field = "data", maxBytes: number = LIMITS.dataBytes): JsonObject | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "object" || Array.isArray(value)) throw invalid(`${field} must be a JSON object`, field);
  const cleaned = checkJson(value, field, 0) as JsonObject;
  const bytes = Buffer.byteLength(JSON.stringify(cleaned), "utf8");
  if (bytes > maxBytes) throw new AggregatorError("payload_too_large", `${field} must serialize to at most ${maxBytes} bytes`, { field });
  return cleaned;
}

export function cleanKind(value: unknown): WorkItemKind {
  if (typeof value !== "string" || !WORK_ITEM_KINDS.includes(value as WorkItemKind)) {
    throw invalid(`kind must be one of ${WORK_ITEM_KINDS.join(", ")}`, "kind");
  }
  return value as WorkItemKind;
}

export function cleanQuestionKind(value: unknown): QuestionKind {
  if (value === undefined || value === null) return "question";
  if (value !== "question" && value !== "approval") throw invalid("kind must be question or approval", "kind");
  return value;
}

export function cleanUrgency(value: unknown): Urgency {
  if (value === undefined || value === null) return "normal";
  if (value !== "low" && value !== "normal" && value !== "high") throw invalid("urgency must be low, normal or high", "urgency");
  return value;
}

export function cleanOptions(value: unknown, kind: QuestionKind): QuestionOption[] {
  if (kind === "approval") {
    if (value !== undefined && value !== null && !(Array.isArray(value) && value.length === 0)) {
      throw invalid("approvals use fixed approve/deny choices; omit options", "options");
    }
    return [
      { id: "approve", label: "Approve" },
      { id: "deny", label: "Deny" },
    ];
  }
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) throw invalid("options must be an array", "options");
  if (value.length > LIMITS.maxOptions) throw invalid(`options may have at most ${LIMITS.maxOptions} entries`, "options");
  const seen = new Set<string>();
  return value.map((entry, index) => {
    const field = `options[${index}]`;
    const raw = typeof entry === "string" ? { id: `opt_${index + 1}`, label: entry } : asObject(entry, field);
    const label = requiredText(raw.label, `${field}.label`, LIMITS.optionLabelLength, false);
    const id = raw.id === undefined ? `opt_${index + 1}` : requiredId(raw.id, `${field}.id`);
    if (seen.has(id)) throw invalid(`option ids must be unique (${id})`, `${field}.id`);
    seen.add(id);
    return { id, label };
  });
}

/** Canonical JSON (sorted keys) for comparisons and deterministic ids. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entries = Object.entries(value as Raw)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
}

export function rejectUnknownKeys(raw: Raw, allowed: readonly string[], field = "body"): void {
  for (const key of Object.keys(raw)) {
    if (!allowed.includes(key)) throw invalid(`${field}.${key} is not a recognized field`, key);
  }
}
