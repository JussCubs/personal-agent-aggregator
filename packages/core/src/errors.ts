export type AggregatorErrorCode =
  | "invalid_request"
  | "unauthorized"
  | "insufficient_scope"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "stale_revision"
  | "limit_exceeded"
  | "payload_too_large"
  | "rate_limited"
  | "unavailable"
  | "internal";

const STATUS: Record<AggregatorErrorCode, number> = {
  invalid_request: 400,
  unauthorized: 401,
  insufficient_scope: 403,
  forbidden: 403,
  not_found: 404,
  conflict: 409,
  stale_revision: 409,
  limit_exceeded: 409,
  payload_too_large: 413,
  rate_limited: 429,
  unavailable: 503,
  internal: 500,
};

/**
 * Every failure the core raises. `message` is safe to return to the caller:
 * it never contains secrets, token material or other tenants' data.
 */
export class AggregatorError extends Error {
  readonly code: AggregatorErrorCode;
  readonly status: number;
  readonly details: Record<string, unknown> | undefined;

  constructor(code: AggregatorErrorCode, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = "AggregatorError";
    this.code = code;
    this.status = STATUS[code];
    this.details = details;
  }

  toJSON(): { error: { code: AggregatorErrorCode; message: string; details?: Record<string, unknown> } } {
    return { error: { code: this.code, message: this.message, ...(this.details ? { details: this.details } : {}) } };
  }
}

export function isAggregatorError(value: unknown): value is AggregatorError {
  return value instanceof AggregatorError;
}

export function invalid(message: string, field?: string): AggregatorError {
  return new AggregatorError("invalid_request", message, field ? { field } : undefined);
}

/** Converts anything thrown into a response-safe error. Unknown errors never leak their message. */
export function toAggregatorError(error: unknown): AggregatorError {
  if (isAggregatorError(error)) return error;
  return new AggregatorError("internal", "Internal error");
}
