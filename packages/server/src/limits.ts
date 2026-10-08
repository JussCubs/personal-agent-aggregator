import { AggregatorError, DEFAULT_RATE_LIMITS, createMemoryRateLimiter, rateBucket, type AgentPrincipal, type RateLimiter } from "@agent-aggregator/core";

/** Server-level budgets on top of the core DEFAULT_RATE_LIMITS. Per client IP, fixed one-minute windows. */
export const SERVER_RATE_LIMITS = {
  /** POST /oauth/token and /oauth/revoke. */
  tokenRequestsPerMinutePerIp: 60,
  /** GET /oauth/authorize (new authorization requests and consent pages). */
  authorizeRequestsPerMinutePerIp: 60,
  /** Requests presenting an unknown, revoked or expired credential. After this many in a window, the IP is refused (429) until the window ends. */
  failedAuthPerMinutePerIp: 30,
} as const;

const MINUTE = 60_000;
const HOUR = 3_600_000;

const AGENT_BUDGETS = {
  read: { limit: DEFAULT_RATE_LIMITS.readsPerMinute, windowMs: MINUTE },
  write: { limit: DEFAULT_RATE_LIMITS.writesPerMinute, windowMs: MINUTE },
  question: { limit: DEFAULT_RATE_LIMITS.questionsPerHour, windowMs: HOUR },
  handoff: { limit: DEFAULT_RATE_LIMITS.handoffsPerHour, windowMs: HOUR },
} as const;

function refuse(retryAfterSeconds: number, what: string): AggregatorError {
  return new AggregatorError("rate_limited", `${what}; retry after ${retryAfterSeconds} seconds`, { retry_after: retryAfterSeconds });
}

/**
 * In-memory limits for a single server process. Agent budgets are keyed by
 * connection, so refreshing or re-issuing a credential does not reset them.
 * Run one instance, or replace the limiter with a shared store.
 */
export class Limits {
  private readonly limiter: RateLimiter;
  private readonly blocked = new Map<string, number>();
  private readonly now: () => number;

  constructor(now: () => number = Date.now) {
    this.now = now;
    this.limiter = createMemoryRateLimiter(now);
  }

  /** Throws rate_limited when the connection exhausted the bucket for this REST route or MCP tool. */
  async agentCall(principal: AgentPrincipal, route: string): Promise<void> {
    const bucket = rateBucket(route);
    const budget = AGENT_BUDGETS[bucket];
    const result = await this.limiter.consume(`agent:${bucket}:${principal.connectionId}`, budget.limit, budget.windowMs);
    if (!result.allowed) throw refuse(result.retryAfterSeconds, `${bucket} rate limit reached for this connection`);
  }

  async perIp(kind: "claim" | "register" | "token" | "authorize", ip: string): Promise<void> {
    const budget =
      kind === "claim" ? { limit: DEFAULT_RATE_LIMITS.claimsPerMinutePerIp, windowMs: MINUTE }
      : kind === "register" ? { limit: DEFAULT_RATE_LIMITS.registrationsPerHourPerIp, windowMs: HOUR }
      : kind === "token" ? { limit: SERVER_RATE_LIMITS.tokenRequestsPerMinutePerIp, windowMs: MINUTE }
      : { limit: SERVER_RATE_LIMITS.authorizeRequestsPerMinutePerIp, windowMs: MINUTE };
    const result = await this.limiter.consume(`ip:${kind}:${ip}`, budget.limit, budget.windowMs);
    if (!result.allowed) throw refuse(result.retryAfterSeconds, `too many ${kind} requests from this address`);
  }

  /** Seconds the IP must wait after too many failed authentications, or 0. */
  blockedFor(ip: string): number {
    const until = this.blocked.get(ip);
    if (!until) return 0;
    const left = until - this.now();
    if (left <= 0) {
      this.blocked.delete(ip);
      return 0;
    }
    return Math.ceil(left / 1000);
  }

  async authFailed(ip: string): Promise<void> {
    // The Nth failure inside the window starts the block, so request N+1 is refused.
    const result = await this.limiter.consume(`ip:authfail:${ip}`, SERVER_RATE_LIMITS.failedAuthPerMinutePerIp - 1, MINUTE);
    if (!result.allowed) this.blocked.set(ip, this.now() + result.retryAfterSeconds * 1000);
  }

  prune(): void {
    const t = this.now();
    for (const [ip, until] of this.blocked) if (until <= t) this.blocked.delete(ip);
  }
}
