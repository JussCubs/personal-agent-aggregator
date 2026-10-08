/** Fixed-window, in-process rate limiter for single-instance deployments. Use a shared store (e.g. Redis) when running several instances. */
export interface RateLimiter {
  consume(key: string, limit: number, windowMs: number): Promise<{ allowed: boolean; retryAfterSeconds: number }>;
}

export function createMemoryRateLimiter(now: () => number = Date.now): RateLimiter {
  const windows = new Map<string, { start: number; count: number }>();
  return {
    async consume(key, limit, windowMs) {
      const t = now();
      if (windows.size > 50_000) for (const [k, w] of windows) if (t - w.start >= windowMs) windows.delete(k);
      const current = windows.get(key);
      if (!current || t - current.start >= windowMs) {
        windows.set(key, { start: t, count: 1 });
        return { allowed: true, retryAfterSeconds: 0 };
      }
      current.count += 1;
      if (current.count <= limit) return { allowed: true, retryAfterSeconds: 0 };
      return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil((current.start + windowMs - t) / 1000)) };
    },
  };
}

/** Default per-credential budgets for agent-facing endpoints. */
export const DEFAULT_RATE_LIMITS = {
  readsPerMinute: 120,
  writesPerMinute: 60,
  questionsPerHour: 60,
  handoffsPerHour: 20,
  claimsPerMinutePerIp: 10,
  registrationsPerHourPerIp: 20,
} as const;

/** Maps a route or tool name to a budget bucket. */
export function rateBucket(route: string): "read" | "write" | "question" | "handoff" {
  if (/^(create_question|questions\.create)$/.test(route)) return "question";
  if (/^(handoff_goal|jobs\.create)$/.test(route)) return "handoff";
  if (/^(whoami|me|list_|get_|check_inbox|inbox\.|.*\.list|.*\.get)/.test(route)) return "read";
  return "write";
}
