import { invalid } from "./errors.js";

/**
 * Inbox cursors are opaque to agents. Internally a cursor is the per-connection
 * event sequence number the agent has already seen. Sequence numbers are
 * allocated under a per-connection row lock, so a reader can never observe
 * event N+1 committed before event N.
 */
const PREFIX = "c1.";

export function encodeCursor(seq: number): string {
  if (!Number.isSafeInteger(seq) || seq < 0) throw new Error("cursor sequence must be a non-negative integer");
  return `${PREFIX}${Buffer.from(String(seq), "utf8").toString("base64url")}`;
}

export function decodeCursor(cursor: unknown): number {
  if (cursor === undefined || cursor === null || cursor === "" || cursor === "0") return 0;
  if (typeof cursor !== "string" || !cursor.startsWith(PREFIX) || cursor.length > 40) throw invalid("cursor is not valid; omit it to read from the beginning", "cursor");
  const decoded = Buffer.from(cursor.slice(PREFIX.length), "base64url").toString("utf8");
  if (!/^\d{1,15}$/.test(decoded)) throw invalid("cursor is not valid; omit it to read from the beginning", "cursor");
  return Number(decoded);
}
