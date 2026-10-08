import { createHash } from "node:crypto";
import {
  ALL_SCOPES,
  CONNECTION_MODES,
  CONTRACT_VERSION,
  EVENT_NAMES,
  LIMITS,
  SCOPES,
  TERMINAL_JOB_STATUSES,
  WORK_ITEM_KINDS,
  parseScopes,
  type Answer,
  type Checkpoint,
  type ConnectionInfo,
  type ConnectionMode,
  type ConnectionStatus,
  type EventName,
  type HubEvent,
  type InboxPage,
  type Job,
  type JobStatus,
  type JsonObject,
  type Question,
  type QuestionOption,
  type QuestionStatus,
  type Scope,
  type WorkItem,
  type WorkItemKind,
} from "./contract.js";
import { decodeCursor, encodeCursor } from "./cursor.js";
import { asBool, asIso, asJson, asNumber, assertPrefix, type AccessScope, type Db, type Row, type SqlDriver } from "./db.js";
import { AggregatorError, invalid } from "./errors.js";
import { isUuid, newId, newUuid } from "./ids.js";
import { generateClaimCode, generateToken, hashToken, normalizeClaimCode, tokenHint, type SecretBox } from "./secrets.js";
import { guardedRequest, validateOutboundUrl, type Resolver, type UrlGuardOptions } from "./url-guard.js";
import {
  asObject,
  canonicalJson,
  cleanBoolean,
  cleanData,
  cleanId,
  cleanInteger,
  cleanKind,
  cleanOptions,
  cleanQuestionKind,
  cleanText,
  cleanTimestamp,
  cleanUrgency,
  requiredId,
  requiredText,
  type Raw,
} from "./validate.js";
import { decodeWebhookSecret, generateWebhookSecret, webhookHeaders } from "./webhooks.js";
import { safeEqual } from "./secrets.js";
import { verifyPkceS256 } from "./oauth.js";

export interface AgentPrincipal {
  kind: "agent";
  ownerId: string;
  connectionId: string;
  credentialId: string;
  credentialKind: "agent" | "oauth_access";
  scopes: Scope[];
  provider: string;
  mode: ConnectionMode;
  /** OAuth audience the credential was issued for, if any. */
  resource: string | null;
}

export interface OwnerPrincipal {
  kind: "owner";
  ownerId: string;
  /** Display name recorded as the answer author. */
  name?: string | null;
  /** Client surface recorded with answers: "web", "desktop", "mobile", "cli", ... */
  surface?: string | null;
  /** The person actually acting, when a host lets one account act for another (delegated, test or support accounts). Audited. */
  actorId?: string | null;
}

export interface ConnectionSummary {
  id: string;
  provider: string;
  display_name: string;
  mode: ConnectionMode;
}

export interface Connection extends ConnectionSummary {
  status: ConnectionStatus;
  scopes: Scope[];
  settings: JsonObject;
  created_at: string;
  updated_at: string;
  last_seen_at: string | null;
  revoked_at: string | null;
}

export interface ConnectionOverview extends Connection {
  counts: { pending_questions: number; open_jobs: number; work_items: number };
  webhook: { url_host: string } | null;
  subscriptions: number;
  credentials: Array<{ id: string; kind: string; hint: string; created_at: string; last_used_at: string | null; expires_at: string | null }>;
}

/** Webhooks receive every event; the signing secret is returned once. */
export interface WebhookConfigResult {
  url: string;
  auth_header_name: string | null;
  signing_secret: string;
}

export interface ServiceHooks {
  questionCreated?(event: { ownerId: string; connection: ConnectionSummary; question: Question }): void | Promise<void>;
  questionChanged?(event: { ownerId: string; connection: ConnectionSummary; question: Question; previousStatus: QuestionStatus }): void | Promise<void>;
  jobCreated?(event: { ownerId: string; connection: ConnectionSummary; job: Job }): void | Promise<void>;
  jobChanged?(event: { ownerId: string; connection: ConnectionSummary; job: Job; previousStatus: JobStatus }): void | Promise<void>;
  connectionRevoked?(event: { ownerId: string; connection: ConnectionSummary }): void | Promise<void>;
  deliveriesQueued?(event: { ownerId: string; connectionId: string; count: number }): void | Promise<void>;
  hookError?(error: unknown, hook: string): void;
}

export interface OutboundOptions extends UrlGuardOptions {
  resolver?: Resolver;
  timeoutMs?: number;
}

export interface AggregatorServiceOptions {
  driver: SqlDriver;
  secretBox: SecretBox;
  prefix?: string;
  /** Credential prefixes. Defaults: agent "agg", OAuth access "aggo", OAuth refresh "aggr". */
  tokenPrefixes?: { agent?: string; access?: string; refresh?: string };
  hooks?: ServiceHooks;
  now?: () => Date;
  outbound?: OutboundOptions;
  claimTtlSeconds?: number;
  oauth?: { accessTokenTtlSeconds?: number; refreshTokenTtlSeconds?: number; codeTtlSeconds?: number; requestTtlSeconds?: number };
  eventRetentionDays?: number;
  /** Checkpoints and audit entries older than this are pruned by sweep(). Default 180. */
  historyRetentionDays?: number;
  /** Custom delivery transport (tests); defaults to the SSRF-guarded HTTP client. */
  send?: (input: { url: string; headers: Record<string, string>; body: string }) => Promise<{ status: number; body: string }>;
}

export interface TokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token: string;
  scope: string;
}

type After = Array<() => void | Promise<void>>;

/** Delay after each failed attempt; the attempt after the last delay is final (8 attempts in all). */
const RETRY_DELAYS_SECONDS = [15, 60, 300, 900, 3600, 3 * 3600, 6 * 3600];
const FORBIDDEN_HEADER_NAMES = new Set([
  "host", "content-length", "content-type", "transfer-encoding", "connection", "upgrade", "te", "trailer", "keep-alive",
  "proxy-authorization", "cookie", "user-agent", "webhook-id", "webhook-timestamp", "webhook-signature", "x-mcp-subscription-id",
]);

function scopeInput(value: unknown): string | string[] {
  if (typeof value === "string") return value;
  if (Array.isArray(value) && value.every((item) => typeof item === "string")) return value as string[];
  throw invalid("scopes must be a list of scope names", "scopes");
}

function optionalConnectionId(value: unknown): string | null {
  if (value === undefined || value === null || value === "") return null;
  if (!isUuid(value)) throw invalid("connection_id must be a connection id", "connection_id");
  return value;
}

function sha(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).host;
  } catch {
    return null;
  }
}

function addSeconds(date: Date, seconds: number): string {
  return new Date(date.getTime() + seconds * 1000).toISOString();
}

export class AggregatorService {
  readonly driver: SqlDriver;
  private readonly box: SecretBox;
  private readonly p: string;
  private readonly hooks: ServiceHooks;
  private readonly clock: () => Date;
  private readonly prefixes: { agent: string; access: string; refresh: string };
  private readonly outbound: OutboundOptions;
  private readonly claimTtl: number;
  private readonly oauthTtl: { access: number; refresh: number; code: number; request: number };
  private readonly retentionDays: number;
  private readonly historyDays: number;
  private readonly sendImpl: AggregatorServiceOptions["send"];

  constructor(opts: AggregatorServiceOptions) {
    this.driver = opts.driver;
    this.box = opts.secretBox;
    this.p = assertPrefix(opts.prefix ?? "aggregator_");
    this.hooks = opts.hooks ?? {};
    this.clock = opts.now ?? (() => new Date());
    this.prefixes = { agent: opts.tokenPrefixes?.agent ?? "agg", access: opts.tokenPrefixes?.access ?? "aggo", refresh: opts.tokenPrefixes?.refresh ?? "aggr" };
    this.outbound = opts.outbound ?? {};
    this.claimTtl = Math.max(60, Math.min(opts.claimTtlSeconds ?? 900, 86_400));
    this.oauthTtl = {
      access: opts.oauth?.accessTokenTtlSeconds ?? 3600,
      refresh: opts.oauth?.refreshTokenTtlSeconds ?? 60 * 86_400,
      code: opts.oauth?.codeTtlSeconds ?? 300,
      request: opts.oauth?.requestTtlSeconds ?? 900,
    };
    this.retentionDays = opts.eventRetentionDays ?? 30;
    this.historyDays = opts.historyRetentionDays ?? 180;
    this.sendImpl = opts.send;
  }

  get tokenPrefixes(): readonly string[] {
    return [this.prefixes.agent, this.prefixes.access];
  }

  private t(name: string): string {
    return `${this.p}${name}`;
  }

  private now(): Date {
    return this.clock();
  }

  private async runHooks(after: After): Promise<void> {
    for (const fn of after) {
      try {
        await fn();
      } catch (error) {
        this.hooks.hookError?.(error, "after-commit");
      }
    }
  }

  private async scoped<T>(scope: AccessScope, fn: (db: Db, after: After) => Promise<T>): Promise<T> {
    const after: After = [];
    const result = await this.driver.scoped(scope, (db) => fn(db, after));
    await this.runHooks(after);
    return result;
  }

  private async privileged<T>(fn: (db: Db, after: After) => Promise<T>): Promise<T> {
    const after: After = [];
    const result = await this.driver.privileged((db) => fn(db, after));
    await this.runHooks(after);
    return result;
  }

  private agentScope(p: AgentPrincipal): AccessScope {
    return { role: "agent", ownerId: p.ownerId, connectionId: p.connectionId };
  }

  private ownerScope(o: OwnerPrincipal): AccessScope {
    return { role: "owner", ownerId: o.ownerId };
  }

  private requireScope(p: AgentPrincipal, ...anyOf: Scope[]): void {
    if (!anyOf.some((scope) => p.scopes.includes(scope))) {
      throw new AggregatorError("insufficient_scope", `this credential needs the ${anyOf.join(" or ")} scope`, { required: anyOf });
    }
  }

  private ownerAudit(o: OwnerPrincipal, detail?: JsonObject): JsonObject | undefined {
    if (!o.actorId || o.actorId === o.ownerId) return detail;
    return { ...(detail ?? {}), actor_id: o.actorId };
  }

  private async audit(db: Db, entry: { ownerId: string; connectionId: string | null; actor: "agent" | "owner" | "system"; action: string; targetType?: string; targetId?: string; detail?: JsonObject }): Promise<void> {
    await db.query(
      `INSERT INTO ${this.t("audit")} (id, owner_id, connection_id, actor, action, target_type, target_id, detail, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9)`,
      [newUuid(), entry.ownerId, entry.connectionId, entry.actor, entry.action, entry.targetType ?? null, entry.targetId ?? null, entry.detail ? JSON.stringify(entry.detail) : null, this.now().toISOString()],
    );
  }

  // ---------------------------------------------------------------- mapping

  private toConnection(row: Row): Connection {
    return {
      id: String(row.id),
      provider: String(row.provider),
      display_name: String(row.display_name),
      mode: String(row.mode) as ConnectionMode,
      status: String(row.status) as ConnectionStatus,
      scopes: parseScopes(String(row.scopes ?? "")),
      settings: asJson<JsonObject>(row.settings) ?? {},
      created_at: asIso(row.created_at)!,
      updated_at: asIso(row.updated_at)!,
      last_seen_at: asIso(row.last_seen_at),
      revoked_at: asIso(row.revoked_at),
    };
  }

  private summary(c: { id: string; provider: string; display_name: string; mode: ConnectionMode }): ConnectionSummary {
    return { id: c.id, provider: c.provider, display_name: c.display_name, mode: c.mode };
  }

  private toWorkItem(row: Row): WorkItem {
    return {
      id: String(row.id),
      kind: String(row.kind) as WorkItemKind,
      title: String(row.title),
      status: (row.status as string | null) ?? null,
      summary: (row.summary as string | null) ?? null,
      blocker: (row.blocker as string | null) ?? null,
      next_step: (row.next_step as string | null) ?? null,
      due_at: asIso(row.due_at),
      parent_id: (row.parent_id as string | null) ?? null,
      data: asJson<JsonObject>(row.data),
      revision: asNumber(row.revision),
      created_at: asIso(row.created_at)!,
      updated_at: asIso(row.updated_at)!,
    };
  }

  private toCheckpoint(row: Row): Checkpoint {
    return {
      id: String(row.id),
      work_item_id: (row.work_item_id as string | null) ?? null,
      summary: String(row.summary),
      status: (row.status as string | null) ?? null,
      data: asJson<JsonObject>(row.data),
      created_at: asIso(row.created_at)!,
    };
  }

  private toQuestion(row: Row): Question {
    return {
      id: String(row.id),
      kind: String(row.kind) as Question["kind"],
      prompt: String(row.prompt),
      details: (row.details as string | null) ?? null,
      options: asJson<QuestionOption[]>(row.options) ?? [],
      allow_free_text: asBool(row.allow_free_text),
      work_item_id: (row.work_item_id as string | null) ?? null,
      affected_action: (row.affected_action as string | null) ?? null,
      action_digest: (row.action_digest as string | null) ?? null,
      urgency: String(row.urgency) as Question["urgency"],
      status: String(row.status) as QuestionStatus,
      status_reason: (row.status_reason as string | null) ?? null,
      revision: asNumber(row.revision),
      expires_at: asIso(row.expires_at),
      answer: asJson<Answer>(row.answer),
      created_at: asIso(row.created_at)!,
      updated_at: asIso(row.updated_at)!,
    };
  }

  private toJob(row: Row): Job {
    return {
      id: String(row.id),
      goal: String(row.goal),
      context: (row.context as string | null) ?? null,
      success_criteria: (row.success_criteria as string | null) ?? null,
      work_item_id: (row.work_item_id as string | null) ?? null,
      status: String(row.status) as JobStatus,
      status_reason: (row.status_reason as string | null) ?? null,
      summary: (row.summary as string | null) ?? null,
      result: asJson<JsonObject>(row.result),
      revision: asNumber(row.revision),
      created_at: asIso(row.created_at)!,
      updated_at: asIso(row.updated_at)!,
      completed_at: asIso(row.completed_at),
    };
  }

  private toEvent(row: Row): HubEvent {
    return {
      eventId: String(row.id),
      name: String(row.name) as EventName,
      timestamp: asIso(row.created_at)!,
      data: asJson<JsonObject>(row.data) ?? {},
      cursor: encodeCursor(asNumber(row.seq)),
    };
  }

  private async connectionRow(db: Db, ownerId: string, connectionId: string, lock = false): Promise<Connection> {
    if (!isUuid(connectionId)) throw new AggregatorError("not_found", "connection not found");
    const rows = await db.query(
      `SELECT id, provider, display_name, mode, status, scopes, settings, created_at, updated_at, last_seen_at, revoked_at
       FROM ${this.t("connections")} WHERE id = $1 AND owner_id = $2${lock ? " FOR UPDATE" : ""}`,
      [connectionId, ownerId],
    );
    if (!rows[0]) throw new AggregatorError("not_found", "connection not found");
    return this.toConnection(rows[0]);
  }

  // ------------------------------------------------------------- events

  /** Appends one event for a connection and fans it out to matching destinations. Call inside a scoped transaction. */
  private async appendEvent(db: Db, after: After, ownerId: string, connectionId: string, name: EventName, data: JsonObject): Promise<HubEvent> {
    const now = this.now().toISOString();
    const seqRows = await db.query(
      `UPDATE ${this.t("connections")} SET event_seq = event_seq + 1, updated_at = $3 WHERE id = $1 AND owner_id = $2 RETURNING event_seq`,
      [connectionId, ownerId, now],
    );
    if (!seqRows[0]) throw new AggregatorError("not_found", "connection not found");
    const seq = asNumber(seqRows[0].event_seq);
    const id = newId("evt");
    await db.query(
      `INSERT INTO ${this.t("events")} (owner_id, connection_id, seq, id, name, data, created_at) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)`,
      [ownerId, connectionId, seq, id, name, JSON.stringify(data), now],
    );
    const destinations = await db.query(
      `SELECT id, event_name, filter, expires_at FROM ${this.t("destinations")} WHERE connection_id = $1 AND owner_id = $2`,
      [connectionId, ownerId],
    );
    let queued = 0;
    for (const destination of destinations) {
      if (destination.event_name && destination.event_name !== name) continue;
      const expires = asIso(destination.expires_at);
      if (expires && expires <= now) continue;
      if (!this.filterMatches(asJson<JsonObject>(destination.filter), data)) continue;
      await db.query(
        `INSERT INTO ${this.t("deliveries")} (id, owner_id, connection_id, destination_id, event_seq, status, attempts, next_attempt_at, created_at)
         VALUES ($1, $2, $3, $4, $5, 'pending', 0, $6, $6) ON CONFLICT (destination_id, event_seq) DO NOTHING`,
        [newUuid(), ownerId, connectionId, String(destination.id), seq, now],
      );
      queued += 1;
    }
    if (queued > 0 && this.hooks.deliveriesQueued) {
      const hook = this.hooks.deliveriesQueued;
      after.push(() => hook({ ownerId, connectionId, count: queued }));
    }
    return { eventId: id, name, timestamp: now, data, cursor: encodeCursor(seq) };
  }

  private filterMatches(filter: JsonObject | null, data: JsonObject): boolean {
    if (!filter) return true;
    for (const [key, value] of Object.entries(filter)) {
      if (value === null || value === undefined) continue;
      if (data[key] !== value) return false;
    }
    return true;
  }

  // -------------------------------------------------------- agent: info

  async getConnectionInfo(p: AgentPrincipal): Promise<ConnectionInfo> {
    return await this.scoped(this.agentScope(p), async (db) => {
      const rows = await db.query(
        `SELECT id, provider, display_name, mode FROM ${this.t("connections")} WHERE id = $1 AND owner_id = $2 AND status = 'active'`,
        [p.connectionId, p.ownerId],
      );
      if (!rows[0]) throw new AggregatorError("unauthorized", "connection is not active");
      const hooks = await db.query(`SELECT url FROM ${this.t("destinations")} WHERE connection_id = $1 AND kind = 'webhook'`, [p.connectionId]);
      return {
        connection_id: String(rows[0].id),
        provider: String(rows[0].provider),
        display_name: String(rows[0].display_name),
        mode: String(rows[0].mode) as ConnectionMode,
        scopes: p.scopes,
        owner_name: null,
        contract_version: CONTRACT_VERSION,
        callback: { configured: hooks.length > 0, url_host: hooks[0] ? hostOf(String(hooks[0].url)) : null },
      };
    });
  }

  // -------------------------------------------------- agent: work items

  private parseWorkItem(raw: Raw, idFallback?: string): Omit<WorkItem, "revision" | "created_at" | "updated_at"> & { expected_revision: number | null } {
    const id = cleanId(raw.id ?? idFallback, "id") ?? newId("wi");
    return {
      id,
      kind: cleanKind(raw.kind),
      title: requiredText(raw.title, "title", LIMITS.titleLength, false),
      status: cleanText(raw.status, "status", LIMITS.statusLength, { multiline: false }),
      summary: cleanText(raw.summary, "summary", LIMITS.summaryLength),
      blocker: cleanText(raw.blocker, "blocker", LIMITS.summaryLength),
      next_step: cleanText(raw.next_step, "next_step", LIMITS.summaryLength),
      due_at: cleanTimestamp(raw.due_at ?? raw.due, "due_at"),
      parent_id: cleanId(raw.parent_id, "parent_id"),
      data: cleanData(raw.data),
      expected_revision: raw.expected_revision === undefined || raw.expected_revision === null ? null : cleanInteger(raw.expected_revision, "expected_revision", { min: 1, max: 1_000_000_000 }),
    };
  }

  private async putWorkItem(db: Db, p: AgentPrincipal, item: ReturnType<AggregatorService["parseWorkItem"]>): Promise<{ item: WorkItem; changed: boolean }> {
    const now = this.now().toISOString();
    const existing = await db.query(`SELECT * FROM ${this.t("work_items")} WHERE connection_id = $1 AND id = $2 FOR UPDATE`, [p.connectionId, item.id]);
    if (!existing[0]) {
      if (item.expected_revision !== null) throw new AggregatorError("stale_revision", "work item does not exist yet; omit expected_revision to create it");
      const count = await db.query(`SELECT count(*) AS n FROM ${this.t("work_items")} WHERE connection_id = $1`, [p.connectionId]);
      if (asNumber(count[0]?.n) >= LIMITS.workItemsPerConnection) throw new AggregatorError("limit_exceeded", `at most ${LIMITS.workItemsPerConnection} work items per connection`);
      const rows = await db.query(
        `INSERT INTO ${this.t("work_items")} (owner_id, connection_id, id, kind, title, status, summary, blocker, next_step, due_at, parent_id, data, revision, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, 1, $13, $13) RETURNING *`,
        [p.ownerId, p.connectionId, item.id, item.kind, item.title, item.status, item.summary, item.blocker, item.next_step, item.due_at, item.parent_id, item.data ? JSON.stringify(item.data) : null, now],
      );
      return { item: this.toWorkItem(rows[0]!), changed: true };
    }
    const current = this.toWorkItem(existing[0]);
    if (item.expected_revision !== null && item.expected_revision !== current.revision) {
      throw new AggregatorError("stale_revision", `work item is at revision ${current.revision}`, { revision: current.revision });
    }
    const same =
      current.kind === item.kind && current.title === item.title && current.status === item.status && current.summary === item.summary &&
      current.blocker === item.blocker && current.next_step === item.next_step && current.due_at === item.due_at &&
      current.parent_id === item.parent_id && canonicalJson(current.data) === canonicalJson(item.data);
    if (same) return { item: current, changed: false };
    const rows = await db.query(
      `UPDATE ${this.t("work_items")} SET kind = $3, title = $4, status = $5, summary = $6, blocker = $7, next_step = $8, due_at = $9, parent_id = $10,
         data = $11::jsonb, revision = revision + 1, updated_at = $12
       WHERE connection_id = $1 AND id = $2 RETURNING *`,
      [p.connectionId, item.id, item.kind, item.title, item.status, item.summary, item.blocker, item.next_step, item.due_at, item.parent_id, item.data ? JSON.stringify(item.data) : null, now],
    );
    return { item: this.toWorkItem(rows[0]!), changed: true };
  }

  async upsertWorkItem(p: AgentPrincipal, rawInput: unknown, idFromPath?: string): Promise<{ item: WorkItem; changed: boolean }> {
    this.requireScope(p, SCOPES.write);
    const raw = asObject(rawInput);
    if (idFromPath && raw.id !== undefined && raw.id !== idFromPath) throw invalid("id in the body does not match the path", "id");
    const item = this.parseWorkItem(raw, idFromPath);
    return await this.scoped(this.agentScope(p), async (db) => {
      const result = await this.putWorkItem(db, p, item);
      if (result.changed) {
        await this.audit(db, { ownerId: p.ownerId, connectionId: p.connectionId, actor: "agent", action: "work_item.upsert", targetType: "work_item", targetId: item.id, detail: { kind: item.kind, revision: result.item.revision } });
      }
      return result;
    });
  }

  async getWorkItem(p: AgentPrincipal, id: string): Promise<WorkItem> {
    this.requireScope(p, SCOPES.read, SCOPES.write);
    const key = requiredId(id, "id");
    return await this.scoped(this.agentScope(p), async (db) => {
      const rows = await db.query(`SELECT * FROM ${this.t("work_items")} WHERE connection_id = $1 AND id = $2`, [p.connectionId, key]);
      if (!rows[0]) throw new AggregatorError("not_found", "work item not found");
      return this.toWorkItem(rows[0]);
    });
  }

  async listWorkItems(p: AgentPrincipal, query: { kind?: unknown; after?: unknown; limit?: unknown } = {}): Promise<{ items: WorkItem[]; next_after: string | null }> {
    this.requireScope(p, SCOPES.read, SCOPES.write);
    const kind = query.kind === undefined || query.kind === null || query.kind === "" ? null : cleanKind(query.kind);
    const after = cleanId(query.after, "after");
    const limit = cleanInteger(query.limit, "limit", { min: 1, max: LIMITS.pageSize, fallback: 50 });
    return await this.scoped(this.agentScope(p), async (db) => {
      const rows = await db.query(
        `SELECT * FROM ${this.t("work_items")} WHERE connection_id = $1 AND ($2::text IS NULL OR kind = $2) AND ($3::text IS NULL OR id > $3) ORDER BY id LIMIT $4`,
        [p.connectionId, kind, after, limit + 1],
      );
      const items = rows.slice(0, limit).map((row) => this.toWorkItem(row));
      return { items, next_after: rows.length > limit ? items[items.length - 1]!.id : null };
    });
  }

  async deleteWorkItem(p: AgentPrincipal, id: string): Promise<{ deleted: boolean }> {
    this.requireScope(p, SCOPES.write);
    const key = requiredId(id, "id");
    return await this.scoped(this.agentScope(p), async (db) => {
      const rows = await db.query(`DELETE FROM ${this.t("work_items")} WHERE connection_id = $1 AND id = $2 RETURNING id`, [p.connectionId, key]);
      if (rows[0]) await this.audit(db, { ownerId: p.ownerId, connectionId: p.connectionId, actor: "agent", action: "work_item.delete", targetType: "work_item", targetId: key });
      return { deleted: rows.length > 0 };
    });
  }

  async postCheckpoint(p: AgentPrincipal, rawInput: unknown): Promise<{ checkpoint: Checkpoint; created: boolean }> {
    this.requireScope(p, SCOPES.write);
    const raw = asObject(rawInput);
    const id = cleanId(raw.id, "id") ?? newId("cp");
    const workItemId = cleanId(raw.work_item_id ?? raw.task_id, "work_item_id");
    const summary = requiredText(raw.summary, "summary", LIMITS.summaryLength);
    const status = cleanText(raw.status, "status", LIMITS.statusLength, { multiline: false });
    const data = cleanData(raw.data);
    return await this.scoped(this.agentScope(p), async (db) => {
      const existing = await db.query(`SELECT * FROM ${this.t("checkpoints")} WHERE connection_id = $1 AND id = $2`, [p.connectionId, id]);
      if (existing[0]) return { checkpoint: this.toCheckpoint(existing[0]), created: false };
      const count = await db.query(`SELECT count(*) AS n FROM ${this.t("checkpoints")} WHERE connection_id = $1`, [p.connectionId]);
      if (asNumber(count[0]?.n) >= LIMITS.checkpointsPerConnection) {
        throw new AggregatorError("limit_exceeded", `at most ${LIMITS.checkpointsPerConnection} checkpoints are kept per connection; older ones are pruned daily`);
      }
      const now = this.now().toISOString();
      const rows = await db.query(
        `INSERT INTO ${this.t("checkpoints")} (owner_id, connection_id, id, work_item_id, summary, status, data, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8) RETURNING *`,
        [p.ownerId, p.connectionId, id, workItemId, summary, status, data ? JSON.stringify(data) : null, now],
      );
      await this.audit(db, { ownerId: p.ownerId, connectionId: p.connectionId, actor: "agent", action: "checkpoint.create", targetType: "checkpoint", targetId: id, detail: { work_item_id: workItemId } });
      return { checkpoint: this.toCheckpoint(rows[0]!), created: true };
    });
  }

  async listCheckpoints(p: AgentPrincipal, query: { work_item_id?: unknown; limit?: unknown } = {}): Promise<Checkpoint[]> {
    this.requireScope(p, SCOPES.read, SCOPES.write);
    const workItemId = cleanId(query.work_item_id, "work_item_id");
    const limit = cleanInteger(query.limit, "limit", { min: 1, max: LIMITS.pageSize, fallback: 50 });
    return await this.scoped(this.agentScope(p), async (db) => {
      const rows = await db.query(
        `SELECT * FROM ${this.t("checkpoints")} WHERE connection_id = $1 AND ($2::text IS NULL OR work_item_id = $2) ORDER BY created_at DESC, id DESC LIMIT $3`,
        [p.connectionId, workItemId, limit],
      );
      return rows.map((row) => this.toCheckpoint(row));
    });
  }

  /**
   * A full snapshot from an agent that keeps its own state: tasks, goals and
   * projects become work items (upserted by id); identity, memory summary and
   * connected apps are stored on one "snapshot" state item. Questions in a
   * snapshot are never raised to the owner; use create_question for that.
   */
  async pushSnapshot(p: AgentPrincipal, rawInput: unknown): Promise<{ upserted: number; unchanged: number; state: WorkItem }> {
    this.requireScope(p, SCOPES.write);
    const raw = asObject(rawInput);
    const lists: Array<[WorkItemKind, unknown]> = [["task", raw.tasks], ["goal", raw.goals], ["project", raw.projects]];
    const items: Array<ReturnType<AggregatorService["parseWorkItem"]>> = [];
    for (const [kind, value] of lists) {
      if (value === undefined || value === null) continue;
      if (!Array.isArray(value)) throw invalid(`${kind}s must be an array`, `${kind}s`);
      if (value.length > LIMITS.snapshotItems) throw invalid(`${kind}s may have at most ${LIMITS.snapshotItems} entries`, `${kind}s`);
      value.forEach((entry, index) => {
        const obj = asObject(entry, `${kind}s[${index}]`);
        const parent = obj.parent_id ?? obj.project_id ?? obj.goal_id;
        items.push(this.parseWorkItem({ ...obj, kind, parent_id: parent, id: obj.id ?? `${kind}-${index + 1}` }));
      });
    }
    const connectedApps = raw.connected_apps === undefined || raw.connected_apps === null ? null : raw.connected_apps;
    if (connectedApps !== null && (!Array.isArray(connectedApps) || connectedApps.length > LIMITS.connectedApps)) {
      throw invalid(`connected_apps must be an array of at most ${LIMITS.connectedApps} entries`, "connected_apps");
    }
    const stateData = cleanData(
      {
        identity: raw.identity ?? null,
        memory_summary: cleanText(raw.memory_summary, "memory_summary", LIMITS.detailsLength),
        connected_apps: connectedApps,
        pending_questions: raw.pending_questions ?? null,
        item_count: items.length,
      },
      "snapshot",
      LIMITS.dataBytes * 2,
    );
    return await this.scoped(this.agentScope(p), async (db) => {
      let upserted = 0;
      let unchanged = 0;
      for (const item of items) {
        const result = await this.putWorkItem(db, p, item);
        if (result.changed) upserted += 1;
        else unchanged += 1;
      }
      const state = await this.putWorkItem(db, p, {
        id: "snapshot", kind: "state", title: "Latest snapshot", status: null, summary: null, blocker: null, next_step: null,
        due_at: null, parent_id: null, data: stateData, expected_revision: null,
      });
      await this.audit(db, { ownerId: p.ownerId, connectionId: p.connectionId, actor: "agent", action: "snapshot.push", targetType: "work_item", targetId: "snapshot", detail: { upserted, unchanged } });
      return { upserted, unchanged, state: state.item };
    });
  }

  // --------------------------------------------------- agent: questions

  async createQuestion(p: AgentPrincipal, rawInput: unknown): Promise<{ question: Question; created: boolean; revised: boolean }> {
    this.requireScope(p, SCOPES.ask);
    const raw = asObject(rawInput);
    const kind = cleanQuestionKind(raw.kind);
    const id = cleanId(raw.id ?? raw.question_id, "id") ?? newId("q");
    const prompt = requiredText(raw.prompt ?? raw.question, "prompt", LIMITS.promptLength);
    const details = cleanText(raw.details ?? raw.context, "details", LIMITS.detailsLength);
    const options = cleanOptions(raw.options, kind);
    const allowFreeText = cleanBoolean(raw.allow_free_text, "allow_free_text", kind === "question");
    if (kind === "question" && options.length === 0 && !allowFreeText) throw invalid("a question needs options or allow_free_text", "options");
    const workItemId = cleanId(raw.work_item_id ?? raw.task_id, "work_item_id");
    const affectedAction = cleanText(raw.affected_action, "affected_action", LIMITS.affectedActionLength);
    const actionDigest = raw.action_digest === undefined || raw.action_digest === null ? null : String(raw.action_digest);
    if (actionDigest !== null && !/^[A-Za-z0-9:_=+/.-]{1,128}$/.test(actionDigest)) throw invalid("action_digest must be 1-128 URL-safe characters", "action_digest");
    const urgency = cleanUrgency(raw.urgency);
    let expiresAt = cleanTimestamp(raw.expires_at, "expires_at");
    const relativeExpiry = !expiresAt && raw.expires_in_seconds !== undefined && raw.expires_in_seconds !== null;
    if (relativeExpiry) {
      expiresAt = addSeconds(this.now(), cleanInteger(raw.expires_in_seconds, "expires_in_seconds", { min: 60, max: 30 * 86_400 }));
    }
    if (expiresAt && (Date.parse(expiresAt) <= this.now().getTime() || Date.parse(expiresAt) > this.now().getTime() + 31 * 86_400_000)) {
      throw invalid("expires_at must be in the future and within 30 days", "expires_at");
    }
    const content = { kind, prompt, details, options, allow_free_text: allowFreeText, work_item_id: workItemId, affected_action: affectedAction, action_digest: actionDigest, urgency, expires_at: expiresAt };
    return await this.scoped(this.agentScope(p), async (db, after) => {
      const connection = await this.connectionRow(db, p.ownerId, p.connectionId);
      const existingRows = await db.query(`SELECT * FROM ${this.t("questions")} WHERE connection_id = $1 AND id = $2 FOR UPDATE`, [p.connectionId, id]);
      const now = this.now().toISOString();
      if (existingRows[0]) {
        const existing = this.toQuestion(existingRows[0]);
        // A relative expiry is fixed when the question is first asked; re-sending it must not move the deadline.
        if (relativeExpiry && existing.expires_at) content.expires_at = existing.expires_at;
        const existingContent = {
          kind: existing.kind, prompt: existing.prompt, details: existing.details, options: existing.options, allow_free_text: existing.allow_free_text,
          work_item_id: existing.work_item_id, affected_action: existing.affected_action, action_digest: existing.action_digest, urgency: existing.urgency, expires_at: existing.expires_at,
        };
        if (canonicalJson(existingContent) === canonicalJson(content)) return { question: existing, created: false, revised: false };
        if (existing.status !== "pending") {
          throw new AggregatorError("conflict", `question ${id} is already ${existing.status}; ask again with a new id`, { status: existing.status, revision: existing.revision });
        }
        const rows = await db.query(
          `UPDATE ${this.t("questions")} SET kind = $3, prompt = $4, details = $5, options = $6::jsonb, allow_free_text = $7, work_item_id = $8,
             affected_action = $9, action_digest = $10, urgency = $11, expires_at = $12, revision = revision + 1, updated_at = $13
           WHERE connection_id = $1 AND id = $2 RETURNING *`,
          [p.connectionId, id, kind, prompt, details, JSON.stringify(options), allowFreeText, workItemId, affectedAction, actionDigest, urgency, content.expires_at, now],
        );
        const question = this.toQuestion(rows[0]!);
        await this.audit(db, { ownerId: p.ownerId, connectionId: p.connectionId, actor: "agent", action: "question.revise", targetType: "question", targetId: id, detail: { revision: question.revision } });
        const hook = this.hooks.questionChanged;
        if (hook) after.push(() => hook({ ownerId: p.ownerId, connection: this.summary(connection), question, previousStatus: "pending" }));
        return { question, created: false, revised: true };
      }
      const open = await db.query(`SELECT count(*) AS n FROM ${this.t("questions")} WHERE connection_id = $1 AND status = 'pending'`, [p.connectionId]);
      if (asNumber(open[0]?.n) >= LIMITS.openQuestionsPerConnection) {
        throw new AggregatorError("limit_exceeded", `at most ${LIMITS.openQuestionsPerConnection} open questions per connection; cancel or wait for answers`);
      }
      const rows = await db.query(
        `INSERT INTO ${this.t("questions")} (key, owner_id, connection_id, id, kind, prompt, details, options, allow_free_text, work_item_id, affected_action, action_digest,
           urgency, status, revision, expires_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11, $12, $13, 'pending', 1, $14, $15, $15) RETURNING *`,
        [newUuid(), p.ownerId, p.connectionId, id, kind, prompt, details, JSON.stringify(options), allowFreeText, workItemId, affectedAction, actionDigest, urgency, expiresAt, now],
      );
      const question = this.toQuestion(rows[0]!);
      await this.audit(db, { ownerId: p.ownerId, connectionId: p.connectionId, actor: "agent", action: "question.create", targetType: "question", targetId: id, detail: { kind, options: options.length, urgency } });
      const hook = this.hooks.questionCreated;
      if (hook) after.push(() => hook({ ownerId: p.ownerId, connection: this.summary(connection), question }));
      return { question, created: true, revised: false };
    });
  }

  async getQuestion(p: AgentPrincipal, id: string): Promise<Question> {
    this.requireScope(p, SCOPES.read, SCOPES.ask);
    const key = requiredId(id, "id");
    return await this.scoped(this.agentScope(p), async (db) => {
      const rows = await db.query(`SELECT * FROM ${this.t("questions")} WHERE connection_id = $1 AND id = $2`, [p.connectionId, key]);
      if (!rows[0]) throw new AggregatorError("not_found", "question not found");
      return this.toQuestion(rows[0]);
    });
  }

  async listQuestions(p: AgentPrincipal, query: { status?: unknown; unacknowledged?: unknown; limit?: unknown } = {}): Promise<Question[]> {
    this.requireScope(p, SCOPES.read, SCOPES.ask);
    const status = query.status === undefined || query.status === null || query.status === "" ? null : String(query.status);
    if (status && !["pending", "answered", "cancelled", "expired"].includes(status)) throw invalid("status must be pending, answered, cancelled or expired", "status");
    const unacked = query.unacknowledged === true || query.unacknowledged === "true" || query.unacknowledged === "1";
    const limit = cleanInteger(query.limit, "limit", { min: 1, max: LIMITS.pageSize, fallback: 50 });
    return await this.scoped(this.agentScope(p), async (db) => {
      const rows = await db.query(
        `SELECT * FROM ${this.t("questions")} WHERE connection_id = $1 AND ($2::text IS NULL OR status = $2)
           AND ($3::boolean = false OR (status = 'answered' AND acknowledged_at IS NULL))
         ORDER BY created_at DESC, id LIMIT $4`,
        [p.connectionId, status, unacked, limit],
      );
      return rows.map((row) => this.toQuestion(row));
    });
  }

  async acknowledgeAnswer(p: AgentPrincipal, id: string, revisionInput?: unknown): Promise<Question> {
    // Acknowledging changes state, so a read-only credential cannot do it.
    this.requireScope(p, SCOPES.ask);
    const key = requiredId(id, "id");
    const revision = revisionInput === undefined || revisionInput === null ? null : cleanInteger(revisionInput, "revision", { min: 1, max: 1_000_000_000 });
    return await this.scoped(this.agentScope(p), async (db) => {
      const rows = await db.query(`SELECT * FROM ${this.t("questions")} WHERE connection_id = $1 AND id = $2 FOR UPDATE`, [p.connectionId, key]);
      if (!rows[0]) throw new AggregatorError("not_found", "question not found");
      const question = this.toQuestion(rows[0]);
      if (question.status !== "answered" || !question.answer) throw new AggregatorError("conflict", `question is ${question.status}, nothing to acknowledge`, { status: question.status });
      if (revision !== null && revision !== question.revision) throw new AggregatorError("stale_revision", `the answer is for revision ${question.revision}`, { revision: question.revision });
      if (question.answer.acknowledged_at) return question;
      const now = this.now().toISOString();
      const answer = { ...question.answer, acknowledged_at: now };
      const updated = await db.query(
        `UPDATE ${this.t("questions")} SET acknowledged_at = $3, answer = $4::jsonb, updated_at = $3 WHERE connection_id = $1 AND id = $2 RETURNING *`,
        [p.connectionId, key, now, JSON.stringify(answer)],
      );
      await this.audit(db, { ownerId: p.ownerId, connectionId: p.connectionId, actor: "agent", action: "answer.acknowledge", targetType: "question", targetId: key, detail: { revision: question.revision } });
      return this.toQuestion(updated[0]!);
    });
  }

  async cancelQuestion(p: AgentPrincipal, id: string): Promise<Question> {
    this.requireScope(p, SCOPES.ask);
    const key = requiredId(id, "id");
    return await this.scoped(this.agentScope(p), async (db, after) => {
      const connection = await this.connectionRow(db, p.ownerId, p.connectionId);
      const rows = await db.query(`SELECT * FROM ${this.t("questions")} WHERE connection_id = $1 AND id = $2 FOR UPDATE`, [p.connectionId, key]);
      if (!rows[0]) throw new AggregatorError("not_found", "question not found");
      const question = this.toQuestion(rows[0]);
      if (question.status !== "pending") return question;
      const now = this.now().toISOString();
      const updated = await db.query(
        `UPDATE ${this.t("questions")} SET status = 'cancelled', status_reason = 'cancelled_by_agent', updated_at = $3 WHERE connection_id = $1 AND id = $2 RETURNING *`,
        [p.connectionId, key, now],
      );
      const next = this.toQuestion(updated[0]!);
      await this.audit(db, { ownerId: p.ownerId, connectionId: p.connectionId, actor: "agent", action: "question.cancel", targetType: "question", targetId: key });
      const hook = this.hooks.questionChanged;
      if (hook) after.push(() => hook({ ownerId: p.ownerId, connection: this.summary(connection), question: next, previousStatus: "pending" }));
      return next;
    });
  }

  // ------------------------------------------------------- agent: inbox

  async readInbox(p: AgentPrincipal, query: { cursor?: unknown; limit?: unknown; names?: unknown } = {}): Promise<InboxPage> {
    this.requireScope(p, SCOPES.read);
    const after = decodeCursor(query.cursor);
    const limit = cleanInteger(query.limit, "limit", { min: 1, max: LIMITS.pageSize, fallback: 50 });
    const names = typeof query.names === "string" && query.names ? query.names.split(",").map((name) => name.trim()) : null;
    if (names && names.some((name) => !EVENT_NAMES.includes(name as EventName))) throw invalid(`names must be a comma-separated subset of ${EVENT_NAMES.join(", ")}`, "names");
    return await this.scoped(this.agentScope(p), async (db) => {
      const rows = await db.query(
        `SELECT seq, id, name, data, created_at FROM ${this.t("events")} WHERE connection_id = $1 AND seq > $2 ORDER BY seq LIMIT $3`,
        [p.connectionId, after, limit + 1],
      );
      const page = rows.slice(0, limit);
      const events = page.map((row) => this.toEvent(row)).filter((event) => !names || names.includes(event.name));
      const lastSeq = page.length ? asNumber(page[page.length - 1]!.seq) : after;
      return { events, cursor: encodeCursor(lastSeq), has_more: rows.length > limit };
    });
  }

  // -------------------------------------------------------- agent: jobs

  async handoffJob(p: AgentPrincipal, rawInput: unknown): Promise<{ job: Job; created: boolean }> {
    this.requireScope(p, SCOPES.handoff);
    const raw = asObject(rawInput);
    const idempotencyKey = cleanId(raw.idempotency_key ?? raw.id, "idempotency_key");
    const goal = requiredText(raw.goal, "goal", LIMITS.goalLength);
    const context = cleanText(raw.context, "context", LIMITS.contextLength);
    const successCriteria = cleanText(raw.success_criteria, "success_criteria", LIMITS.summaryLength);
    const workItemId = cleanId(raw.work_item_id ?? raw.task_id, "work_item_id");
    return await this.scoped(this.agentScope(p), async (db, after) => {
      const connection = await this.connectionRow(db, p.ownerId, p.connectionId);
      if (idempotencyKey) {
        const existing = await db.query(`SELECT * FROM ${this.t("jobs")} WHERE connection_id = $1 AND idempotency_key = $2`, [p.connectionId, idempotencyKey]);
        if (existing[0]) return { job: this.toJob(existing[0]), created: false };
      }
      const active = await db.query(
        `SELECT count(*) AS n FROM ${this.t("jobs")} WHERE connection_id = $1 AND status IN ('needs_user','running','blocked')`,
        [p.connectionId],
      );
      if (asNumber(active[0]?.n) >= LIMITS.activeJobsPerConnection) throw new AggregatorError("limit_exceeded", `at most ${LIMITS.activeJobsPerConnection} open jobs per connection`);
      const now = this.now().toISOString();
      const id = newId("job");
      const rows = await db.query(
        `INSERT INTO ${this.t("jobs")} (key, owner_id, connection_id, id, idempotency_key, goal, context, success_criteria, work_item_id, status, status_reason, revision, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'needs_user', 'awaiting_owner_approval', 1, $10, $10) RETURNING *`,
        [newUuid(), p.ownerId, p.connectionId, id, idempotencyKey, goal, context, successCriteria, workItemId, now],
      );
      const job = this.toJob(rows[0]!);
      await this.appendEvent(db, after, p.ownerId, p.connectionId, "job.updated", this.jobEventData(job));
      await this.audit(db, { ownerId: p.ownerId, connectionId: p.connectionId, actor: "agent", action: "job.create", targetType: "job", targetId: id });
      const hook = this.hooks.jobCreated;
      if (hook) after.push(() => hook({ ownerId: p.ownerId, connection: this.summary(connection), job }));
      return { job, created: true };
    });
  }

  private jobEventData(job: Job): JsonObject {
    return {
      job_id: job.id,
      status: job.status,
      status_reason: job.status_reason,
      summary: job.summary,
      result: job.result,
      revision: job.revision,
      work_item_id: job.work_item_id,
      updated_at: job.updated_at,
    };
  }

  async getJob(p: AgentPrincipal, id: string): Promise<Job> {
    this.requireScope(p, SCOPES.read, SCOPES.handoff);
    const key = requiredId(id, "id");
    return await this.scoped(this.agentScope(p), async (db) => {
      const rows = await db.query(`SELECT * FROM ${this.t("jobs")} WHERE connection_id = $1 AND id = $2`, [p.connectionId, key]);
      if (!rows[0]) throw new AggregatorError("not_found", "job not found");
      return this.toJob(rows[0]);
    });
  }

  async listJobs(p: AgentPrincipal, query: { status?: unknown; limit?: unknown } = {}): Promise<Job[]> {
    this.requireScope(p, SCOPES.read, SCOPES.handoff);
    const status = query.status ? String(query.status) : null;
    const limit = cleanInteger(query.limit, "limit", { min: 1, max: LIMITS.pageSize, fallback: 50 });
    return await this.scoped(this.agentScope(p), async (db) => {
      const rows = await db.query(
        `SELECT * FROM ${this.t("jobs")} WHERE connection_id = $1 AND ($2::text IS NULL OR status = $2) ORDER BY created_at DESC, id LIMIT $3`,
        [p.connectionId, status, limit],
      );
      return rows.map((row) => this.toJob(row));
    });
  }

  async cancelJob(p: AgentPrincipal, id: string): Promise<Job> {
    this.requireScope(p, SCOPES.handoff);
    const key = requiredId(id, "id");
    return await this.scoped(this.agentScope(p), async (db, after) => {
      const connection = await this.connectionRow(db, p.ownerId, p.connectionId);
      const rows = await db.query(`SELECT * FROM ${this.t("jobs")} WHERE connection_id = $1 AND id = $2 FOR UPDATE`, [p.connectionId, key]);
      if (!rows[0]) throw new AggregatorError("not_found", "job not found");
      const job = this.toJob(rows[0]);
      if (TERMINAL_JOB_STATUSES.includes(job.status)) return job;
      const now = this.now().toISOString();
      const updated = await db.query(
        `UPDATE ${this.t("jobs")} SET status = 'cancelled', status_reason = 'cancelled_by_agent', revision = revision + 1, updated_at = $3, completed_at = $3
         WHERE connection_id = $1 AND id = $2 RETURNING *`,
        [p.connectionId, key, now],
      );
      const next = this.toJob(updated[0]!);
      await this.audit(db, { ownerId: p.ownerId, connectionId: p.connectionId, actor: "agent", action: "job.cancel", targetType: "job", targetId: key });
      const hook = this.hooks.jobChanged;
      if (hook) after.push(() => hook({ ownerId: p.ownerId, connection: this.summary(connection), job: next, previousStatus: job.status }));
      return next;
    });
  }

  // ------------------------------------------- webhooks & event subscriptions

  private parseWebhookConfig(raw: Raw): { url: string; headerName: string | null; headerValue: string | null } {
    const url = validateOutboundUrl(raw.url, this.outbound).toString();
    const value = raw.auth_header_value === undefined || raw.auth_header_value === null || raw.auth_header_value === "" ? null : raw.auth_header_value;
    let headerName = raw.auth_header_name === undefined || raw.auth_header_name === null || raw.auth_header_name === "" ? null : raw.auth_header_name;
    if (value !== null) {
      if (typeof value !== "string" || value.length > 2048 || /[\r\n\0]/.test(value)) throw invalid("auth_header_value must be a single-line string of at most 2048 characters", "auth_header_value");
      headerName = headerName ?? "Authorization";
    }
    if (headerName !== null) {
      if (typeof headerName !== "string" || !/^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$/.test(headerName) || FORBIDDEN_HEADER_NAMES.has(headerName.toLowerCase())) {
        throw invalid("auth_header_name must be a valid, non-reserved HTTP header name", "auth_header_name");
      }
      if (value === null) throw invalid("auth_header_value is required with auth_header_name", "auth_header_value");
    }
    return { url, headerName: headerName as string | null, headerValue: value as string | null };
  }

  private async writeWebhook(db: Db, ownerId: string, connectionId: string, config: ReturnType<AggregatorService["parseWebhookConfig"]>): Promise<WebhookConfigResult> {
    const secret = generateWebhookSecret();
    const now = this.now().toISOString();
    await db.query(`DELETE FROM ${this.t("destinations")} WHERE connection_id = $1 AND owner_id = $2 AND kind = 'webhook'`, [connectionId, ownerId]);
    await db.query(
      `INSERT INTO ${this.t("destinations")} (id, owner_id, connection_id, kind, external_id, event_name, filter, url, auth_header_name, auth_header_value_enc, signing_secret_enc, expires_at, created_at, updated_at)
       VALUES ($1, $2, $3, 'webhook', 'webhook', NULL, NULL, $4, $5, $6, $7, NULL, $8, $8)`,
      [newUuid(), ownerId, connectionId, config.url, config.headerName, config.headerValue ? this.box.encrypt(config.headerValue) : null, this.box.encrypt(secret), now],
    );
    return { url: config.url, auth_header_name: config.headerName, signing_secret: secret };
  }

  /** Registers (or replaces) the connection's webhook. The signing secret is returned once. */
  async setWebhook(p: AgentPrincipal, rawInput: unknown): Promise<WebhookConfigResult> {
    this.requireScope(p, SCOPES.read);
    const config = this.parseWebhookConfig(asObject(rawInput));
    return await this.scoped(this.agentScope(p), async (db) => {
      const result = await this.writeWebhook(db, p.ownerId, p.connectionId, config);
      await this.audit(db, { ownerId: p.ownerId, connectionId: p.connectionId, actor: "agent", action: "webhook.set", targetType: "destination", targetId: "webhook", detail: { host: hostOf(config.url) } });
      return result;
    });
  }

  async clearWebhook(p: AgentPrincipal): Promise<{ removed: boolean }> {
    this.requireScope(p, SCOPES.read);
    return await this.scoped(this.agentScope(p), async (db) => {
      const rows = await db.query(`DELETE FROM ${this.t("destinations")} WHERE connection_id = $1 AND kind = 'webhook' RETURNING id`, [p.connectionId]);
      if (rows[0]) await this.audit(db, { ownerId: p.ownerId, connectionId: p.connectionId, actor: "agent", action: "webhook.clear", targetType: "destination", targetId: "webhook" });
      return { removed: rows.length > 0 };
    });
  }

  private subscriptionId(connectionId: string, url: string, name: string, args: JsonObject): string {
    return `sub_${sha(`${connectionId}\n${url}\n${name}\n${canonicalJson(args)}`).slice(0, 32)}`;
  }

  private parseSubscriptionArgs(name: EventName, value: unknown): JsonObject {
    if (value === undefined || value === null) return {};
    const raw = asObject(value, "arguments");
    const allowed = name === "job.updated" ? ["job_id"] : ["question_id"];
    const out: JsonObject = {};
    for (const [key, item] of Object.entries(raw)) {
      if (!allowed.includes(key)) throw invalid(`arguments.${key} is not supported for ${name}`, `arguments.${key}`);
      if (item === null || item === undefined) continue;
      out[key] = requiredId(item, `arguments.${key}`);
    }
    return out;
  }

  private async send(url: string, headers: Record<string, string>, body: string): Promise<{ status: number; body: string }> {
    if (this.sendImpl) return await this.sendImpl({ url, headers, body });
    const response = await guardedRequest({ ...this.outbound, url, method: "POST", headers, body, timeoutMs: this.outbound.timeoutMs ?? 10_000, maxResponseBytes: 16_384 });
    return { status: response.status, body: response.body };
  }

  /**
   * MCP Events `events/subscribe`: validates the callback, proves it answers a
   * signed verification challenge, then stores the subscription. Subscription
   * ids are deterministic per (connection, url, event, arguments), so
   * re-subscribing refreshes rather than duplicates.
   */
  async subscribeEvent(p: AgentPrincipal, params: unknown): Promise<{ id: string; refreshBefore: string | null; cursor: string; truncated: boolean }> {
    this.requireScope(p, SCOPES.read);
    const raw = asObject(params, "params");
    const name = raw.name;
    if (typeof name !== "string" || !EVENT_NAMES.includes(name as EventName)) throw invalid(`name must be one of ${EVENT_NAMES.join(", ")}`, "name");
    const eventName = name as EventName;
    const args = this.parseSubscriptionArgs(eventName, raw.arguments);
    const delivery = asObject(raw.delivery, "delivery");
    if (delivery.mode !== "webhook") throw invalid("delivery.mode must be webhook", "delivery.mode");
    const url = validateOutboundUrl(delivery.url, this.outbound).toString();
    const secret = delivery.secret;
    if (typeof secret !== "string") throw invalid("delivery.secret is required", "delivery.secret");
    try {
      decodeWebhookSecret(secret, { minBytes: 24, maxBytes: 64 });
    } catch (error) {
      throw invalid(error instanceof Error ? error.message : "delivery.secret is invalid", "delivery.secret");
    }
    let ttlMs = 7 * 86_400_000;
    if (raw.ttlMs === null) ttlMs = 30 * 86_400_000;
    else if (raw.ttlMs !== undefined) ttlMs = Math.max(3_600_000, Math.min(cleanInteger(raw.ttlMs, "ttlMs", { min: 1, max: 365 * 86_400_000 }), 30 * 86_400_000));
    const subscriptionId = this.subscriptionId(p.connectionId, url, eventName, args);

    // Prove the callback is live and holds the secret before storing anything.
    const challenge = generateToken("chal", 24);
    const verificationBody = JSON.stringify({ type: "verification", challenge });
    const verificationHeaders = {
      "content-type": "application/json",
      ...webhookHeaders(secret, newId("msg_verification"), verificationBody, this.now()),
      "x-mcp-subscription-id": subscriptionId,
    };
    let verified = false;
    let reason = "challenge_failed";
    try {
      const response = await this.send(url, verificationHeaders, verificationBody);
      if (response.status >= 200 && response.status < 300) {
        const echoed = (asJson<Raw>(response.body) ?? {}).challenge;
        verified = typeof echoed === "string" && safeEqual(echoed, challenge);
      } else {
        reason = "http_error";
      }
    } catch (error) {
      reason = error instanceof AggregatorError && error.code === "unavailable" ? (error.details?.reason === "dns" ? "unreachable" : "timeout") : "unreachable";
    }
    if (!verified) throw new AggregatorError("invalid_request", "callback endpoint did not complete verification", { callback_error: true, reason });

    const cursorSeq = raw.cursor === undefined || raw.cursor === null ? null : decodeCursor(raw.cursor);
    return await this.scoped(this.agentScope(p), async (db, after) => {
      const now = this.now();
      const expiresAt = new Date(now.getTime() + ttlMs).toISOString();
      const existing = await db.query(`SELECT id FROM ${this.t("destinations")} WHERE connection_id = $1 AND external_id = $2`, [p.connectionId, subscriptionId]);
      const destinationId = existing[0] ? String(existing[0].id) : newUuid();
      if (existing[0]) {
        await db.query(
          `UPDATE ${this.t("destinations")} SET url = $3, signing_secret_enc = $4, expires_at = $5, updated_at = $6, filter = $7::jsonb WHERE connection_id = $1 AND external_id = $2`,
          [p.connectionId, subscriptionId, url, this.box.encrypt(secret), expiresAt, now.toISOString(), JSON.stringify(args)],
        );
      } else {
        await db.query(
          `INSERT INTO ${this.t("destinations")} (id, owner_id, connection_id, kind, external_id, event_name, filter, url, auth_header_name, auth_header_value_enc, signing_secret_enc, expires_at, created_at, updated_at)
           VALUES ($1, $2, $3, 'mcp_event', $4, $5, $6::jsonb, $7, NULL, NULL, $8, $9, $10, $10)`,
          [destinationId, p.ownerId, p.connectionId, subscriptionId, eventName, JSON.stringify(args), url, this.box.encrypt(secret), expiresAt, now.toISOString()],
        );
      }
      const head = await db.query(`SELECT event_seq FROM ${this.t("connections")} WHERE id = $1 AND owner_id = $2`, [p.connectionId, p.ownerId]);
      const currentSeq = asNumber(head[0]?.event_seq);
      let truncated = false;
      if (cursorSeq !== null && cursorSeq < currentSeq) {
        const oldest = await db.query(`SELECT min(seq) AS s FROM ${this.t("events")} WHERE connection_id = $1`, [p.connectionId]);
        const oldestSeq = asNumber(oldest[0]?.s);
        truncated = oldestSeq > cursorSeq + 1;
        const missed = await db.query(
          `SELECT seq, name, data FROM ${this.t("events")} WHERE connection_id = $1 AND seq > $2 AND name = $3 ORDER BY seq LIMIT 500`,
          [p.connectionId, cursorSeq, eventName],
        );
        let queued = 0;
        for (const event of missed) {
          if (!this.filterMatches(args, asJson<JsonObject>(event.data) ?? {})) continue;
          await db.query(
            `INSERT INTO ${this.t("deliveries")} (id, owner_id, connection_id, destination_id, event_seq, status, attempts, next_attempt_at, created_at)
             VALUES ($1, $2, $3, $4, $5, 'pending', 0, $6, $6) ON CONFLICT (destination_id, event_seq) DO NOTHING`,
            [newUuid(), p.ownerId, p.connectionId, destinationId, asNumber(event.seq), now.toISOString()],
          );
          queued += 1;
        }
        if (queued && this.hooks.deliveriesQueued) {
          const hook = this.hooks.deliveriesQueued;
          after.push(() => hook({ ownerId: p.ownerId, connectionId: p.connectionId, count: queued }));
        }
      }
      await this.audit(db, { ownerId: p.ownerId, connectionId: p.connectionId, actor: "agent", action: "subscription.upsert", targetType: "destination", targetId: subscriptionId, detail: { name: eventName, host: hostOf(url) } });
      return { id: subscriptionId, refreshBefore: expiresAt, cursor: encodeCursor(currentSeq), truncated };
    });
  }

  async unsubscribeEvent(p: AgentPrincipal, params: unknown): Promise<Record<string, never>> {
    this.requireScope(p, SCOPES.read);
    const raw = asObject(params, "params");
    const name = raw.name;
    if (typeof name !== "string" || !EVENT_NAMES.includes(name as EventName)) throw invalid(`name must be one of ${EVENT_NAMES.join(", ")}`, "name");
    const args = this.parseSubscriptionArgs(name as EventName, raw.arguments);
    const delivery = asObject(raw.delivery, "delivery");
    const url = validateOutboundUrl(delivery.url, this.outbound).toString();
    const subscriptionId = this.subscriptionId(p.connectionId, url, name, args);
    await this.scoped(this.agentScope(p), async (db) => {
      const rows = await db.query(`DELETE FROM ${this.t("destinations")} WHERE connection_id = $1 AND external_id = $2 RETURNING id`, [p.connectionId, subscriptionId]);
      if (rows[0]) await this.audit(db, { ownerId: p.ownerId, connectionId: p.connectionId, actor: "agent", action: "subscription.delete", targetType: "destination", targetId: subscriptionId });
    });
    return {};
  }

  // ------------------------------------------------------- owner: setup

  async createConnection(o: OwnerPrincipal, rawInput: unknown): Promise<Connection> {
    const raw = asObject(rawInput);
    const provider = typeof raw.provider === "string" && /^[a-z][a-z0-9_]{1,39}$/.test(raw.provider) ? raw.provider : null;
    if (!provider) throw invalid("provider must be 2-40 lowercase letters, digits or underscores", "provider");
    const displayName = requiredText(raw.display_name, "display_name", 80, false);
    const mode = raw.mode;
    if (typeof mode !== "string" || !CONNECTION_MODES.includes(mode as ConnectionMode)) throw invalid(`mode must be one of ${CONNECTION_MODES.join(", ")}`, "mode");
    const scopes = raw.scopes === undefined ? [...ALL_SCOPES] : parseScopes(scopeInput(raw.scopes));
    if (scopes.length === 0) throw invalid("grant at least one scope", "scopes");
    const settings = cleanData(raw.settings, "settings") ?? {};
    const now = this.now().toISOString();
    return await this.scoped(this.ownerScope(o), async (db) => {
      const count = await db.query(`SELECT count(*) AS n FROM ${this.t("connections")} WHERE owner_id = $1 AND status <> 'revoked'`, [o.ownerId]);
      if (asNumber(count[0]?.n) >= LIMITS.connectionsPerOwner) throw new AggregatorError("limit_exceeded", `at most ${LIMITS.connectionsPerOwner} connections per owner`);
      const id = newUuid();
      const rows = await db.query(
        `INSERT INTO ${this.t("connections")} (id, owner_id, provider, display_name, mode, status, scopes, event_seq, settings, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, 'pending', $6, 0, $7::jsonb, $8, $8)
         RETURNING id, provider, display_name, mode, status, scopes, settings, created_at, updated_at, last_seen_at, revoked_at`,
        [id, o.ownerId, provider, displayName, mode, scopes.join(" "), JSON.stringify(settings), now],
      );
      await this.audit(db, { ownerId: o.ownerId, connectionId: id, actor: "owner", action: "connection.create", targetType: "connection", targetId: id, detail: this.ownerAudit(o, { provider, mode }) });
      return this.toConnection(rows[0]!);
    });
  }

  /** Mints a long-lived agent credential, shown once. Revokes earlier agent credentials for the connection. */
  async issueAgentCredential(o: OwnerPrincipal, connectionId: string): Promise<{ token: string; hint: string; connection: Connection }> {
    return await this.scoped(this.ownerScope(o), async (db) => {
      const connection = await this.connectionRow(db, o.ownerId, connectionId, true);
      if (connection.status === "revoked") throw new AggregatorError("conflict", "connection is revoked; create a new one");
      return await this.mintAgentCredential(db, o.ownerId, connection, "owner");
    });
  }

  private async mintAgentCredential(db: Db, ownerId: string, connection: Connection, actor: "owner" | "system"): Promise<{ token: string; hint: string; connection: Connection }> {
    const now = this.now().toISOString();
    await db.query(
      `UPDATE ${this.t("credentials")} SET revoked_at = $3 WHERE connection_id = $1 AND owner_id = $2 AND kind = 'agent' AND revoked_at IS NULL`,
      [connection.id, ownerId, now],
    );
    const token = generateToken(this.prefixes.agent);
    await db.query(
      `INSERT INTO ${this.t("credentials")} (id, owner_id, connection_id, kind, secret_hash, hint, scopes, created_at) VALUES ($1, $2, $3, 'agent', $4, $5, $6, $7)`,
      [newUuid(), ownerId, connection.id, hashToken(token), tokenHint(token), connection.scopes.join(" "), now],
    );
    const rows = await db.query(
      `UPDATE ${this.t("connections")} SET status = 'active', updated_at = $3 WHERE id = $1 AND owner_id = $2
       RETURNING id, provider, display_name, mode, status, scopes, settings, created_at, updated_at, last_seen_at, revoked_at`,
      [connection.id, ownerId, now],
    );
    await this.audit(db, { ownerId, connectionId: connection.id, actor, action: "credential.issue", targetType: "connection", targetId: connection.id, detail: { kind: "agent", hint: tokenHint(token) } });
    return { token, hint: tokenHint(token), connection: this.toConnection(rows[0]!) };
  }

  /**
   * A one-time setup code. The agent exchanges it (POST /v1/claim) for its
   * credential and stores that in its own secret store; the credential never
   * passes through a chat.
   */
  async issueClaimCode(o: OwnerPrincipal, connectionId: string, ttlSeconds?: number): Promise<{ code: string; expires_at: string }> {
    const ttl = Math.max(60, Math.min(ttlSeconds ?? this.claimTtl, 86_400));
    return await this.scoped(this.ownerScope(o), async (db) => {
      const connection = await this.connectionRow(db, o.ownerId, connectionId, true);
      if (connection.status === "revoked") throw new AggregatorError("conflict", "connection is revoked; create a new one");
      const now = this.now();
      await db.query(
        `UPDATE ${this.t("credentials")} SET revoked_at = $3 WHERE connection_id = $1 AND owner_id = $2 AND kind = 'claim' AND revoked_at IS NULL AND used_at IS NULL`,
        [connectionId, o.ownerId, now.toISOString()],
      );
      const code = generateClaimCode();
      const expiresAt = addSeconds(now, ttl);
      await db.query(
        `INSERT INTO ${this.t("credentials")} (id, owner_id, connection_id, kind, secret_hash, hint, scopes, expires_at, created_at) VALUES ($1, $2, $3, 'claim', $4, $5, $6, $7, $8)`,
        [newUuid(), o.ownerId, connectionId, hashToken(code), `${code.slice(0, 5)}…`, connection.scopes.join(" "), expiresAt, now.toISOString()],
      );
      await this.audit(db, { ownerId: o.ownerId, connectionId, actor: "owner", action: "claim_code.issue", targetType: "connection", targetId: connectionId, detail: this.ownerAudit(o, { expires_at: expiresAt }) });
      return { code, expires_at: expiresAt };
    });
  }

  async listConnections(o: OwnerPrincipal): Promise<ConnectionOverview[]> {
    return await this.scoped(this.ownerScope(o), async (db) => {
      const rows = await db.query(
        `SELECT id, provider, display_name, mode, status, scopes, settings, created_at, updated_at, last_seen_at, revoked_at
         FROM ${this.t("connections")} WHERE owner_id = $1 ORDER BY created_at DESC LIMIT 100`,
        [o.ownerId],
      );
      const out: ConnectionOverview[] = [];
      for (const row of rows) out.push(await this.overview(db, o.ownerId, this.toConnection(row)));
      return out;
    });
  }

  async getConnection(o: OwnerPrincipal, connectionId: string): Promise<ConnectionOverview> {
    return await this.scoped(this.ownerScope(o), async (db) => this.overview(db, o.ownerId, await this.connectionRow(db, o.ownerId, connectionId)));
  }

  private async overview(db: Db, ownerId: string, connection: Connection): Promise<ConnectionOverview> {
    const [questions, jobs, items, destinations, credentials] = await Promise.all([
      db.query(`SELECT count(*) AS n FROM ${this.t("questions")} WHERE connection_id = $1 AND owner_id = $2 AND status = 'pending'`, [connection.id, ownerId]),
      db.query(`SELECT count(*) AS n FROM ${this.t("jobs")} WHERE connection_id = $1 AND owner_id = $2 AND status IN ('needs_user','running','blocked')`, [connection.id, ownerId]),
      db.query(`SELECT count(*) AS n FROM ${this.t("work_items")} WHERE connection_id = $1 AND owner_id = $2`, [connection.id, ownerId]),
      db.query(`SELECT kind, url, filter FROM ${this.t("destinations")} WHERE connection_id = $1 AND owner_id = $2`, [connection.id, ownerId]),
      db.query(
        `SELECT id, kind, hint, created_at, last_used_at, expires_at FROM ${this.t("credentials")}
         WHERE connection_id = $1 AND owner_id = $2 AND revoked_at IS NULL AND kind IN ('agent','oauth_refresh') ORDER BY created_at DESC LIMIT 10`,
        [connection.id, ownerId],
      ),
    ]);
    const webhook = destinations.find((d) => d.kind === "webhook");
    return {
      ...connection,
      counts: { pending_questions: asNumber(questions[0]?.n), open_jobs: asNumber(jobs[0]?.n), work_items: asNumber(items[0]?.n) },
      webhook: webhook ? { url_host: hostOf(String(webhook.url)) ?? "" } : null,
      subscriptions: destinations.filter((d) => d.kind === "mcp_event").length,
      credentials: credentials.map((c) => ({
        id: String(c.id), kind: String(c.kind), hint: String(c.hint), created_at: asIso(c.created_at)!, last_used_at: asIso(c.last_used_at), expires_at: asIso(c.expires_at),
      })),
    };
  }

  async updateConnection(o: OwnerPrincipal, connectionId: string, rawInput: unknown): Promise<Connection> {
    const raw = asObject(rawInput);
    const displayName = raw.display_name === undefined ? undefined : requiredText(raw.display_name, "display_name", 80, false);
    const scopes = raw.scopes === undefined ? undefined : parseScopes(scopeInput(raw.scopes));
    if (scopes && scopes.length === 0) throw invalid("grant at least one scope", "scopes");
    const settings = raw.settings === undefined ? undefined : cleanData(raw.settings, "settings") ?? {};
    return await this.scoped(this.ownerScope(o), async (db) => {
      const current = await this.connectionRow(db, o.ownerId, connectionId, true);
      if (current.status === "revoked") throw new AggregatorError("conflict", "connection is revoked");
      const now = this.now().toISOString();
      const rows = await db.query(
        `UPDATE ${this.t("connections")} SET display_name = $3, scopes = $4, settings = $5::jsonb, updated_at = $6 WHERE id = $1 AND owner_id = $2
         RETURNING id, provider, display_name, mode, status, scopes, settings, created_at, updated_at, last_seen_at, revoked_at`,
        [connectionId, o.ownerId, displayName ?? current.display_name, (scopes ?? current.scopes).join(" "), JSON.stringify(settings ?? current.settings), now],
      );
      await this.audit(db, { ownerId: o.ownerId, connectionId, actor: "owner", action: "connection.update", targetType: "connection", targetId: connectionId, detail: this.ownerAudit(o, { fields: Object.keys(raw) }) });
      return this.toConnection(rows[0]!);
    });
  }

  /** Disconnect: every credential dies immediately, webhooks and subscriptions stop, open questions and jobs close. Data stays until deleted. */
  async revokeConnection(o: OwnerPrincipal, connectionId: string): Promise<Connection> {
    return await this.scoped(this.ownerScope(o), async (db, after) => this.revokeInTx(db, after, o.ownerId, connectionId, o));
  }

  private async revokeInTx(db: Db, after: After, ownerId: string, connectionId: string, o?: OwnerPrincipal): Promise<Connection> {
    const connection = await this.connectionRow(db, ownerId, connectionId, true);
    const now = this.now().toISOString();
    await db.query(`UPDATE ${this.t("credentials")} SET revoked_at = $3 WHERE connection_id = $1 AND owner_id = $2 AND revoked_at IS NULL`, [connectionId, ownerId, now]);
    await db.query(`DELETE FROM ${this.t("destinations")} WHERE connection_id = $1 AND owner_id = $2`, [connectionId, ownerId]);
    const closedQuestions = await db.query(
      `UPDATE ${this.t("questions")} SET status = 'cancelled', status_reason = 'connection_revoked', updated_at = $3 WHERE connection_id = $1 AND owner_id = $2 AND status = 'pending' RETURNING *`,
      [connectionId, ownerId, now],
    );
    const closedJobs = await db.query(
      `UPDATE ${this.t("jobs")} SET status = 'cancelled', status_reason = 'connection_revoked', revision = revision + 1, updated_at = $3, completed_at = $3
       WHERE connection_id = $1 AND owner_id = $2 AND status IN ('needs_user','running','blocked') RETURNING *`,
      [connectionId, ownerId, now],
    );
    const rows = await db.query(
      `UPDATE ${this.t("connections")} SET status = 'revoked', revoked_at = coalesce(revoked_at, $3), updated_at = $3 WHERE id = $1 AND owner_id = $2
       RETURNING id, provider, display_name, mode, status, scopes, settings, created_at, updated_at, last_seen_at, revoked_at`,
      [connectionId, ownerId, now],
    );
    const revokeDetail = { questions_closed: closedQuestions.length, jobs_closed: closedJobs.length };
    await this.audit(db, { ownerId, connectionId, actor: "owner", action: "connection.revoke", targetType: "connection", targetId: connectionId, detail: o ? this.ownerAudit(o, revokeDetail) : revokeDetail });
    const summary = this.summary(connection);
    const qHook = this.hooks.questionChanged;
    if (qHook) for (const row of closedQuestions) { const q = this.toQuestion(row); after.push(() => qHook({ ownerId, connection: summary, question: q, previousStatus: "pending" })); }
    const jHook = this.hooks.jobChanged;
    if (jHook) for (const row of closedJobs) { const j = this.toJob(row); after.push(() => jHook({ ownerId, connection: summary, job: j, previousStatus: "running" })); }
    const rHook = this.hooks.connectionRevoked;
    if (rHook && connection.status !== "revoked") after.push(() => rHook({ ownerId, connection: summary }));
    return this.toConnection(rows[0]!);
  }

  /** Disconnects, then deletes every row the connection produced. One audit entry records the deletion. */
  async deleteConnection(o: OwnerPrincipal, connectionId: string): Promise<{ deleted: Record<string, number> }> {
    return await this.scoped(this.ownerScope(o), async (db, after) => {
      await this.revokeInTx(db, after, o.ownerId, connectionId, o);
      const counts: Record<string, number> = {};
      for (const table of ["work_items", "checkpoints", "questions", "jobs", "events", "deliveries", "credentials"]) {
        const rows = await db.query(`SELECT count(*) AS n FROM ${this.t(table)} WHERE connection_id = $1 AND owner_id = $2`, [connectionId, o.ownerId]);
        counts[table] = asNumber(rows[0]?.n);
      }
      await db.query(`DELETE FROM ${this.t("audit")} WHERE connection_id = $1 AND owner_id = $2`, [connectionId, o.ownerId]);
      await db.query(`DELETE FROM ${this.t("connections")} WHERE id = $1 AND owner_id = $2`, [connectionId, o.ownerId]);
      await this.audit(db, { ownerId: o.ownerId, connectionId, actor: "owner", action: "connection.delete", targetType: "connection", targetId: connectionId, detail: this.ownerAudit(o, counts) });
      return { deleted: counts };
    });
  }

  // ---------------------------------------------------- owner: questions

  async listOwnerQuestions(o: OwnerPrincipal, query: { status?: unknown; connection_id?: unknown; limit?: unknown } = {}): Promise<Array<{ connection: ConnectionSummary; question: Question }>> {
    const status = query.status === undefined || query.status === null || query.status === "" ? "pending" : String(query.status);
    if (!["pending", "answered", "cancelled", "expired", "all"].includes(status)) throw invalid("status must be pending, answered, cancelled, expired or all", "status");
    const connectionId = optionalConnectionId(query.connection_id);
    const limit = cleanInteger(query.limit, "limit", { min: 1, max: LIMITS.pageSize, fallback: 50 });
    return await this.scoped(this.ownerScope(o), async (db) => {
      const rows = await db.query(
        `SELECT q.*, c.provider AS c_provider, c.display_name AS c_display_name, c.mode AS c_mode
         FROM ${this.t("questions")} q JOIN ${this.t("connections")} c ON c.id = q.connection_id AND c.owner_id = q.owner_id
         WHERE q.owner_id = $1 AND ($2::text = 'all' OR q.status = $2) AND ($3::uuid IS NULL OR q.connection_id = $3::uuid)
         ORDER BY CASE q.urgency WHEN 'high' THEN 0 WHEN 'normal' THEN 1 ELSE 2 END, q.created_at DESC LIMIT $4`,
        [o.ownerId, status, connectionId, limit],
      );
      return rows.map((row) => ({
        connection: { id: String(row.connection_id), provider: String(row.c_provider), display_name: String(row.c_display_name), mode: String(row.c_mode) as ConnectionMode },
        question: this.toQuestion(row),
      }));
    });
  }

  async getOwnerQuestion(o: OwnerPrincipal, connectionId: string, questionId: string): Promise<{ connection: ConnectionSummary; question: Question }> {
    const id = requiredId(questionId, "question_id");
    return await this.scoped(this.ownerScope(o), async (db) => {
      const connection = await this.connectionRow(db, o.ownerId, connectionId);
      const rows = await db.query(`SELECT * FROM ${this.t("questions")} WHERE connection_id = $1 AND owner_id = $2 AND id = $3`, [connectionId, o.ownerId, id]);
      if (!rows[0]) throw new AggregatorError("not_found", "question not found");
      return { connection: this.summary(connection), question: this.toQuestion(rows[0]) };
    });
  }

  /**
   * Records the owner's answer. `revision` must equal the question's current
   * revision, so an answer can never apply to wording the owner did not see.
   */
  async answerQuestion(o: OwnerPrincipal, rawInput: unknown): Promise<Question> {
    const raw = asObject(rawInput);
    const connectionId = typeof raw.connection_id === "string" ? raw.connection_id : "";
    const questionId = requiredId(raw.question_id, "question_id");
    const revision = cleanInteger(raw.revision, "revision", { min: 1, max: 1_000_000_000 });
    return await this.scoped(this.ownerScope(o), async (db, after) => {
      const connection = await this.connectionRow(db, o.ownerId, connectionId);
      const rows = await db.query(`SELECT * FROM ${this.t("questions")} WHERE connection_id = $1 AND owner_id = $2 AND id = $3 FOR UPDATE`, [connectionId, o.ownerId, questionId]);
      if (!rows[0]) throw new AggregatorError("not_found", "question not found");
      const question = this.toQuestion(rows[0]);
      const now = this.now();
      if (question.status === "pending" && question.expires_at && Date.parse(question.expires_at) <= now.getTime()) {
        throw new AggregatorError("conflict", "this question expired", { status: "expired" });
      }
      if (question.status !== "pending") throw new AggregatorError("conflict", `this question is already ${question.status}`, { status: question.status, question: question as unknown as JsonObject });
      if (revision !== question.revision) throw new AggregatorError("stale_revision", "the agent changed this question; review it again", { revision: question.revision, question: question as unknown as JsonObject });
      let choice = raw.choice === undefined || raw.choice === null || raw.choice === "" ? null : String(raw.choice);
      const text = cleanText(raw.text, "text", LIMITS.answerTextLength);
      let decision: "approved" | "denied" | null = null;
      if (question.kind === "approval") {
        if (raw.decision === "approved" || raw.decision === "denied") choice = raw.decision === "approved" ? "approve" : "deny";
        if (choice !== "approve" && choice !== "deny") throw invalid("approvals need choice approve or deny", "choice");
        decision = choice === "approve" ? "approved" : "denied";
        if (text && !question.allow_free_text) throw invalid("this approval does not take a note", "text");
      } else {
        if (choice !== null && !question.options.some((option) => option.id === choice)) throw invalid("choice must be one of the question's option ids", "choice");
        if (text && !question.allow_free_text) throw invalid("this question only accepts one of its options", "text");
        if (choice === null && !text) throw invalid("answer with a choice or text", "choice");
      }
      const answer: Answer = {
        choice,
        choice_label: question.options.find((option) => option.id === choice)?.label ?? null,
        text,
        decision,
        question_revision: question.revision,
        action_digest: question.action_digest,
        author: { kind: "owner", name: o.name ?? null, verified: true, surface: o.surface ?? null },
        answered_at: now.toISOString(),
        acknowledged_at: null,
      };
      const updated = await db.query(
        `UPDATE ${this.t("questions")} SET status = 'answered', status_reason = NULL, answer = $4::jsonb, answered_at = $5, updated_at = $5
         WHERE connection_id = $1 AND owner_id = $2 AND id = $3 AND status = 'pending' RETURNING *`,
        [connectionId, o.ownerId, questionId, JSON.stringify(answer), answer.answered_at],
      );
      if (!updated[0]) throw new AggregatorError("conflict", "this question was answered elsewhere");
      const next = this.toQuestion(updated[0]);
      if (connection.status === "active") {
        await this.appendEvent(db, after, o.ownerId, connectionId, "answer.created", {
          question_id: next.id,
          kind: next.kind,
          revision: next.revision,
          status: next.status,
          work_item_id: next.work_item_id,
          answer: answer as unknown as JsonObject,
        });
      }
      await this.audit(db, { ownerId: o.ownerId, connectionId, actor: "owner", action: "question.answer", targetType: "question", targetId: questionId, detail: this.ownerAudit(o, { surface: o.surface ?? null, decision }) });
      const hook = this.hooks.questionChanged;
      if (hook) after.push(() => hook({ ownerId: o.ownerId, connection: this.summary(connection), question: next, previousStatus: "pending" }));
      return next;
    });
  }

  async dismissQuestion(o: OwnerPrincipal, connectionId: string, questionId: string): Promise<Question> {
    const id = requiredId(questionId, "question_id");
    return await this.scoped(this.ownerScope(o), async (db, after) => {
      const connection = await this.connectionRow(db, o.ownerId, connectionId);
      const rows = await db.query(`SELECT * FROM ${this.t("questions")} WHERE connection_id = $1 AND owner_id = $2 AND id = $3 FOR UPDATE`, [connectionId, o.ownerId, id]);
      if (!rows[0]) throw new AggregatorError("not_found", "question not found");
      const question = this.toQuestion(rows[0]);
      if (question.status !== "pending") return question;
      const now = this.now().toISOString();
      const updated = await db.query(
        `UPDATE ${this.t("questions")} SET status = 'cancelled', status_reason = 'dismissed_by_owner', updated_at = $4 WHERE connection_id = $1 AND owner_id = $2 AND id = $3 RETURNING *`,
        [connectionId, o.ownerId, id, now],
      );
      const next = this.toQuestion(updated[0]!);
      if (connection.status === "active") {
        await this.appendEvent(db, after, o.ownerId, connectionId, "question.updated", { question_id: next.id, status: next.status, reason: "dismissed_by_owner", revision: next.revision });
      }
      await this.audit(db, { ownerId: o.ownerId, connectionId, actor: "owner", action: "question.dismiss", targetType: "question", targetId: id, detail: this.ownerAudit(o) });
      const hook = this.hooks.questionChanged;
      if (hook) after.push(() => hook({ ownerId: o.ownerId, connection: this.summary(connection), question: next, previousStatus: "pending" }));
      return next;
    });
  }

  // --------------------------------------------------------- owner: jobs

  async listOwnerJobs(o: OwnerPrincipal, query: { status?: unknown; connection_id?: unknown; limit?: unknown } = {}): Promise<Array<{ connection: ConnectionSummary; job: Job }>> {
    const status = query.status ? String(query.status) : "open";
    const connectionId = optionalConnectionId(query.connection_id);
    const limit = cleanInteger(query.limit, "limit", { min: 1, max: LIMITS.pageSize, fallback: 50 });
    return await this.scoped(this.ownerScope(o), async (db) => {
      const rows = await db.query(
        `SELECT j.*, c.provider AS c_provider, c.display_name AS c_display_name, c.mode AS c_mode
         FROM ${this.t("jobs")} j JOIN ${this.t("connections")} c ON c.id = j.connection_id AND c.owner_id = j.owner_id
         WHERE j.owner_id = $1 AND ($2::text = 'all' OR ($2::text = 'open' AND j.status IN ('needs_user','running','blocked')) OR j.status = $2)
           AND ($3::uuid IS NULL OR j.connection_id = $3::uuid)
         ORDER BY j.created_at DESC LIMIT $4`,
        [o.ownerId, status, connectionId, limit],
      );
      return rows.map((row) => ({
        connection: { id: String(row.connection_id), provider: String(row.c_provider), display_name: String(row.c_display_name), mode: String(row.c_mode) as ConnectionMode },
        job: this.toJob(row),
      }));
    });
  }

  async getOwnerJob(o: OwnerPrincipal, connectionId: string, jobId: string): Promise<{ connection: ConnectionSummary; job: Job }> {
    const id = requiredId(jobId, "job_id");
    return await this.scoped(this.ownerScope(o), async (db) => {
      const connection = await this.connectionRow(db, o.ownerId, connectionId);
      const rows = await db.query(`SELECT * FROM ${this.t("jobs")} WHERE connection_id = $1 AND owner_id = $2 AND id = $3`, [connectionId, o.ownerId, id]);
      if (!rows[0]) throw new AggregatorError("not_found", "job not found");
      return { connection: this.summary(connection), job: this.toJob(rows[0]) };
    });
  }

  /** The owner approves (job becomes running and the host dispatches it) or declines a handed-off goal. */
  async decideJob(o: OwnerPrincipal, rawInput: unknown): Promise<Job> {
    const raw = asObject(rawInput);
    const connectionId = typeof raw.connection_id === "string" ? raw.connection_id : "";
    const jobId = requiredId(raw.job_id, "job_id");
    const approve = cleanBoolean(raw.approve, "approve", false);
    const note = cleanText(raw.note, "note", LIMITS.summaryLength);
    return await this.updateJobAsOwner(o, connectionId, jobId, (job) => {
      if (job.status !== "needs_user" || job.status_reason !== "awaiting_owner_approval") throw new AggregatorError("conflict", `job is ${job.status}`, { status: job.status });
      return approve
        ? { status: "running", status_reason: "approved_by_owner", summary: note ?? job.summary, result: job.result }
        : { status: "declined", status_reason: "declined_by_owner", summary: note, result: null };
    }, approve ? "job.approve" : "job.decline");
  }

  /** Progress from the host's own agent working on an approved job. */
  async reportJobProgress(o: OwnerPrincipal, rawInput: unknown): Promise<Job> {
    const raw = asObject(rawInput);
    const connectionId = typeof raw.connection_id === "string" ? raw.connection_id : "";
    const jobId = requiredId(raw.job_id, "job_id");
    const status = raw.status;
    if (status !== "running" && status !== "blocked" && status !== "needs_user" && status !== "done" && status !== "failed") {
      throw invalid("status must be running, blocked, needs_user, done or failed", "status");
    }
    const summary = cleanText(raw.summary, "summary", LIMITS.summaryLength);
    const reason = cleanText(raw.reason, "reason", 80, { multiline: false });
    const result = cleanData(raw.result, "result");
    return await this.updateJobAsOwner(o, connectionId, jobId, (job) => {
      if (TERMINAL_JOB_STATUSES.includes(job.status)) throw new AggregatorError("conflict", `job is already ${job.status}`, { status: job.status });
      if (job.status === "needs_user" && job.status_reason === "awaiting_owner_approval") throw new AggregatorError("conflict", "job has not been approved");
      return { status, status_reason: reason, summary: summary ?? job.summary, result: result ?? job.result };
    }, "job.progress");
  }

  private async updateJobAsOwner(
    o: OwnerPrincipal,
    connectionId: string,
    jobId: string,
    decide: (job: Job) => { status: JobStatus; status_reason: string | null; summary: string | null; result: JsonObject | null },
    action: string,
  ): Promise<Job> {
    return await this.scoped(this.ownerScope(o), async (db, after) => {
      const connection = await this.connectionRow(db, o.ownerId, connectionId);
      const rows = await db.query(`SELECT * FROM ${this.t("jobs")} WHERE connection_id = $1 AND owner_id = $2 AND id = $3 FOR UPDATE`, [connectionId, o.ownerId, jobId]);
      if (!rows[0]) throw new AggregatorError("not_found", "job not found");
      const job = this.toJob(rows[0]);
      const next = decide(job);
      const now = this.now().toISOString();
      const terminal = TERMINAL_JOB_STATUSES.includes(next.status);
      const updated = await db.query(
        `UPDATE ${this.t("jobs")} SET status = $4, status_reason = $5, summary = $6, result = $7::jsonb, revision = revision + 1, updated_at = $8, completed_at = $9
         WHERE connection_id = $1 AND owner_id = $2 AND id = $3 RETURNING *`,
        [connectionId, o.ownerId, jobId, next.status, next.status_reason, next.summary, next.result ? JSON.stringify(next.result) : null, now, terminal ? now : null],
      );
      const saved = this.toJob(updated[0]!);
      if (connection.status === "active") await this.appendEvent(db, after, o.ownerId, connectionId, "job.updated", this.jobEventData(saved));
      await this.audit(db, { ownerId: o.ownerId, connectionId, actor: "owner", action, targetType: "job", targetId: jobId, detail: this.ownerAudit(o, { status: saved.status }) });
      const hook = this.hooks.jobChanged;
      if (hook) after.push(() => hook({ ownerId: o.ownerId, connection: this.summary(connection), job: saved, previousStatus: job.status }));
      return saved;
    });
  }

  // ------------------------------------------------- owner: shared state

  async listOwnerWorkItems(o: OwnerPrincipal, query: { connection_id?: unknown; kind?: unknown; limit?: unknown } = {}): Promise<Array<{ connection: ConnectionSummary; item: WorkItem }>> {
    const kind = query.kind ? cleanKind(query.kind) : null;
    const connectionId = optionalConnectionId(query.connection_id);
    const limit = cleanInteger(query.limit, "limit", { min: 1, max: LIMITS.pageSize, fallback: 50 });
    return await this.scoped(this.ownerScope(o), async (db) => {
      const rows = await db.query(
        `SELECT w.*, c.provider AS c_provider, c.display_name AS c_display_name, c.mode AS c_mode
         FROM ${this.t("work_items")} w JOIN ${this.t("connections")} c ON c.id = w.connection_id AND c.owner_id = w.owner_id
         WHERE w.owner_id = $1 AND ($2::text IS NULL OR w.kind = $2) AND ($3::uuid IS NULL OR w.connection_id = $3::uuid)
         ORDER BY w.updated_at DESC LIMIT $4`,
        [o.ownerId, kind, connectionId, limit],
      );
      return rows.map((row) => ({
        connection: { id: String(row.connection_id), provider: String(row.c_provider), display_name: String(row.c_display_name), mode: String(row.c_mode) as ConnectionMode },
        item: this.toWorkItem(row),
      }));
    });
  }

  async listOwnerCheckpoints(o: OwnerPrincipal, query: { connection_id?: unknown; work_item_id?: unknown; limit?: unknown } = {}): Promise<Array<{ connection_id: string; checkpoint: Checkpoint }>> {
    const connectionId = optionalConnectionId(query.connection_id);
    const workItemId = cleanId(query.work_item_id, "work_item_id");
    const limit = cleanInteger(query.limit, "limit", { min: 1, max: LIMITS.pageSize, fallback: 50 });
    return await this.scoped(this.ownerScope(o), async (db) => {
      const rows = await db.query(
        `SELECT * FROM ${this.t("checkpoints")} WHERE owner_id = $1 AND ($2::uuid IS NULL OR connection_id = $2::uuid) AND ($3::text IS NULL OR work_item_id = $3)
         ORDER BY created_at DESC LIMIT $4`,
        [o.ownerId, connectionId, workItemId, limit],
      );
      return rows.map((row) => ({ connection_id: String(row.connection_id), checkpoint: this.toCheckpoint(row) }));
    });
  }

  async listAudit(o: OwnerPrincipal, query: { connection_id?: unknown; limit?: unknown } = {}): Promise<Array<{ id: string; connection_id: string | null; actor: string; action: string; target_type: string | null; target_id: string | null; detail: JsonObject | null; created_at: string }>> {
    const connectionId = optionalConnectionId(query.connection_id);
    const limit = cleanInteger(query.limit, "limit", { min: 1, max: 200, fallback: 50 });
    return await this.scoped(this.ownerScope(o), async (db) => {
      const rows = await db.query(
        `SELECT * FROM ${this.t("audit")} WHERE owner_id = $1 AND ($2::uuid IS NULL OR connection_id = $2::uuid) ORDER BY created_at DESC LIMIT $3`,
        [o.ownerId, connectionId, limit],
      );
      return rows.map((row) => ({
        id: String(row.id), connection_id: (row.connection_id as string | null) ?? null, actor: String(row.actor), action: String(row.action),
        target_type: (row.target_type as string | null) ?? null, target_id: (row.target_id as string | null) ?? null, detail: asJson<JsonObject>(row.detail), created_at: asIso(row.created_at)!,
      }));
    });
  }

  async ownerSetWebhook(o: OwnerPrincipal, connectionId: string, rawInput: unknown): Promise<WebhookConfigResult> {
    const config = this.parseWebhookConfig(asObject(rawInput));
    return await this.scoped(this.ownerScope(o), async (db) => {
      const connection = await this.connectionRow(db, o.ownerId, connectionId, true);
      if (connection.status === "revoked") throw new AggregatorError("conflict", "connection is revoked");
      const result = await this.writeWebhook(db, o.ownerId, connectionId, config);
      await this.audit(db, { ownerId: o.ownerId, connectionId, actor: "owner", action: "webhook.set", targetType: "destination", targetId: "webhook", detail: this.ownerAudit(o, { host: hostOf(config.url) }) });
      return result;
    });
  }

  async ownerClearWebhook(o: OwnerPrincipal, connectionId: string): Promise<{ removed: boolean }> {
    return await this.scoped(this.ownerScope(o), async (db) => {
      await this.connectionRow(db, o.ownerId, connectionId);
      const rows = await db.query(`DELETE FROM ${this.t("destinations")} WHERE connection_id = $1 AND owner_id = $2 AND kind = 'webhook' RETURNING id`, [connectionId, o.ownerId]);
      if (rows[0]) await this.audit(db, { ownerId: o.ownerId, connectionId, actor: "owner", action: "webhook.clear", targetType: "destination", targetId: "webhook", detail: this.ownerAudit(o) });
      return { removed: rows.length > 0 };
    });
  }

  // ------------------------------------------------------- privileged

  /** Resolves a bearer credential. Revoked, expired or disconnected credentials resolve to null. */
  async authenticate(token: string): Promise<AgentPrincipal | null> {
    if (typeof token !== "string" || token.length < 20 || token.length > 300) return null;
    if (!this.tokenPrefixes.some((prefix) => token.startsWith(`${prefix}_`))) return null;
    const digest = hashToken(token);
    return await this.privileged(async (db) => {
      const now = this.now();
      const rows = await db.query(
        `SELECT cr.id AS credential_id, cr.owner_id, cr.connection_id, cr.kind, cr.scopes AS credential_scopes, cr.resource, cr.last_used_at,
                c.scopes AS connection_scopes, c.provider, c.mode
         FROM ${this.t("credentials")} cr JOIN ${this.t("connections")} c ON c.id = cr.connection_id AND c.owner_id = cr.owner_id
         WHERE cr.secret_hash = $1 AND cr.revoked_at IS NULL AND cr.kind IN ('agent','oauth_access') AND c.status = 'active'
           AND (cr.expires_at IS NULL OR cr.expires_at > $2)`,
        [digest, now.toISOString()],
      );
      const row = rows[0];
      if (!row) return null;
      const connectionScopes = parseScopes(String(row.connection_scopes ?? ""));
      const scopes = parseScopes(String(row.credential_scopes ?? "")).filter((scope) => connectionScopes.includes(scope));
      const lastUsed = asIso(row.last_used_at);
      if (!lastUsed || now.getTime() - Date.parse(lastUsed) > 60_000) {
        await db.query(`UPDATE ${this.t("credentials")} SET last_used_at = $2 WHERE id = $1`, [row.credential_id, now.toISOString()]);
        await db.query(`UPDATE ${this.t("connections")} SET last_seen_at = $2 WHERE id = $1`, [row.connection_id, now.toISOString()]);
      }
      return {
        kind: "agent",
        ownerId: String(row.owner_id),
        connectionId: String(row.connection_id),
        credentialId: String(row.credential_id),
        credentialKind: String(row.kind) as "agent" | "oauth_access",
        scopes,
        provider: String(row.provider),
        mode: String(row.mode) as ConnectionMode,
        resource: (row.resource as string | null) ?? null,
      };
    });
  }

  /** Exchanges a one-time setup code for the connection's credential. Each code works once. */
  async claim(codeInput: unknown): Promise<{ token: string; connection: ConnectionSummary; scopes: Scope[] }> {
    const code = typeof codeInput === "string" ? normalizeClaimCode(codeInput) : null;
    if (!code) throw new AggregatorError("unauthorized", "setup code is not valid");
    return await this.privileged(async (db) => {
      const now = this.now().toISOString();
      const rows = await db.query(
        `UPDATE ${this.t("credentials")} SET used_at = $2
         WHERE secret_hash = $1 AND kind = 'claim' AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $2
         RETURNING owner_id, connection_id`,
        [hashToken(code), now],
      );
      if (!rows[0]) throw new AggregatorError("unauthorized", "setup code is not valid, was already used, or expired; ask the owner for a new one");
      const ownerId = String(rows[0].owner_id);
      const connection = await this.connectionRow(db, ownerId, String(rows[0].connection_id), true);
      if (connection.status === "revoked") throw new AggregatorError("unauthorized", "connection is revoked");
      const minted = await this.mintAgentCredential(db, ownerId, connection, "system");
      return { token: minted.token, connection: this.summary(minted.connection), scopes: minted.connection.scopes };
    });
  }

  // ------------------------------------------------------------- OAuth

  async registerOAuthClient(meta: { client_name: string | null; redirect_uris: string[]; metadata: JsonObject }): Promise<{ client_id: string; issued_at: number }> {
    const id = newId("dcr");
    const now = this.now();
    await this.privileged(async (db) => {
      await db.query(
        `INSERT INTO ${this.t("oauth_clients")} (id, kind, client_name, redirect_uris, metadata, created_at, refreshed_at) VALUES ($1, 'dcr', $2, $3::jsonb, $4::jsonb, $5, $5)`,
        [id, meta.client_name, JSON.stringify(meta.redirect_uris), JSON.stringify(meta.metadata), now.toISOString()],
      );
    });
    return { client_id: id, issued_at: Math.floor(now.getTime() / 1000) };
  }

  async getOAuthClient(clientId: string): Promise<{ id: string; kind: "dcr" | "cimd"; client_name: string | null; redirect_uris: string[]; metadata: JsonObject; refreshed_at: string } | null> {
    return await this.privileged(async (db) => {
      const rows = await db.query(`SELECT * FROM ${this.t("oauth_clients")} WHERE id = $1`, [clientId]);
      if (!rows[0]) return null;
      return {
        id: String(rows[0].id), kind: String(rows[0].kind) as "dcr" | "cimd", client_name: (rows[0].client_name as string | null) ?? null,
        redirect_uris: asJson<string[]>(rows[0].redirect_uris) ?? [], metadata: asJson<JsonObject>(rows[0].metadata) ?? {}, refreshed_at: asIso(rows[0].refreshed_at)!,
      };
    });
  }

  async cacheCimdClient(clientId: string, meta: { client_name: string | null; redirect_uris: string[]; metadata: JsonObject }): Promise<void> {
    const now = this.now().toISOString();
    await this.privileged(async (db) => {
      await db.query(
        `INSERT INTO ${this.t("oauth_clients")} (id, kind, client_name, redirect_uris, metadata, created_at, refreshed_at) VALUES ($1, 'cimd', $2, $3::jsonb, $4::jsonb, $5, $5)
         ON CONFLICT (id) DO UPDATE SET client_name = excluded.client_name, redirect_uris = excluded.redirect_uris, metadata = excluded.metadata, refreshed_at = excluded.refreshed_at`,
        [clientId, meta.client_name, JSON.stringify(meta.redirect_uris), JSON.stringify(meta.metadata), now],
      );
    });
  }

  async createAuthorizationRequest(input: { client_id: string; client_name: string | null; redirect_uri: string; state: string | null; code_challenge: string; scopes: Scope[]; resource: string }): Promise<{ id: string; expires_at: string }> {
    const id = newUuid();
    const now = this.now();
    const expiresAt = addSeconds(now, this.oauthTtl.request);
    await this.privileged(async (db) => {
      await db.query(
        `INSERT INTO ${this.t("oauth_requests")} (id, client_id, client_name, redirect_uri, state, code_challenge, scopes, resource, status, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', $9, $10)`,
        [id, input.client_id, input.client_name, input.redirect_uri, input.state, input.code_challenge, input.scopes.join(" "), input.resource, now.toISOString(), expiresAt],
      );
    });
    return { id, expires_at: expiresAt };
  }

  async getAuthorizationRequest(id: string): Promise<{ id: string; client_id: string; client_name: string | null; redirect_uri: string; state: string | null; scopes: Scope[]; resource: string; status: string; expires_at: string } | null> {
    if (!/^[0-9a-f-]{36}$/i.test(id)) return null;
    return await this.privileged(async (db) => {
      const rows = await db.query(`SELECT * FROM ${this.t("oauth_requests")} WHERE id = $1`, [id]);
      const row = rows[0];
      if (!row) return null;
      const expired = Date.parse(asIso(row.expires_at)!) <= this.now().getTime();
      return {
        id: String(row.id), client_id: String(row.client_id), client_name: (row.client_name as string | null) ?? null, redirect_uri: String(row.redirect_uri),
        state: (row.state as string | null) ?? null, scopes: parseScopes(String(row.scopes)), resource: String(row.resource),
        status: expired && row.status === "pending" ? "expired" : String(row.status), expires_at: asIso(row.expires_at)!,
      };
    });
  }

  /**
   * The owner approved on the consent screen: bind (or create) the connection
   * and mint a single-use authorization code. Returns the code for the
   * redirect; only its digest is stored.
   */
  async approveAuthorizationRequest(o: OwnerPrincipal, requestId: string, target: { connection_id?: string; provider?: string; display_name?: string }): Promise<{ code: string; redirect_uri: string; state: string | null; connection: Connection }> {
    const request = await this.getAuthorizationRequest(requestId);
    if (!request || request.status !== "pending") throw new AggregatorError("conflict", "this authorization request is no longer pending");
    let connection: Connection;
    if (target.connection_id) {
      connection = await this.scoped(this.ownerScope(o), async (db) => this.connectionRow(db, o.ownerId, target.connection_id!));
      if (connection.status === "revoked") throw new AggregatorError("conflict", "connection is revoked");
      if (connection.mode !== "oauth_events") throw new AggregatorError("conflict", "only OAuth connections can be linked this way");
    } else {
      connection = await this.createConnection(o, { provider: target.provider ?? "custom", display_name: target.display_name ?? request.client_name ?? "OAuth app", mode: "oauth_events", scopes: request.scopes });
    }
    const code = generateToken("aggc", 32);
    const now = this.now();
    const claimed = await this.privileged(async (db) => {
      const rows = await db.query(
        `UPDATE ${this.t("oauth_requests")} SET status = 'approved', owner_id = $2, connection_id = $3, code_hash = $4, code_expires_at = $5
         WHERE id = $1 AND status = 'pending' AND expires_at > $6 RETURNING redirect_uri, state`,
        [requestId, o.ownerId, connection.id, hashToken(code), addSeconds(now, this.oauthTtl.code), now.toISOString()],
      );
      if (rows[0]) {
        await db.query(`UPDATE ${this.t("connections")} SET status = 'active', updated_at = $3 WHERE id = $1 AND owner_id = $2 AND status = 'pending'`, [connection.id, o.ownerId, now.toISOString()]);
        await this.audit(db, { ownerId: o.ownerId, connectionId: connection.id, actor: "owner", action: "oauth.approve", targetType: "oauth_client", targetId: request.client_id.slice(0, 200), detail: this.ownerAudit(o) });
      }
      return rows[0];
    });
    if (!claimed) throw new AggregatorError("conflict", "this authorization request is no longer pending");
    return { code, redirect_uri: String(claimed.redirect_uri), state: (claimed.state as string | null) ?? null, connection };
  }

  async denyAuthorizationRequest(requestId: string): Promise<{ redirect_uri: string; state: string | null } | null> {
    return await this.privileged(async (db) => {
      const rows = await db.query(`UPDATE ${this.t("oauth_requests")} SET status = 'denied' WHERE id = $1 AND status = 'pending' RETURNING redirect_uri, state`, [requestId]);
      return rows[0] ? { redirect_uri: String(rows[0].redirect_uri), state: (rows[0].state as string | null) ?? null } : null;
    });
  }

  private async issueOAuthPair(db: Db, ownerId: string, connectionId: string, scopes: Scope[], resource: string, clientId: string, familyId: string): Promise<TokenResponse> {
    const now = this.now();
    const access = generateToken(this.prefixes.access);
    const refresh = generateToken(this.prefixes.refresh);
    await db.query(
      `INSERT INTO ${this.t("credentials")} (id, owner_id, connection_id, kind, secret_hash, hint, scopes, resource, client_id, family_id, expires_at, created_at)
       VALUES ($1, $2, $3, 'oauth_access', $4, $5, $6, $7, $8, $9, $10, $11), ($12, $2, $3, 'oauth_refresh', $13, $14, $6, $7, $8, $9, $15, $11)`,
      [newUuid(), ownerId, connectionId, hashToken(access), tokenHint(access), scopes.join(" "), resource, clientId.slice(0, 500), familyId,
        addSeconds(now, this.oauthTtl.access), now.toISOString(), newUuid(), hashToken(refresh), tokenHint(refresh), addSeconds(now, this.oauthTtl.refresh)],
    );
    return { access_token: access, token_type: "Bearer", expires_in: this.oauthTtl.access, refresh_token: refresh, scope: scopes.join(" ") };
  }

  /** authorization_code grant with PKCE (S256). A replayed code revokes everything issued from it. */
  async exchangeAuthorizationCode(input: { code: string; code_verifier: string; client_id: string; redirect_uri: string; resource?: string | null }): Promise<TokenResponse> {
    // Revocations triggered by replay must commit even though the request fails.
    const result = await this.privileged(async (db): Promise<TokenResponse | "replayed"> => {
      const now = this.now();
      const rows = await db.query(`SELECT * FROM ${this.t("oauth_requests")} WHERE code_hash = $1 FOR UPDATE`, [hashToken(input.code)]);
      const row = rows[0];
      if (!row) throw new AggregatorError("invalid_request", "invalid_grant");
      if (row.status === "exchanged") {
        await db.query(`UPDATE ${this.t("credentials")} SET revoked_at = $2 WHERE family_id = $1 AND revoked_at IS NULL`, [row.id, now.toISOString()]);
        return "replayed";
      }
      if (row.status !== "approved" || !row.code_expires_at || Date.parse(asIso(row.code_expires_at)!) <= now.getTime()) throw new AggregatorError("invalid_request", "invalid_grant");
      if (String(row.client_id) !== input.client_id || String(row.redirect_uri) !== input.redirect_uri) throw new AggregatorError("invalid_request", "invalid_grant");
      if (input.resource && input.resource !== String(row.resource)) throw new AggregatorError("invalid_request", "invalid_target");
      if (!verifyPkceS256(input.code_verifier, String(row.code_challenge))) throw new AggregatorError("invalid_request", "invalid_grant");
      const connection = await this.connectionRow(db, String(row.owner_id), String(row.connection_id));
      if (connection.status !== "active") throw new AggregatorError("invalid_request", "invalid_grant");
      await db.query(`UPDATE ${this.t("oauth_requests")} SET status = 'exchanged' WHERE id = $1`, [row.id]);
      const scopes = parseScopes(String(row.scopes)).filter((scope) => connection.scopes.includes(scope));
      const pair = await this.issueOAuthPair(db, String(row.owner_id), connection.id, scopes, String(row.resource), input.client_id, String(row.id));
      await this.audit(db, { ownerId: String(row.owner_id), connectionId: connection.id, actor: "system", action: "oauth.token", targetType: "connection", targetId: connection.id });
      return pair;
    });
    if (result === "replayed") throw new AggregatorError("invalid_request", "invalid_grant");
    return result;
  }

  /** refresh_token grant with rotation. Presenting an already-used refresh token revokes the whole family. */
  async refreshAccessToken(input: { refresh_token: string; client_id: string; resource?: string | null }): Promise<TokenResponse> {
    const result = await this.privileged(async (db): Promise<TokenResponse | "reused"> => {
      const now = this.now();
      const rows = await db.query(
        `SELECT cr.*, c.status AS connection_status, c.scopes AS connection_scopes FROM ${this.t("credentials")} cr
         JOIN ${this.t("connections")} c ON c.id = cr.connection_id AND c.owner_id = cr.owner_id
         WHERE cr.secret_hash = $1 AND cr.kind = 'oauth_refresh' FOR UPDATE`,
        [hashToken(input.refresh_token)],
      );
      const row = rows[0];
      if (!row) throw new AggregatorError("invalid_request", "invalid_grant");
      if (row.used_at || row.revoked_at) {
        await db.query(`UPDATE ${this.t("credentials")} SET revoked_at = $2 WHERE family_id = $1 AND revoked_at IS NULL`, [row.family_id, now.toISOString()]);
        return "reused";
      }
      if (row.connection_status !== "active" || (row.expires_at && Date.parse(asIso(row.expires_at)!) <= now.getTime())) throw new AggregatorError("invalid_request", "invalid_grant");
      if (String(row.client_id) !== input.client_id) throw new AggregatorError("invalid_request", "invalid_grant");
      if (input.resource && input.resource !== String(row.resource)) throw new AggregatorError("invalid_request", "invalid_target");
      await db.query(`UPDATE ${this.t("credentials")} SET used_at = $2 WHERE id = $1`, [row.id, now.toISOString()]);
      const connectionScopes = parseScopes(String(row.connection_scopes));
      const scopes = parseScopes(String(row.scopes)).filter((scope) => connectionScopes.includes(scope));
      return await this.issueOAuthPair(db, String(row.owner_id), String(row.connection_id), scopes, String(row.resource), input.client_id, String(row.family_id));
    });
    if (result === "reused") throw new AggregatorError("invalid_request", "invalid_grant");
    return result;
  }

  /** RFC 7009: revoking an access or refresh token revokes its family. Unknown tokens are not an error. */
  async revokeOAuthToken(token: string): Promise<void> {
    await this.privileged(async (db) => {
      const rows = await db.query(`SELECT family_id FROM ${this.t("credentials")} WHERE secret_hash = $1 AND kind IN ('oauth_access','oauth_refresh')`, [hashToken(token)]);
      if (rows[0]?.family_id) {
        await db.query(`UPDATE ${this.t("credentials")} SET revoked_at = $2 WHERE family_id = $1 AND revoked_at IS NULL`, [rows[0].family_id, this.now().toISOString()]);
      }
    });
  }

  // ----------------------------------------------------- delivery worker

  /**
   * Delivers due webhook and MCP-event deliveries. Safe to run from several
   * workers: rows are leased with SKIP LOCKED. Retries keep the event id and
   * re-sign with a fresh timestamp. 410 removes a subscription; 413 is final.
   */
  async deliverDue(opts: { limit?: number } = {}): Promise<{ delivered: number; failed: number; retried: number }> {
    const limit = Math.max(1, Math.min(opts.limit ?? 25, 200));
    const leased = await this.privileged(async (db) => {
      const now = this.now();
      const due = await db.query(
        `SELECT id FROM ${this.t("deliveries")} WHERE status = 'pending' AND next_attempt_at <= $1 ORDER BY next_attempt_at LIMIT $2 FOR UPDATE SKIP LOCKED`,
        [now.toISOString(), limit],
      );
      const out: Row[] = [];
      for (const { id } of due) {
        await db.query(`UPDATE ${this.t("deliveries")} SET next_attempt_at = $2 WHERE id = $1`, [id, addSeconds(now, 120)]);
        const rows = await db.query(
          `SELECT d.id, d.attempts, d.connection_id, d.owner_id, d.event_seq, ds.id AS destination_id, ds.kind, ds.external_id, ds.url, ds.auth_header_name,
                  ds.auth_header_value_enc, ds.signing_secret_enc, ds.expires_at, e.id AS event_id, e.name, e.data, e.created_at AS event_created_at
           FROM ${this.t("deliveries")} d
           JOIN ${this.t("destinations")} ds ON ds.id = d.destination_id AND ds.connection_id = d.connection_id AND ds.owner_id = d.owner_id
           JOIN ${this.t("events")} e ON e.connection_id = d.connection_id AND e.owner_id = d.owner_id AND e.seq = d.event_seq
           WHERE d.id = $1`,
          [id],
        );
        if (rows[0]) out.push(rows[0]);
        else await db.query(`UPDATE ${this.t("deliveries")} SET status = 'failed', last_error = 'missing_event' WHERE id = $1`, [id]);
      }
      return out;
    });
    let delivered = 0;
    let failed = 0;
    let retried = 0;
    for (const row of leased) {
      const outcome = await this.attemptDelivery(row);
      await this.privileged(async (db) => {
        const now = this.now();
        const attempts = asNumber(row.attempts) + 1;
        if (outcome.kind === "delivered") {
          delivered += 1;
          await db.query(`UPDATE ${this.t("deliveries")} SET status = 'delivered', attempts = $2, last_status = $3, last_error = NULL, delivered_at = $4 WHERE id = $1`, [row.id, attempts, outcome.status, now.toISOString()]);
        } else if (outcome.kind === "gone") {
          failed += 1;
          await db.query(`UPDATE ${this.t("deliveries")} SET status = 'failed', attempts = $2, last_status = 410, last_error = 'gone' WHERE id = $1`, [row.id, attempts]);
          if (row.kind === "mcp_event") await db.query(`DELETE FROM ${this.t("destinations")} WHERE id = $1`, [row.destination_id]);
        } else if (outcome.kind === "final" || attempts > RETRY_DELAYS_SECONDS.length) {
          failed += 1;
          await db.query(`UPDATE ${this.t("deliveries")} SET status = 'failed', attempts = $2, last_status = $3, last_error = $4 WHERE id = $1`, [row.id, attempts, outcome.status ?? null, outcome.error]);
        } else {
          retried += 1;
          await db.query(
            `UPDATE ${this.t("deliveries")} SET attempts = $2, last_status = $3, last_error = $4, next_attempt_at = $5 WHERE id = $1`,
            [row.id, attempts, outcome.status ?? null, outcome.error, addSeconds(now, RETRY_DELAYS_SECONDS[attempts - 1]!)],
          );
        }
      });
    }
    return { delivered, failed, retried };
  }

  private async attemptDelivery(row: Row): Promise<{ kind: "delivered"; status: number } | { kind: "gone" } | { kind: "final" | "retry"; status?: number; error: string }> {
    const expires = asIso(row.expires_at);
    if (expires && Date.parse(expires) <= this.now().getTime()) return { kind: "final", error: "subscription_expired" };
    const envelope: HubEvent = {
      eventId: String(row.event_id),
      name: String(row.name) as EventName,
      timestamp: asIso(row.event_created_at)!,
      data: asJson<JsonObject>(row.data) ?? {},
      cursor: encodeCursor(asNumber(row.event_seq)),
    };
    let body = JSON.stringify(envelope);
    if (Buffer.byteLength(body, "utf8") > LIMITS.eventBodyBytes) {
      body = JSON.stringify({ ...envelope, data: { truncated: true, ...Object.fromEntries(Object.entries(envelope.data).filter(([key]) => key.endsWith("_id") || key === "status" || key === "revision")) } });
    }
    let secret: string;
    let headerValue: string | null = null;
    try {
      secret = this.box.decrypt(String(row.signing_secret_enc));
      if (row.auth_header_value_enc) headerValue = this.box.decrypt(String(row.auth_header_value_enc));
    } catch {
      return { kind: "final", error: "secret_unavailable" };
    }
    const headers: Record<string, string> = {
      "content-type": "application/json",
      ...webhookHeaders(secret, envelope.eventId, body, this.now()),
    };
    if (row.kind === "mcp_event") headers["x-mcp-subscription-id"] = String(row.external_id);
    if (row.auth_header_name && headerValue) {
      const name = String(row.auth_header_name);
      headers[name.toLowerCase()] = name.toLowerCase() === "authorization" && !/^\S+\s/.test(headerValue) ? `Bearer ${headerValue}` : headerValue;
    }
    try {
      const response = await this.send(String(row.url), headers, body);
      if (response.status >= 200 && response.status < 300) return { kind: "delivered", status: response.status };
      if (response.status === 410) return { kind: "gone" };
      if (response.status === 413) return { kind: "final", status: 413, error: "payload_too_large" };
      return { kind: "retry", status: response.status, error: `http_${response.status}` };
    } catch (error) {
      if (error instanceof AggregatorError && error.code === "invalid_request") return { kind: "final", error: "destination_rejected" };
      if (error instanceof AggregatorError && error.details?.reason === "dns") return { kind: "retry", error: "dns" };
      return { kind: "retry", error: error instanceof AggregatorError && error.code === "unavailable" ? "timeout" : "network" };
    }
  }

  /** Expires due questions, prunes old events/deliveries and stale OAuth requests. */
  async sweep(): Promise<{ expired: number; prunedEvents: number }> {
    const now = this.now();
    const expired = await this.privileged(async (db, after) => {
      const rows = await db.query(
        `SELECT q.*, c.provider AS c_provider, c.display_name AS c_display_name, c.mode AS c_mode, c.status AS c_status FROM ${this.t("questions")} q
         JOIN ${this.t("connections")} c ON c.id = q.connection_id AND c.owner_id = q.owner_id
         WHERE q.status = 'pending' AND q.expires_at IS NOT NULL AND q.expires_at <= $1 ORDER BY q.expires_at LIMIT 200 FOR UPDATE SKIP LOCKED`,
        [now.toISOString()],
      );
      for (const row of rows) {
        const updated = await db.query(
          `UPDATE ${this.t("questions")} SET status = 'expired', status_reason = 'expired', updated_at = $3 WHERE connection_id = $1 AND id = $2 AND status = 'pending' RETURNING *`,
          [row.connection_id, row.id, now.toISOString()],
        );
        if (!updated[0]) continue;
        const question = this.toQuestion(updated[0]);
        const ownerId = String(row.owner_id);
        const connection = { id: String(row.connection_id), provider: String(row.c_provider), display_name: String(row.c_display_name), mode: String(row.c_mode) as ConnectionMode };
        if (row.c_status === "active") {
          await this.appendEvent(db, after, ownerId, connection.id, "question.updated", { question_id: question.id, status: "expired", reason: "expired", revision: question.revision });
        }
        const hook = this.hooks.questionChanged;
        if (hook) after.push(() => hook({ ownerId, connection, question, previousStatus: "pending" }));
      }
      return rows.length;
    });
    const prunedEvents = await this.privileged(async (db) => {
      const cutoff = new Date(now.getTime() - this.retentionDays * 86_400_000).toISOString();
      await db.query(`DELETE FROM ${this.t("deliveries")} WHERE status <> 'pending' AND created_at < $1`, [cutoff]);
      const rows = await db.query(`DELETE FROM ${this.t("events")} WHERE created_at < $1 AND NOT EXISTS (SELECT 1 FROM ${this.t("deliveries")} d WHERE d.connection_id = ${this.t("events")}.connection_id AND d.event_seq = ${this.t("events")}.seq AND d.status = 'pending') RETURNING seq`, [cutoff]);
      await db.query(`DELETE FROM ${this.t("destinations")} WHERE expires_at IS NOT NULL AND expires_at < $1`, [now.toISOString()]);
      const dayAgo = new Date(now.getTime() - 86_400_000).toISOString();
      await db.query(
        `DELETE FROM ${this.t("oauth_requests")} WHERE (expires_at < $1 AND status IN ('pending','denied','exchanged','expired'))
           OR (status = 'approved' AND code_expires_at IS NOT NULL AND code_expires_at < $1)`,
        [dayAgo],
      );
      const weekAgo = new Date(now.getTime() - 7 * 86_400_000).toISOString();
      await db.query(`DELETE FROM ${this.t("credentials")} WHERE expires_at IS NOT NULL AND expires_at < $1`, [weekAgo]);
      await db.query(`DELETE FROM ${this.t("credentials")} WHERE revoked_at IS NOT NULL AND revoked_at < $1`, [weekAgo]);
      await db.query(`DELETE FROM ${this.t("credentials")} WHERE kind IN ('claim','oauth_refresh') AND used_at IS NOT NULL AND used_at < $1`, [weekAgo]);
      // Bounded history: checkpoints and audit entries older than the retention window are removed.
      const historyCutoff = new Date(now.getTime() - this.historyDays * 86_400_000).toISOString();
      await db.query(`DELETE FROM ${this.t("checkpoints")} WHERE created_at < $1`, [historyCutoff]);
      await db.query(`DELETE FROM ${this.t("audit")} WHERE created_at < $1`, [historyCutoff]);
      // Client registrations no live grant uses, and stale client-metadata cache rows.
      await db.query(
        `DELETE FROM ${this.t("oauth_clients")} WHERE created_at < $1
           AND NOT EXISTS (SELECT 1 FROM ${this.t("credentials")} cr WHERE cr.client_id = ${this.t("oauth_clients")}.id AND cr.revoked_at IS NULL)
           AND NOT EXISTS (SELECT 1 FROM ${this.t("oauth_requests")} r WHERE r.client_id = ${this.t("oauth_clients")}.id)`,
        [new Date(now.getTime() - 86_400_000).toISOString()],
      );
      return rows.length;
    });
    return { expired, prunedEvents };
  }
}

export { WORK_ITEM_KINDS };
