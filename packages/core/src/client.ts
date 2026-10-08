import type { Checkpoint, ConnectionInfo, InboxPage, Job, Message, Question, Thread, WorkItem } from "./contract.js";

export class AggregatorApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: unknown;
  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message);
    this.name = "AggregatorApiError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export interface AggregatorClientOptions {
  /** Base URL of the agent API; requests go to `${baseUrl}/v1/...`. */
  baseUrl: string;
  token?: string;
  fetch?: typeof fetch;
  /** Some edge networks block generic client user agents; send a descriptive one. */
  userAgent?: string;
  timeoutMs?: number;
}

type Query = Record<string, string | number | boolean | undefined | null>;

/** Typed client for the agent REST API. No retries on writes: every write is idempotent by id, so callers can retry safely. */
export class AggregatorClient {
  private readonly base: string;
  private readonly token: string | undefined;
  private readonly fetchImpl: typeof fetch;
  private readonly userAgent: string;
  private readonly timeoutMs: number;

  constructor(opts: AggregatorClientOptions) {
    const url = new URL(opts.baseUrl);
    if (url.protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)) throw new Error("baseUrl must use https");
    this.base = opts.baseUrl.replace(/\/+$/, "");
    this.token = opts.token;
    this.fetchImpl = opts.fetch ?? fetch;
    this.userAgent = opts.userAgent ?? "agent-aggregator-client/0.1";
    this.timeoutMs = opts.timeoutMs ?? 20_000;
  }

  private async request<T>(method: string, path: string, opts: { query?: Query; body?: unknown; auth?: boolean } = {}): Promise<T> {
    const url = new URL(`${this.base}${path}`);
    for (const [key, value] of Object.entries(opts.query ?? {})) if (value !== undefined && value !== null && value !== "") url.searchParams.set(key, String(value));
    const headers: Record<string, string> = { accept: "application/json", "user-agent": this.userAgent };
    if (opts.body !== undefined) headers["content-type"] = "application/json";
    if (opts.auth !== false) {
      if (!this.token) throw new AggregatorApiError(401, "unauthorized", "no credential configured");
      headers.authorization = `Bearer ${this.token}`;
    }
    const response = await this.fetchImpl(url, {
      method,
      headers,
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      redirect: "error",
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    const text = await response.text();
    let parsed: unknown = null;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      parsed = null;
    }
    if (!response.ok) {
      const error = (parsed as { error?: { code?: string; message?: string; details?: unknown } } | null)?.error;
      throw new AggregatorApiError(response.status, error?.code ?? `http_${response.status}`, error?.message ?? `request failed with HTTP ${response.status}`, error?.details);
    }
    return parsed as T;
  }

  me(): Promise<ConnectionInfo> {
    return this.request("GET", "/v1/me");
  }
  claim(code: string): Promise<{ token: string; connection: { id: string; provider: string; display_name: string; mode: string }; scopes: string[] }> {
    return this.request("POST", "/v1/claim", { body: { code }, auth: false });
  }
  upsertWorkItem(item: Record<string, unknown> & { id: string }): Promise<{ item: WorkItem; changed: boolean }> {
    return this.request("PUT", `/v1/work-items/${encodeURIComponent(item.id)}`, { body: item });
  }
  listWorkItems(query: Query = {}): Promise<{ items: WorkItem[]; next_after: string | null }> {
    return this.request("GET", "/v1/work-items", { query });
  }
  getWorkItem(id: string): Promise<{ item: WorkItem }> {
    return this.request("GET", `/v1/work-items/${encodeURIComponent(id)}`);
  }
  deleteWorkItem(id: string): Promise<{ deleted: boolean }> {
    return this.request("DELETE", `/v1/work-items/${encodeURIComponent(id)}`);
  }
  postCheckpoint(checkpoint: Record<string, unknown>): Promise<{ checkpoint: Checkpoint; created: boolean }> {
    return this.request("POST", "/v1/checkpoints", { body: checkpoint });
  }
  listCheckpoints(query: Query = {}): Promise<{ checkpoints: Checkpoint[] }> {
    return this.request("GET", "/v1/checkpoints", { query });
  }
  pushSnapshot(snapshot: Record<string, unknown>): Promise<{ upserted: number; unchanged: number; state: WorkItem }> {
    return this.request("PUT", "/v1/snapshot", { body: snapshot });
  }
  createQuestion(question: Record<string, unknown>): Promise<{ question: Question; created: boolean; revised: boolean }> {
    return this.request("POST", "/v1/questions", { body: question });
  }
  listQuestions(query: Query = {}): Promise<{ questions: Question[] }> {
    return this.request("GET", "/v1/questions", { query });
  }
  getQuestion(id: string): Promise<{ question: Question }> {
    return this.request("GET", `/v1/questions/${encodeURIComponent(id)}`);
  }
  acknowledgeAnswer(id: string, revision?: number): Promise<{ question: Question }> {
    return this.request("POST", `/v1/questions/${encodeURIComponent(id)}/ack`, { body: revision === undefined ? {} : { revision } });
  }
  cancelQuestion(id: string): Promise<{ question: Question }> {
    return this.request("POST", `/v1/questions/${encodeURIComponent(id)}/cancel`, { body: {} });
  }
  readInbox(cursor?: string | null, limit?: number): Promise<InboxPage> {
    return this.request("GET", "/v1/inbox", { query: { cursor: cursor ?? undefined, limit } });
  }
  handoffGoal(job: Record<string, unknown>): Promise<{ job: Job; created: boolean }> {
    return this.request("POST", "/v1/jobs", { body: job });
  }
  listJobs(query: Query = {}): Promise<{ jobs: Job[] }> {
    return this.request("GET", "/v1/jobs", { query });
  }
  getJob(id: string): Promise<{ job: Job }> {
    return this.request("GET", `/v1/jobs/${encodeURIComponent(id)}`);
  }
  cancelJob(id: string): Promise<{ job: Job }> {
    return this.request("POST", `/v1/jobs/${encodeURIComponent(id)}/cancel`, { body: {} });
  }
  checkMessages(query: Query = {}): Promise<{ messages: Message[] }> {
    return this.request("GET", "/v1/messages", { query });
  }
  postMessage(message: { text: string; reply_to?: string; thread_id?: string; kind?: "reply" | "progress"; id?: string }): Promise<{ message: Message; thread: Thread; created: boolean }> {
    return this.request("POST", "/v1/messages", { body: message });
  }
  acknowledgeMessage(id: string): Promise<{ message: Message }> {
    return this.request("POST", `/v1/messages/${encodeURIComponent(id)}/ack`, { body: {} });
  }
  setWebhook(config: { url: string; auth_header_name?: string; auth_header_value?: string }): Promise<{ url: string; auth_header_name: string | null; signing_secret: string }> {
    return this.request("PUT", "/v1/webhook", { body: config });
  }
  clearWebhook(): Promise<{ removed: boolean }> {
    return this.request("DELETE", "/v1/webhook");
  }
}
