/**
 * The wire contract shared by the REST API, the MCP tools, the CLI and the
 * webhook/event payloads. Field names are snake_case on the wire.
 *
 * Every string an agent sends is untrusted data. The aggregator stores and
 * displays it; it never executes it or forwards it to another agent as an
 * instruction without the owner's explicit approval.
 */

export const CONTRACT_VERSION = "2026-10-01";

export const LIMITS = {
  idLength: 128,
  titleLength: 200,
  statusLength: 40,
  summaryLength: 4000,
  detailsLength: 8000,
  promptLength: 1000,
  affectedActionLength: 500,
  actionDigestLength: 128,
  optionLabelLength: 120,
  maxOptions: 8,
  answerTextLength: 4000,
  dataBytes: 16384,
  dataDepth: 8,
  goalLength: 4000,
  contextLength: 8000,
  snapshotItems: 200,
  connectedApps: 50,
  openQuestionsPerConnection: 100,
  workItemsPerConnection: 5000,
  checkpointsPerConnection: 20000,
  activeJobsPerConnection: 20,
  pageSize: 100,
  requestBodyBytes: 262144,
  eventBodyBytes: 262144,
} as const;

/** Scopes a connection credential can carry. Least privilege: grant only what the agent uses. */
export const SCOPES = {
  read: "hub:read",
  write: "hub:write",
  ask: "hub:ask",
  handoff: "hub:handoff",
} as const;
export type Scope = (typeof SCOPES)[keyof typeof SCOPES];
export const ALL_SCOPES: readonly Scope[] = [SCOPES.read, SCOPES.write, SCOPES.ask, SCOPES.handoff];

export const SCOPE_DESCRIPTIONS: Record<Scope, string> = {
  "hub:read": "Read the work items, answers, inbox and jobs this agent created",
  "hub:write": "Create and update this agent's tasks, goals, projects, state and checkpoints",
  "hub:ask": "Ask the owner questions and request approvals",
  "hub:handoff": "Hand goals to the owner's primary agent (each one waits for the owner's OK)",
};

export function parseScopes(value: string | readonly string[] | null | undefined): Scope[] {
  const raw = typeof value === "string" ? value.split(/[\s,]+/) : [...(value ?? [])];
  const known = new Set<string>(ALL_SCOPES);
  const out: Scope[] = [];
  for (const item of raw) {
    const scope = item.trim();
    if (known.has(scope) && !out.includes(scope as Scope)) out.push(scope as Scope);
  }
  return out;
}

export type WorkItemKind = "task" | "goal" | "project" | "state";
export const WORK_ITEM_KINDS: readonly WorkItemKind[] = ["task", "goal", "project", "state"];

export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

export interface WorkItem {
  id: string;
  kind: WorkItemKind;
  title: string;
  status: string | null;
  summary: string | null;
  blocker: string | null;
  next_step: string | null;
  due_at: string | null;
  parent_id: string | null;
  data: JsonObject | null;
  revision: number;
  created_at: string;
  updated_at: string;
}

export interface Checkpoint {
  id: string;
  work_item_id: string | null;
  summary: string;
  status: string | null;
  data: JsonObject | null;
  created_at: string;
}

export type QuestionKind = "question" | "approval";
export type QuestionStatus = "pending" | "answered" | "cancelled" | "expired";
export type Urgency = "low" | "normal" | "high";

export interface QuestionOption {
  id: string;
  label: string;
}

export interface AnswerAuthor {
  /** Always the connection's owner, authenticated by the aggregator. */
  kind: "owner";
  name: string | null;
  verified: true;
  /** Which client the owner answered from (for example "web", "desktop", "mobile", "cli"). */
  surface: string | null;
}

export interface Answer {
  /** Option id the owner chose, or null for a free-text-only answer. */
  choice: string | null;
  choice_label: string | null;
  text: string | null;
  /** For approvals: the owner's decision. */
  decision: "approved" | "denied" | null;
  /** The question revision the owner saw when answering. */
  question_revision: number;
  /** Echo of the question's action_digest at answer time, so the agent can bind the answer to the exact action. */
  action_digest: string | null;
  author: AnswerAuthor;
  answered_at: string;
  acknowledged_at: string | null;
}

export interface Question {
  id: string;
  kind: QuestionKind;
  prompt: string;
  details: string | null;
  options: QuestionOption[];
  allow_free_text: boolean;
  work_item_id: string | null;
  affected_action: string | null;
  action_digest: string | null;
  urgency: Urgency;
  status: QuestionStatus;
  /** Why a closed question closed: cancelled_by_agent, dismissed_by_owner, connection_revoked, expired. */
  status_reason: string | null;
  revision: number;
  expires_at: string | null;
  answer: Answer | null;
  created_at: string;
  updated_at: string;
}

export type JobStatus = "needs_user" | "running" | "blocked" | "done" | "declined" | "cancelled" | "failed";
export const TERMINAL_JOB_STATUSES: readonly JobStatus[] = ["done", "declined", "cancelled", "failed"];

export interface Job {
  id: string;
  goal: string;
  context: string | null;
  success_criteria: string | null;
  work_item_id: string | null;
  status: JobStatus;
  /** Machine-readable reason for the current status, e.g. "awaiting_owner_approval". */
  status_reason: string | null;
  summary: string | null;
  result: JsonObject | null;
  revision: number;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
}

export type EventName = "answer.created" | "question.updated" | "job.updated";
export const EVENT_NAMES: readonly EventName[] = ["answer.created", "question.updated", "job.updated"];

/** One inbox entry. The same envelope is POSTed to webhooks and MCP event subscriptions. */
export interface HubEvent {
  eventId: string;
  name: EventName;
  timestamp: string;
  data: JsonObject;
  /** Inbox cursor positioned just after this event. Pass it to the inbox to resume. */
  cursor: string;
}

export interface InboxPage {
  events: HubEvent[];
  cursor: string;
  has_more: boolean;
}

export interface ConnectionInfo {
  connection_id: string;
  provider: string;
  display_name: string;
  mode: ConnectionMode;
  scopes: Scope[];
  owner_name: string | null;
  contract_version: string;
  callback: { configured: boolean; url_host: string | null } | null;
}

/**
 * How the agent connects and how it is woken:
 * - mcp_webhook: MCP with a bearer credential, woken by a signed webhook to a URL it gives us.
 * - oauth_events: an OAuth-protected MCP plugin, woken by signed MCP event deliveries.
 * - cli_poll: CLI or plain HTTPS with a bearer credential, woken by polling the inbox cursor.
 */
export type ConnectionMode = "mcp_webhook" | "oauth_events" | "cli_poll";
export const CONNECTION_MODES: readonly ConnectionMode[] = ["mcp_webhook", "oauth_events", "cli_poll"];

export type ConnectionStatus = "pending" | "active" | "revoked";
