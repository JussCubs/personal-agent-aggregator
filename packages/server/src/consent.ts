import { randomBytes } from "node:crypto";
import { SCOPE_DESCRIPTIONS, type Scope } from "@agent-aggregator/core";
import { escapeHtml } from "./http.js";

/**
 * The OAuth consent page: minimal server-rendered HTML, no scripts. Every
 * value from the client (name, redirect URI) is escaped, and the page states
 * which parts are self-declared by the client and which the server verified.
 */
export interface ConsentView {
  requestId: string;
  csrf: string;
  clientName: string | null;
  clientKind: "dcr" | "cimd";
  clientIdHost: string | null;
  redirectHost: string;
  scopes: Scope[];
  expiresAt: string;
  error: string | null;
}

const STYLE = `body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;max-width:38rem;margin:2rem auto;padding:0 1rem;line-height:1.5;color:#111;background:#fff}
h1{font-size:1.4rem}dt{font-weight:600;margin-top:.8rem}dd{margin:0}code{background:#f2f2f2;padding:0 .2rem;border-radius:3px}
.notice{border-left:4px solid #b26b00;background:#fff7e6;padding:.6rem .8rem}.error{border-left:4px solid #b00020;background:#fdecee;padding:.6rem .8rem}
label{display:block;font-weight:600;margin-top:1rem}input[type=password],input[type=text]{width:100%;padding:.5rem;font:inherit;box-sizing:border-box}
.actions{margin-top:1.2rem;display:flex;gap:.8rem}button{font:inherit;padding:.5rem 1.2rem;cursor:pointer}
@media (prefers-color-scheme:dark){body{background:#111;color:#eee}code{background:#222}.notice{background:#2a2112}.error{background:#2a1215}}`;

export const CONSENT_ERRORS: Record<string, string> = {
  credential: "That owner credential is not valid. Nothing was approved.",
  csrf: "This form expired or was opened in another browser. Review the request again.",
  connection: "That connection id cannot be reconnected (unknown, revoked, or not an OAuth connection).",
  blocked: "Too many failed attempts from this address. Wait a minute and try again.",
};

export function cspNonce(): string {
  return randomBytes(16).toString("base64");
}

function page(nonce: string, title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${escapeHtml(title)}</title>
<style nonce="${nonce}">${STYLE}</style>
</head>
<body>
<main>
${body}
</main>
</body>
</html>
`;
}

export function renderConsentPage(view: ConsentView, nonce: string): string {
  const name = view.clientName ? escapeHtml(view.clientName) : "<em>(no name given)</em>";
  const identity = view.clientKind === "cimd" && view.clientIdHost
    ? `Metadata document published at <code>${escapeHtml(view.clientIdHost)}</code>`
    : "Registered itself with this server (dynamic registration; identity not verified)";
  const scopes = view.scopes
    .map((scope) => `<li><code>${escapeHtml(scope)}</code> — ${escapeHtml(SCOPE_DESCRIPTIONS[scope])}</li>`)
    .join("\n");
  const error = view.error ? `<p class="error" role="alert">${escapeHtml(view.error)}</p>` : "";
  return page(nonce, "Approve an agent connection", `<h1>Approve an agent connection</h1>
<p class="notice">Approve only if you started this connection yourself, just now. The approval is sent to the host below; anyone who controls that host gets this access.</p>
${error}
<dl>
<dt>Application name (supplied by the application)</dt>
<dd>${name}</dd>
<dt>Approval is sent to</dt>
<dd><code>${escapeHtml(view.redirectHost)}</code></dd>
<dt>Client identity</dt>
<dd>${identity}</dd>
<dt>Requested access</dt>
<dd><ul>
${scopes}
</ul></dd>
<dt>This request expires</dt>
<dd>${escapeHtml(view.expiresAt)}</dd>
</dl>
<form method="post" action="/oauth/authorize">
<input type="hidden" name="request_id" value="${escapeHtml(view.requestId)}">
<input type="hidden" name="csrf" value="${escapeHtml(view.csrf)}">
<label for="owner_credential">Owner credential (required to approve)</label>
<input id="owner_credential" name="owner_credential" type="password" autocomplete="current-password" spellcheck="false">
<details>
<summary>Reconnect an existing OAuth connection instead of creating a new one (optional)</summary>
<label for="connection_id">Connection id</label>
<input id="connection_id" name="connection_id" type="text" autocomplete="off" spellcheck="false" pattern="[0-9a-fA-F-]{36}">
</details>
<div class="actions">
<button type="submit" name="action" value="approve">Approve</button>
<button type="submit" name="action" value="deny" formnovalidate>Deny</button>
</div>
</form>`);
}

export function renderMessagePage(title: string, message: string, nonce: string): string {
  return page(nonce, title, `<h1>${escapeHtml(title)}</h1>\n<p>${escapeHtml(message)}</p>`);
}

/** Headers for HTML pages. `formTargets` are origins the consent form may redirect to (CSP form-action covers redirects). */
export function htmlHeaders(nonce: string, formTargets: readonly string[] = []): Record<string, string> {
  const formAction = ["'self'", ...formTargets.filter((origin) => /^https?:\/\/[A-Za-z0-9.\-[\]:]+$/.test(origin))].join(" ");
  return {
    "content-type": "text/html; charset=utf-8",
    "content-security-policy": `default-src 'none'; style-src 'nonce-${nonce}'; form-action ${formAction}; frame-ancestors 'none'; base-uri 'none'`,
    "x-frame-options": "DENY",
  };
}
