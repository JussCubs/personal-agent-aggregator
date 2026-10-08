# Secrets

Every secret the system handles, how it is stored, when it is shown, and how
to rotate it.

## Inventory

| Secret | Format | Created by | Stored as | Shown | Lifetime |
| --- | --- | --- | --- | --- | --- |
| Agent credential | `agg_` + 32 random bytes, base64url | Owner (`credential issue`) or setup-code claim | SHA-256 hex in `credentials.secret_hash`, plus a hint (`agg_` + 4 characters + `…`) | Once, in the issuing response | Until revoked |
| Setup code | 20 symbols, `XXXXX-XXXXX-XXXXX-XXXXX` (about 98 bits) | Owner (`claim-code`) | SHA-256 hex; hint = first 5 symbols | Once | Single use; 900 s default, 60-86400 s |
| OAuth authorization code | `aggc_` + 32 bytes | Consent approval | SHA-256 in `oauth_requests.code_hash` | Once, in the redirect | Single use; 300 s |
| OAuth access token | `aggo_` + 32 bytes | Token endpoint | SHA-256, with `family_id`, `client_id`, `resource` | Once | 3600 s |
| OAuth refresh token | `aggr_` + 32 bytes | Token endpoint | SHA-256, same family | Once | Single use (rotated); 60 days |
| Owner credential | `aggown_` + 32 bytes | `agg-owner init` / `reset-credential` / `POST /owner/credential/rotate` | SHA-256 in `owners.secret_hash` | Once (or written to `owner.json` with `--save`) | Until rotated |
| Webhook signing secret | `whsec_` + base64 of 32 bytes | Server, on `set_callback_webhook` / `PUT /v1/webhook` | AES-256-GCM in `destinations.signing_secret_enc` | Once, in that response | Until the webhook is set again or cleared |
| Routine key (`auth_header_value`) | Whatever the receiver expects (one line, at most 2048 characters) | Agent or owner | AES-256-GCM in `destinations.auth_header_value_enc` | Never returned | Same as the webhook |
| Event subscription secret | `whsec_` + base64 of 24-64 bytes | The subscribing client | AES-256-GCM in `destinations.signing_secret_enc` | Never returned | Until it re-subscribes, unsubscribes or the subscription expires |
| Verification challenge | `chal_` + 24 bytes | Server, per `events/subscribe` | Not stored | Sent once to the callback | One request |
| Consent CSRF nonce and token | 32 random bytes; HMAC-SHA256 | Consent page | Not stored (cookie + form) | In the page | 15 minutes |
| `AGG_ENCRYPTION_KEY` | 64 hex characters (32 bytes) | `agg-server keygen` | Environment only | Never logged | Until rotated (below) |
| Database password | In `AGG_DATABASE_URL` | Operator | Environment only | Never logged (redacted if it appears in an error) | Operator's policy |

## Hashed, encrypted, never stored

- **Hashed (SHA-256, no salt):** everything the server only has to
  *recognize* — agent credentials, OAuth tokens and codes, setup codes, owner
  credentials. These are 256-bit (setup codes: about 98-bit, short-lived and
  single-use) random values, not passwords, so an unsalted fast hash is the
  right tool: a stolen database gives nothing to brute-force, and the digest
  is the lookup key. Hints are short, non-secret labels so a person can tell
  credentials apart.
- **Encrypted (AES-256-GCM, random 96-bit IV per value, format
  `v1:<iv>:<tag>:<ciphertext>`):** everything the server has to *use* later —
  webhook signing secrets, routine keys, subscription secrets. The key comes
  only from `AGG_ENCRYPTION_KEY`.
- **Never stored:** plaintext credentials, codes and owner credentials (only
  shown once), verification challenges, CSRF tokens, request bodies in logs,
  `Authorization` headers.

Comparisons of secrets the server holds in memory (verification challenges,
CSRF tokens, webhook signatures, PKCE) use constant-time comparison.

## Where clients keep secrets

| File | Written by | Mode |
| --- | --- | --- |
| `${XDG_CONFIG_HOME:-~/.config}/agent-aggregator/hub.json` | `agg setup` | 0600 (directory 0700) |
| `.../agent-aggregator/inbox.cursor` | `agg inbox` | 0600 |
| `.../agent-aggregator/owner.json` | `agg-owner init --save`, `reset-credential --save`, `rotate-credential --save` | 0600 (directory 0700) |
| `.../agent-aggregator/poller.env` | You, for `install-poller.sh` | Must be 0600: the installer refuses group- or world-readable files |
| `./data/aggregator.db` | `agg-server` (SQLite) | 0600 (directory 0700) |

`agg setup --print-token` prints the credential for a vault instead of writing
`hub.json`; pass it back as `AGG_TOKEN`.

## Rotation

| What | Command | Effect |
| --- | --- | --- |
| Agent credential | `agg-owner credential issue --connection <id>` | New credential; every earlier agent credential of that connection stops working in the same transaction |
| Setup code | `agg-owner claim-code --connection <id>` | New code; unused earlier codes are revoked |
| OAuth tokens | Client refreshes; or `POST /oauth/revoke token=<refresh or access token>` | Refresh rotates the pair; revoke kills the whole family |
| All of a connection's credentials and deliveries | `agg-owner connection revoke --id <id>` | Credentials, webhook and subscriptions gone; open questions and jobs cancelled |
| Owner credential | `agg-owner rotate-credential [--save]` (needs the current one) or `agg-owner reset-credential [--owner-id <id>] [--save]` (direct database access) | The previous owner credential stops working at once |
| Webhook signing secret / routine key | `set_callback_webhook` again (agent) or `agg-owner webhook set --connection <id> --url ... --header ... --value ...`, always with the routine key (current or new): the call replaces the whole configuration | New secret returned once; the old one no longer signs; deliveries still pending for the old configuration are dropped (catch up from the inbox) |
| Subscription secret | `events/subscribe` again with a new `secret` | Same subscription id, new secret and expiry |
| `AGG_ENCRYPTION_KEY` | See below | |

### Rotating the encryption key

The ciphertext format carries no key identifier, so the server uses exactly
one key. To rotate it:

1. Generate a new key: `npx agg-server keygen`.
2. Restart the server with the new `AGG_ENCRYPTION_KEY`.
3. Every stored webhook and subscription secret is now unreadable: their
   deliveries fail with `secret_unavailable` (final, not retried; events stay
   in the inbox). Set each webhook again (`set_callback_webhook` or
   `agg-owner webhook set`) and let OAuth clients re-subscribe.
4. Destroy the old key.

Consent forms open during the restart stop validating (the CSRF key is
derived from the encryption key); reloading the page fixes it.

## Key management

- Generate keys only with `agg-server keygen` (32 bytes from the operating
  system's CSPRNG) or an equivalent: `openssl rand -hex 32`.
- Keep `AGG_ENCRYPTION_KEY` in a secret manager or a 0600 environment file
  outside the repository; `.gitignore` already excludes `.env` and `.env.*`.
- Keep key backups separate from database backups; a backup of both is a
  backup of the delivery secrets.
- The server refuses to start with a key that is not exactly 64 hex characters.
