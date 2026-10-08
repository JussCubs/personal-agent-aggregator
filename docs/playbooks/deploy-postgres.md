# Playbook: deploy on Postgres

**Goal:** the reference server running as a service on a Linux host, storing
data in Postgres with forced row-level security, reachable at an https
`AGG_PUBLIC_URL` behind a TLS-terminating reverse proxy, with a tested backup.

**You need:** PostgreSQL 16 or newer and an admin connection string
(`ADMIN_URL`) for it; a Linux host with Node.js 22.5+, git and systemd; a DNS
name for the server (`aggregator.example.com` below) and a reverse proxy that
terminates TLS for it. For Supabase use [deploy on Supabase](deploy-supabase.md).

**Conventions:** run each command, compare with *Expected*, run *Check*
(prints `PASS` or `FAIL`), stop at the first `FAIL`.

## 1. Check the database

```sh
export ADMIN_URL='postgres://postgres:<admin password>@db.example.com:5432/postgres?sslmode=verify-full'
export PGSSLROOTCERT=system   # libpq 16+: verify against the system CAs; or the path of the provider's CA file
psql "$ADMIN_URL" -Atc "SELECT current_setting('server_version_num')::int >= 160000"
```

Expected: `t`. `PGSSLROOTCERT` is for the PostgreSQL client tools (`psql`,
`pg_dump`, `pg_restore`) used in this playbook; the server itself uses
Node's CA store plus `NODE_EXTRA_CA_CERTS` (step 4).

Check:

```sh
test "$(psql "$ADMIN_URL" -Atc "SELECT current_setting('server_version_num')::int >= 160000")" = t && echo PASS || echo FAIL
```

## 2. Create the API role

```sh
DB_PASSWORD=$(node -e 'console.log(require("crypto").randomBytes(24).toString("base64url"))')
psql "$ADMIN_URL" -v ON_ERROR_STOP=1 \
  -c "CREATE ROLE aggregator_api LOGIN BYPASSRLS CREATEROLE PASSWORD '$DB_PASSWORD'" \
  -c "GRANT CREATE ON SCHEMA public TO aggregator_api"
```

Expected: `CREATE ROLE` and `GRANT`. Why these attributes:
[storage](../storage.md#why-the-api-role-needs-bypassrls-and-createrole).

Check:

```sh
test "$(psql "$ADMIN_URL" -Atc "SELECT rolbypassrls AND rolcreaterole AND NOT rolsuper FROM pg_roles WHERE rolname = 'aggregator_api'")" = t && echo PASS || echo FAIL
```

## 3. Install the server

```sh
sudo useradd --system --home-dir /opt/personal-agent-aggregator --shell /usr/sbin/nologin aggregator
sudo git clone <repository-url> /opt/personal-agent-aggregator
cd /opt/personal-agent-aggregator && sudo npm ci && sudo npm run build
```

Check:

```sh
test "$(node /opt/personal-agent-aggregator/packages/server/bin/agg-server.js --version)" = "0.2.1" && echo PASS || echo FAIL
```

## 4. Write the environment file

```sh
sudo install -m 600 -o aggregator -g aggregator /dev/null /etc/agent-aggregator.env
sudo tee /etc/agent-aggregator.env >/dev/null <<EOF
AGG_DATABASE_URL=postgres://aggregator_api:$DB_PASSWORD@db.example.com:5432/postgres?sslmode=verify-full
AGG_ENCRYPTION_KEY=$(node /opt/personal-agent-aggregator/packages/server/bin/agg-server.js keygen)
AGG_PUBLIC_URL=https://aggregator.example.com
AGG_HOST=127.0.0.1
AGG_PORT=8787
AGG_TRUST_PROXY=1
EOF
```

If the database's CA is not publicly trusted, add
`NODE_EXTRA_CA_CERTS=/etc/ssl/certs/<provider-ca>.crt`. Store a copy of
`AGG_ENCRYPTION_KEY` in your secret manager now ([secrets](../security/secrets.md)).

Check:

```sh
sudo stat -c '%a %U' /etc/agent-aggregator.env | grep -qx '600 aggregator' && echo PASS || echo FAIL
```

For the remaining manual commands, open a root shell with `sudo -i` and set
everything again there (`sudo -i` starts with a fresh environment):

```sh
export ADMIN_URL='postgres://postgres:<admin password>@db.example.com:5432/postgres?sslmode=verify-full'
export PGSSLROOTCERT=system
set -a && . /etc/agent-aggregator.env && set +a
cd /opt/personal-agent-aggregator
```

## 5. Migrate and run the doctor

```sh
node packages/server/bin/agg-server.js migrate
node packages/server/bin/agg-server.js doctor
```

Expected: `{"ok":true,"storage":"postgres","schema":"public","schema_version":"<16 hex>"}`,
then a doctor line with `"ok":true` and six checks: `role_bypassrls`
(`bypassrls=true superuser=false`), `role_can_switch`, `schema_current`,
`rls_forced` (`13/13 tables ...`), `public_roles_revoked`, `scoped_roles`.

Check:

```sh
node packages/server/bin/agg-server.js doctor >/dev/null && echo PASS || echo FAIL
```

Then run the SQL checks in [verify RLS](verify-rls.md) against `ADMIN_URL`.

## 6. Create the owner

```sh
node packages/server/bin/agg-owner.js init --name "Your name"
```

Expected: `{"ok":true,"owner_id":"<uuid>","name":"Your name","credential":"aggown_...","note":"Shown once. ..."}`.
Put the credential in your password manager now. On the machine where you
run `agg-owner` day to day, store it owner-only:

```sh
(umask 077 && mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/agent-aggregator" && \
  printf '{"server":"https://aggregator.example.com","token":"%s"}\n' '<owner credential>' > "${XDG_CONFIG_HOME:-$HOME/.config}/agent-aggregator/owner.json")
```

Check:

```sh
test "$(psql "$ADMIN_URL" -Atc 'SELECT count(*) FROM aggregator_owners')" -ge 1 && echo PASS || echo FAIL
```

## 7. Run as a service

```sh
sudo tee /etc/systemd/system/agent-aggregator.service >/dev/null <<'EOF'
[Unit]
Description=Personal agent aggregator
After=network-online.target
Wants=network-online.target

[Service]
User=aggregator
Group=aggregator
EnvironmentFile=/etc/agent-aggregator.env
WorkingDirectory=/opt/personal-agent-aggregator
ExecStart=/usr/bin/env node packages/server/bin/agg-server.js
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable --now agent-aggregator
```

`ExecStart` needs `node` on the service's `PATH`; otherwise use its absolute
path. Logs are JSON lines in the journal: `journalctl -u agent-aggregator -f`.

Check:

```sh
curl -fsS http://127.0.0.1:8787/healthz | grep -q '"ok":true' && echo PASS || echo FAIL
```

## 8. Put the reverse proxy in front

Configure the proxy for `aggregator.example.com` to:

- terminate TLS and forward every path to `http://127.0.0.1:8787`;
- append the client address to `X-Forwarded-For` (the server takes the
  right-most entry because `AGG_TRUST_PROXY=1`; never set it with more than
  one proxy hop or with the port exposed directly);
- allow request bodies of at least 256 KiB and not buffer or rewrite
  `WWW-Authenticate`, `Location` and `Set-Cookie` headers.

Check (from another machine):

```sh
curl -fsS https://aggregator.example.com/.well-known/oauth-authorization-server | grep -q '"issuer":"https://aggregator.example.com"' && echo PASS || echo FAIL
```

## 9. Test a backup and restore

```sh
with_db() { node -e 'const u = new URL(process.argv[1]); u.pathname = "/" + process.argv[2]; console.log(u.toString())' "$1" "$2"; }
pg_dump --format=custom --data-only --table='public.aggregator_*' "$AGG_DATABASE_URL" > /var/backups/aggregator.dump
psql "$ADMIN_URL" -c 'CREATE DATABASE aggregator_restore_test'
psql "$(with_db "$ADMIN_URL" aggregator_restore_test)" -c 'GRANT CREATE ON SCHEMA public TO aggregator_api'
TARGET_URL=$(with_db "$AGG_DATABASE_URL" aggregator_restore_test)
AGG_DATABASE_URL="$TARGET_URL" node packages/server/bin/agg-server.js migrate
pg_restore --data-only --single-transaction --dbname="$TARGET_URL" /var/backups/aggregator.dump
```

Expected: no errors. Check:

```sh
test "$(psql "$TARGET_URL" -Atc 'SELECT count(*) FROM aggregator_owners')" = "$(psql "$AGG_DATABASE_URL" -Atc 'SELECT count(*) FROM aggregator_owners')" && echo PASS || echo FAIL
```

Clean up with `psql "$ADMIN_URL" -c 'DROP DATABASE aggregator_restore_test'`.
Schedule the `pg_dump` line (or rely on the provider's backups) and keep the
encryption key backed up separately.

## 10. Upgrade

```sh
cd /opt/personal-agent-aggregator && sudo git pull && sudo npm ci && sudo npm run build && sudo systemctl restart agent-aggregator
```

The server migrates on start. Check:

```sh
sudo -u aggregator sh -c 'set -a && . /etc/agent-aggregator.env && node /opt/personal-agent-aggregator/packages/server/bin/agg-server.js doctor' >/dev/null && echo PASS || echo FAIL
```

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| migrate: `{"error":{"code":"startup","message":"PostgresError P0001: aggregator_api needs SET membership in aggregator_agent; recreate the role under createrole_self_grant=set"}}` | The scoped roles exist already (created by another role) | As that role or a superuser: `GRANT aggregator_agent, aggregator_owner TO aggregator_api;`, then migrate again |
| migrate: `permission denied for schema public` | Step 2's `GRANT CREATE` missing | Run it again |
| doctor `role_bypassrls` fails | The role lacks `BYPASSRLS` | `ALTER ROLE aggregator_api BYPASSRLS;` as a superuser |
| `{"error":{"code":"config","message":"AGG_PUBLIC_URL must use https unless it is a loopback address ..."}}` | `AGG_PUBLIC_URL` is http | Use the https URL the proxy serves |
| Every client gets 429 | `AGG_TRUST_PROXY` unset: all requests appear to come from the proxy | Set `AGG_TRUST_PROXY=1` |
| `self-signed certificate in certificate chain` | `sslmode=verify-full` and a private CA | `NODE_EXTRA_CA_CERTS` (step 4) |
