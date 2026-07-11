# Compose secrets directory

Used by `deploy/docker-compose.platform.yml`, `docker-compose.fullstack.yml`,
and `docker-compose.yml` to mount credentials as files instead of env vars.
Secrets must never live in `.env`, compose interpolation, or git.

Populate before `docker compose up` (or run
`python scripts/deploy/hosted_poc_preflight.py --write-secret --skip-compose`):

```bash
mkdir -p deploy/secrets

# Postgres: bootstrap (image init only) + DML-only app role (API)
printf %s "$(openssl rand -hex 32)" > deploy/secrets/postgres_password
printf %s "$(openssl rand -hex 32)" > deploy/secrets/postgres_app_password

# Control-plane crypto / auth material
printf %s "$(openssl rand -hex 32)" > deploy/secrets/api_key
printf %s "$(openssl rand -hex 32)" > deploy/secrets/audit_hmac_key
printf %s "$(openssl rand -hex 32)" > deploy/secrets/browser_session_signing_key
printf %s "$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')" \
  > deploy/secrets/connections_key

# Optional (mount manually or via preflight --write-secret)
# printf %s "$(openssl rand -hex 32)" > deploy/secrets/rate_limit_key
# printf %s "$(openssl rand -hex 32)" > deploy/secrets/trust_proxy_auth_secret
# printf %s "$(openssl rand -hex 32)" > deploy/secrets/scim_bearer_token

chmod 0400 deploy/secrets/postgres_password deploy/secrets/postgres_app_password \
  deploy/secrets/api_key deploy/secrets/audit_hmac_key \
  deploy/secrets/browser_session_signing_key deploy/secrets/connections_key
```

`*.example` files are non-secret documentation placeholders only.
Compose defaults to the real `deploy/secrets/*` paths so a shared stack fails
closed if a real secret file is missing.

The API reads `AGENT_BOM_*_FILE` mounts (file wins over plain env). Helm may
still inject via Secret→env; compose/local is file-only. This file-first
resolution also covers the signing PEMs, so a mounted file works everywhere the
inline env var did:

- `AGENT_BOM_OAUTH_AS_PRIVATE_KEY_PEM_FILE` — RSA PEM for the OAuth AS token
  signing key (unset → ephemeral per-restart key).
- `AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM_FILE` — Ed25519 PEM for
  compliance-bundle signing (unset → HMAC-SHA256 fallback).

The API never connects as the Postgres bootstrap/admin/superuser role — only
`agent_bom_app`.
