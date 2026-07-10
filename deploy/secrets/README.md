# Compose secrets directory

Used by `deploy/docker-compose.platform.yml`, `docker-compose.fullstack.yml`,
and `docker-compose.yml` to mount Postgres credentials as files instead of env
vars. Passwords must never live in `.env`, compose interpolation, or git.

Populate before `docker compose up`:

```bash
# Bootstrap role secret (Postgres image init only — API never uses this role)
printf %s "$(openssl rand -hex 32)" > deploy/secrets/postgres_password
chmod 0400 deploy/secrets/postgres_password

# DML-only app role secret (agent_bom_app — what the API uses)
printf %s "$(openssl rand -hex 32)" > deploy/secrets/postgres_app_password
chmod 0400 deploy/secrets/postgres_app_password
```

`*.example` files are non-secret documentation placeholders only.
Compose defaults to the real `deploy/secrets/postgres_*` paths so a shared
stack fails closed if a real secret file is missing.

The `chmod 0400` prevents the file from being world-readable; Docker still
mounts it read-only inside the container at `/run/secrets/...`.

The postgres image reads `POSTGRES_PASSWORD_FILE` from the bootstrap mount.
The API reads `AGENT_BOM_POSTGRES_PASSWORD_FILE` for `agent_bom_app` and never
connects as the bootstrap/admin/superuser role.

Hosted POC preflight writes both secret files when asked (`--write-secret`).
