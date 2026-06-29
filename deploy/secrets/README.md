# Compose secrets directory

Used by `deploy/docker-compose.platform.yml` (and any production-shaped compose
overlay) to mount Postgres credentials as files instead of env vars.

Populate before `docker compose up`:

```bash
# Postgres admin password (mandatory for platform.yml)
printf %s "$POSTGRES_PASSWORD" > deploy/secrets/postgres_password
chmod 0400 deploy/secrets/postgres_password
```

`postgres_password.example` is a non-secret placeholder for documentation only.
The platform compose file defaults to `deploy/secrets/postgres_password` so a
shared stack fails closed if a real secret file is missing.

The `chmod 0400` prevents the file from being world-readable; Docker still
mounts it read-only inside the container at `/run/secrets/postgres_password`.

The postgres image natively reads `POSTGRES_PASSWORD_FILE` from this mount,
so the password never appears in `docker inspect`, `docker compose config`,
or process environment listings. Tracking: #1962.

Hosted POC preflight:

```bash
POSTGRES_PASSWORD=preflight POSTGRES_APP_PASSWORD=preflight docker compose \
  -f deploy/docker-compose.platform.yml \
  -f deploy/docker-compose.hosted-poc.yml \
  config | grep -E '0.0.0.0:3000|0.0.0.0:8422|postgres_password.example' && \
  { echo "Unsafe hosted compose output"; exit 1; } || true
```

For the hosted POC, also set `AGENT_BOM_SESSION_COOKIE_SECURE=1`; the hosted
overlay sets it for the API service by default.
