# Compose secrets directory

Used by `deploy/docker-compose.platform.yml` (and any production-shaped compose
overlay) to mount Postgres credentials as files instead of env vars.

Populate before `docker compose up`:

```bash
# Postgres admin password (mandatory for platform.yml)
printf %s "$POSTGRES_PASSWORD" > deploy/secrets/postgres_password
chmod 0400 deploy/secrets/postgres_password
```

`postgres_password.example` is a non-secret placeholder for first-run
`docker compose config` rendering only. Copy it to `postgres_password` or
write a real secret before starting any shared or long-lived stack.

The `chmod 0400` prevents the file from being world-readable; Docker still
mounts it read-only inside the container at `/run/secrets/postgres_password`.

The postgres image natively reads `POSTGRES_PASSWORD_FILE` from this mount,
so the password never appears in `docker inspect`, `docker compose config`,
or process environment listings. Tracking: #1962.
