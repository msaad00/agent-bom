# Hosted POC Runbook

This runbook is for a gated customer-0 deployment: a live URL that shows how
agent-bom works, lets a small set of users connect read-only accounts, and
proves the product loop before a managed cloud edition is offered.

It is not a claim that public `agent-bom Cloud` is generally available.

## Recommended path

Use an AWS VM first for the public demo URL, then keep Snowflake Native App as
the enterprise distribution lane. Recommended domain split:

- `agentbom.io` — primary product/brand site.
- `demo.agent-bom.com` — public seeded demo.
- `app.agent-bom.com` — gated customer-0 / hot-lead POC.

For the domains you already own, use `agent-bom.com` on Cloudflare for the
first live link because DNS, proxying, and TLS controls are already in one
place. Keep `agentbom.io` for the cleaner product site once the public surface
is ready.

| Need | Use | Why |
|---|---|---|
| Public demo link | AWS VM + Caddy + platform compose | Fastest custom URL, simple TLS, works for any tester |
| Customer-owned warehouse install | Snowflake Native App | Runs inside the customer's Snowflake account with Snowflake auth and SPCS |
| Later managed product | Hosted chart + connect roles | Same control plane, stricter tenant onboarding and quotas |

## Customer-0 AWS VM

Run one small CPU-only VM. Recommended starting point:

- Instance: `t3.large` or equivalent, 4 vCPU / 8-16 GB RAM
- OS: Ubuntu LTS or Amazon Linux
- Region: closest to you and the first demo users
- Security group: `443` open; SSH/admin only from your IP

1. Create DNS, for example `demo.agent-bom.com`, pointing to the VM.
2. Open inbound `443` only. Restrict SSH/admin access to known IPs.
3. Install Docker, Compose, and Caddy.
4. Deploy `deploy/docker-compose.platform.yml`.
5. Use Caddy or an ALB for HTTPS. Do not expose plain HTTP.
6. Set production secrets:
   - `AGENT_BOM_AUDIT_HMAC_KEY`
   - `AGENT_BOM_BROWSER_SESSION_SIGNING_KEY`
   - `AGENT_BOM_CONNECTIONS_KEY`
   - the initial admin API key or OIDC reverse-proxy session settings
7. Keep `AGENT_BOM_ALLOW_UNAUTHENTICATED_API` unset.
8. Mint one admin tenant/key for the customer-0 account.
9. Connect read-only AWS, Azure, GCP, and Snowflake targets.
10. Run the first scan and verify findings, graph, posture, and exports.

This gives prospects the product experience: sign in, connect read-only,
scan, inspect graph/blast radius, and export evidence.

### Cloudflare DNS

For `agent-bom.com`, create one proxied `A` record per lane:

| Record | Target | Purpose |
|---|---|---|
| `demo.agent-bom.com` | AWS VM public IPv4 | seeded public demo |
| `app.agent-bom.com` | AWS VM public IPv4 | gated customer-0 account |

Use Cloudflare proxy mode or DNS-only mode consistently with the chosen TLS
setup:

- **DNS-only + Caddy** — simplest. Caddy terminates Let's Encrypt directly.
- **Proxied + Caddy** — set Cloudflare SSL mode to `Full (strict)` and let
  Caddy still hold a valid origin certificate.

Do not point the apex/root domain at the POC VM unless it is also serving the
product site.

### Minimal VM setup

Generate local secrets on the VM:

```bash
cp .env.example .env

export POSTGRES_PASSWORD="$(openssl rand -hex 32)"
export POSTGRES_APP_PASSWORD="$(openssl rand -hex 32)"
export AGENT_BOM_API_KEY="$(openssl rand -hex 32)"
export AGENT_BOM_AUDIT_HMAC_KEY="$(openssl rand -hex 32)"
export AGENT_BOM_BROWSER_SESSION_SIGNING_KEY="$(openssl rand -hex 32)"
export AGENT_BOM_CONNECTIONS_KEY="$(
  python - <<'PY'
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
PY
)"
export NEXT_PUBLIC_API_URL="https://demo.agent-bom.com"
export CORS_ORIGINS="https://demo.agent-bom.com,http://ui:3000"
export AGENT_BOM_SESSION_COOKIE_SECURE=1

mkdir -p deploy/secrets
printf '%s' "$POSTGRES_PASSWORD" > deploy/secrets/postgres_password
chmod 0400 deploy/secrets/postgres_password
```

Start the platform:

```bash
docker compose \
  -f deploy/docker-compose.platform.yml \
  -f deploy/docker-compose.hosted-poc.yml \
  up -d --build

docker compose \
  -f deploy/docker-compose.platform.yml \
  -f deploy/docker-compose.hosted-poc.yml \
  ps
```

Seed a disposable demo graph after the API is healthy:

```bash
docker compose \
  -f deploy/docker-compose.platform.yml \
  -f deploy/docker-compose.hosted-poc.yml \
  exec api \
  agent-bom quickstart --run --offline --force
```

The compose profile persists `/root/.agent-bom` in a named volume so the seeded
demo graph survives container replacement. Replace it with real connected
cloud scans as soon as the first account is connected.

Before opening the VM to testers, confirm the composed stack does not expose
API/UI ports on all interfaces and does not mount the placeholder Postgres
password:

```bash
python scripts/deploy/hosted_poc_preflight.py --write-postgres-secret
```

The preflight fails closed when required secrets are missing, the browser API
URL is still localhost, CORS is wildcarded, unauthenticated API mode is enabled,
API/UI ports bind publicly, or the composed stack would mount placeholder
secrets. Run it again after any `.env`, DNS, or compose change.

### Caddy front door

Example `Caddyfile`:

```caddyfile
demo.agent-bom.com {
  encode zstd gzip

  reverse_proxy /v1/* localhost:8422
  reverse_proxy /health localhost:8422
  reverse_proxy /openapi.json localhost:8422
  reverse_proxy localhost:3000
}
```

Keep Caddy as the only public listener. The Postgres container remains internal
and `deploy/docker-compose.hosted-poc.yml` binds the API/UI ports to loopback,
so they are reachable only from Caddy on the VM.

### Customer-0 proof checklist

Run this checklist before inviting anyone:

1. `https://demo.agent-bom.com/health` returns healthy through Caddy.
2. The UI opens at `https://demo.agent-bom.com` and does not require direct
   access to ports `3000` or `8422`.
3. `AGENT_BOM_ALLOW_UNAUTHENTICATED_API` is unset.
4. A seeded scan appears in the dashboard with findings, graph, posture, and
   export links.
5. Connections can add at least one read-only cloud account or Snowflake
   account.
6. A connection scan hands off to scan details, findings, graph, jobs, and
   compliance surfaces.
7. Audit export and compliance export work for the customer-0 tenant.

If any item fails, treat the POC as not ready for external users.

## Snowflake Native App lane

Use Snowflake when the buyer wants agent-bom to run inside their Snowflake
account. This is the stronger enterprise data-boundary story, but it has more
packaging steps than a VM demo.

### CPU sizing

agent-bom is CPU-only. It scans packages, cloud metadata, IaC, graph evidence,
and model artifacts with lightweight static analysis. It does not perform GPU
model inference.

Use:

- `CPU_X64_XS` for the first smoke test.
- `CPU_X64_S` for a more comfortable POC with UI + API + scanner.

Do not use GPU pools for agent-bom.

### SPCS gate

Confirm the account can create a Snowpark Container Services pool:

```sql
USE ROLE ACCOUNTADMIN;

CREATE COMPUTE POOL AGENT_BOM_POC_POOL
  MIN_NODES = 1
  MAX_NODES = 1
  INSTANCE_FAMILY = CPU_X64_XS
  AUTO_RESUME = TRUE;

DROP COMPUTE POOL AGENT_BOM_POC_POOL;
```

If this succeeds, the account can run the Native App containers.

### Stand-up checklist

1. Run the Snowflake Native App package validation:

   ```bash
   gh workflow run release-snowflake.yml -f dry_run=true
   ```

2. Build and push the four release-tagged images to the Snowflake image
   repository:

   - `agent-bom`
   - `agent-bom-ui`
   - `agent-bom-scanner`
   - `agent-bom-mcp-runtime`

3. Create the application package and application in the demo account.
4. Bind only the references the demo needs: cloud asset tables, IAM tables,
   vulnerability tables, log tables, and artifact stages.
5. Leave advisory egress disabled unless the demo needs OSV, CISA KEV, EPSS,
   or GHSA enrichment.
6. Open the default web endpoint for the UI.
7. Run:

   ```sql
   CALL agent_bom.core.health_check();
   SHOW SERVICES IN APPLICATION agent_bom;
   ```

8. Enable optional services only when needed:

   ```sql
   CALL agent_bom.core.enable_scanner_service();
   CALL agent_bom.core.enable_mcp_runtime_service('<32+ character token>');
   ```

## What to avoid

- Do not present the AWS demo as generally available managed SaaS.
- Do not ask testers for long-lived cloud keys when assumable roles work.
- Do not enable unauthenticated API access.
- Do not publish Grafana, observability, or development compose profiles.
- Do not run Snowflake GPU pools for agent-bom.
