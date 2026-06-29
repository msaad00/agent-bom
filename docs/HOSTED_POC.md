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

mkdir -p deploy/secrets
printf '%s' "$POSTGRES_PASSWORD" > deploy/secrets/postgres_password
chmod 0400 deploy/secrets/postgres_password
```

Start the platform:

```bash
docker compose -f deploy/docker-compose.platform.yml up -d --build
docker compose -f deploy/docker-compose.platform.yml ps
```

Seed a disposable demo graph after the API is healthy:

```bash
docker compose -f deploy/docker-compose.platform.yml exec api \
  agent-bom quickstart --run --offline --force
```

The compose profile persists `/root/.agent-bom` in a named volume so the seeded
demo graph survives container replacement. Replace it with real connected
cloud scans as soon as the first account is connected.

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
and the API/UI ports can be restricted to the VM security boundary once the
front door is verified.

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
