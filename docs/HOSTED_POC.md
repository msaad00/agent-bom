# Hosted POC Runbook

This runbook is for a gated customer-0 deployment: a live URL that shows how
agent-bom works, lets a small set of invited users connect read-only accounts,
and proves the product loop with operator-controlled access.

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

export NEXT_PUBLIC_API_URL="https://demo.agent-bom.com"
export CORS_ORIGINS="https://demo.agent-bom.com,http://ui:3000"
export AGENT_BOM_SESSION_COOKIE_SECURE=1

# All secrets are file mounts only — never .env / compose env.
python scripts/deploy/hosted_poc_preflight.py --write-secret --skip-compose
# Or write files manually — see deploy/secrets/README.md
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
API/UI ports bind publicly, required secrets are reused, audit integrity is
allowed to fall back to an ephemeral key, or the composed stack would mount
placeholder secrets. Run it again after any `.env`, DNS, or compose change.

Mint the first invited admin key from inside the API container so the key record
lands in the same persistent store used by the API:

```bash
docker compose \
  -f deploy/docker-compose.platform.yml \
  -f deploy/docker-compose.hosted-poc.yml \
  exec api \
  python scripts/deploy/mint_hosted_admin_key.py \
    --tenant-id customer-0 \
    --name customer-0-admin \
    --raw-key-file /tmp/customer0-admin.key
```

The JSON response includes key metadata only. The raw key is written once to the
private `0600` file passed with `--raw-key-file`; store that value in your
password manager, then delete or move the file into your secret store. Do not
commit it or paste it into docs, screenshots, tickets, or chat transcripts.

Run the hosted smoke before inviting anyone:

```bash
AGENT_BOM_SMOKE_URL="https://demo.agent-bom.com" \
AGENT_BOM_SMOKE_API_KEY="<raw admin key>" \
scripts/deploy/hosted_poc_smoke.sh
```

After at least one cloud/Snowflake connection is stored, verify the broker path
without launching a full scan:

```bash
AGENT_BOM_SMOKE_URL="https://demo.agent-bom.com" \
AGENT_BOM_SMOKE_API_KEY="<raw admin key>" \
AGENT_BOM_SMOKE_CONNECTION_ID="<connection id>" \
scripts/deploy/hosted_poc_smoke.sh
```

### Production auth checklist

For the gated POC, users are invited manually and access is revoked manually.
Keep the surface operator-controlled; this profile is not a public registration
flow.

Before sharing the link, verify:

| Boundary | Required setting |
|---|---|
| Browser session | `AGENT_BOM_BROWSER_SESSION_SIGNING_KEY` is set, random, and stored as a secret. `AGENT_BOM_SESSION_COOKIE_SECURE=1` is enabled behind HTTPS. |
| API auth | `AGENT_BOM_API_KEY` or OIDC/SAML/proxy auth is configured. `AGENT_BOM_ALLOW_UNAUTHENTICATED_API` is unset. |
| Tenant binding | Each invited account has an explicit tenant. Do not use default-tenant OIDC/SAML fallbacks for multi-tenant testing. |
| Connection broker | `AGENT_BOM_CONNECTIONS_KEY` is a Fernet key and is never committed, logged, or reused across unrelated environments. |
| Audit integrity | `AGENT_BOM_AUDIT_HMAC_KEY` is set and survives restarts so audit signatures remain verifiable. |
| MCP read access | `AGENT_BOM_MCP_BEARER_TOKEN` is tenant/environment-scoped and has an expiry where possible. |
| MCP write access | `AGENT_BOM_MCP_OPERATOR_TOKEN` is separate from the read token, expires, and is issued only to operators who need Shield/gateway write tools. |
| CORS/TLS | `CORS_ORIGINS` contains only the hosted URL and internal UI origin. Caddy/ALB terminates HTTPS; API/UI bind to loopback/private network only. |
| Usage control | Invitees have explicit scan windows, provider/account scope, and a manual revoke path before they connect a cloud or Snowflake account. |

If any row is unknown, stop and keep the deployment internal.

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

### Demo redeploy

Redeploying by hand (SSH in, `git pull`, `docker compose up`, rerun preflight +
smoke) is easy to forget after a release. The `.github/workflows/demo-redeploy.yml`
workflow automates it without any stored SSH keys or long-lived AWS credentials:

- **Triggers:** every published GitHub release, plus manual `workflow_dispatch`
  with an optional `reset_demo` boolean.
- **Transport:** AWS SSM Run Command (`AWS-RunShellScript`) against the demo
  instance — no inbound SSH. AWS auth is short-lived OIDC role assumption via
  `aws-actions/configure-aws-credentials`.
- **Remote steps on the VM:** `git pull --ff-only` → `docker compose -f
  deploy/docker-compose.platform.yml -f deploy/docker-compose.hosted-poc.yml up
  -d --build` → `scripts/deploy/hosted_poc_preflight.py --write-postgres-secret`
  (fail-closed) → `scripts/deploy/hosted_poc_smoke.sh`. The job fails if the
  preflight or smoke fails, so a bad redeploy never gets promoted silently. When
  dispatched with `reset_demo=true` it also runs `scripts/deploy/demo-reset.sh`.
- **No plaintext secrets in CI.** All secret material stays on the VM as the
  existing `deploy/secrets/` file mounts. The remote script sources an optional
  on-VM env file `deploy/secrets/redeploy.env` (chmod `0400`, owned by the deploy
  user) for the non-secret URL wiring the preflight needs and the admin key the
  smoke/reset need:

  ```bash
  # /opt/agent-bom/deploy/secrets/redeploy.env  (0400, not committed)
  NEXT_PUBLIC_API_URL="https://demo.agent-bom.com"
  CORS_ORIGINS="https://demo.agent-bom.com,http://ui:3000"
  AGENT_BOM_SMOKE_URL="https://demo.agent-bom.com"
  AGENT_BOM_SMOKE_API_KEY="<raw admin key>"
  # AGENT_BOM_DEMO_TENANT="default"   # only needed if reset targets a non-default tenant
  ```

The workflow is **inert until configured** — if `DEMO_INSTANCE_ID` is unset it
logs the required settings and exits successfully instead of failing. To enable
it, set these repo Actions **variables** and **secret**:

| Setting | Kind | Purpose |
|---|---|---|
| `DEMO_INSTANCE_ID` | var | EC2 instance id of the demo VM (`i-...`). Gate: unset ⇒ workflow no-ops. |
| `AWS_REGION` | var | Region of the demo VM. Defaults to `us-east-1` if unset. |
| `DEMO_DEPLOY_DIR` | var | Repo checkout dir on the VM. Defaults to `/opt/agent-bom`. |
| `DEMO_DEPLOY_ROLE_ARN` | secret | IAM role ARN the workflow assumes via OIDC. Its trust policy must allow this repo's GitHub OIDC subject, and its permissions must allow `ssm:SendCommand` / `ssm:GetCommandInvocation` on the instance. |

The instance also needs the SSM agent running and an instance profile granting
`AmazonSSMManagedInstanceCore` so Run Command can reach it.

#### Public-repo hardening (required)

This repo is public, so fork/PR contributors must never be able to trigger the
deploy or assume the AWS role. Two independent defenses:

- **Protected environment.** The deploy job declares `environment: demo`. Create
  a repo Actions **Environment** named `demo` with **yourself as a required
  reviewer**, and optionally restrict its deployment branches/tags to the default
  branch and `v*.*.*` tags. Then every `release` / `workflow_dispatch` run
  **pauses for your approval** before any AWS call. The workflow has **no**
  `pull_request` / `pull_request_target` trigger — it is release +
  `workflow_dispatch` only, so PRs cannot start it at all.
- **Scoped OIDC trust.** Provision the deploy role with the
  `deploy/terraform/demo-deploy-oidc` module. Its trust policy pins the GitHub
  OIDC `sub` to **exactly** `repo:<owner>/<repo>:environment:demo` (StringEquals,
  no wildcard) and grants only `ssm:SendCommand` to the demo instance +
  `ssm:GetCommandInvocation`. Fork/PR runs present a different `sub` and STS
  rejects them. `terraform output -raw role_arn` gives the value for
  `DEMO_DEPLOY_ROLE_ARN`.

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

- Do not present the AWS demo as anything beyond an invite-only hosted POC.
- Do not ask testers for long-lived cloud keys when assumable roles work.
- Do not enable unauthenticated API access.
- Do not publish Grafana, observability, or development compose profiles.
- Do not run Snowflake GPU pools for agent-bom.
