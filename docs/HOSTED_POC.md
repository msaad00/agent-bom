# Hosted deployment runbook

Two unrelated deployments live in this file. Read the one you need:

| Lane | Who runs it | What it is |
|---|---|---|
| [Public demo](#public-demo-cloud-run) | This project | A stateless, anonymous, seeded estate on Cloud Run. Deployed by CI. Nothing for you to stand up. |
| [Self-host](#self-host-your-own-instance) | You | A gated instance on your own infrastructure that holds real connections and state in Postgres. |
| [Snowflake Native App](#snowflake-native-app-lane) | Your buyer | agent-bom running inside the customer's own Snowflake account. |

They differ in the property that matters: the demo keeps **nothing** between
boots, so it can be a scale-to-zero container. A self-hosted instance holds real
connections, so it needs a persistent Postgres and a real secret story.

## Public demo (Cloud Run)

The public demo runs on **Google Cloud Run**, deployed by
[`.github/workflows/demo-deploy-cloudrun.yml`](../.github/workflows/demo-deploy-cloudrun.yml).
It serves the seeded estate anonymously at viewer role — there is no login, no
Postgres, and no VM.

The service is reachable at its Cloud Run URL
(`https://<service>-<project-number>.<region>.run.app`); the exact URL is linked
from the README and printed in each deploy's job summary. **No custom domain is
currently mapped** — see [Custom domain](#custom-domain-optional).

### How a deploy happens

1. The **Release** workflow finishes successfully. This workflow triggers on
   `workflow_run` completion rather than on the release event directly, because
   a direct release trigger races the still-running release and would deploy
   twice. Manual `workflow_dispatch` is also supported, with an optional
   `image_ref` to pin a specific tag.
2. The run pauses on the protected `demo` environment for owner approval. The
   repository is public and the workflow has no `pull_request` trigger, so a
   fork can neither start it nor reach the cloud credentials.
3. The job authenticates to Google Cloud with **Workload Identity Federation
   over OIDC** (`google-github-actions/auth`). No service-account key is stored
   in this repository.
4. It deploys `ghcr.io/<owner>/agent-bom:<tag>` to the Cloud Run service. The
   published image is the CLI (`ENTRYPOINT agent-bom`, default `CMD --help`), so
   the workflow overrides the args to `api --host 0.0.0.0 --port 8080`, matching
   how `docker-compose.platform.yml` starts it. `8080` is the port Cloud Run
   routes to by default.
5. It verifies the result, and **fails closed** on either of the two failure
   modes that a plain `200` would hide:
   - `/health` must report the version that was just deployed, so a deploy that
     silently keeps serving the previous revision is caught.
   - `/v1/findings?limit=1` must report a non-empty total, so a demo that boots
     at the right version over an unseeded estate is caught. Every visitor
     landing on empty tables is an outage, not a healthy deploy.

A `concurrency` group (`demo-deploy-cloudrun`, `cancel-in-progress: false`)
serializes deploys, so two releases can never race on the same service.

### Configuration

All settings live on the protected `demo` environment. The workflow stays inert
until they exist — an unconfigured fork or clone logs the required settings and
exits successfully rather than failing.

| Setting | Purpose |
| --- | --- |
| `vars.DEMO_GCP_PROJECT` | GCP project id hosting the demo |
| `vars.DEMO_CLOUD_RUN_SERVICE` | Cloud Run service name (e.g. `agent-bom-demo`) |
| `secrets.DEMO_GCP_WIF_PROVIDER` | Workload Identity provider resource name |
| `secrets.DEMO_GCP_SERVICE_ACCOUNT` | Service account the workflow impersonates |
| `vars.DEMO_GCP_REGION` | Optional; defaults to `us-central1` |
| `vars.DEMO_MIN_INSTANCES` | Optional; defaults to `0` (scale to zero) |
| `vars.DEMO_MAX_INSTANCES` | Optional; defaults to `2` (hard ceiling on concurrent instances) |

The demo container opts into the anonymous seeded estate with the same three
environment variables the self-host overlay `deploy/docker-compose.demo-override.yml`
sets, so the two ways of running the demo cannot drift apart:

```
AGENT_BOM_DEMO_ESTATE=1
AGENT_BOM_ALLOW_UNAUTHENTICATED_API=1
AGENT_BOM_NO_AUTH_ROLE=viewer
```

### Why not a VM

The demo is a stateless container: it seeds its estate in-process from
`agent_bom.demo_estate`, bakes no advisory database, and keeps nothing worth
preserving between boots — the curated scan job is TTL-wiped and reseeded by the
API's own cleanup loop. An always-on VM therefore bills around the clock to
serve traffic that arrives in bursts. `--min-instances=0` scales to zero, so an
idle demo costs nothing.

**The tradeoff.** The first visitor after an idle period pays a cold start
(image pull, boot, demo seed). If that becomes unacceptable, set
`vars.DEMO_MIN_INSTANCES=1`; it is wired into the workflow and costs roughly one
always-on small instance.

### Cost posture

Cloud Run bills CPU only while a request is executing, so a demo sitting at
`--min-instances=0` costs **nothing** when nobody is looking at it. The free
tier is 2M requests, 400,000 vCPU-seconds and 1M GiB-seconds per month, which a
demo does not realistically exceed on organic traffic.

The exposure is therefore not steady-state hosting — it is a crawler hammering
the URL. Three settings bound that, and all are in the workflow:
`--max-instances` caps how much can ever run at once, `--concurrency=80` packs
more requests onto each instance so load costs fewer instances rather than more,
and `--timeout=60` bounds what any single abusive request can spend.

Set a GCP **budget alert** on the project as the backstop; it is free, and it is
the only mechanism that tells you about a surprise before the invoice does.

### Custom domain (optional)

The demo is served from its Cloud Run URL. Mapping `demo.agent-bom.com` to it is
an **optional future step**, not an outstanding fault — nothing depends on the
custom domain today, and the README links the Cloud Run URL directly.

If you do map it, note that Google documents three paths and they are not
equivalent:

- **Global external Application Load Balancer** — Google's recommended,
  generally-available option, and the right choice for anything load-bearing.
- **Cloud Run domain mappings** — a one-command path
  (`gcloud beta run domain-mappings create --service SERVICE --domain DOMAIN`),
  but it is in **preview**, explicitly not production-ready, and available in
  only a subset of regions. `us-central1` (this deploy's default) is one of
  them.
- **Firebase Hosting** — a third option Google documents.

Either way, ownership of the domain must first be verified through Google Search
Console unless it was bought through Google. See
[Cloud Run: mapping custom domains](https://cloud.google.com/run/docs/mapping-custom-domains)
for current details; the preview status and the supported-region list both move.

Whatever is chosen, point DNS at the new front door — **not** at any prior
origin. The demo has no non-Cloud-Run origin.

## Self-host: your own instance

This lane is for an instance **you** operate: a gated deployment that holds real
connections and state, for a customer-0 POC, an internal pilot, or your own
production use. It is not how the public demo above runs, and it needs a
persistent Postgres.

Throughout this section, `agent-bom.example.com` stands in for your own
hostname.

### Host sizing

One small CPU-only host is enough to start:

- 4 vCPU / 8-16 GB RAM
- Ubuntu LTS or equivalent
- A region close to you and your first users
- Inbound `443` from your trusted edge only; no inbound SSH/admin port. Use your
  cloud's session-manager equivalent for operator access.

### Stand-up

1. Point DNS for your hostname at the host.
2. Allow inbound `443` only from the trusted edge (for example, your CDN's
   published proxy CIDRs).
3. Install Docker, Compose, and a TLS terminator (Caddy below, or a managed load
   balancer).
4. Deploy `deploy/docker-compose.platform.yml`.
5. Terminate HTTPS at the front door. Do not expose plain HTTP.
6. Set production secrets:
   - `AGENT_BOM_AUDIT_HMAC_KEY`
   - `AGENT_BOM_BROWSER_SESSION_SIGNING_KEY`
   - `AGENT_BOM_CONNECTIONS_KEY`
   - the initial admin API key or OIDC reverse-proxy session settings
7. Keep `AGENT_BOM_ALLOW_UNAUTHENTICATED_API` unset.
8. Mint one admin tenant/key for the first account.
9. Connect read-only AWS, Azure, GCP, and Snowflake targets.
10. Run the first scan and verify findings, graph, posture, and exports.

This gives users the full product experience: sign in, connect read-only, scan,
inspect graph/blast radius, and export evidence.

### DNS

Create one record per lane you serve, pointing at your host:

| Record | Purpose |
|---|---|
| `agent-bom.example.com` | the instance UI + API |

If you front the host with a proxying CDN, keep proxy mode and TLS mode
consistent:

- **DNS-only + Caddy** — simplest. Caddy terminates Let's Encrypt directly.
- **Proxied + Caddy** — set the CDN's SSL mode to `Full (strict)` and let Caddy
  still hold a valid origin certificate.

Do not point the apex/root domain at the instance unless it is also serving your
product site.

### Minimal host setup

Generate local secrets on the host:

```bash
cp .env.example .env

export NEXT_PUBLIC_API_URL="https://agent-bom.example.com"
export CORS_ORIGINS="https://agent-bom.example.com,http://ui:3000"
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

`up` runs a one-shot `migrate` service before `api` (Alembic stamp + `upgrade
head`), so image upgrades apply schema changes without a manual migration step.
See [DEPLOY_PLATFORM.md](DEPLOY_PLATFORM.md) for the Compose vs Helm contract.

Seed a disposable demo graph after the API is healthy:

```bash
docker compose \
  -f deploy/docker-compose.platform.yml \
  -f deploy/docker-compose.hosted-poc.yml \
  exec api \
  agent-bom quickstart --run --offline --force
```

The compose profile persists `/root/.agent-bom` in a named volume so the seeded
demo graph survives container replacement. Offline quickstart inventories and
graphs the sample without package-CVE lookup; use the separate bundled demo
scan for offline CVE proof:

```bash
agent-bom scan --demo --offline
```

Replace the sample with real connected cloud scans as soon as the first account
is connected.

Before opening the host to testers, confirm the composed stack does not expose
API/UI ports on all interfaces and does not mount the placeholder Postgres
password:

```bash
python scripts/deploy/hosted_poc_preflight.py --write-secret
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
AGENT_BOM_SMOKE_URL="https://agent-bom.example.com" \
AGENT_BOM_SMOKE_API_KEY="<raw admin key>" \
scripts/deploy/hosted_poc_smoke.sh
```

After at least one cloud/Snowflake connection is stored, verify the broker path
without launching a full scan:

```bash
AGENT_BOM_SMOKE_URL="https://agent-bom.example.com" \
AGENT_BOM_SMOKE_API_KEY="<raw admin key>" \
AGENT_BOM_SMOKE_CONNECTION_ID="<connection id>" \
scripts/deploy/hosted_poc_smoke.sh
```

### Self-serve invite endpoint

`scripts/deploy/mint_hosted_admin_key.py` is the bootstrap path for the very
first admin key. Once an operator holds an admin key, the same tenant-and-key
provisioning is available over the API without shelling into the container:

```bash
curl -sS -X POST https://agent-bom.example.com/v1/auth/invitations \
  -H "X-API-Key: <raw operator admin key>" \
  -H "Content-Type: application/json" \
  -d '{"organization": "Acme Corp", "email": "owner@acme.example"}'
```

The endpoint is admin-only (same RBAC + `auth.keys:write` scope as
`POST /v1/auth/keys`) and reuses the shared key-minting crypto — it does **not**
introduce a new key format. It:

- creates a **brand-new tenant** with a server-generated id (an invite can never
  target or leak into an existing tenant),
- mints one scoped API key for that tenant (default role `admin`), and
- returns a one-time invite payload: `raw_key` (shown once, never logged),
  `tenant_id`, `key_id`, `expires_at`, the applied default `quota`, and — only
  when `AGENT_BOM_HOSTED_INVITE_BASE_URL` is set — an `invite_url` sign-in link
  that never carries the key.

Deliver the `raw_key` to the invited admin over a trusted channel; the operator
still owns who is invited and holds the manual revoke path (`DELETE
/v1/auth/keys/{key_id}`). The endpoint never accepts a provider secret or any
per-action credential — it mints a credential, it does not take one.

### Smallest defensible MVP defaults

The new tenant is bounded by the conservative default tenant quotas
(`active_scan_jobs`, `retained_scan_jobs`, `fleet_agents`, `schedules`) the
moment it is created — those defaults apply to any tenant with no overrides, and
per-tenant overrides are managed at `/v1/auth/quota`. For a multi-replica hosted
deploy, run the **Postgres** rate limiter and set
`AGENT_BOM_REQUIRE_SHARED_RATE_LIMIT=1` so rate limiting is cluster-safe and
fails closed rather than degrading to per-replica in-memory counters. See
`docs/operations/ENV_VARS.md` for the full rate-limit and quota env reference.

### Production auth checklist

For a gated POC, users are invited manually and access is revoked manually. Keep
the surface operator-controlled; this profile is not a public registration flow.

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
| CORS/TLS | `CORS_ORIGINS` contains only your hosted URL and the internal UI origin. The front door terminates HTTPS; API/UI bind to loopback/private network only. |
| Usage control | Invitees have explicit scan windows, provider/account scope, and a manual revoke path before they connect a cloud or Snowflake account. |

If any row is unknown, stop and keep the deployment internal.

### Caddy front door

Example `Caddyfile`:

```caddyfile
agent-bom.example.com {
  encode zstd gzip

  reverse_proxy /v1/* localhost:8422
  reverse_proxy /health localhost:8422
  reverse_proxy /openapi.json localhost:8422
  reverse_proxy localhost:3000
}
```

Keep the front door as the only public listener. The Postgres container remains
internal and `deploy/docker-compose.hosted-poc.yml` binds the API/UI ports to
loopback, so they are reachable only from the proxy on the host.

An anonymous seeded demo (seeded estate + viewer without login) is **not** this
overlay. That layers `deploy/docker-compose.demo-override.yml` on top of
platform + hosted-poc, and it is deliberately excluded from the preflight
security gate — never combine it with a gated instance holding real connections.

### Proof checklist

Run this checklist before inviting anyone:

1. `https://agent-bom.example.com/health` returns healthy through the front door.
2. The UI opens at `https://agent-bom.example.com` and does not require direct
   access to ports `3000` or `8422`.
3. `AGENT_BOM_ALLOW_UNAUTHENTICATED_API` is unset.
4. A seeded scan appears in the dashboard with findings, graph, posture, and
   export links.
5. Connections can add at least one read-only cloud account or Snowflake
   account.
6. A connection scan hands off to scan details, findings, graph, jobs, and
   compliance surfaces.
7. Audit export and compliance export work for the tenant.

If any item fails, treat the instance as not ready for external users.

## Snowflake Native App lane

Use Snowflake when the buyer wants agent-bom to run inside their Snowflake
account. This is the stronger enterprise data-boundary story, but it has more
packaging steps than a self-hosted instance.

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

- Do not present a self-hosted instance as anything beyond an invite-only POC
  until it has been through the production auth checklist.
- Do not ask testers for long-lived cloud keys when assumable roles work.
- Do not enable unauthenticated API access on an instance holding real
  connections. It is correct only for the anonymous seeded demo.
- Do not publish Grafana, observability, or development compose profiles.
- Do not run Snowflake GPU pools for agent-bom.
