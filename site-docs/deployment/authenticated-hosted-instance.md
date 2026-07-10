# Hosted Authenticated Instance + Connect Your Cloud

This runbook stands up the **private customer / CISO experience**: a single-host,
**login-gated** `agent-bom` instance with **no synthetic data**, real
authentication, a least-privilege Postgres role, and a **real cloud account
connected read-only**. It is the deliberate opposite of the public anonymous
demo.

!!! danger "Safety rule — never mix the two"
    **Never connect a real cloud account to the anonymous demo.** The public
    demo (`AGENT_BOM_DEMO_ESTATE=1` + `AGENT_BOM_ALLOW_UNAUTHENTICATED_API=1`)
    serves synthetic data to unauthenticated viewers. Real cloud posture,
    findings, and graph data must only ever live behind the authenticated
    profile described here.

## Demo vs. authenticated product

Both run from the same `deploy/docker-compose.platform.yml` base; only the
**overlay** differs.

| Setting | Public anonymous demo | Authenticated product |
|---|---|---|
| Overlay | `deploy/docker-compose.hosted-poc.yml` | `deploy/docker-compose.product.yml` |
| `AGENT_BOM_DEMO_ESTATE` | `1` (synthetic estate seeded) | `0` (never seeded) |
| `AGENT_BOM_ALLOW_UNAUTHENTICATED_API` | `1` (anonymous read) | `0` (auth required) |
| `AGENT_BOM_NO_AUTH_ROLE` | `viewer` (implicit role) | unset (no implicit role) |
| Auth | none — anyone with the URL | API key and/or OIDC/SAML SSO |
| Postgres role | falls back to admin owner | **requires** `agent_bom_app` (DML-only, NOSUPERUSER/NOBYPASSRLS) |
| Data | curated fake graph | real connected cloud posture / CIS / graph |

The product overlay is minimal on purpose: it flips the demo guards off,
forces the non-superuser app role via `:?` (fail-closed) env expansion, and
keeps browser-session cookies Secure. Auth env is wired by the platform base.

## 0. Prerequisites

- A small CPU-only host (4 vCPU / 8–16 GB RAM) with Docker + Compose.
- DNS pointing at the host, for example `app.agent-bom.com`. Open inbound `443`
  only; restrict SSH to your IP.
- A checkout of this repository on the host.

## 1. Stand up the gated instance

### 1a. Generate secrets and the non-superuser DB role

The app connects as `agent_bom_app`, the DML-only role created by
`deploy/supabase/postgres/init.sql` on first boot. Provide its secret via
`deploy/secrets/postgres_app_password` (Docker secret mount); the init wrapper
reads that file and the init SQL creates the role `NOSUPERUSER NOBYPASSRLS`,
satisfying the RLS superuser guard (#3665) by least privilege. Never put
Postgres passwords in `.env` or compose environment variables.

```bash
cp .env.example .env

# Control-plane secrets
export AGENT_BOM_API_KEY="$(openssl rand -hex 32)"          # bootstrap admin key
export AGENT_BOM_AUDIT_HMAC_KEY="$(openssl rand -hex 32)"
export AGENT_BOM_BROWSER_SESSION_SIGNING_KEY="$(openssl rand -hex 32)"
export AGENT_BOM_CONNECTIONS_KEY="$(
  python - <<'PY'
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
PY
)"

# Public URL wiring (Caddy terminates TLS on 443)
export AGENT_BOM_HOSTED_DOMAIN="app.agent-bom.com"
export ACME_EMAIL="ops@example.com"
export NEXT_PUBLIC_API_URL="https://app.agent-bom.com"
export CORS_ORIGINS="https://app.agent-bom.com,http://ui:3000"

# Postgres: bootstrap secret (image init only) + DML-only app role (runtime)
mkdir -p deploy/secrets
printf '%s' "$(openssl rand -hex 32)" > deploy/secrets/postgres_password
printf '%s' "$(openssl rand -hex 32)" > deploy/secrets/postgres_app_password
chmod 0400 deploy/secrets/postgres_password deploy/secrets/postgres_app_password
```

`AGENT_BOM_API_KEY` seeds a single **admin** key. To seed viewer/analyst keys
by env instead of (or in addition to) OIDC, set
`AGENT_BOM_API_KEYS="<raw-key>:viewer,<raw-key>:analyst"` — each entry is
`<raw-key>:<admin|analyst|viewer>`.

### 1b. Optional — wire OIDC / SAML SSO instead of (or alongside) API keys

```bash
export AGENT_BOM_OIDC_ISSUER="https://login.example.com/"
export AGENT_BOM_OIDC_AUDIENCE="agent-bom"
# For multi-tenant IdP setups also set AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON.
```

The CLI refuses to expose the API on a non-loopback host unless **at least one**
of API key, `AGENT_BOM_API_KEYS`, OIDC, or a SCIM bearer token is configured, so
the gated posture is enforced at boot, not just documented.

### 1c. Boot the authenticated stack

```bash
docker compose \
  -f deploy/docker-compose.platform.yml \
  -f deploy/docker-compose.product.yml \
  up -d --build

docker compose \
  -f deploy/docker-compose.platform.yml \
  -f deploy/docker-compose.product.yml \
  ps
```

The platform base binds API (`8422`) and UI (`3000`) to loopback. Do **not**
seed a demo graph — the product overlay sets `AGENT_BOM_DEMO_ESTATE=0`.

### 1d. Front door: TLS via Caddy

Run Caddy on the host as the only public listener, reusing the shipped
`deploy/caddy/Caddyfile.hosted-poc` (it already splits `/v1/*`, `/health`, and
`/ws/*` to `127.0.0.1:8422` and everything else to `127.0.0.1:3000`, and sets
HSTS/security headers). `AGENT_BOM_HOSTED_DOMAIN` and `ACME_EMAIL` from step 1a
drive its TLS.

```bash
caddy run --config deploy/caddy/Caddyfile.hosted-poc
```

### 1e. Preflight (fail-closed)

```bash
python scripts/deploy/hosted_poc_preflight.py --write-postgres-secret
```

This fails closed when required secrets are missing, `AGENT_BOM_ALLOW_UNAUTHENTICATED_API`
is enabled, CORS is wildcarded, or API/UI ports bind publicly. Re-run it after
any `.env`, DNS, or compose change.

## 2. Create the first admin and issue a viewer/analyst key

Mint the first admin key **inside the API container** so the record lands in the
same persistent store the API reads:

```bash
docker compose \
  -f deploy/docker-compose.platform.yml \
  -f deploy/docker-compose.product.yml \
  exec api \
  python scripts/deploy/mint_hosted_admin_key.py \
    --tenant-id customer-0 \
    --name customer-0-admin \
    --raw-key-file /tmp/customer0-admin.key
```

The raw key is written once to the `0600` file passed with `--raw-key-file`.
Store it in your password manager; never commit, screenshot, or paste it.

Issue scoped viewer/analyst keys for the account with the admin key against the
RBAC endpoint (`POST /v1/auth/keys` requires the `admin` role):

```bash
curl -sS -X POST "https://app.agent-bom.com/v1/auth/keys" \
  -H "Authorization: Bearer <raw admin key>" \
  -H "Content-Type: application/json" \
  -d '{"name": "ciso-viewer", "role": "viewer"}'
```

If you wired OIDC in step 1b instead, skip key issuance and map IdP group claims
to roles via `AGENT_BOM_OIDC_ROLE_CLAIM`; each invited user signs in at
`/login`.

## 3. Connect a real cloud account read-only

`agent-bom` never mutates the target and does no cloud I/O until you opt in. Use
the built-in onboarding helper to print the exact read-only setup and confirm
your credentials are detectable:

```bash
agent-bom connect aws     # or: connect azure | connect gcp
```

### 3a. Apply the read-only Terraform (AWS)

`deploy/terraform/connect-aws` mints a least-privilege role: AWS-managed
`SecurityAudit` (+ optional `ViewOnlyAccess`), a unique non-guessable name, and
an **always-enforced high-entropy `sts:ExternalId`**. No access keys, no
write permissions.

```bash
cd deploy/terraform/connect-aws
terraform init
terraform apply \
  -var 'trusted_principal_arns=["arn:aws:iam::<scanner-acct>:role/agent-bom-scanner"]'

terraform output -raw role_arn        # the read-only role to assume
terraform output -raw external_id     # sensitive; confused-deputy defense
```

GCP and Azure follow the same pattern with their own modules:
`deploy/terraform/connect-gcp` (viewer + `iam.securityReviewer`, keyless
Workload Identity Federation) and `deploy/terraform/connect-azure` (Reader +
Security Reader, pinned federated identity credential).

### 3b. Run the first authenticated scan against the tenant

Authenticate via the standard provider chain (named profile, assumed role, or
SSO — no secrets stored in `agent-bom`), opt in with the per-provider inventory
flag, and scan from inside the API container so findings land in the customer-0
tenant store:

```bash
docker compose \
  -f deploy/docker-compose.platform.yml \
  -f deploy/docker-compose.product.yml \
  exec \
    -e AGENT_BOM_AWS_INVENTORY=1 \
    -e AWS_PROFILE=abom-readonly \
    api \
  agent-bom agents --preset enterprise --aws --aws-cis-benchmark
```

Azure and GCP equivalents:

```bash
# Azure — Reader / Security Reader via DefaultAzureCredential
AGENT_BOM_AZURE_INVENTORY=1 agent-bom agents --preset enterprise --azure

# GCP — roles/viewer + roles/iam.securityReviewer via ADC
AGENT_BOM_GCP_INVENTORY=1 agent-bom cloud gcp --project <PROJECT_ID> --cis
```

For org/tenant fan-out use `AGENT_BOM_AWS_ORG_INVENTORY=1`,
`AGENT_BOM_AZURE_ALL_SUBSCRIPTIONS=1`, or `AGENT_BOM_GCP_ALL_PROJECTS=1`. See
[`docs/CLOUD_CONNECT.md`](https://github.com/msaad00/agent-bom/blob/main/docs/CLOUD_CONNECT.md)
for the full per-provider matrix and scale caps.

## 4. Log in and see real posture

1. Open `https://app.agent-bom.com` and sign in at `/login` (API key or SSO).
2. Confirm the dashboard shows the connected account's **real** findings, CIS
   benchmark posture, and blast-radius graph — not the demo estate.
3. Run the smoke check before inviting others:

   ```bash
   AGENT_BOM_SMOKE_URL="https://app.agent-bom.com" \
   AGENT_BOM_SMOKE_API_KEY="<raw admin key>" \
   scripts/deploy/hosted_poc_smoke.sh
   ```

## Verify the gated posture

Re-confirm the anti-demo guards any time you change config:

```bash
docker compose \
  -f deploy/docker-compose.platform.yml \
  -f deploy/docker-compose.product.yml \
  config | grep -E 'AGENT_BOM_DEMO_ESTATE|AGENT_BOM_ALLOW_UNAUTHENTICATED_API|AGENT_BOM_POSTGRES_URL'
# expect: DEMO_ESTATE "0", ALLOW_UNAUTHENTICATED_API "0",
#         POSTGRES_URL using agent_bom_app (never the admin owner)
```

If `AGENT_BOM_ALLOW_UNAUTHENTICATED_API` is anything but `0`, or the Postgres
URL is not using `agent_bom_app`, stop and fix before connecting any cloud.

## Related

- Public anonymous demo runbook: [`docs/HOSTED_POC.md`](https://github.com/msaad00/agent-bom/blob/main/docs/HOSTED_POC.md)
- Cloud connect reference: [`docs/CLOUD_CONNECT.md`](https://github.com/msaad00/agent-bom/blob/main/docs/CLOUD_CONNECT.md)
- Auth model and tenancy: [Enterprise Auth and Tenancy](enterprise-auth-and-tenancy.md)
