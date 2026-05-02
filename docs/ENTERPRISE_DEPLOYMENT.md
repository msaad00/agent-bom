# Enterprise Deployment Guide

Deploy agent-bom across your organization — from developer endpoints to cloud infrastructure.

If you want a code-mapped explanation of the enterprise claims in this guide, start with [ENTERPRISE.md](ENTERPRISE.md).

## Architecture Principles

agent-bom is built on four security principles:

| Principle | Implementation |
|-----------|---------------|
| **Read-only** | Only `List*`, `Describe*`, `Get*` APIs. Zero write calls to any target. |
| **Agentless** | No agent installed on targets. Uses standard SDK credential chains. |
| **Zero-credential** | Never stores, logs, or transmits credential values. Only names (`ANTHROPIC_KEY`, never the key itself). |
| **Least privilege** | Each cloud provider tells you the exact read-only IAM policy on access denied. |

## Container images — do I need both?

agent-bom publishes two images. They are a deployment-flexibility split, **not a hard requirement** for the dashboard to work.

| Image | Base | What's inside | When to pull it |
|---|---|---|---|
| `agentbom/agent-bom` | Python 3.14 Alpine (~150 MB) | FastAPI/Starlette + scanner + cloud SDKs + MCP server. The pre-built Next.js dashboard is **bundled inside the wheel** as static assets. | Always. Single-host pilots and `pip install` users only need this one. |
| `agentbom/agent-bom-ui` | Node 24 Debian slim (~250 MB) | Next.js standalone server only. No Python, no cloud SDKs, no MCP runtime. | K8s deployments that want the UI tier scaled / deployed / restricted independently of the API tier. |

### Why the API image alone serves the dashboard

The `agent-bom serve` process mounts `ui_dist/` as static files when present in the install (`src/agent_bom/api/server.py:685-708`). The wheel's `[tool.setuptools.package-data]` declaration (`pyproject.toml:189`) ships `ui_dist/**` so a `pip install agent-bom[api]` is sufficient. The dashboard answers at the same origin as the API — no second container, no reverse proxy, no separate ingress.

```bash
pip install 'agent-bom[api]'
agent-bom serve --port 8422        # API at :8422, UI at the same port
```

The Docker quickstart works the same way — `docker run --rm -p 8422:8422 agentbom/agent-bom serve` is enough for a pilot. The UI image is purely additive.

### Why the second image exists at all

Reasons that hold up:

1. **Independent scaling.** UI is light SSR + static; API does CPU-heavy scanning. Kubernetes wants different replica counts and different HPA / KEDA triggers (see [`scaling-slo.md`](../site-docs/deployment/scaling-slo.md)). Co-locating them forces every UI scale event to also start a Python interpreter.
2. **Smaller attack surface for the UI tier.** No `boto3` / `azure-*` / `google-cloud-*` SDKs reachable from the UI container, no MCP subprocess, no cloud creds in scope. The ExternalSecrets / IRSA bindings can stay scoped to the API Deployment alone.
3. **Independent dep churn.** UI deps (recharts, lucide-react, react-virtual) update fast and noisy; backend deps (boto3, OSV libs) update slow and quiet. Two images means UI patch releases ship without forcing a backend image rebuild.
4. **Different runtimes.** A combined image would carry both Python 3.14 and Node 24 — roughly doubles the image footprint and the security-advisory surface.

Reasons that **do not** hold up:

- *"You need the UI image for the dashboard to work."* — false. Verified above.

### Practical operator guidance

**Default**: pull `agentbom/agent-bom` only. The dashboard ships inside the wheel and serves at the same origin as the API. This is the right answer for single-host pilots, dev, CI, air-gapped registry mirrors, and the majority of pilots under ~500 agents.

**Pull both** when you specifically want one of these properties:

- the UI tier scales / restarts / rolls out **separately** from the API (different HPA / KEDA / PDB)
- the UI tier sits behind a **different ingress, gateway, or auth boundary** than the API
- the UI tier needs a **smaller attack-surface container** with no Python, no cloud SDKs, no MCP subprocess in scope (the second image is intentionally minimal)
- a separate UI image lets your release cadence ship UI patches without re-rolling the backend image

If none of those properties matter for your deployment, the second image is just bytes you don't need to pull, scan, or sign.
| Kubernetes with shared ingress and modest scale | either is fine; the chart defaults to both for the multi-replica case |

The Helm chart (`deploy/helm/agent-bom`) deploys both by default because the production EKS preset assumes the multi-replica case. To run API-only, set `controlPlane.ui.enabled=false` and the chart skips the UI Deployment, Service, and HPA.

## Deployment Models

### 1. CI/CD Pipeline — scan on every PR

Start with a familiar adoption pattern: a single CI step that fails on policy, uploads SARIF, and produces artifacts security teams can review.

```yaml
# GitHub Actions
- uses: msaad00/agent-bom@v0.85.0
  with:
    scan-type: agents        # auto-detect MCP configs + deps
    severity-threshold: high # fail PR on HIGH+ CVEs
    upload-sarif: true       # push to GitHub Security tab
    enrich: true             # add EPSS + CISA KEV context
    fail-on-kev: true        # block known exploited vulns
```

**What it scans:** repo dependencies, MCP configs, IaC files, instruction files.
**What leaves the machine:** package names + versions only (to OSV API).
**Credentials:** never accessed — scans manifest files, not environments.
**Enterprise networks:** the GitHub Action preserves the same proxy/custom-CA env contract as the Docker and API deployment surfaces: `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, and `PIP_CERT`.

**Common CI/CD patterns**

```yaml
# Container image gate
- uses: msaad00/agent-bom@v0.85.0
  with:
    scan-type: image
    scan-ref: ghcr.io/acme/agent-runtime:sha-abcdef
    severity-threshold: critical

# IaC gate
- uses: msaad00/agent-bom@v0.85.0
  with:
    scan-type: iac
    iac: Dockerfile,k8s/,infra/main.tf
    severity-threshold: high

# Air-gapped or fully cached CI
- uses: msaad00/agent-bom@v0.85.0
  with:
    auto-update-db: false
    enrich: false
```

**Recommended rollout**
1. Start with `severity-threshold: critical` and `upload-sarif: true`.
2. Turn on `enrich: true` and `fail-on-kev: true` after the baseline is clean.
3. Add `policy` or `warn-on-severity` once teams are comfortable with the signal.

### 2. Endpoint Fleet — MDM-pushed scan

For discovering MCP servers and AI agents on employee workstations:

```bash
# Jamf / Intune / Kandji pushes this command
agent-bom agents --format json --output /var/log/agent-bom/scan.json
```

**How it works:**
1. MDM pushes `agent-bom` as a scheduled script (daily/weekly)
2. Runs locally on each endpoint — reads config files, extracts package metadata
3. Outputs JSON scan results to a local file
4. MDM collects the JSON file (not the configs, not the credentials)
5. Results shipped to fleet API for centralized visibility

**What stays on the endpoint:** config files, credential values, source code.
**What leaves:** agent names, server names, package names/versions, CVE IDs, blast radius metadata.

**Credential safety:**
- `sanitize_env_vars()` replaces ALL sensitive values with `***REDACTED***` before any output
- Triple-layer detection: key name patterns + value regex + base64/entropy analysis
- Secret scanner shows only first 8 characters as preview, never the full value
- PII findings show `[PII]`, never actual data

For managed proxy onboarding on the same endpoints, generate a rollout bundle instead of hand-editing every client config:

```bash
agent-bom proxy-bootstrap \
  --bundle-dir ./endpoint-bundle \
  --control-plane-url https://agent-bom.example.com \
  --push-url https://agent-bom.example.com/v1/fleet/sync
```

That bundle includes:
- a macOS/Linux shell bootstrap script
- a Windows PowerShell bootstrap script
- Jamf and Kandji shell wrappers
- Intune install and detect PowerShell wrappers
- a `fleet-sync.env` file for the shipped timer/service assets
- a rendered launchd plist for managed macOS rollout

The generated bootstrap scripts install or upgrade `agent-bom`, then run `agent-bom proxy-configure --apply` with the control-plane policy/audit settings you chose, so supported JSON MCP clients no longer need manual config edits.

For packaged rollout beyond shell scripts, the repo now also ships:

- `scripts/build-pkg.sh` for macOS `.pkg` assembly from a generated endpoint bundle
- `scripts/build-msi.ps1` for Windows `.msi` assembly via WiX from the same bundle
- `scripts/render_homebrew_formula.py` for publishing a version-pinned Homebrew formula into your tap/release pipeline
- static Jamf / Intune / Kandji templates under `deploy/endpoints/`

### 3. Centralized API Server — fleet dashboard

```bash
# Security team hosts the API + dashboard
agent-bom serve --port 8422 --persist jobs.db
```

**Endpoints:**
- `POST /v1/scan` — submit scans from any source
- `GET /v1/fleet/list` — view all discovered agents across the org
- `GET /v1/fleet/stats` — fleet-wide trust scores and posture
- `POST /v1/fleet/sync` — ingest endpoint scan results
- `GET /v1/compliance` — 14-framework compliance posture plus AISVS benchmark summary
- `GET /v1/compliance/aisvs` — latest tenant-scoped OWASP AISVS benchmark result

Fleet trust scoring is advisory and evidence-backed. The score combines registry verification, active vulnerability posture, credential hygiene, permission profile, configuration quality, discovery provenance, package provenance attestation, runtime drift evidence, and inventory freshness. API responses include factor breakdowns plus evidence references so operators can explain why an agent is trusted or risky instead of treating the score as an opaque compliance certification.

**Operator env-var reference:** the full `AGENT_BOM_*` knob inventory is auto-generated from `src/agent_bom/config.py` to [`docs/operations/ENV_VARS.md`](operations/ENV_VARS.md). CI gates new env vars: any new `AGENT_BOM_*` reference under `src/agent_bom/` must be declared in `config.py` (preferred) or explicitly listed in `scripts/env_var_allowlist.txt` with a one-line reason, or the build fails.

**Authentication:** localhost binds are allowed for local development. Non-loopback binds fail closed unless you set `AGENT_BOM_API_KEY`, configure `AGENT_BOM_OIDC_ISSUER`, configure `AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON`, or explicitly pass `--allow-insecure-no-auth`. Rate limiting and CORS controls are built in.

**Tracing:** every API response includes `X-Request-ID`, `X-Trace-ID`, `X-Span-ID`, and W3C `traceparent`. If your ingress or collector already sends `traceparent`, `tracestate`, or bounded W3C `baggage`, `agent-bom` preserves the upstream trace context and continues the chain. `GET /health` also reports the current tracing contract (`w3c_trace_context`, `w3c_tracestate`, `w3c_baggage`) plus OTLP export state so operators can confirm whether tracing is merely available or actively exported. Set `AGENT_BOM_OTEL_TRACES_ENDPOINT` to export API request spans over OTLP/HTTP, and use `AGENT_BOM_OTEL_TRACES_HEADERS` for collector auth headers when needed.

For OIDC-backed enterprise deployments, keep tenant scoping explicit in the token contract:

```bash
export AGENT_BOM_OIDC_ISSUER="https://idp.example.com"
export AGENT_BOM_OIDC_AUDIENCE="agent-bom"
export AGENT_BOM_OIDC_ROLE_CLAIM="agent_bom_role"
export AGENT_BOM_OIDC_TENANT_CLAIM="tenant_id"      # or a custom claim like org_slug
# export AGENT_BOM_OIDC_ALLOW_DEFAULT_TENANT=1      # only for explicit single-tenant compatibility mode
# export AGENT_BOM_OIDC_REQUIRED_NONCE="replace-me"  # optional when your IdP flow emits nonce
```

That keeps API roles and tenant boundaries aligned with the upstream identity provider. Missing tenant claims now fail closed by default instead of silently falling back to a shared tenant; `AGENT_BOM_OIDC_ALLOW_DEFAULT_TENANT=1` is the explicit compatibility escape hatch for single-tenant deployments.

For tenant-bound issuers, configure one issuer per tenant and do not also set `AGENT_BOM_OIDC_ISSUER`:

```bash
export AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON='{
  "tenant-alpha": {
    "issuer": "https://alpha.okta.example",
    "audience": "agent-bom",
    "tenant_claim": "tenant_id",
    "require_tenant_claim": true
  },
  "tenant-beta": {
    "issuer": "https://beta.okta.example",
    "audience": "agent-bom",
    "tenant_claim": "tenant_id",
    "require_tenant_claim": true
  }
}'
```

At startup, `agent-bom` treats `AGENT_BOM_OIDC_ISSUER` and `AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON` as mutually exclusive. Mixed configuration now fails closed instead of silently choosing one mode.

For SCIM-backed enterprise identity provisioning, use the dedicated SCIM token and tenant binding:

```bash
export AGENT_BOM_SCIM_BEARER_TOKEN="replace-with-idp-scim-token"
export AGENT_BOM_SCIM_TENANT_ID="tenant-alpha"
# export AGENT_BOM_SCIM_BASE_PATH="/scim/v2"
```

SCIM lifecycle traffic is available under `/scim/v2/Users`, `/scim/v2/Groups`, `/scim/v2/ServiceProviderConfig`, `/scim/v2/Schemas`, and `/scim/v2/ResourceTypes`. These routes require `AGENT_BOM_SCIM_BEARER_TOKEN`; dashboard sessions and general API keys are not accepted. The tenant is always taken from `AGENT_BOM_SCIM_TENANT_ID`, so tenant fields in the IdP payload cannot steer writes into another tenant.

Provisioned SCIM users carry Agent BOM role and membership metadata. Set
`AGENT_BOM_SCIM_ROLE_ATTRIBUTE` when the IdP sends roles under a custom
attribute; otherwise users default to `AGENT_BOM_SCIM_DEFAULT_ROLE` (`viewer`).
Accepted role values are `admin`, `analyst`, and `viewer` (`contributor` is
normalized to `analyst`). SCIM remains the lifecycle store: deleting or
deactivating a SCIM user updates provisioned identity state and audit evidence,
while runtime API-key, OIDC, SAML, and reverse-proxy sessions are revoked by
their own upstream auth path.

Compatibility coverage is maintained for common IdP payload shapes:

- Okta user/group lifecycle payloads with `externalId`, `emails`, `groups`, and active-state patches
- Microsoft Entra ID SCIM replace patches that send a value object instead of a single path
- Google Cloud Identity payloads that rely on `name.formatted` when `displayName` is absent

Check `/v1/auth/policy` or `/v1/auth/scim/config` for the non-secret
`verified_idp_templates` posture before procurement or IdP rollout reviews.

For PostgreSQL-backed deployments, `agent-bom` now also pushes the authenticated tenant into the database session (`app.tenant_id`) so Postgres row-level security can enforce the same tenant boundary for fleet and schedule data. Internal scheduler work uses an explicit trusted bypass rather than silently reading across tenants.

For horizontally scaled control-plane APIs, shared rate limiting is mandatory. `agent-bom` now fails closed when `AGENT_BOM_CONTROL_PLANE_REPLICAS > 1` (or `AGENT_BOM_REQUIRE_SHARED_RATE_LIMIT=1`) and no PostgreSQL-backed limiter is configured via `AGENT_BOM_POSTGRES_URL`.

#### Postgres sizing for typical estates

The numbers below are derived from the synthetic graph cardinalities published
in [`docs/perf/ingest-throughput.md`](perf/ingest-throughput.md). They are
floor estimates for the `graph_nodes` and `graph_edges` tables in
`src/agent_bom/api/postgres_store.py` only — multiply by retention factor and
add the audit log (`audit_events`, append-only) when sizing total disk.

| Estate size | Nodes | Edges | Graph rows | RDS storage floor (graph) | Recommended `db.t4g.medium`+ profile |
|---|---:|---:|---:|---|---|
| 1k agents  |  5,201 |  5,200 |  10,401 |  ~24 MiB | 2 vCPU / 4 GiB / 20 GiB gp3 |
| 5k agents  | 26,001 | 26,000 |  52,001 | ~120 MiB | 2 vCPU / 4 GiB / 50 GiB gp3 |
| 10k agents | 52,001 | 52,000 | 104,001 | ~240 MiB | 4 vCPU / 8 GiB / 100 GiB gp3 |

Verify the actual disk used by the graph tables in your deployment with:

```sql
SELECT relname,
       pg_size_pretty(pg_total_relation_size(C.oid)) AS total_size,
       pg_size_pretty(pg_relation_size(C.oid))       AS table_size,
       pg_size_pretty(pg_indexes_size(C.oid))        AS index_size
FROM   pg_class C
LEFT   JOIN pg_namespace N ON (N.oid = C.relnamespace)
WHERE  relkind = 'r' AND nspname = 'public'
   AND relname IN ('graph_nodes', 'graph_edges', 'audit_events',
                   'scan_jobs', 'compliance_evidence')
ORDER  BY pg_total_relation_size(C.oid) DESC;
```

Persistence throughput against these row counts is tracked in #1806; the
weekly `perf-scale-evidence.yml` workflow regenerates the in-process scale
floor on the lightweight 1k-estate set.

For horizontally scaled SCIM, shared identity storage is also mandatory. Set `AGENT_BOM_POSTGRES_URL` for EKS or any multi-replica control plane, and keep `AGENT_BOM_REQUIRE_SHARED_SCIM_STORE=1` enabled in production values. SQLite is acceptable only for a single-node pilot.

Production deployments must keep cryptographic keys separated by purpose:

- `AGENT_BOM_AUDIT_HMAC_KEY` signs the tamper-evident audit chain and audit exports.
- `AGENT_BOM_RATE_LIMIT_KEY` fingerprints API keys for rate-limit buckets.
- `AGENT_BOM_BROWSER_SESSION_SIGNING_KEY` signs httpOnly browser session cookies.
- `AGENT_BOM_TRUST_PROXY_AUTH_SECRET` attests trusted reverse-proxy identity headers and must contain at least 32 bytes of secret material.

Do not reuse the API key or audit HMAC key as a rate-limit, browser-session, or proxy-attestation secret. Set `AGENT_BOM_TRUST_PROXY_AUTH_ISSUER` when the upstream proxy can inject a stable issuer identifier; the API will then reject trusted-proxy requests from any other issuer.

### Proxy-to-control-plane mTLS posture

The recommended production pattern is delegated mTLS: terminate TLS and verify
proxy or gateway client certificates at the ingress, Envoy sidecar, or service
mesh boundary, then keep trusted-proxy header attestation enabled so direct
client-supplied identity headers remain ignored. This keeps certificate
lifecycle, rotation, and policy in the mesh or ingress layer.

Declare the operator posture with:

```bash
AGENT_BOM_PROXY_CONTROL_PLANE_MTLS_MODE=delegated
AGENT_BOM_PROXY_CONTROL_PLANE_MTLS_PROVIDER=istio
AGENT_BOM_PROXY_CONTROL_PLANE_MTLS_CLIENT_CA_REF=secret/agent-bom/proxy-client-ca
AGENT_BOM_PROXY_CONTROL_PLANE_MTLS_EVIDENCE_REF=deploy/helm/agent-bom/templates/controlplane-istio-peer-authentication.yaml
AGENT_BOM_PROXY_CONTROL_PLANE_MTLS_CERT_HEADER=x-forwarded-client-cert
AGENT_BOM_TRUST_PROXY_AUTH=1
AGENT_BOM_TRUST_PROXY_AUTH_SECRET=<32+ byte shared attestation secret>
AGENT_BOM_TRUST_PROXY_AUTH_ISSUER=edge-envoy
```

`GET /v1/auth/policy` exposes `proxy_control_plane_mtls` with one of three
honest states:

- `disabled` — no mTLS posture has been declared.
- `needs_evidence` — delegated mTLS is declared, but client-CA evidence,
  evidence reference, or trusted-proxy issuer pinning is incomplete.
- `ok` — delegated mTLS is declared, client-CA evidence is referenced, and
  trusted-proxy auth is issuer-pinned.

For NGINX, set `ssl_verify_client on;`, trust the proxy client CA with
`ssl_client_certificate`, and forward only sanitized identity headers from the
verified location block. For Envoy, use `DownstreamTlsContext` with
`require_client_certificate: true` and forward `x-forwarded-client-cert` only
after SAN/URI validation. For Istio, use `PeerAuthentication` `STRICT` plus an
`AuthorizationPolicy` that limits caller identities to the proxy/gateway service
accounts. In all three patterns, `AGENT_BOM_TRUST_PROXY_AUTH_SECRET` and
`AGENT_BOM_TRUST_PROXY_AUTH_ISSUER` remain the application-level guard against
spoofed `X-Agent-Bom-*` headers.

For non-mesh deployments such as a single VM, air-gapped host, or bare Docker
deployment, `agent-bom` also supports an app-native mTLS fallback through
uvicorn TLS settings:

```bash
AGENT_BOM_PROXY_CONTROL_PLANE_MTLS_MODE=app_native
AGENT_BOM_TLS_CERT_FILE=/etc/agent-bom/tls/tls.crt
AGENT_BOM_TLS_KEY_FILE=/etc/agent-bom/tls/tls.key
AGENT_BOM_TLS_CLIENT_CA_FILE=/etc/agent-bom/tls/client-ca.crt
AGENT_BOM_TLS_REQUIRE_CLIENT_CERT=1
```

`agent-bom serve` and `agent-bom api` pass these files to uvicorn and require
client certificates when `AGENT_BOM_TLS_REQUIRE_CLIENT_CERT=1` is set.
`GET /v1/auth/policy` reports this as
`proxy_control_plane_mtls.mtls_mode=app_native`.

Direct-hop rule: if the FastAPI listener is behind ingress or a sidecar, bind
it to `127.0.0.1`, a Unix socket, or a Kubernetes NetworkPolicy path that only
allows the sidecar or ingress to reach the pod. In production or clustered
control planes, `agent-bom` fails closed when a non-loopback listener is exposed
without either trusted-proxy attestation or app-native mTLS.

API-local filesystem scan endpoints are meant for workstation pilots. In EKS
and other shared control planes, keep `AGENT_BOM_API_LOCAL_PATH_SCANS=disabled`
and collect filesystem evidence through endpoint agents or mounted tenant
workspaces. If a single-tenant deployment must enable API-local scans, set
`AGENT_BOM_API_SCAN_ROOT` to the tenant workspace mount; paths are still
relative-only, resolved through symlinks, confined to that root, and rejected
when owned outside the API process unless `AGENT_BOM_API_SCAN_ALLOW_FOREIGN_OWNER=1`
is explicitly set.

For secret lifecycle posture, production deployments should declare the external
secret authority and rotation metadata without exposing secret values:

```bash
export AGENT_BOM_SECRET_PROVIDER="aws_secrets_manager" # or hashicorp_vault, external_secrets, csi
export AGENT_BOM_EXTERNAL_SECRETS_ENABLED=1
export AGENT_BOM_AUDIT_HMAC_LAST_ROTATED="2026-04-24T00:00:00+00:00"
export AGENT_BOM_COMPLIANCE_SIGNING_LAST_ROTATED="2026-04-24T00:00:00+00:00"
export AGENT_BOM_BROWSER_SESSION_SIGNING_KEY_LAST_ROTATED="2026-04-24T00:00:00+00:00"
export AGENT_BOM_SCIM_BEARER_TOKEN_LAST_ROTATED="2026-04-24T00:00:00+00:00"
```

Operators can verify the non-secret posture at `GET /v1/auth/secrets/lifecycle`
or inside `GET /v1/auth/policy`. For change windows, use
`GET /v1/auth/secrets/rotation-plan` to generate a non-secret operator plan
that names the affected env vars, customer secret-manager action, rollout
commands, verification curl, and `*_LAST_ROTATED` timestamp to record. The plan
never returns secret values and is safe to attach to an internal change ticket.

**Storage:** SQLite for single-node and local persistence, PostgreSQL-compatible backends such as PostgreSQL and Supabase for the transactional control plane, ClickHouse for analytics, and Snowflake for selected enterprise store paths where parity is explicitly implemented. Snowflake does not yet have full parity for every transactional API store, so PostgreSQL-compatible backends remain the primary control-plane default when you need tenant-scoped keys, exceptions, graph state, and trend history.

Use the backend story this way:

- `SQLite`: local and single-node
- `Postgres` / `Supabase`: control-plane default
- `ClickHouse`: analytics add-on
- `Snowflake`: warehouse-native and governance-oriented mode with explicit parity limits

For the EKS reference installer, local Terraform/OpenTofu state under
`~/.agent-bom/eks-reference` is pilot convenience state and may include generated
database credentials, secret ARNs, and Helm override paths. Production operators
should migrate that Terraform root to customer-managed encrypted remote state,
for example S3 with SSE-KMS, versioning, locked-down IAM, and state locking.
Do not commit, ticket, or share local state artifacts without redaction.

For the detailed matrix, see `site-docs/deployment/backend-parity.md`.

For ClickHouse-backed analytics, make the backend explicit instead of relying on ambient environment alone:

```bash
agent-bom api \
  --api-key "$AGENT_BOM_API_KEY" \
  --analytics-backend clickhouse \
  --clickhouse-url "http://clickhouse.internal:8123"
```

Server mode enables buffered ClickHouse writes by default so scan and runtime paths do not block on OLAP round-trips. `GET /health` now reports the active analytics contract (`backend`, `enabled`, `buffered`, `flush_interval_seconds`, `max_batch`) alongside tracing so operators can confirm both observability and analytics posture from one probe. The ClickHouse analytics path stores scan metadata, vulnerability rows, runtime events, posture snapshots, fleet trust/lifecycle snapshots, compliance control measurements, and audit-event trends so the fleet backend matches the operator story more closely.

For a packaged self-hosted EKS pilot, use the shipped Helm profile installer instead of hand-assembling the values stack:

```bash
python scripts/install_helm_profile.py focused-pilot
```

List the available packaged profiles first if you want to inspect the matrix without installing:

```bash
python scripts/install_helm_profile.py --list
```

### 4. Cloud Infrastructure — agentless discovery

```bash
# Scan configured providers individually
agent-bom cloud aws
agent-bom cloud azure
agent-bom cloud gcp

# With CIS benchmarks
agent-bom cloud aws --cis
```

**Authentication per provider:**

| Provider | Preferred Auth | Fallback | What We Read |
|----------|---------------|----------|--------------|
| AWS | IAM role / OIDC (GitHub Actions) | `~/.aws/credentials` | `List*`, `Describe*`, `Get*` only |
| Azure | Managed identity / `az login` | Service principal | Read-only resource listing |
| GCP | Application Default Credentials | `GOOGLE_APPLICATION_CREDENTIALS` | Read-only resource listing |
| Snowflake | SSO (`externalbrowser`) | Key-pair auth | Read-only SQL on `ACCOUNT_USAGE` |
| Databricks | SDK credential chain / OAuth | `DATABRICKS_TOKEN` PAT | Read-only cluster/library listing |

**Required IAM policies (AWS example):**
```
AmazonBedrockReadOnly
AmazonECSReadOnlyAccess
AmazonSageMakerReadOnly
AWSLambda_ReadOnlyAccess
AmazonEKSReadOnlyAccess
AWSStepFunctionsReadOnlyAccess
AmazonEC2ReadOnlyAccess
```

### 5. Docker — air-gapped or isolated scans

```bash
docker run --rm \
  -v ~/.config:/home/abom/.config:ro \
  -v $(pwd):/workspace:ro \
  agentbom/agent-bom:0.85.0 agents --format json
```

Multi-arch: `linux/amd64` + `linux/arm64`. Non-root container. SHA-pinned base image.

**Best uses**
- Isolated scans in CI where you do not want to install Python or Node.
- Air-gapped environments with a pre-synced local vulnerability DB.
- Reproducible image scans across developer laptops and build runners.

## Output Integration

| Target | Command | Format |
|--------|---------|--------|
| GitHub Security tab | `--format sarif --output results.sarif` | SARIF |
| SIEM (Splunk, Elastic) | `--format json` | JSON |
| Compliance audit | `--format cyclonedx --output sbom.json` | CycloneDX 1.6 |
| Jira/ServiceNow | Fleet API + webhook | JSON webhook |
| Prometheus/Grafana | `--format prometheus` | Exposition format |
| CI/CD gate | `--fail-on-severity critical` | Exit code |

## What We Never Do

- Never write to any cloud resource (pure read-only)
- Never cache credentials to disk
- Never log credential values (`sanitize_error()` strips them)
- Never require admin or write permissions
- Never make third-party network calls beyond explicitly listed data sources.
  Local UI-to-API traffic is expected when using the dashboard or browser client.
- Never install agents on target systems
- Never store PII or secret values in scan results

## Supply Chain Integrity

agent-bom protects its own supply chain:

- **Docker images:** base image SHA-pinned, non-root user, OS patches applied
- **GitHub Actions:** all pinned to full SHA digests (not floating tags)
- **Dependencies:** every transitive dep pinned with CVE reference in pyproject.toml
- **Releases:** SLSA L3 provenance attestation + Sigstore signing
- **No eval/exec:** zero `eval()`, `exec()`, or `shell=True` in production code
- **Self-scan:** agent-bom scans itself on every merge (post-merge-self-scan.yml)

## Adoption path by team

| Team | First rollout step | Next step |
|------|--------------------|-----------|
| Developers | `agent-bom agents -p .` | `agent-bom skills scan .` + local `agent-bom check` |
| AppSec / security engineering | GitHub Action with SARIF | Fleet API + policy-as-code gates |
| Platform / DevOps | Docker image gate + IaC scan | Air-gapped DB sync + runtime proxy |
| Enterprise security | Central `agent-bom serve` | Postgres/Snowflake/ClickHouse + webhook integrations |
