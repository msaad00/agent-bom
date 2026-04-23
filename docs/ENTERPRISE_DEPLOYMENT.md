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

## Deployment Models

### 1. CI/CD Pipeline — scan on every PR

Start with a familiar adoption pattern: a single CI step that fails on policy, uploads SARIF, and produces artifacts security teams can review.

```yaml
# GitHub Actions
- uses: msaad00/agent-bom@v0.81.1
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
- uses: msaad00/agent-bom@v0.81.1
  with:
    scan-type: image
    scan-ref: ghcr.io/acme/agent-runtime:sha-abcdef
    severity-threshold: critical

# IaC gate
- uses: msaad00/agent-bom@v0.81.1
  with:
    scan-type: iac
    iac: Dockerfile,k8s/,infra/main.tf
    severity-threshold: high

# Air-gapped or fully cached CI
- uses: msaad00/agent-bom@v0.81.1
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
- `GET /v1/compliance` — 14-framework compliance posture

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

For PostgreSQL-backed deployments, `agent-bom` now also pushes the authenticated tenant into the database session (`app.tenant_id`) so Postgres row-level security can enforce the same tenant boundary for fleet and schedule data. Internal scheduler work uses an explicit trusted bypass rather than silently reading across tenants.

For horizontally scaled control-plane APIs, shared rate limiting is mandatory. `agent-bom` now fails closed when `AGENT_BOM_CONTROL_PLANE_REPLICAS > 1` (or `AGENT_BOM_REQUIRE_SHARED_RATE_LIMIT=1`) and no PostgreSQL-backed limiter is configured via `AGENT_BOM_POSTGRES_URL`.

**Storage:** SQLite for single-node and local persistence, PostgreSQL-compatible backends such as PostgreSQL and Supabase for the transactional control plane, ClickHouse for analytics, and Snowflake for selected enterprise store paths where parity is explicitly implemented. Snowflake does not yet have full parity for every transactional API store, so PostgreSQL-compatible backends remain the primary control-plane default when you need tenant-scoped keys, exceptions, schedules, graph state, and trend history.

Use the backend story this way:

- `SQLite`: local and single-node
- `Postgres` / `Supabase`: control-plane default
- `ClickHouse`: analytics add-on
- `Snowflake`: warehouse-native and governance-oriented mode with explicit parity limits

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
# Scan all cloud providers in one command
agent-bom cloud aws,azure,gcp

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
  -v ~/.config:/root/.config:ro \
  -v $(pwd):/workspace:ro \
  agentbom/agent-bom:0.81.1 agents --format json
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
