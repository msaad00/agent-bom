# Enterprise Deployment Guide

Deploy agent-bom across your organization — from developer endpoints to cloud infrastructure.

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

```yaml
# GitHub Actions
- uses: msaad00/agent-bom@v0
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
- `GET /v1/compliance` — 16-framework compliance posture

**Authentication:** API key auth (`AGENT_BOM_API_KEY`), rate limiting, CORS controls.
**Storage:** SQLite (single node), PostgreSQL (team), Snowflake/ClickHouse (enterprise).

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
  agentbom/agent-bom:v0.75.7 agents --format json
```

Multi-arch: `linux/amd64` + `linux/arm64`. Non-root container. SHA-pinned base image.

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
- Never make network calls beyond explicitly listed data sources
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
