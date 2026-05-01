# CLI Reference

## Commands

### Scanning

| Command | Description |
|---------|-------------|
| `agents` | Discover MCP clients, extract dependencies, scan packages, and compute blast radius |
| `skills` | Scan, verify, and rescan AI instruction files and skills |
| `image` | Scan a container image |
| `fs` | Scan a filesystem directory or mounted VM disk snapshot |
| `iac` | Scan Dockerfile, Kubernetes, Terraform, CloudFormation, and live Kubernetes posture |
| `sbom` | Ingest an existing CycloneDX or SPDX SBOM and scan it |
| `cloud` | Scan AWS, Azure, or GCP infrastructure posture |
| `check` | Check one package before install or approval |
| `verify` | Verify package integrity / provenance or self-verify `agent-bom` |
| `secrets` | Scan a directory for hardcoded secrets and PII |
| `code` | Analyze source code for AI components, prompts, guardrails, and tools |

### Runtime

| Command | Description |
|---------|-------------|
| `proxy` | Run an MCP server through the agent-bom security proxy |
| `audit` | View and analyze a proxy audit JSONL log |

### MCP

| Command | Description |
|---------|-------------|
| `mcp` | Discover, scan, and manage MCP agents and servers |
| `mcp inventory` | Discover MCP agents and servers without CVE scanning |
| `mcp scan` | Check a single MCP server package or npx/uvx spec |
| `mcp introspect` | Connect to live servers and list tools |
| `mcp registry` | Browse and manage the MCP server security registry |
| `mcp server` | Start agent-bom as an MCP server over stdio |
| `mcp where` | Show MCP discovery paths checked on this machine |
| `mcp validate` | Validate an MCP/client inventory file |
| `where` | Top-level shortcut for MCP discovery paths |

### Reporting

| Command | Description |
|---------|-------------|
| `graph` | Export the transitive dependency graph from a scan report |
| `mesh` | Show lightweight agent/MCP topology without CVE scanning |
| `report` | History, diff, analytics, dashboard, and compliance narrative workflows |

### Governance And Operations

| Command | Description |
|---------|-------------|
| `policy` | Policy templates, application, and install-guard checks |
| `trust` | Show data access, network, auth, and storage boundaries |
| `fleet` | Manage AI agent fleet discovery, lifecycle, and posture |
| `serve` | Start the API server and dashboard |
| `api` | Start the REST API server |
| `schedule` | Manage recurring scan schedules |
| `remediate` | Generate a prioritized remediation plan |
| `teardown` | Tear down the AWS/EKS reference install owned by agent-bom |

### Database And Utilities

| Command | Description |
|---------|-------------|
| `db` | Manage the local vulnerability database |
| `doctor` | Check environment readiness for scanning |
| `gateway` | Multi-MCP gateway commands |
| `proxy-bootstrap` | Generate managed endpoint onboarding material |
| `samples` | Create bundled sample inputs for demos and first runs |
| `sidecar-injector` | Run the TLS admission webhook for sidecar injection |
| `upgrade` | Check for and install the latest version of agent-bom |
| `completions` | Print a shell completion script |

## Command contracts

- `check` supports terminal output by default plus `--format json` for machine-readable pre-install verdicts.
- `report history` and `report diff` support `--format json` for CI and automation.
- `remediate` supports `--format json` as the machine-readable remediation contract.
- Use `agent-bom agents -f <format> -o <path>` for SARIF, HTML, SBOM, and richer environment exports.
- Use `agent-bom agents -f sarif -o -` when you need SARIF on stdout for piping.
- `where` is available both as `agent-bom where` and `agent-bom mcp where`.
- `agent-bom verify` and `agent-bom verify agent-bom` both self-verify the installed package.

## Common flags

```bash
# Output format
agent-bom agents -f json|html|sarif|csv|cyclonedx|spdx

# Output file
agent-bom agents -o report.json
agent-bom check requests@2.33.0 -e pypi -f json -o check.json
agent-bom report diff before.json after.json -f json -o diff.json

# Compliance
agent-bom agents --compliance owasp-llm,eu-ai-act,all

# SBOM
agent-bom agents -f cyclonedx -o bom.json
agent-bom agents -f spdx -o bom.spdx.json

# Image scanning
agent-bom agents --image python:3.12-slim

# Policy
agent-bom agents --policy policy.json

# Enrichment
agent-bom agents --enrich    # NVD CVSS v4 + EPSS

# Prometheus
agent-bom agents --push-gateway http://pushgateway:9091

# VEX
agent-bom agents --vex vex.json
agent-bom agents --generate-vex --vex-output vex.json

# Config directory
agent-bom agents --config-dir /path/to/configs
```

## Troubleshooting

See [CLI Debug Guide](cli-debug.md) for quiet/logging behavior, stdout vs file output, discovery triage, and package verification workflows.

For the JSON contract behind `agent-bom remediate`, see [`remediate` Output
Contract](remediate-output.md).

## Environment variables

| Variable | Purpose | Required |
|----------|---------|----------|
| `NVD_API_KEY` | Increase NVD rate limit | No |
| `SNYK_TOKEN` | Optional commercial vuln-API enrichment | No |
| `AGENT_BOM_CLICKHOUSE_URL` | Analytics storage | No |
| `AWS_PROFILE` | AWS CIS benchmark | Only for `cis-benchmark --provider aws` |
| `SNOWFLAKE_ACCOUNT` | Snowflake CIS benchmark | Only for `cis-benchmark --provider snowflake` |
