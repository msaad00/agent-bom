# CLI Reference

## Commands

| Command | Description |
|---------|-------------|
| `scan` | Discover MCP clients + scan for vulnerabilities |
| `check` | Check a specific package for CVEs |
| `image` | Container image scan |
| `fs` | Filesystem / VM scan |
| `iac` | Infrastructure-as-code misconfigurations |
| `mcp` | Discover, scan, and manage MCP agents |
| `mcp server` | Start MCP server (stdio) |
| `cloud` | Cloud posture + CIS benchmarks |
| `runtime proxy` | Runtime MCP proxy with enforcement |
| `runtime protect` | 7-detector anomaly engine |
| `runtime watch` | Config file change monitoring |
| `report` | History, diff, analytics, dashboard |
| `policy` | Templates and remediation |
| `serve` | Start REST API server |
| `guard` | Pre-install CVE check |
| `registry` | Registry management (list, search, update) |

## Common flags

```bash
# Output format
agent-bom scan -f json|table|html|sarif|csv

# Output file
agent-bom scan -o report.json

# Compliance
agent-bom scan --compliance owasp-llm,eu-ai-act,all

# SBOM
agent-bom scan --sbom cyclonedx|spdx

# Image scanning
agent-bom scan --image python:3.12-slim

# Policy
agent-bom scan --policy policy.json

# Enrichment
agent-bom scan --enrich    # NVD CVSS v4 + EPSS

# Prometheus
agent-bom scan --push-gateway http://pushgateway:9091

# VEX
agent-bom scan --vex vex.json
agent-bom scan --generate-vex --vex-output vex.json

# Config directory
agent-bom scan --config-dir /path/to/configs
```

## Environment variables

| Variable | Purpose | Required |
|----------|---------|----------|
| `NVD_API_KEY` | Increase NVD rate limit | No |
| `SNYK_TOKEN` | Snyk enrichment | No |
| `AGENT_BOM_CLICKHOUSE_URL` | Analytics storage | No |
| `AWS_PROFILE` | AWS CIS benchmark | Only for `cis-benchmark --provider aws` |
| `SNOWFLAKE_ACCOUNT` | Snowflake CIS benchmark | Only for `cis-benchmark --provider snowflake` |
