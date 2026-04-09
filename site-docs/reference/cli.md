# CLI Reference

## Commands

| Command | Description |
|---------|-------------|
| `agents` | Discover MCP clients + scan for vulnerabilities |
| `check` | Check a specific package for CVEs |
| `verify` | Verify package integrity / provenance or self-verify `agent-bom` |
| `where` | Show MCP discovery paths checked on this machine |
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

## Command contracts

- `check` supports terminal output by default plus `--format json` for machine-readable pre-install verdicts.
- `report history` and `report diff` support `--format json` for CI and automation.
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

## Environment variables

| Variable | Purpose | Required |
|----------|---------|----------|
| `NVD_API_KEY` | Increase NVD rate limit | No |
| `SNYK_TOKEN` | Snyk enrichment | No |
| `AGENT_BOM_CLICKHOUSE_URL` | Analytics storage | No |
| `AWS_PROFILE` | AWS CIS benchmark | Only for `cis-benchmark --provider aws` |
| `SNOWFLAKE_ACCOUNT` | Snowflake CIS benchmark | Only for `cis-benchmark --provider snowflake` |
