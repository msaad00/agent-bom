# MCP Server Review

> Evaluate an MCP server before adopting it — registry lookup, package vulnerability scan, tool risk analysis, and trust assessment.

## Goal

Before adding a new MCP server to your AI agent configuration, assess its security posture: Is it in the verified registry? Do its packages have CVEs? What tools does it expose? Does it require dangerous permissions?

## Prerequisites

```bash
pip install agent-bom
```

## Steps

### 1. Registry Lookup

Check if the server is in agent-bom's curated registry (100 servers, 58 verified):

```bash
# Check the registry via REST API
agent-bom api &  # Start API server
curl http://127.0.0.1:8422/v1/registry/<server-name> | python3 -m json.tool
```

Or check the registry file directly: `data/mcp-registry.yaml`

The registry provides:
- **Verified status** — has the server been independently verified?
- **Risk level** — low/medium/high/critical based on tool capabilities
- **Package name + version** — what npm/PyPI package it installs
- **Tool names** — what tools the server exposes
- **Credential env vars** — what API keys it requires
- **License** — open source license
- **Source URL** — link to source code

**Decision point**: If the server is **not in the registry**, it's unverified. Proceed with extra caution — scan its packages and review its tools manually.

### 2. Package Vulnerability Scan

Check the server's packages for known CVEs:

```bash
# Pre-install check — scan before installing
agent-bom check <package>@<version> -e <ecosystem>

# Examples:
agent-bom check @modelcontextprotocol/server-filesystem@0.6.2 -e npm
agent-bom check mcp-server-sqlite@0.1.0 -e pypi
```

**Decision point**:
- **CRITICAL CVEs** — do not install
- **HIGH CVEs** — check if a patched version exists, install that instead
- **MEDIUM/LOW** — acceptable risk, monitor for updates

### 3. Tool Risk Assessment

Review the tools the server exposes. Key risk indicators:

| Tool pattern | Risk | OWASP | Why |
|-------------|------|-------|-----|
| `execute_command`, `run_shell`, `bash` | CRITICAL | LLM02 | Arbitrary command execution |
| `read_file`, `write_file` | HIGH | LLM07 | File system access |
| `query_database`, `execute_sql` | HIGH | LLM02 | Database access |
| `send_email`, `send_message` | MEDIUM | LLM08 | Outbound communication |
| `search`, `read_url` | LOW | LLM07 | Information gathering |

**Decision point**: If the server exposes > 5 tools (excessive agency) or shell/exec tools, consider:
- Do you actually need all those tools?
- Can you restrict tool access in your MCP client config?
- Is there a more focused server with fewer tools?

### 4. Credential Exposure Check

Review what environment variables the server requires:

```bash
# Check the server's config in your MCP client
# Look for env vars in the server configuration
```

Sensitive patterns:
- `*_API_KEY`, `*_SECRET`, `*_TOKEN` — API credentials
- `DATABASE_URL`, `*_CONNECTION_STRING` — database access
- `AWS_*`, `AZURE_*`, `GCP_*` — cloud credentials

**Decision point**: If the server requires cloud credentials + has shell tools, the blast radius is maximum. A compromised server package means an attacker gets cloud access + command execution.

### 5. Full Config Scan

Add the server to your config, then run a full scan to see the blast radius:

```bash
agent-bom scan --enrich -f json -o review-scan.json
```

Check the blast radius section for the new server:
- How many credentials does it expose?
- How many tools are reachable through it?
- Does adding it change the threat framework coverage?

### 6. Policy Check

Apply your organization's policy rules:

```bash
agent-bom scan --policy policy.json --enrich -q
```

If the server triggers policy violations (e.g., unverified + HIGH severity), it should be blocked until reviewed and approved.

### 7. Ongoing Monitoring

After installing, set up continuous monitoring:

```bash
# Save baseline scan
agent-bom scan --enrich --save -f json -o baseline.json

# Periodic check — diff against baseline
agent-bom scan --enrich --baseline baseline.json -f json -o current.json
```

New CVEs in the server's packages will show up as new vulnerabilities in the diff.

## Server Trust Matrix

```
                    Verified    Unverified
                   ┌───────────┬───────────┐
  No CVEs          │  ACCEPT   │  REVIEW   │
                   ├───────────┼───────────┤
  LOW/MED CVEs     │  MONITOR  │  CAUTION  │
                   ├───────────┼───────────┤
  HIGH/CRIT CVEs   │  PATCH    │  REJECT   │
                   └───────────┴───────────┘
```

## Outputs

| Artifact | Purpose |
|----------|---------|
| Registry lookup | Verified status, risk level, tool list |
| Package scan | CVE list with CVSS + EPSS scores |
| Blast radius | Impact on agents, credentials, tools |
| Policy result | Pass/fail against org security rules |
