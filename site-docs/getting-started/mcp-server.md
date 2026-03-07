# MCP Server Setup

agent-bom runs as an MCP server, exposing 22 security tools to any MCP client.

## Local (stdio)

Add to your MCP client config:

=== "Claude Desktop / Claude Code"

    ```json
    {
      "mcpServers": {
        "agent-bom": {
          "command": "uvx",
          "args": ["agent-bom", "mcp-server"]
        }
      }
    }
    ```

=== "Cursor"

    ```json
    {
      "mcpServers": {
        "agent-bom": {
          "command": "uvx",
          "args": ["agent-bom", "mcp-server"]
        }
      }
    }
    ```

=== "VS Code"

    ```json
    {
      "mcpServers": {
        "agent-bom": {
          "command": "uvx",
          "args": ["agent-bom", "mcp-server"]
        }
      }
    }
    ```

## Self-hosted SSE

```bash
docker build -f Dockerfile.sse -t agent-bom-sse .
docker run -p 8080:8080 agent-bom-sse
```

Connect with:
```json
{
  "mcpServers": {
    "agent-bom": {
      "type": "sse",
      "url": "http://localhost:8080/sse"
    }
  }
}
```

## Available tools

| Tool | Description |
|------|-------------|
| `scan` | Full discovery + vulnerability scan |
| `check` | Check a package for CVEs |
| `blast_radius` | Map CVE impact chain |
| `registry_lookup` | Look up MCP server security metadata |
| `compliance` | Run compliance framework checks |
| `remediate` | Prioritized remediation plan |
| `verify` | Package integrity + SLSA provenance |
| `skill_trust` | Assess skill file trust level |
| `generate_sbom` | Generate SBOM (CycloneDX / SPDX) |
| `policy_check` | Evaluate against security policy |
| `diff` | Compare two scan reports |
| `marketplace_check` | Pre-install trust check |
| `code_scan` | SAST scanning via Semgrep |
| `where` | Show discovery paths |
| `inventory` | List discovered agents/servers/packages |
| `context_graph` | Agent topology with lateral movement |
| `analytics_query` | Query vulnerability trends |
| `cis_benchmark` | CIS benchmark checks (AWS/Snowflake) |
| `fleet_scan` | Batch registry lookup + risk scoring |
| `runtime_correlate` | Cross-reference runtime logs with CVEs |
