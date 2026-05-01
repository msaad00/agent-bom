# MCP Server Setup

agent-bom runs as an MCP server, exposing 36 read-only security tools to any MCP client.
The server card also advertises 6 resources and 6 workflow prompts so agents can
choose structured playbooks instead of guessing tool order.

## Local (stdio)

Add to your MCP client config:

=== "Claude Desktop / Claude Code"

    ```json
    {
      "mcpServers": {
        "agent-bom": {
          "command": "uvx",
          "args": ["agent-bom", "mcp", "server"]
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
          "args": ["agent-bom", "mcp", "server"]
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
          "args": ["agent-bom", "mcp", "server"]
        }
      }
    }
    ```

## Self-hosted SSE

```bash
docker build -f deploy/docker/Dockerfile.sse -t agent-bom-sse .
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
| `skill_scan` | Scan instruction files for trust, findings, and provenance |
| `skill_verify` | Verify Sigstore provenance for instruction files |
| `verify` | Package integrity + SLSA provenance |
| `skill_trust` | Assess skill file trust level |
| `generate_sbom` | Generate SBOM (CycloneDX / SPDX) |
| `policy_check` | Evaluate against security policy |
| `diff` | Compare two scan reports |
| `marketplace_check` | Pre-install trust check |
| `code_scan` | SAST scanning via Semgrep |
| `where` | Show discovery paths |
| `tool_risk_assessment` | Score live MCP tool capabilities and server risk |
| `inventory` | List discovered agents/servers/packages |
| `context_graph` | Agent topology with lateral movement |
| `graph_export` | Export graph data as GraphML, Cypher, DOT, or Mermaid |
| `analytics_query` | Query vulnerability trends |
| `cis_benchmark` | CIS benchmark checks (AWS/Snowflake) |
| `fleet_scan` | Batch registry lookup + risk scoring |
| `runtime_correlate` | Cross-reference runtime logs with CVEs |
| `vector_db_scan` | Probe vector DBs for auth misconfigurations |
| `aisvs_benchmark` | OWASP AISVS v1.0 compliance checks |
| `gpu_infra_scan` | GPU/AI compute infrastructure scanning |
| `dataset_card_scan` | Scan dataset cards for supply chain risks |
| `training_pipeline_scan` | Scan training pipeline configs for risks |
| `browser_extension_scan` | Scan browser extensions for MCP/AI risks |
| `model_provenance_scan` | Verify model provenance and integrity |
| `prompt_scan` | Scan prompts for injection and exfiltration |
| `model_file_scan` | Scan model files for embedded threats |
| `ai_inventory_scan` | Detect AI SDK imports, shadow AI, and deprecated models |
| `license_compliance_scan` | SPDX license compliance and compatibility checks |
| `ingest_external_scan` | Import Trivy, Grype, or Syft scan output |

## Resources

| URI | Description |
|-----|-------------|
| `registry://servers` | Browse the MCP server security metadata registry |
| `policy://template` | Default policy-as-code template |
| `metrics://tools` | Bounded MCP tool execution metrics |
| `schema://inventory-v1` | Canonical pushed-inventory schema contract |
| `bestpractices://mcp-hardening` | MCP hardening checklist |
| `compliance://framework-controls` | Framework coverage and evidence mapping |

## Prompts

| Prompt | Use |
|--------|-----|
| `quick-audit` | Discover and scan local AI agent and MCP configuration |
| `pre-install-check` | Check an MCP package before adding it to a client config |
| `compliance-report` | Produce a multi-framework security posture summary |
| `fleet-audit` | Validate and scan a pushed inventory or fleet export |
| `incident-triage` | Prioritize a CVE or suspicious MCP finding by blast radius |
| `remediation-plan` | Draft a human-reviewed remediation plan without file writes |
