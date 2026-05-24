# MCP Server Setup

agent-bom runs as an MCP server, exposing 55 MCP tools to any MCP client.
The server card also advertises 6 resources and 6 workflow prompts so agents can
choose structured playbooks instead of guessing tool order.
Most tools are read-only. Shield write actions require `operator_role=admin`,
`operator_scopes=shield:write`, and an audit reason.

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

=== "Codex CLI"

    Add to `~/.codex/config.toml`:

    ```toml
    [mcp_servers.agent-bom]
    command = "uvx"
    args = ["agent-bom", "mcp", "server"]
    ```

=== "Cortex Code"

    Add to `~/.snowflake/cortex/mcp.json`:

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

    `agent-bom agents --snowflake` also discovers Snowflake Cortex, MCP server,
    Snowpark, notebook, Streamlit, package, and query-history evidence when the
    Snowflake connector is configured.

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
| `intel_lookup` | Look up a CVE, GHSA, or OSV advisory |
| `intel_match` | Match package or purl inventory against local advisories |
| `intel_sources` | List threat-intel source freshness and licensing metadata |
| `blast_radius` | Map CVE impact chain |
| `exposure_paths` | Return ranked ExposurePath investigation paths |
| `should_i_deploy` | Return allow/warn/block deploy guidance from ExposurePath risk |
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
| `runtime_production_index` | Metadata-only runtime production posture |
| `runtime_blueprints` | Role/profile blueprints for runtime policy design |
| `runtime_blueprint_drift` | Evaluate runtime posture against a role/profile blueprint |
| `proxy_status` | Current MCP proxy metrics and alert posture |
| `proxy_alerts` | Recent tenant-scoped runtime proxy alerts |
| `gateway_status` | Gateway policy and inter-agent firewall runtime statistics |
| `shield_status` | Shield session status without changing enforcement |
| `shield_start` | Start Shield enforcement with admin role, `shield:write` scope, and audit reason |
| `shield_unblock` | Unblock Shield enforcement with admin role, `shield:write` scope, and audit reason |
| `shield_break_glass` | Emergency Shield override with admin role, `shield:write` scope, and audit reason |
| `firewall_check` | Read-only inter-agent firewall decision dry run |
| `audit_query` | Tenant-scoped control-plane audit records |
| `audit_integrity` | Control-plane and runtime audit-chain verification |
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
| `ingest_external_scan` | Import third-party SBOM / SCA scan output (CycloneDX, SPDX, SARIF, scanner JSON) |

## Resources

| URI | Description |
|-----|-------------|
| `registry://servers` | Browse the MCP server security metadata registry |
| `policy://template` | Default policy-as-code template |
| `metrics://tools` | Bounded MCP tool execution metrics |
| `schema://inventory-v1` | Canonical pushed-inventory schema contract |
| `bestpractices://mcp-hardening` | NSA-informed MCP hardening control mapping |
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

## Client and skill guides

- [MCP client matrix](https://github.com/msaad00/agent-bom/blob/main/docs/MCP_CLIENT_GUIDES.md)
- [Claude Desktop / Claude Code](https://github.com/msaad00/agent-bom/blob/main/docs/CLAUDE_INTEGRATION.md)
- [Codex CLI](https://github.com/msaad00/agent-bom/blob/main/docs/CODEX_CLI.md)
- [Cortex CoCo / Cortex Code](https://github.com/msaad00/agent-bom/blob/main/docs/CORTEX_CODE.md)
- [Snowflake Native App](https://github.com/msaad00/agent-bom/blob/main/docs/snowflake-native-app/INSTALL.md)
- [Contributing agent-bom skills](https://github.com/msaad00/agent-bom/blob/main/docs/CONTRIBUTING_SKILLS.md)
