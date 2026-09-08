# MCP Server — Connect agent-bom to AI Assistants

agent-bom starts with 8 focused MCP tools. Select a task profile for graph, cloud, runtime or audit work;
`--profile full` explicitly exposes the complete compatibility catalog of 86 MCP tools. Clients that negotiate the
locked MCP SDK's session-era `2025-11-25` handshake can connect over stdio or
Streamable HTTP and use vulnerability scanning, blast radius analysis,
compliance checks, runtime posture, and supply-chain verification. SSE remains
available as a deprecated transport, but it has not been wire-verified by the
compatibility contract.

The current official MCP revision is `2026-07-28`; agent-bom does not claim
compatibility with it. Clients must retain a `2025-11-25` fallback until the
2026 protocol lane, including stateless requests, `server/discover`, required
headers, extensions, and updated authorization rules, has executable evidence.
See `src/agent_bom/data/mcp_protocol_compatibility.json` for the bounded matrix.

See also:

- [MCP client guides](MCP_CLIENT_GUIDES.md)
- [Claude Desktop / Claude Code guide](CLAUDE_INTEGRATION.md)
- [Cortex CoCo / Cortex Code guide](CORTEX_CODE.md)
- [Codex CLI guide](CODEX_CLI.md)
- [Runtime Monitoring](RUNTIME_MONITORING.md)

## Quick Start

### Claude Desktop

Add to your `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/`):

```json
{
  "mcpServers": {
    "agent-bom": {
      "command": "agent-bom",
      "args": ["mcp", "server"]
    }
  }
}
```

Restart Claude Desktop. You can now ask: *"Scan my AI agents for vulnerabilities"*

### Claude Code

If you already use the Claude CLI, add agent-bom directly:

```bash
claude mcp add agent-bom -- uvx agent-bom mcp server
```

Claude Code project-level MCP servers are also discovered from `~/.claude.json`.

### Cortex CoCo

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

CoCo starts with the same 8 scan-profile tools. Add `--profile full` only for the complete compatibility catalog.

agent-bom also discovers Cortex auxiliary security files alongside `mcp.json`:

- `settings.json`
- `permissions.json`
- `hooks.json`

### Cursor / Windsurf / VS Code

Add to your MCP settings (`.cursor/mcp.json` or equivalent):

```json
{
  "mcpServers": {
    "agent-bom": {
      "command": "agent-bom",
      "args": ["mcp", "server"]
    }
  }
}
```

agent-bom discovers these MCP client config paths directly:

- Cursor: `~/Library/Application Support/Cursor/User/globalStorage/cursor.mcp/mcp.json`, `~/.cursor/mcp.json`
- Windsurf: `~/.windsurf/mcp.json`, `~/Library/Application Support/Windsurf/User/globalStorage/windsurf.mcp/mcp.json`
- VS Code: `~/Library/Application Support/Code/User/mcp.json`, plus workspace `.vscode/mcp.json`

### Codex CLI

Add to `~/.codex/config.toml`:

```toml
[mcp_servers.agent-bom]
command = "uvx"
args = ["agent-bom", "mcp", "server"]
```

Codex uses TOML, so manual proxy wrapping is the right path when you want runtime inspection around a third-party server.

### SSE Transport (Remote / Multi-Client)

```bash
agent-bom mcp server --transport sse --host 0.0.0.0 --port 8000 --bearer-token "$AGENT_BOM_MCP_BEARER_TOKEN"
```

Connect any SSE-capable MCP client to `https://your-server/sse`.
For non-loopback SSE or Streamable HTTP binds, `agent-bom` now fails closed unless you set
`--bearer-token` / `AGENT_BOM_MCP_BEARER_TOKEN` or explicitly pass
`--allow-insecure-no-auth`. Keep TLS at your proxy or ingress for remote deployments.
The regular bearer token is read-only. To enable audited Shield or identity
write tools, configure a distinct `AGENT_BOM_MCP_OPERATOR_TOKEN`; startup rejects
identical read and operator credential values. Write calls still need
`operator_role=admin`, the matching `operator_scopes` value, and an audit reason,
but those arguments no longer authorize the write by themselves.
Every configured HTTP/SSE token requires an absolute timezone-aware ISO-8601
expiry: `AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT` for read access and
`AGENT_BOM_MCP_OPERATOR_TOKEN_EXPIRES_AT` when an operator token is configured.
Startup rejects missing, malformed, expired, or more-than-one-hour deadlines;
requests are rejected at expiry before any read or write scope is returned.
Provision a fresh token and its deadline through your own credential-management
workflow; Agent-Bom does not issue or automatically rotate these credentials.
Supply both through the deployment's secure environment mechanism. The one-hour
bound limits remaining acceptance, not proof of when the token was created.
Local stdio does not use these HTTP credentials or require a token expiry.

MCP HTTP authentication uses operator-provisioned bearer credentials. The MCP
server does not expose an embedded OAuth authorization server or accept tokens
previously minted by that embedded issuer. Unattended dynamic registration and
OAuth token issuance are unavailable: PKCE alone does not establish permission
to read the server's private evidence. Configure the existing bearer credential
in the client through its supported secure credential mechanism. API SSO/OIDC
and gateway authentication are separate surfaces.

Rotate the token and its absolute deadline together, then restart the MCP
process to load the replacement. Environment changes do not hot-reload into a
running verifier. Preserve the same deadline across ordinary restarts; never
regenerate a deadline at boot for an unchanged token. A restart cannot extend an
expired configured credential. There is no embedded OAuth refresh flow. Existing
remote deployments must provision bounded credentials before upgrading; registry
clients must receive the replacement through their secure credential settings.


### Enterprise Control-Plane Contract

Local MCP server mode stays intentionally low-friction for workstation scans.
Enterprise MCP Gateway deployments should consume the same control-plane
contract as the API and UI: tenant identity, policy, audit, secret-manager
posture, and lifecycle state come from the control plane. Gateway credentials
belong in Helm/Kubernetes secrets or the operator secret manager, not in client
configs, and gateway audit events should flow back through the tenant-scoped
control-plane audit path.

### Docker

```bash
docker run -it --rm \
  -v ~/.config:/home/abom/.config:ro \
  -v ~/.agent-bom:/home/abom/.agent-bom \
  agentbom/agent-bom:latest mcp server
```

## Runtime proxy

Use the proxy when you want to inspect or enforce on MCP traffic between a client and a third-party server:

```bash
agent-bom proxy "npx @modelcontextprotocol/server-filesystem /workspace"
```

This keeps the real server behind `agent-bom` and enables runtime detectors for tool drift, credential leakage, injection patterns, sequence risk, and related policy decisions.

For JSON-configured clients like Claude Desktop or Cortex CoCo, use:

```bash
agent-bom proxy-configure --log-dir ~/.agent-bom/logs --detect-credentials
```

Add `--apply` to write the wrapped config back to compatible JSON MCP config files.

For IT-owned rollout across managed laptops, use:

```bash
agent-bom proxy-bootstrap \
  --bundle-dir ./endpoint-bundle \
  --control-plane-url https://agent-bom.example.com \
  --push-url https://agent-bom.example.com/v1/fleet/sync
```

`proxy-configure` is best for JSON MCP clients such as Claude Desktop, Cursor, Windsurf, and Cortex CoCo. TOML-based clients like Codex CLI need manual proxy wrapping.

## Tool Categories (86 tools)

These categories describe `--profile full`, not the default startup catalog.
The [profile guide](MCP_WORKFLOWS.md) lists the smaller task surfaces.

| Category | Tools | What They Do |
|----------|-------|-------------|
| **Scan** | `scan`, `code_scan`, `vector_db_scan`, `gpu_infra_scan`, `ai_inventory_scan` | Discover agents; execute Semgrep SAST with typed findings/clean/skipped/failed status; scan packages, vector stores, GPU infra, and AI usage |
| **Check** | `check`, `verify`, `marketplace_check`, `license_compliance_scan` | Pre-install CVE gate, integrity verification, marketplace trust, and license policy |
| **Blast Radius** | `blast_radius`, `exposure_paths`, `graph_correlate`, `graph_correlation_status`, `should_i_deploy` | Map package → vulnerability finding → MCP server (tools + credential env names) → connected agents; correlate exact snapshot receipts; return ranked ExposurePath JSON and allow/warn/block deploy guidance for headless agents |
| **Registry** | `registry_lookup`, `inventory`, `where`, `fleet_scan` | Query the MCP registry, inspect discovery paths, and summarize fleet inventories |
| **Compliance** | `compliance`, `cis_benchmark`, `aisvs_benchmark` | Run OWASP, NIST, MITRE ATLAS, CIS, and AISVS-aligned posture checks |
| **Policy** | `policy_check`, `remediate` | Evaluate policies and generate guided remediation plans |
| **Inventory** | `inventory` | List agents/servers without CVE scanning |
| **Trust** | `marketplace_check`, `runtime_correlate`, `tool_risk_assessment` | Score package trust, correlate runtime usage, and assess live tool capability risk |
| **Skills** | `skill_scan`, `skill_verify`, `skill_trust` | Instruction-file trust, provenance, and tool-poisoning detection |
| **Graph / Runtime** | `exposure_paths`, `should_i_deploy`, `context_graph`, `graph_export`, `runtime_correlate`, `runtime_production_index`, `runtime_blueprints`, `runtime_blueprint_drift`, `proxy_status`, `proxy_alerts`, `gateway_status`, `shield_status`, `shield_start`, `shield_unblock`, `shield_break_glass`, `firewall_check`, `audit_query`, `audit_integrity`, `tool_risk_assessment` | Return ranked investigation paths, deploy decisions, graph exports, runtime posture, blueprints, drift checks, cursor-paged gateway activity, operator self-posture, audit-chain evidence, read-only firewall decisions, and audited Shield actions |
| **AI supply chain** | `dataset_card_scan`, `training_pipeline_scan`, `browser_extension_scan`, `model_provenance_scan`, `prompt_scan`, `model_file_scan`, `ingest_external_scan`, `runtime_evidence_ingest` | Scan AI artifacts, prompts, model files, and browser extensions; import tool-agnostic SARIF/SBOM/scanner evidence without executing its producer; merge CWPP runtime signals |

<details>
<summary>Complete current catalog (86 tools)</summary>

`scan`, `check`, `intel_lookup`, `intel_match`, `intel_sources`,
`intel_daily_brief`, `youcom_search`, `blast_radius`, `exposure_paths`, `graph_correlate`,
`graph_correlation_status`, `should_i_deploy`,
`policy_check`, `registry_lookup`, `generate_sbom`, `compliance`, `remediate`,
`skill_scan`, `skill_verify`, `skill_trust`, `verify`, `inventory_summary`,
`inventory_list`, `inventory_asset`, `where`, `tool_risk_assessment`,
`inventory`, `diff`, `marketplace_check`, `code_scan`, `context_graph`,
`graph_export`, `analytics_query`, `cis_benchmark`, `kspm_cluster_posture`,
`fleet_scan`, `runtime_correlate`, `runtime_production_index`,
`runtime_blueprints`, `runtime_blueprint_drift`, `cost_report`, `anomaly_scan`,
`drift_incidents`, `proxy_status`, `proxy_alerts`, `gateway_status`,
`shield_status`, `shield_start`, `shield_unblock`, `shield_break_glass`,
`identity_issue`, `identity_rotate`, `identity_revoke`, `identity_grant_jit`,
`identity_revoke_jit`, `firewall_check`, `audit_query`, `audit_integrity`,
`vector_db_scan`, `aisvs_benchmark`, `gpu_infra_scan`, `registry_sweep_scan`,
`dataset_card_scan`, `training_pipeline_scan`, `browser_extension_scan`,
`model_provenance_scan`, `prompt_scan`, `model_file_scan`, `ai_inventory_scan`,
`license_compliance_scan`, `ingest_external_scan`, `runtime_evidence_ingest`,
`cost_forecast`, `cost_allocation`, `credential_expiry`, `nhi_discover`,
`cloud_inventory`, `access_review`, `create_ticket`, `sync_ticket_status`,
`findings_triage`, `list_exceptions`, `request_exception`,
`approve_exception`, `risk_campaign_workflow`, `cloud_side_scan`.

</details>

## Agent-facing decision tools

Two graph-native tools are the primary MCP entry points for headless security
agents:

- `exposure_paths` returns ranked `ExposurePath` JSON from the graph store so
  an agent can explain what is exposed, why it matters, which entities prove
  it, and what fix path is recommended.
- `should_i_deploy` returns allow/warn/block deploy guidance based on matched
  `ExposurePath` risk and caller-supplied thresholds.

Both tools are read-only decision aids. They do not modify repositories,
create tickets, deploy workloads, or mutate cloud resources. Use proxy,
gateway, Shield, or API audit evidence when a decision depends on selected
live runtime traffic rather than static reachability.

## Example Conversations

**"Are my AI agents vulnerable?"**
> Agent-bom discovers your Claude Desktop, Cursor, and VS Code MCP configs,
> extracts all server packages, queries OSV/NVD for CVEs, and shows the
> blast radius chain.

**"Is it safe to install mcp-server-sqlite?"**
> Runs pre-install check: CVE scan, typosquat detection, OpenSSF Scorecard,
> license analysis, and supply chain provenance verification.

**"Show me my compliance posture"**
> Runs OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF, and CIS benchmarks
> against your infrastructure. Returns per-framework pass/fail/warn.

## Security Model

- **Read-mostly**: scanner, graph, audit, and posture tools are read-only.
  The 20 write-annotated tools cover scan-history diff, Shield, identity,
  external ingest, CWPP runtime-evidence ingest, access review, finding
  triage and exception approval, snapshot correlation, remediation campaigns,
  and ticket workflows. One process-execution tool can launch a discovered
  local MCP server only with explicit authorization. These tools require an
  authenticated MCP operator token plus admin role, their specific write
  scope (`cloud:write`, `findings:write`, `identity:write`, `scan:write`, `shield:write`,
  or `ticketing:write`), and an audit reason; stdio cannot invoke them.
- **No credential storage**: Never stores, logs, or transmits your credentials.
- **No network exfiltration**: Scans local configs, queries public CVE databases.
- **Agentless**: No agents installed on targets.

## Resources

The server exposes six MCP resources:

- `registry://servers` — Browse the full 1133-entry server security metadata registry
- `policy://template` — Default security policy template
- `metrics://tools` — Bounded MCP tool execution metrics
- `schema://inventory-v1` — Canonical pushed-inventory schema contract
- `bestpractices://mcp-hardening` — NSA-informed MCP hardening control mapping
- `compliance://framework-controls` — Framework coverage and evidence mapping

## Prompts

Built-in prompts for common workflows:

- `quick-audit` — Full agent + MCP server vulnerability scan
- `pre-install-check` — Check a package before installing
- `compliance-report` — Multi-framework compliance assessment
- `fleet-audit` — Endpoint or cloud inventory audit with graph-ready findings
- `incident-triage` — CVE or suspicious MCP finding triage using blast radius and runtime evidence
- `remediation-plan` — Human-reviewed remediation plan without modifying files
- `cloud-connection-review` — Read-only cloud or Snowflake connection review before first scan
- `gateway-fleet-live-demo` — Gateway and fleet enforcement walkthrough for a live demo

See [MCP workflow bundles](MCP_WORKFLOWS.md) for the tool order, evidence
outputs, and demo script behind each workflow.
- `fleet-audit` — Inventory and fleet scan playbook
- `incident-triage` — Finding triage with blast radius and runtime context
- `remediation-plan` — Human-reviewed remediation plan without file writes

### Runtime ingestion credentials

`runtime_evidence_ingest` sends metadata to the configured control-plane API.
It accepts no credential arguments. Provision a source-bound, expiring API key
or OIDC bearer credential in the server environment; the API verifies its exact
source scope, tenant and lifetime (at most one hour). MCP write authorization
remains independently required. See [runtime producer authentication](CLOUD_CONNECT.md#runtime-producer-authentication)
for source registration, rotation and migration from shared-secret producers.
