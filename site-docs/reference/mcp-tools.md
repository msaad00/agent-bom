# MCP Tools Reference

agent-bom exposes MCP tools for scanning, blast radius, trust, compliance,
runtime, and remediation. The tools are read-only by default: agent consumers
can request evidence and deploy guidance without mutating repos, cloud
resources, or runtime targets. Shield write actions are the exception: they
fail closed unless the caller supplies an admin role, `shield:write` scope, and
audit reason.

## Tools

### scan
Full discovery + vulnerability scan pipeline. Auto-discovers MCP clients,
extracts servers and packages, scans for CVEs, computes blast radius, or scans
a direct MCP launch package when no local config is available.
```
scan(package="npx @modelcontextprotocol/server-filesystem@2025.1.14")
```

### check
Check a single package for vulnerabilities.
```
check(package="langchain", ecosystem="pypi")
```

### intel_lookup
Look up a CVE, GHSA, or OSV advisory in the local threat-intel database.
```
intel_lookup(advisory_id="CVE-2026-12345")
```

### intel_match
Match package or purl inventory coordinates against local threat-intel advisories.
```
intel_match(purl="pkg:pypi/requests@2.31.0")
```

### intel_sources
List governed threat-intel sources, source policy, and local feed freshness metadata.
```
intel_sources()
```

### intel_daily_brief
Return a local analyst brief with KEV lookback, high-EPSS inventory matches,
vendor advisory matches, caller-supplied IoC telemetry hits, sector/geo campaign
matches, ransomware claim matches, and source-registry freshness. It summarizes
local DB evidence plus governed caller inputs; it does not scrape vendor pages.
```
intel_daily_brief(
  packages=[{"purl": "pkg:pypi/requests@2.31.0"}],
  telemetry_indicators=[{"indicator": "198.51.100.42", "hit_count": 2}],
  tenant_profile={"sectors": ["ai infrastructure"], "geos": ["us"]}
)
```

### blast_radius
Map the full impact chain of a CVE across agents, servers, credentials, and tools.
```
blast_radius(cve_id="CVE-2024-21538")
```

### exposure_paths
Return ranked ExposurePath JSON from the graph store for headless security agents.
```
exposure_paths(tenant_id="default", limit=5, min_risk=70)
```

Use this when an AI agent needs the same ranked investigation queue that a
human reviews in the graph cockpit.

### should_i_deploy
Return an allow/warn/block deployment decision from matched ExposurePath risk.
```
should_i_deploy(candidate="requests", tenant_id="default", block_risk=80)
```

Use this as a decision aid in CI or assistant workflows. It returns reasons,
matched paths, and a verdict; it does not deploy, remediate, or open pull
requests.

### registry_lookup
Look up an MCP server in the 427+ server security metadata registry.
```
registry_lookup(server_name="brave-search")
```

### compliance
Run compliance framework checks (OWASP, MITRE ATLAS, EU AI Act, NIST, CIS, SOC 2, ISO 27001).
```
compliance(frameworks=["owasp-llm", "eu-ai-act"])
```

### remediate
Generate a prioritized remediation plan for discovered vulnerabilities.

For the JSON contract and example artifact shape, see [`remediate` Output
Contract](remediate-output.md).

### skill_scan
Scan instruction files such as `CLAUDE.md`, `.cursorrules`, `AGENTS.md`, and `skills/*.md` for package references, MCP server configs, credential env vars, trust verdicts, and audit findings.
```
skill_scan(path=".")
```

### skill_verify
Verify Sigstore provenance for instruction and skill files.
```
skill_verify(path=".")
```

### verify
Package integrity check with Sigstore signature and SLSA provenance verification.
```
verify(package="agent-bom@0.60.0")
```

### skill_trust
Audit an AI instruction file (SKILL.md, CLAUDE.md, .cursorrules, AGENTS.md) for supply chain risks, malicious behavioral patterns, and trust level.

Runs 17 behavioral risk patterns (credential file access, confirmation bypass, messaging/impersonation, voice/telephony, filesystem exfiltration, data exfiltration, and more) plus 5-category structural trust assessment:

| Category | Checks |
|----------|--------|
| Purpose & Capability | name/description consistency, binary/network scope |
| Instruction Scope | file reads bounded, data handling documented |
| Install Mechanism | install source, Sigstore signature, provenance |
| Credentials | proportionate, scoped, documented env vars |
| Persistence & Privilege | no persistence, no escalation, no telemetry |

Returns a backward-compatible verdict (`benign` / `suspicious` /
`malicious`), dual-axis `content_verdict` and `provenance_verdict` fields,
`review_verdict`, `overall_recommendation`, confidence level, per-category
results, and all findings with severity and recommendations. Clean content
with missing provenance should remain content-benign while routing the overall
recommendation to review.

```
skill_trust(skill_path="./SKILL.md")
# → {
#     "verdict": "benign",
#     "content_verdict": "benign",
#     "provenance_verdict": "unverified",
#     "review_verdict": "review",
#     "overall_recommendation": "review",
#     "confidence": "high",
#     "categories": [
#       { "name": "Install Mechanism", "level": "fail", "summary": "Unverified install source" },
#       ...
#     ],
#     "findings": [
#       { "severity": "critical", "title": "Credential/secret file access", "detail": "..." },
#       ...
#     ]
#   }
```

### generate_sbom
Generate an SBOM in CycloneDX or SPDX format.
```
generate_sbom(format="cyclonedx")
```

### policy_check
Evaluate scan results against a security policy file.

### diff
Compare two scan reports showing new, resolved, and persistent findings.

### marketplace_check
Pre-install trust check combining registry lookup with integrity verification.

### code_scan
SAST scanning via Semgrep with CWE-based compliance mapping.

### where
Show all MCP client config discovery paths and what was found.

### tool_risk_assessment
Use live MCP introspection to classify tool capabilities and risky combinations.

### inventory
List all discovered agents, servers, and packages.

### context_graph
Agent context graph with BFS lateral movement analysis.

### graph_export
Export dependency graph data for graph-native tooling.
```
graph_export(format="graphml")
```

### analytics_query
Query vulnerability trends and posture history from ClickHouse.

### cis_benchmark
Run CIS benchmark checks against AWS or Snowflake accounts.
```
cis_benchmark(provider="aws")
```

### fleet_scan
Batch registry lookup + risk scoring for MCP server inventories.
```
fleet_scan(servers=["brave-search", "filesystem", "postgres"])
```

### runtime_correlate
Cross-reference runtime audit logs with CVE findings for risk amplification.

### runtime_production_index
Return metadata-only runtime production posture for proxy and gateway traffic.
```
runtime_production_index(tenant_id="default")
```

### runtime_blueprints
Return all runtime role/profile blueprints, or a single blueprint by id.
```
runtime_blueprints(blueprint_id="security_analyst")
```

### runtime_blueprint_drift
Evaluate live runtime posture against a role/profile blueprint.
```
runtime_blueprint_drift(blueprint_id="developer", tenant_id="default")
```

### proxy_status
Return current MCP proxy metrics and runtime alert posture.
```
proxy_status(tenant_id="default")
```

### proxy_alerts
Return recent tenant-scoped runtime proxy alerts with optional severity and detector filters.
```
proxy_alerts(tenant_id="default", severity="critical", detector="", limit=50)
```

### gateway_status
Return gateway policy and inter-agent firewall runtime statistics.
```
gateway_status(tenant_id="default")
```

### shield_status
Return Shield session status without starting, stopping, or unblocking a session.
```
shield_status(session_id="default")
```

### shield_start
Start Shield enforcement for a session. Remote MCP requests must authenticate
with `AGENT_BOM_MCP_OPERATOR_TOKEN`; the call also requires
`operator_role="admin"`, `operator_scopes="shield:write"`, and an audit reason
of at least eight characters.
```
shield_start(session_id="default", operator_role="admin", operator_scopes="shield:write", reason="incident response")
```

### shield_unblock
Unblock Shield enforcement for a session. Remote MCP requests must authenticate
with `AGENT_BOM_MCP_OPERATOR_TOKEN`; the call also requires
`operator_role="admin"`, `operator_scopes="shield:write"`, and an audit reason
of at least eight characters.
```
shield_unblock(session_id="default", operator_role="admin", operator_scopes="shield:write", reason="validated unblock")
```

### shield_break_glass
Activate the Shield emergency override. Remote MCP requests must authenticate
with `AGENT_BOM_MCP_OPERATOR_TOKEN`; the call also requires
`operator_role="admin"`, `operator_scopes="shield:write"`, and an audit reason
of at least eight characters. The action is audit logged.
```
shield_break_glass(session_id="default", operator_role="admin", operator_scopes="shield:write", reason="approved emergency override")
```

### firewall_check
Dry-run an inter-agent firewall decision without recording control-plane state.
```
firewall_check(source_agent="developer-agent", target_agent="ticketing-agent")
```

### audit_query
Read tenant-scoped control-plane audit records with action, resource, time, and pagination filters.
```
audit_query(tenant_id="default", action="", resource="", since="", limit=100, offset=0)
```

### audit_integrity
Verify control-plane and runtime audit-chain integrity without mutating enforcement state.
```
audit_integrity(tenant_id="default", limit=1000, include_runtime=true)
```

### vector_db_scan
Probe Qdrant, Weaviate, Chroma, and Milvus instances for authentication misconfigurations and exposure.
```
vector_db_scan()
```

### aisvs_benchmark
Run OWASP AISVS v1.0 compliance checks — 9 AI security verification checks across model, data, and inference layers.
```
aisvs_benchmark()
```

### gpu_infra_scan
Scan GPU and AI compute infrastructure — Docker GPU containers, Kubernetes GPU nodes, DCGM unauthenticated endpoint detection.
```
gpu_infra_scan()
```

### dataset_card_scan
Scan dataset cards (Hugging Face, custom) for supply chain risks, license issues, and data provenance gaps.
```
dataset_card_scan(path="/path/to/dataset_card.md")
```

### training_pipeline_scan
Scan training pipeline configurations for security risks — untrusted data sources, insecure checkpoints, credential exposure.
```
training_pipeline_scan(path="/path/to/training_config.yaml")
```

### browser_extension_scan
Scan browser extensions for MCP and AI-related risks — nativeMessaging, broad host permissions, AI assistant domain access.
```
browser_extension_scan()
```

### model_provenance_scan
Verify model provenance and integrity — check Sigstore signatures, SLSA provenance, and supply chain attestations.
```
model_provenance_scan(model="org/model-name")
```

### prompt_scan
Scan prompts for injection patterns, exfiltration attempts, and manipulation techniques.
```
prompt_scan(prompt="<prompt text>")
```

### model_file_scan
Scan model files (ONNX, pickle, SafeTensors, etc.) for embedded threats, unsafe deserialization, and hidden payloads.
```
model_file_scan(path="/path/to/model.onnx")
```

### ai_inventory_scan
Scan source code for AI SDK imports, model references, shadow AI, and deprecated models.
```
ai_inventory_scan(path=".")
```

### license_compliance_scan
SPDX license compliance and compatibility checks — full SPDX catalog support, network-copyleft detection, license conflict identification.
```
license_compliance_scan()
```

### ingest_external_scan
Import third-party scanner output (CycloneDX, SPDX, SARIF, or scanner-native JSON) and return packages with blast-radius analysis.
```
ingest_external_scan(path="scan.json")
```

## Resources

| URI | Description |
|-----|-------------|
| `registry://servers` | Browse the full MCP server security metadata registry |
| `policy://template` | Default security policy template |
| `metrics://tools` | Bounded MCP tool execution metrics |
| `schema://inventory-v1` | Canonical pushed-inventory schema contract |
| `bestpractices://mcp-hardening` | NSA-informed MCP hardening control mapping |
| `compliance://framework-controls` | Framework coverage and evidence mapping |

## Prompts

| Prompt | Description |
|--------|-------------|
| `quick-audit` | Run a complete security audit of local AI agent and MCP setup |
| `pre-install-check` | Check an MCP server package before installing |
| `compliance-report` | Generate OWASP, ATLAS, and NIST compliance posture |
| `fleet-audit` | Audit an endpoint or cloud inventory file and return graph-ready findings |
| `incident-triage` | Prioritize a CVE or suspicious MCP finding using blast radius and runtime evidence |
| `remediation-plan` | Draft a human-reviewed remediation plan without modifying files |
