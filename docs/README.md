# Docs Index

`docs/` holds the engineering and operator reference. The onboarding site is
built from [`../site-docs/`](../site-docs/index.md) and published at
<https://msaad00.github.io/agent-bom/>. When a topic appears in both, `docs/`
owns the reference detail and `site-docs/` owns the walkthrough.

New here? Read [`START_HERE.md`](START_HERE.md) for role-based paths, then
[`ARCHITECTURE.md`](ARCHITECTURE.md) for the one-page system overview.

## Using agent-bom

- [`FIRST_RUN.md`](FIRST_RUN.md) — install, first scan, first artifact, CI gate
- [`START_HERE.md`](START_HERE.md) — role-based entry paths
- [`HOW_IT_WORKS.md`](HOW_IT_WORKS.md) — five-stage evidence flow
- [`GALLERY.md`](GALLERY.md) — product scenarios with captures
- [`SCAN_EVIDENCE_JOURNEY.md`](SCAN_EVIDENCE_JOURNEY.md) — inspect scan evidence and a per-agent BOM
- [`CLI_MAP.md`](CLI_MAP.md) — all 50 top-level commands grouped by domain + intentional aliases
- [`cli.md`](cli.md) · [`CLI_DEBUG_GUIDE.md`](CLI_DEBUG_GUIDE.md) — CLI reference and debugging
- [`MCP_SERVER.md`](MCP_SERVER.md) — run the MCP server with 8 default tools and optional task profiles
- [`MCP_WORKFLOWS.md`](MCP_WORKFLOWS.md) · [`MCP_CLIENT_GUIDES.md`](MCP_CLIENT_GUIDES.md) · [`MCP_ERROR_CODES.md`](MCP_ERROR_CODES.md) · [`MCP_OAUTH.md`](MCP_OAUTH.md) — MCP workflows, clients, errors, remote OAuth
- [`CLAUDE_INTEGRATION.md`](CLAUDE_INTEGRATION.md) · [`CODEX_CLI.md`](CODEX_CLI.md) · [`CORTEX_CODE.md`](CORTEX_CODE.md) — assistant integrations
- [`INTEGRATIONS.md`](INTEGRATIONS.md) — integration capability matrix
- [`PYTHON_API.md`](PYTHON_API.md) · [`PLUGIN_ENTRYPOINTS.md`](PLUGIN_ENTRYPOINTS.md) — Python client and plugin loader
- [`GITHUB_ACTION_SARIF_TROUBLESHOOTING.md`](GITHUB_ACTION_SARIF_TROUBLESHOOTING.md) — SARIF upload troubleshooting
- [`AI_INFRASTRUCTURE_SCANNING.md`](AI_INFRASTRUCTURE_SCANNING.md) · [`AI_ENRICHMENT.md`](AI_ENRICHMENT.md) — AI infrastructure scanning and enrichment
- [`AGENT_BOM_PROFILE.md`](AGENT_BOM_PROFILE.md) · [`AGENT_LIFECYCLE.md`](AGENT_LIFECYCLE.md) · [`AGENT_IDENTITY_BINDINGS.md`](AGENT_IDENTITY_BINDINGS.md) — per-agent BOM, retained history, identity
- [`RISK_CAMPAIGNS.md`](RISK_CAMPAIGNS.md) — remediation campaigns, ticketing, verification
- [`COST_MODEL.md`](COST_MODEL.md) — open cost model for LLM spend
- [`INACCURATE_FINDING_REPORT.md`](INACCURATE_FINDING_REPORT.md) — report a wrong finding

## Deploying

- [`DEPLOY_PLATFORM.md`](DEPLOY_PLATFORM.md) — deployment hub (Compose, Helm, EKS, hosted)
- [`DEPLOY_QUICKSTART.md`](DEPLOY_QUICKSTART.md) · [`DEPLOYMENT.md`](DEPLOYMENT.md) — quickstart and scalability architecture
- [`STORAGE_BACKENDS.md`](STORAGE_BACKENDS.md) — storage backend support tiers, tenant-isolation evidence and migration to Postgres
- [`EDITIONS.md`](EDITIONS.md) · [`PRODUCT_MAP.md`](PRODUCT_MAP.md) — deployment lanes and surface chooser
- [`CLOUD_CONNECT.md`](CLOUD_CONNECT.md) · [`DATA_SOURCES.md`](DATA_SOURCES.md) · [`INGEST_PATHS.md`](INGEST_PATHS.md) — cloud connections, intake mechanisms, ingest paths
- [`ENDPOINT_CONNECTORS.md`](ENDPOINT_CONNECTORS.md) · [`DATABASE_EVIDENCE.md`](DATABASE_EVIDENCE.md) — endpoint and database connectors
- [`AUTH_SSO.md`](AUTH_SSO.md) — single sign-on setup
- [`RUNTIME_REFERENCE.md`](RUNTIME_REFERENCE.md) · [`RUNTIME_MONITORING.md`](RUNTIME_MONITORING.md) · [`RUNTIME_FAIL_MODES.md`](RUNTIME_FAIL_MODES.md) · [`RUNTIME_PROXY_AUDIT_JSONL.md`](RUNTIME_PROXY_AUDIT_JSONL.md) — proxy and gateway
- [`AGENT_FIREWALL.md`](AGENT_FIREWALL.md) · [`POLICY_PRECEDENCE.md`](POLICY_PRECEDENCE.md) — inter-agent firewall and policy order
- [`HOSTED_POC.md`](HOSTED_POC.md) — hosted deployment runbook
- [`snowflake-native-app/`](snowflake-native-app/INSTALL.md) — Snowflake Native App preview

## Security and compliance

- [`TRUST.md`](TRUST.md) · [`PERMISSIONS.md`](PERMISSIONS.md) · [`PRODUCT_BOUNDARIES.md`](PRODUCT_BOUNDARIES.md) — what is read, stored and never touched
- [`THREAT_MODEL.md`](THREAT_MODEL.md) · [`SECURITY_ARCHITECTURE.md`](SECURITY_ARCHITECTURE.md) — threat model and security architecture
- [`MCP_SECURITY_MODEL.md`](MCP_SECURITY_MODEL.md) · [`SCIM_SECURITY_MODEL.md`](SCIM_SECURITY_MODEL.md) · [`TENANT_RESOLUTION.md`](TENANT_RESOLUTION.md) — MCP, SCIM and tenant boundaries
- [`SECURITY_TESTING_EVIDENCE.md`](SECURITY_TESTING_EVIDENCE.md) · [`SECURITY_AUTH_TENANCY_AUDIT.md`](SECURITY_AUTH_TENANCY_AUDIT.md) · [`PENTEST_READINESS.md`](PENTEST_READINESS.md) — test evidence and pentest scope
- [`CONTROL_MAPPING.md`](CONTROL_MAPPING.md) · [`ATLAS_COVERAGE.md`](ATLAS_COVERAGE.md) · [`COMPLIANCE_SIGNING.md`](COMPLIANCE_SIGNING.md) — control mappings and signed evidence bundles
- [`VULNERABILITY_MATCHING.md`](VULNERABILITY_MATCHING.md) · [`SCANNER_ACCURACY_BASELINE.md`](SCANNER_ACCURACY_BASELINE.md) · [`SCANNER_CONTEXT_CONTRACT.md`](SCANNER_CONTEXT_CONTRACT.md) — matching method and measured accuracy
- [`SUPPLY_CHAIN.md`](SUPPLY_CHAIN.md) · [`IMAGE_SECURITY.md`](IMAGE_SECURITY.md) · [`GOLDEN_IMAGE_PROGRAM.md`](GOLDEN_IMAGE_PROGRAM.md) · [`RELEASE_VERIFICATION.md`](RELEASE_VERIFICATION.md) — our own supply chain and release verification
- [`DATA_GOVERNANCE_RETENTION.md`](DATA_GOVERNANCE_RETENTION.md) — retention and tenant deletion
- [`SELF_GOVERNANCE.md`](SELF_GOVERNANCE.md) — scanning agent-bom with agent-bom
- [`security/`](security/) — focused security notes

## Architecture and decisions

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — system overview, layer rules, module notes
- [`ARCHITECTURE_BOUNDARIES.md`](ARCHITECTURE_BOUNDARIES.md) · [`CHANGE_GUARDRAILS.md`](CHANGE_GUARDRAILS.md) — enforced boundaries and change gates
- [`decisions/`](decisions/README.md) — architecture decision records
- [`PROJECT_STRUCTURE.md`](PROJECT_STRUCTURE.md) — repository map
- [`DATA_MODEL.md`](DATA_MODEL.md) · [`IDENTITY_AND_NAMING_CONTRACT.md`](IDENTITY_AND_NAMING_CONTRACT.md) · [`DISCOVERY_ENVELOPE.md`](DISCOVERY_ENVELOPE.md) — data model and identifiers
- [`graph/CONTRACT.md`](graph/CONTRACT.md) · [`GRAPH_MIGRATION.md`](GRAPH_MIGRATION.md) — graph guarantees and limits
- [`CONCURRENCY_AND_FAILURE_MODEL.md`](CONCURRENCY_AND_FAILURE_MODEL.md) · [`SESSION_FLOWS.md`](SESSION_FLOWS.md) — concurrency, failure and enforcement flows
- [`OCSF_BOUNDARY.md`](OCSF_BOUNDARY.md) · [`POSTURE_EVENT_STREAMING.md`](POSTURE_EVENT_STREAMING.md) · [`WAREHOUSE_EXPORTS.md`](WAREHOUSE_EXPORTS.md) — export contracts
- [`FLEET_CONTAINMENT_IDENTITY.md`](FLEET_CONTAINMENT_IDENTITY.md) — fleet containment identity
- [`design/`](design/) — design contracts · [`openapi/v1.json`](openapi/v1.json) — REST contract · [`schemas/`](schemas/) — JSON schemas

## Operations and enterprise

- [`ENTERPRISE.md`](ENTERPRISE.md) — enterprise hub: controls-to-code map and the sibling docs below
- [`ENTERPRISE_DEPLOYMENT.md`](ENTERPRISE_DEPLOYMENT.md) · [`ENTERPRISE_SECURITY_POSTURE.md`](ENTERPRISE_SECURITY_POSTURE.md) · [`ENTERPRISE_SECURITY_PLAYBOOK.md`](ENTERPRISE_SECURITY_PLAYBOOK.md)
- [`ENTERPRISE_PROCUREMENT_PACKET.md`](ENTERPRISE_PROCUREMENT_PACKET.md) · [`ENTERPRISE_OPERATIONS_EVIDENCE.md`](ENTERPRISE_OPERATIONS_EVIDENCE.md) · [`ENTERPRISE_SUPPORT_MODEL.md`](ENTERPRISE_SUPPORT_MODEL.md)
- [`ENTERPRISE_DEMO.md`](ENTERPRISE_DEMO.md) — synthetic enterprise estate demo
- [`CONTROL_PLANE_TESTING.md`](CONTROL_PLANE_TESTING.md) · [`PERFORMANCE_BENCHMARKS.md`](PERFORMANCE_BENCHMARKS.md) · [`perf/`](perf/) — test matrix, benchmarks, workload receipts
- [`OBSERVABILITY_METRICS.md`](OBSERVABILITY_METRICS.md) · [`operations/`](operations/) — metrics and runbooks
- [`PRODUCT_BRIEF.md`](PRODUCT_BRIEF.md) · [`PRODUCT_METRICS.md`](PRODUCT_METRICS.md) · [`AGENT_CAPABILITY.md`](AGENT_CAPABILITY.md) — positioning, metrics snapshot, capability manifest
- [`PUBLISHING.md`](PUBLISHING.md) · [`PUBLICATION_POLICY.md`](PUBLICATION_POLICY.md) · [`release/`](release/) · [`registry/`](registry/) — publishing and registry listings
- [`CAPTURE.md`](CAPTURE.md) · [`VISUAL_LANGUAGE.md`](VISUAL_LANGUAGE.md) · [`CONTRIBUTING_SKILLS.md`](CONTRIBUTING_SKILLS.md) — screenshots, visual rules, skill contributions

Historical writeups live in [`archive/`](archive/README.md).
