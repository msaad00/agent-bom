# Architecture

Module dependency map and data flow guide for contributors.

## Data Flow

```
Discovery ──> Scanning ──> Enrichment ──> Blast Radius ──> Compliance ──> Output
    │              │            │              │                │            │
    ▼              ▼            ▼              ▼                ▼            ▼
 21 MCP         OSV API      NVD/EPSS      Risk scoring     10 frameworks  JSON/SARIF/
 clients        batch        KEV/GHSA      per CVE with     mapped per     CycloneDX/
 parsed         query        enrichment    agent/cred/tool  finding        SPDX/SVG
                                           reachability
```

## Entry Points

| Entry point | File | Purpose |
|---|---|---|
| CLI | `cli.py` | Click-based CLI with 22+ commands and groups |
| MCP Server | `mcp_server.py` | FastMCP server with 22 tools |
| Proxy | `proxy.py` | MCP JSON-RPC proxy with runtime enforcement |
| API | `api/server.py` | FastAPI REST server with job queue |

## Module Map

### Core Pipeline

```
src/agent_bom/
├── discovery/           # MCP client/server discovery
│   └── __init__.py      # CONFIG_LOCATIONS for 21 agent types, JSON/TOML/YAML parsers
├── scanners/            # Vulnerability scanning
│   ├── __init__.py      # OSV batch queries, scan_packages(), scan_agents_with_enrichment()
│   ├── ghsa_advisory.py # GitHub Security Advisories (supplemental)
│   └── nvidia_advisory.py # NVIDIA CSAF 2.0 advisories
├── enrichment.py        # NVD CVSS, EPSS scores, CISA KEV lookups
├── transitive.py        # Transitive dep resolution via deps.dev API
├── models.py            # Agent, MCPServer, Package, Vulnerability, BlastRadius, AIBOMReport
│                        #   BlastRadius.calculate_risk_score() — 8-factor risk computation
├── security.py          # validate_path(), sanitize_env_vars(), credential redaction
└── output/
    └── __init__.py      # JSON, SARIF, CycloneDX, SPDX, SVG, text formatters
```

### Compliance Frameworks (10)

Each module exports `tag_blast_radius(br: BlastRadius)` to annotate findings.

```
├── owasp.py             # OWASP LLM Top 10 (2025)
├── owasp_agentic.py     # OWASP Agentic Top 10
├── owasp_mcp.py         # OWASP MCP Top 10
├── atlas.py             # MITRE ATLAS (9 techniques)
├── eu_ai_act.py         # EU AI Act (6 articles)
├── nist_ai_rmf.py       # NIST AI RMF (12 subcategories)
├── nist_csf.py          # NIST CSF 2.0 (14 categories)
├── cis_controls.py      # CIS Controls v8 (9 safeguards)
├── iso_27001.py         # ISO 27001:2022 (8 controls)
├── soc2.py              # SOC 2 TSC (9 criteria)
├── vuln_compliance.py   # CVE-level framework tagging
└── constants.py         # AI_PACKAGES, TRAINING_DATA_PACKAGES, SAST_CWE_MAP (52 CWEs)
```

### Runtime & Enforcement

```
├── proxy.py             # MCP JSON-RPC proxy — policy enforcement, 6 detectors,
│                        #   Prometheus metrics, JSONL audit trail, webhook alerts
├── runtime/
│   ├── __init__.py      # Public exports
│   ├── detectors.py     # 7 detectors: ToolDrift, ArgumentAnalyzer, CredentialLeak,
│   │                    #   RateLimit, SequenceAnalyzer, ResponseInspector,
│   │                    #   VectorDBInjectionDetector (RAG/cache-poison, CRITICAL severity)
│   └── patterns.py      # Regex patterns for credentials, args, cloaking, SVG, Unicode
├── enforcement.py       # Tool poisoning detection (8 checks): injection scanning,
│                        #   inputSchema analysis, capability combos, CVE exposure,
│                        #   drift detection, config analysis, over-permission
├── mcp_introspect.py    # Live MCP server connection — tools/list, resources/list, drift
├── watch.py             # Filesystem watcher on MCP configs, diff-on-change, webhook alerts
├── runtime_correlation.py # Cross-reference proxy audit logs with CVE findings
└── prompt_scanner.py    # Prompt injection pattern detection (reused by enforcement)
```

### Cloud & Infrastructure (14 modules)

```
├── cloud/
│   ├── base.py                    # Base cloud provider abstraction
│   ├── aws.py                     # AWS account scanning
│   ├── aws_cis_benchmark.py       # AWS CIS Foundations v3.0 (16 checks via boto3)
│   ├── azure.py                   # Azure account scanning
│   ├── gcp.py                     # GCP account scanning
│   ├── snowflake.py               # Snowflake account scanning
│   ├── snowflake_cis_benchmark.py # Snowflake CIS v1.0 (12 checks via SQL)
│   ├── databricks.py              # Databricks workspace scanning
│   ├── huggingface.py             # HuggingFace model registry
│   ├── ollama.py                  # Ollama local model scanning
│   ├── openai_provider.py         # OpenAI integration
│   ├── clickhouse.py              # ClickHouse analytics storage
│   └── ...                        # coreweave, mlflow, wandb, nebius providers
├── scorecard.py         # OpenSSF Scorecard fetching → risk boost
├── malicious.py         # Typosquat detection, known malicious package flagging
└── model_files.py       # ML model file detection (.pt, .pkl, .h5, .safetensors)
```

### Policy, SBOM & Verification

```
├── policy.py            # Policy-as-code engine (17 conditions incl. expression parser)
├── sbom.py              # CycloneDX 1.x + SPDX 2.x/3.0 JSON parsing
├── vex.py               # OpenVEX load/generate/apply/export
├── integrity.py         # Package verification: npm/PyPI hashes, SLSA provenance, Sigstore
├── sast.py              # Semgrep SAST integration with CWE-to-compliance mapping
├── context_graph.py     # Lateral movement analysis — BFS pathfinding, interaction risk
├── risk_analyzer.py     # Capability classification, dangerous combo detection
└── parsers/
    ├── skills.py        # SKILL.md YAML frontmatter parser
    ├── skill_audit.py   # Skill trust assessment (5-category analysis)
    └── trust_assessment.py # Trust scoring engine
```

### API & Storage Layer

```
├── api/
│   ├── server.py          # FastAPI REST server with job queue
│   ├── auth.py            # scrypt KDF API keys, RBAC roles (admin/analyst/viewer)
│   ├── audit_log.py       # HMAC-SHA256 signed audit log (InMemory + SQLite backends)
│   ├── store.py           # Base data store abstraction
│   ├── postgres_store.py  # PostgreSQL backend
│   ├── snowflake_store.py # Snowflake backend
│   ├── clickhouse_store.py # ClickHouse backend
│   ├── fleet_store.py     # Fleet inventory storage
│   └── scheduler.py       # Async job scheduler
├── gateway.py             # API gateway with rate limiting
└── http_client.py         # Shared HTTP client with retry, timeout, user-agent
```

### Integrations, Alerts & SIEM

```
├── integrations/
│   ├── slack.py           # Slack alert/notification dispatcher
│   ├── jira.py            # Jira issue creation
│   ├── vanta.py           # Vanta compliance sync
│   └── drata.py           # Drata compliance sync
├── connectors/
│   ├── base.py            # Base connector with CONNECTOR_HEALTH_TIMEOUT
│   ├── slack_connector.py # Slack connector
│   ├── jira_connector.py  # Jira connector
│   └── servicenow_connector.py # ServiceNow connector
├── alerts/
│   ├── dispatcher.py      # Alert routing (Slack, Teams, PagerDuty)
│   ├── scan_alerts.py     # Scan-triggered alerts
│   └── dedup.py           # Alert deduplication
└── siem/
    └── ocsf.py            # Open Cybersecurity Schema Format export
```

### Output & Visualization (8 modules)

```
├── output/
│   ├── __init__.py        # JSON, SARIF, CycloneDX, SPDX, text formatters
│   ├── html.py            # HTML dashboard report
│   ├── svg.py             # SVG diagrams (architecture, blast radius, compliance)
│   ├── mermaid.py         # Mermaid diagram syntax
│   ├── graph.py           # NetworkX graph generation
│   ├── agent_mesh.py      # Agent mesh topology visualization
│   ├── attack_flow.py     # Attack flow visualization
│   └── prometheus.py      # Prometheus metrics export
├── remediate.py           # Actionable remediation plan generation
└── push.py                # Push results to external platforms
```

### Shared Utilities

```
├── config.py              # Global configuration constants and weights
├── constants.py           # AI_PACKAGES, TRAINING_DATA_PACKAGES, SAST_CWE_MAP (52 CWEs)
├── models.py              # Core data classes
├── security.py            # validate_path(), sanitize_env_vars(), credential redaction
├── mcp_registry.json      # 427+ MCP server security metadata (bundled)
└── http_client.py         # Shared HTTP client with retry, timeout, user-agent
```

## Dependency Graph (simplified)

```
cli.py / mcp_server.py / api/server.py
    │
    ├── discovery/         (standalone — no deps on scanning)
    ├── scanners/          (depends on: models, enrichment, http_client)
    ├── enrichment.py      (depends on: http_client, models)
    ├── models.py          (depends on: config, constants)
    │     └── BlastRadius  (depends on: all compliance modules for tagging)
    ├── policy.py          (depends on: models)
    ├── enforcement.py     (depends on: mcp_introspect, prompt_scanner, risk_analyzer)
    ├── proxy.py           (depends on: runtime/, policy, enforcement)
    ├── cloud/             (depends on: models, cloud SDKs)
    ├── integrations/      (depends on: models, connectors/)
    ├── alerts/            (depends on: models, integrations/)
    └── output/            (depends on: models)
```

## Module Stats

| Metric | Count |
|---|---|
| Python modules | 148 |
| Test files | 144 |
| Test functions | 3,419 (3,480 collected by pytest) |
| MCP tools | 22 |
| Compliance frameworks | 10 |
| Runtime detectors | 7 |
| Cloud providers | 12 |
| SAST CWE mappings | 52 |

## How to Add...

### A new compliance framework

1. Create `src/agent_bom/my_framework.py`
2. Export `tag_blast_radius(br: BlastRadius) -> None` — mutate `br.compliance_tags`
3. Import and call it in `scanners/__init__.py` alongside the other `tag_*` calls
4. Add tests in `tests/test_my_framework.py`

### A new CIS benchmark

1. Create `src/agent_bom/cloud/my_cloud_cis.py`
2. Follow the pattern in `aws_cis_benchmark.py` — return list of `CISCheckResult`
3. Wire into the `cis_benchmark` MCP tool in `mcp_server.py`
4. Add tests with mocked cloud SDK clients

### A new MCP client discovery parser

1. Add entry to `CONFIG_LOCATIONS` dict in `discovery/__init__.py`
2. Add a `parse_my_client_config()` function following existing patterns
3. Call `sanitize_env_vars()` on any env blocks before returning
4. Add tests

### A new runtime detector

1. Add class to `runtime/detectors.py` following existing detector pattern
2. Add patterns to `runtime/patterns.py` if needed
3. Export from `runtime/__init__.py`
4. Wire into `proxy.py` event loop
5. Add tests in `tests/test_runtime_detectors.py`

### A new SAST CWE mapping

1. Add entry to `SAST_CWE_MAP` in `constants.py`
2. Map to framework tags: `owasp_llm`, `iso_27001`, `nist_csf`, `soc2`, `cis`
3. No code changes needed — the mapping is data-driven
