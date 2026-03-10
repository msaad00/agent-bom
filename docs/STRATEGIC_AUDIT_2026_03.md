# agent-bom Strategic Audit — March 2026

## Table of Contents

1. [Competitive Landscape](#1-competitive-landscape)
2. [agent-bom Capability Audit](#2-agent-bom-capability-audit)
3. [Differentiators & Uniqueness](#3-differentiators--uniqueness)
4. [Snowflake Coco / Cortex Code Integration](#4-snowflake-coco--cortex-code-integration)
5. [OpenAI Frontier Platform](#5-openai-frontier-platform)
6. [Gap Analysis & Roadmap](#6-gap-analysis--roadmap)
7. [Trademark & IP Protection](#7-trademark--ip-protection)

---

## 1. Competitive Landscape

### Direct Competitors (AI Agent Security Scanners)

| Tool | Vendor | GitHub Stars | Focus | Key Capabilities | Gaps vs agent-bom |
|------|--------|-------------|-------|-------------------|-------------------|
| **agent-scan** | Snyk | ~1.7k | MCP + Skills | 15+ risk types, auto-discovery (Claude/Cursor/Gemini/Windsurf), prompt injection, tool poisoning, tool shadowing, toxic flows, rug pull, background monitoring, Snyk Evo integration | No CVE scanning, no blast radius, no SBOM, no runtime proxy, no cloud scanning, no compliance mapping, no enrichment pipeline |
| **skill-scanner** | Cisco AI Defense | ~900 | Skill files | Static analysis of SKILL.md files, comprehensive but CLI-only, requires Python 3.10+ and 3 API keys | No MCP scanning, no runtime, no CVE/vuln scanning, no cloud, heavy setup |
| **SkillCheck** | Repello AI | N/A (SaaS) | Browser-based | Prompt injection, policy violations, payload delivery, severity score /100, zero setup | Browser-only, no CLI, no MCP scanning, no CVE, no runtime |
| **mcp-scan** | Invariant Labs | ~3k+ | MCP servers | Tool poisoning, prompt injection, cross-origin escalation, WhitelistGuard | No CVE scanning, no skills, no cloud, no compliance |
| **MCP Scan** | Enkrypt AI | N/A (SaaS) | MCP assessment | Security assessment of MCP servers | Limited scope |
| **GuardFive** | GuardFive | N/A (SaaS) | MCP security | Tool poisoning, credential theft detection, enterprise features | SaaS-only, limited public info |
| **Proximity** | Open source | ~500 | MCP scanning | Open-source MCP security scanner | Narrower scope |
| **mcp-guard** | SaravanaGuhan | <100 | MCP servers | Comprehensive MCP server scanning | Small project, limited maintenance |

### Indirect Competitors

| Tool | Focus | Overlap with agent-bom |
|------|-------|------------------------|
| **Grype/Syft** (Anchore) | Container/package CVE scanning | CVE scanning only — agent-bom uses these as optional engines |
| **Trivy** (Aqua) | Container/IaC scanning | CVE + IaC, no AI agent awareness |
| **Snyk CLI** | Dependency/container scanning | CVE scanning, no MCP/agent awareness |
| **Wiz** | Cloud security posture | Cloud scanning, no MCP/agent focus |

### Key Insight

**No single competitor covers what agent-bom covers.** The market is fragmented:
- Snyk agent-scan: skill/MCP *behavioral* scanning (prompt injection, poisoning) — no CVEs
- Grype/Trivy/Snyk CLI: CVE scanning — no AI agent awareness
- Wiz/Prisma: cloud posture — no MCP, no agent runtime

**agent-bom is the only tool that combines:** CVE scanning + AI agent discovery + MCP tool security + blast radius + runtime proxy + compliance mapping + cloud scanning + enrichment pipeline + SBOM + VEX + policy engine. This is the core differentiator.

---

## 2. agent-bom Capability Audit

### 2.1 Scanner Engine

| Dimension | Details |
|-----------|---------|
| **Package ecosystems** | npm, pip/PyPI, Go (go.mod), Maven (pom.xml), Ruby (Gemfile.lock), .NET (*.csproj/*.deps.json), RPM (sqlite), Rust (Cargo.lock) |
| **Container scanning** | OCI layer parsing (native, no Docker/Grype required), Grype/Syft as optional engines for `--image` |
| **Native OCI parsers** | Java JARs, Go binaries, Ruby gems, .NET assemblies, RPM sqlite — full ecosystem coverage without external tools |
| **Filesystem scanning** | `--filesystem` flag, dpkg/rpm/pip native parsers with Syft fallback |
| **SBOM ingestion** | CycloneDX 1.x, SPDX 2.x/3.0 JSON |
| **SBOM generation** | CycloneDX output |
| **VEX** | OpenVEX load/generate/apply/export, CLI flags |
| **SAST** | 52 CWE rule map, code_scan MCP tool |
| **Browser extensions** | Chrome/Chromium/Brave/Edge/Firefox, Manifest V2+V3, nativeMessaging/debugger/cookies/clipboardRead/broad-host detection, AI assistant domain access (claude.ai, chatgpt.com, cursor.sh) |
| **SKILL.md scanning** | 17 behavioral risk patterns, typosquat detection, Sigstore provenance, auto-discovery of CLAUDE.md/.cursorrules/AGENTS.md/.windsurfrules |
| **Output formats** | JSON, SARIF, HTML, CycloneDX, DOT, Mermaid |

### 2.2 Enrichment Pipeline

| Source | Data | Cache TTL |
|--------|------|-----------|
| **OSV** | Primary vuln database | Real-time |
| **GHSA** | Supplemental GitHub advisories | Real-time |
| **NVD** | CVSS scores, CWE mapping | 90 days |
| **EPSS** | Exploit probability scores | 30 days |
| **CISA KEV** | Known exploited vulns | 24 hours |
| **NVIDIA advisories** | GPU/CUDA/TensorRT/NCCL vulns | Supplemental |
| **OpenSSF Scorecard** | Project health → risk boost | On-demand |
| **MITRE ATT&CK** | CWE→CAPEC→ATT&CK via STIX | 30 days |

### 2.3 MCP Server (23 Tools)

| # | Tool | Purpose |
|---|------|---------|
| 1 | `scan` | Full vulnerability scan |
| 2 | `check` | Quick package check |
| 3 | `blast_radius` | Dependency blast radius analysis |
| 4 | `policy_check` | Policy-as-code evaluation |
| 5 | `registry_lookup` | MCP server registry metadata |
| 6 | `generate_sbom` | SBOM generation |
| 7 | `compliance` | Compliance framework mapping |
| 8 | `remediate` | Remediation suggestions |
| 9 | `verify` | Verify scan results |
| 10 | `where` | Locate packages in dependency tree |
| 11 | `inventory` | Full dependency inventory |
| 12 | `diff` | Compare scan results |
| 13 | `skill_trust` | SKILL.md trust assessment |
| 14 | `marketplace_check` | Check marketplace listings |
| 15 | `code_scan` | SAST code scanning |
| 16 | `context_graph` | BFS lateral movement graph |
| 17 | `analytics_query` | Analytics/metrics query |
| 18 | `cis_benchmark` | CIS benchmark scanning |
| 19 | `fleet_scan` | Fleet/batch scanning |
| 20 | `runtime_correlate` | Cross-reference proxy audit with CVEs |
| 21 | `vector_db_scan` | Pinecone/vector DB scanning |
| 22 | `aisvs_benchmark` | AI security verification standard |
| 23 | `gpu_infra_scan` | GPU/AI compute infrastructure |

### 2.4 CLI UX

- Rich spinners on all network operations
- Exit codes for CI/CD gating
- `--help` on all commands
- Key commands: `scan`, `graph`, `proxy`, `protect`, `watch`, `mcp-server`, `proxy-configure`, `health-check`
- Key flags: `--image`, `--filesystem`, `--sbom`, `--vex`, `--browser-extensions`, `--skill`, `--gpu-scan`, `--k8s-mcp`, `--siem`, `--health-check`, `--include-processes`, `--include-containers`
- Output: JSON, SARIF, HTML, CycloneDX
- "No known vulnerabilities found" vs "N finding(s)" — clear UX

### 2.5 Runtime & Proxy

| Component | Capabilities |
|-----------|-------------|
| **proxy.py** | stdio MCP proxy, policy enforcement, credential leak detection, replay detection, per-tool rate limiting (sliding window), Prometheus metrics, JSONL audit, HMAC signing, JWKS signature verification (RS256/RS384/RS512/ES256/ES384/ES512), OIDC discovery, client readline timeout (120s), relay task exception logging |
| **protect** | 7 detectors: ToolDrift (rug pull), ArgumentAnalyzer (injection), CredentialLeak, RateLimit, SequenceAnalyzer (exfil patterns), ResponseInspector (cloaking/SVG/invisible chars), VectorDBInjectionDetector |
| **watch** | Filesystem watchers on MCP configs, diff-on-change, webhook alerts (Slack/Teams/PagerDuty) |
| **introspect** | Live MCP server connection, tools/list + resources/list, drift detection |
| **enforcement** | Tool poisoning detection, unicode normalization, description drift, inputSchema injection scanning |
| **OTel ingest** | Parse OTel traces, cross-reference tool calls with CVE data, `gen_ai.*` span detection, flag deprecated models |
| **runtime_correlation** | Cross-reference proxy audit JSONL with CVE findings, risk amplification (1.5-3.0x) |
| **audit_replay** | Rich TUI viewer for proxy JSONL logs |

### 2.6 Security Posture

- `validate_path(restrict_to_home=True)` — path traversal protection
- HMAC proxy signing
- JWKS signature verification (6 algorithms, 'none' rejected)
- OIDC/SSO JWT auth for API
- Credential leak detection in tool arguments/responses
- Input validation (JSON schema, size limits, pollution guards)
- Rate limiting (per-tool sliding window)
- 10 MB proxy DoS limit
- `.agent-bom.yaml` per-project config (like .grype.yaml)

### 2.7 Cloud Coverage (12 Providers)

| Provider | Scanner | Capabilities |
|----------|---------|-------------|
| AWS | Cloud posture | IAM, S3, security groups |
| Azure | CIS Benchmark | Compliance scanning |
| GCP | CIS Benchmark | Compliance scanning |
| CoreWeave | GPU infra | GPU container detection |
| Databricks | Security audit | Workspace security (custom, no CIS exists for Databricks) |
| Snowflake | Security audit | Account security posture |
| Nebius | Cloud posture | GPU cloud scanning |
| HuggingFace | Model registry | Model provenance |
| Weights & Biases | ML ops | Experiment tracking security |
| MLflow | ML ops | Model registry security |
| OpenAI | API posture | API key/model scanning |
| Ollama | Local models | Local model security |

### 2.8 Compliance Frameworks (10)

OWASP LLM Top 10, OWASP MCP Top 10, OWASP Agentic Security, MITRE ATLAS, NIST AI RMF, EU AI Act, NIST CSF, ISO 27001, SOC 2, CIS Controls

### 2.9 MCP Client Discovery (21 Types)

Claude Desktop, Claude Code, Cursor, Windsurf, Cline, Continue, Zed, VS Code Copilot, JetBrains AI, and 12+ more — auto-discovers configs from known locations.

### 2.10 UI/Dashboard

- **Next.js**: 15 pages including SupplyChainTreemap, BlastRadiusRadial, PipelineFlow, EpssVsCvssChart, VulnTrendChart, Insights page
- **Streamlit**: Legacy dashboard, Snowflake Native App compatible
- **Validators**: Runtime JSON validation for file imports (size limit, schema, pollution guard)

### 2.11 Tests

- **3,841 collected** by pytest (3,760 `def test_` functions)
- Meta-tests enforce MCP tool count alignment
- Integration tests for all major features
- 168 test files across 160 Python modules

### 2.12 Integrations

| Platform | Status |
|----------|--------|
| PyPI | Live |
| Docker Hub | Live (multi-arch: amd64 + arm64) |
| GHCR | Live |
| GitHub Action / Marketplace | Live |
| Smithery | Live |
| Glama | Live |
| ClawHub/OpenClaw | 4 split skills |
| MCP Registry | Live (OIDC auth) |
| Railway SSE | Live |
| ToolHive | PR open |
| awesome-mcp-servers | Listed |
| Helm chart | Available |
| Snowflake Native App | Streamlit path |

---

## 3. Differentiators & Uniqueness

### What ONLY agent-bom does (no competitor matches all):

1. **Full-spectrum AI infra scanning**: CVE + MCP tool security + skill trust + blast radius + compliance — in one tool
2. **Blast radius analysis**: No competitor does dependency blast radius with compliance framework mapping
3. **Runtime proxy with enforcement**: Not just scanning — real-time interception, rate limiting, credential leak blocking, rug pull detection
4. **30 MCP tools**: Deepest MCP server integration — usable by any AI assistant
5. **12 cloud provider coverage**: AWS/Azure/GCP + AI-specific (CoreWeave, Databricks, Snowflake, HuggingFace, W&B, MLflow, OpenAI, Ollama, Nebius)
6. **10 compliance frameworks**: Every finding mapped to OWASP LLM/MCP/Agentic, ATLAS, NIST, EU AI Act, ISO 27001, SOC 2, CIS
7. **Enrichment depth**: OSV + GHSA + NVD + EPSS + CISA KEV + NVIDIA + OpenSSF Scorecard + MITRE ATT&CK
8. **Browser extension scanning**: AI assistant domain access detection — unique capability
9. **SKILL.md behavioral analysis**: 17 risk patterns + typosquat + Sigstore provenance
10. **OTel provenance**: Parse agent traces, flag deprecated models, cross-reference with CVEs
11. **Context graph**: BFS lateral movement analysis from any agent
12. **Native OCI parsing**: Scan container images without Docker/Grype/Syft installed
13. **Policy-as-code**: 17 conditions + expression engine with AND/OR/NOT — custom enforcement
14. **SIEM push**: Splunk/Datadog/Elasticsearch in OCSF format
15. **VEX**: Full OpenVEX lifecycle (load/generate/apply/export) — no competitor in this space has VEX

### Competitive Matrix

| Capability | agent-bom | Snyk agent-scan | Cisco skill-scanner | mcp-scan | Grype | Trivy |
|------------|-----------|-----------------|---------------------|----------|-------|-------|
| CVE scanning | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| MCP tool security | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ |
| Skill/AGENTS.md scanning | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| Blast radius | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Runtime proxy | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Compliance mapping | ✅ (10) | ❌ | ❌ | ❌ | ❌ | ✅ (partial) |
| Cloud scanning | ✅ (12) | ❌ | ❌ | ❌ | ❌ | ✅ (IaC) |
| SBOM/VEX | ✅ | ❌ | ❌ | ❌ | ✅ (SBOM) | ✅ (SBOM) |
| MCP server (AI tool) | ✅ (23) | ❌ | ❌ | ❌ | ❌ | ❌ |
| GPU/AI compute | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| SIEM integration | ✅ | Via Snyk | ❌ | ❌ | ❌ | ❌ |
| Browser extensions | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| OTel trace analysis | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Policy engine | ✅ (17) | ❌ | ❌ | ❌ | ❌ | ✅ (Rego) |
| Open source | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| GitHub Action | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |

---

## 4. Snowflake Coco / Cortex Code Integration

### 4.1 What is Cortex Code (Coco)?

Cortex Code is Snowflake's AI coding agent, unveiled at BUILD London (Feb 3, 2026):
- **Access**: Snowsight (web) + CLI (local shell) — **desktop app is coming** (per Renxu)
- **Models**: Claude Opus 4.6, Claude Sonnet 4.5, GPT 5.2
- **MCP support**: First-class — `mcp.json` at `~/.snowflake/cortex/`, connects to GitHub, Jira, custom MCP servers
- **Extensibility**: Custom commands, tools, subagents, hooks, AGENTS.md, skills (SKILL.md)
- **Expanding scope**: Beyond Snowflake-native — now supports dbt, Apache Airflow, any data source

### 4.2 Cortex Code Security Model

Cortex Code has a sophisticated security model that agent-bom should integrate with:

| Feature | Details |
|---------|---------|
| **Three-tier approval** | Confirm (prompts), Plan (review), Bypass (trusted only) |
| **Risk classification** | SAFE → LOW → MEDIUM → HIGH → CRITICAL for commands |
| **SQL categorization** | READ_ONLY, WRITE, USE_ROLE — different approval levels |
| **Dangerous pattern detection** | Pipe-to-shell, -rf, --force, system paths, hidden files |
| **RBAC** | Full Snowflake role-based access control |
| **OS sandboxing** | OS-level sandboxing for CLI operations |
| **MCP security** | "Verify source and integrity" guidance — but no automated scanning |
| **Permission caching** | Session and persistent (permissions.json) |
| **PAT management** | ≤90-day expiration, rotation, revocation |
| **Private mode** | `cortex --private` disables session saving |

### 4.3 Integration Opportunities

#### Immediate (High Value)

1. **agent-bom as Cortex Code MCP server**
   - Cortex Code supports MCP via `mcp.json` — agent-bom can be added as an MCP server
   - All 30 tools become available to Cortex Code users
   - Users can scan their Snowflake pipelines for CVEs, check MCP server trust, run compliance audits — all through natural language in Cortex Code
   - Config: add agent-bom to `~/.snowflake/cortex/mcp.json`

2. **Cortex Code config discovery**
   - Add `CORTEX_CODE` to `CONFIG_LOCATIONS` in `discovery/__init__.py`
   - Path: `~/.snowflake/cortex/mcp.json`
   - Discover and scan all MCP servers configured for Cortex Code

3. **Cortex Code skill for agent-bom**
   - Create an agent-bom SKILL.md for Cortex Code's skills directory
   - Cortex Code supports the same SKILL.md format — our existing skills work
   - Deploy as a Cortex Code skill that wraps `agent-bom scan`

4. **Scan Cortex Code's MCP servers**
   - Auto-discover `~/.snowflake/cortex/mcp.json`
   - Scan all configured MCP servers for tool poisoning, credential exposure, drift
   - Scan their npm/pip dependencies for CVEs

#### Medium-term

5. **Snowflake Native App integration**
   - Streamlit dashboard already works as Native App
   - Can receive scan results from Cortex Code skill → visualize in Snowsight
   - Compliance dashboards for enterprise Snowflake deployments

6. **Cortex Agent MCP server scanning**
   - Snowflake has `CREATE MCP SERVER` SQL command — managed MCP servers
   - Scan these for tool configuration, SQL permissions, tool descriptions
   - Verify `sql_statement_permissions` settings

7. **Cortex Code permissions.json audit**
   - Scan `~/.snowflake/cortex/permissions.json` for overly permissive cached approvals
   - Flag "Always allow (persist)" entries for high-risk tools
   - Detect MCP servers approved without integrity verification

#### Strategic

8. **Pre-built Cortex Code hook**
   - Cortex Code supports hooks (like Claude Code)
   - Create a pre-execution hook that runs agent-bom scan before installing new MCP servers
   - Automatic supply chain check before any new tool is added

9. **Snowflake Marketplace listing**
   - List agent-bom as a Snowflake Marketplace offering
   - Enterprise customers can deploy via Snowflake's ecosystem

### 4.4 What Coco Needs That agent-bom Provides

| Coco Security Gap | agent-bom Solution |
|-------------------|--------------------|
| "Verify MCP server integrity" — manual guidance only | Automated MCP server scanning (30 tools) |
| No CVE scanning of MCP server dependencies | Full enrichment pipeline (OSV+GHSA+NVD+EPSS+KEV) |
| No blast radius analysis | Blast radius with compliance mapping |
| Permission caching risks (permissions.json) | Audit cached approvals, flag overly permissive |
| AGENTS.md/SKILL.md trust unknown | 17 behavioral risk patterns + typosquat detection |
| No runtime MCP traffic inspection | Proxy with 7 detectors, JSONL audit |
| SQL injection via MCP tool descriptions | InputSchema injection scanning |
| No supply chain visibility | SBOM generation, dependency graph, context graph |

---

## 5. OpenAI Frontier Platform

### 5.1 What Is It

OpenAI launched **Frontier** on Feb 5, 2026 — an enterprise platform for building, deploying, and managing AI agents:
- **Customers**: Uber, State Farm, Intuit, Thermo Fisher Scientific
- **Partners**: Accenture, BCG, Capgemini, McKinsey (multiyear deals)
- **Architecture**: Intelligence layer stitching together enterprise systems and data
- **Features**: Shared context, onboarding, learning with feedback, permissions and boundaries

### 5.2 Security Implications for agent-bom

| Frontier Feature | agent-bom Scanning Opportunity |
|------------------|-------------------------------|
| Agent permissions & boundaries | Scan permission configurations for overly broad access |
| Enterprise system integration | Blast radius analysis of agent → system connections |
| Agent onboarding/learning | Detect prompt injection in training/feedback loops |
| Multi-agent orchestration | Cross-agent trust boundary analysis (context graph) |
| MCP tool usage (via Agents SDK) | All existing MCP scanning capabilities apply |

### 5.3 OpenAI Agents SDK (Confirmed)

- Open-sourced March 2025, actively developed
- **MCP support**: First-party — agents consume MCP tools
- **Guardrails**: Input/output validation via secondary LLM
- **Tracing**: OpenTelemetry-compatible (agent-bom's OTel ingest handles this)
- **Security gaps**: No built-in sandboxing, no credential management, no policy enforcement, no tool signing

### 5.4 Broader Agent Framework Landscape

| Framework | MCP Support | Security Model | agent-bom Coverage |
|-----------|------------|----------------|-------------------|
| OpenAI Agents SDK | ✅ | Guardrails only | OTel ingest, MCP scanning |
| Google ADK | ✅ | Vertex AI guardrails | MCP scanning, OTel ingest |
| AWS Bedrock Agents | ❌ (action groups) | Managed guardrails, CloudFormation | Cloud scanning (AWS) |
| LangGraph | Via tools | None built-in | Dependency scanning |
| CrewAI | Via tools | None built-in | Dependency scanning |
| AutoGen | Via tools | None built-in | Dependency scanning |
| Mastra | ✅ | None built-in | MCP scanning |

---

## 6. Gap Analysis & Roadmap

### 6.1 Critical Gaps to Close

| Priority | Gap | Effort | Impact |
|----------|-----|--------|--------|
| **P0** | Add Cortex Code to CONFIG_LOCATIONS discovery | Small (1 PR) | Direct Coco integration |
| **P0** | Create Cortex Code SKILL.md for agent-bom | Small (1 PR) | Coco users can use agent-bom |
| **P1** | Multi-agent handoff trust analysis | Medium | Frontier/Agents SDK coverage |
| **P1** | MCP transport security checks (HTTPS, auth) | Medium | 43% of MCP servers vulnerable |
| **P1** | Guardrail adequacy scanning | Medium | Detect unprotected agents |
| **P2** | Code execution sandbox verification | Medium | Safety check for code interpreters |
| **P2** | Model weights provenance (checksums/signatures) | Medium | Model supply chain |
| **P2** | Cross-framework agent discovery (ADK, Bedrock, CrewAI, LangGraph) | Large | Broader agent coverage |
| **P3** | RAG poisoning detection in vector stores | Medium | Extend vector DB scanning |
| **P3** | MCP OAuth 2.1 auth verification | Medium | As MCP auth standardizes |

### 6.2 Competitive Responses Needed

| Competitor Move | Our Response |
|-----------------|-------------|
| Snyk agent-scan: background monitoring + Snyk Evo dashboard | agent-bom watch + SIEM push already covers this; consider adding `--daemon` mode |
| Cisco skill-scanner: deep static analysis | Our SKILL.md scanning already does 17 patterns + typosquat; add Cisco's API-key-gated patterns if publicly documented |
| Repello SkillCheck: zero-setup browser scanner | Consider a hosted web UI for quick scans (lower priority — our CLI/MCP/Action coverage is stronger) |
| mcp-scan: WhitelistGuard | Our policy engine can do this — document `allowed_tools` policy condition |

### 6.3 Scalability Assessment

| Dimension | Status | Notes |
|-----------|--------|-------|
| Fleet scanning | ✅ | `fleet_scan` MCP tool, batch operations |
| Async patterns | ✅ | asyncio throughout proxy/runtime |
| K8s discovery | ✅ | Pod labels, images, envs, CRDs |
| Caching | ✅ | NVD 90d, EPSS 30d, KEV 24h, MITRE 30d |
| Docker multi-arch | ✅ | amd64 + arm64 |
| Helm chart | ✅ | K8s deployment ready |
| CI/CD integration | ✅ | GitHub Action + SARIF upload |
| Horizontal scaling | ⚠️ | No distributed scanning mode yet — single-process |
| Database backend | ⚠️ | File-based caching, no shared state for multi-instance |

---

## 7. Trademark & IP Protection

### 7.1 Trademark (Recommended — File Now)

| Item | Details |
|------|---------|
| **What to file** | Word mark "AGENT-BOM" (covers the name in any stylization) |
| **Classes** | Class 9 (downloadable software) + Class 42 (SaaS security services) |
| **Filing method** | USPTO TEAS Standard ($350/class) or TEAS Plus ($250/class if using pre-approved descriptions) |
| **Total cost (self-filing)** | $500-700 for two classes |
| **With attorney** | $1,500-3,000 total |
| **Timeline** | 8-12 months to registration |
| **US system** | First-to-use (you already have priority from first commercial use) |
| **Evidence needed** | Screenshots of PyPI listing, GitHub, Docker Hub showing the mark in commerce |
| **International** | Madrid Protocol filing ($1,000-2,000 additional) for multi-country protection after US filing |

**Action items:**
1. Do a USPTO TESS search for "AGENT-BOM" and similar marks
2. File TEAS Plus application (~$500 for 2 classes)
3. Prepare specimens: screenshot of CLI output, PyPI page, Docker Hub page showing "agent-bom" branding
4. Consider also filing for the logo if you have one

### 7.2 Patent (Consider Later)

Potentially patentable novel methods:
- Blast radius analysis combined with compliance framework mapping
- MCP tool poisoning detection via description drift + unicode normalization
- Context graph BFS lateral movement analysis for AI agents
- Cross-reference of OTel traces with CVE databases for runtime risk amplification

**Recommendation**: File a provisional patent ($320 self, $1,600 with attorney) to establish priority date, then decide within 12 months whether to pursue full utility patent ($5-15K).

---

## Summary

**agent-bom is uniquely positioned** — no competitor combines CVE scanning + AI agent security + runtime enforcement + compliance. The Coco opportunity is immediate and high-value:

1. **File trademark NOW** — protect the name before the space gets crowded
2. **Add Cortex Code discovery** — `~/.snowflake/cortex/mcp.json` to CONFIG_LOCATIONS (tiny PR, huge signal)
3. **Create Cortex Code skill** — SKILL.md that wraps `agent-bom scan` for Coco users
4. **Engage Renxu** — he can champion internal adoption at Snowflake
5. **Position clearly**: "agent-bom is the only security scanner that covers the full AI agent stack — from CVEs to MCP tools to runtime enforcement to compliance"

The competitive landscape is fragmented. Snyk has brand recognition but narrow scope. Cisco has static analysis but no runtime. Nobody else has the depth we have. The window to establish agent-bom as the definitive AI infrastructure security scanner is now.
