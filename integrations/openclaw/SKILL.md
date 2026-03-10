---
name: agent-bom
description: >-
  AI agent infrastructure security scanner — discovers MCP clients and servers,
  scans for CVEs, maps blast radius, runs CIS benchmarks (AWS, Azure, GCP,
  Snowflake), OWASP/NIST/MITRE compliance, AISVS v1.0, MAESTRO layer tagging,
  and vector database security checks. Use when the user mentions vulnerability
  scanning, MCP server trust, compliance, SBOM generation, CIS benchmarks,
  blast radius, or AI supply chain risk.
version: 0.68.0
license: Apache-2.0
compatibility: >-
  Requires Python 3.11+. Install via pipx or pip. No credentials required for
  basic scanning. CIS benchmark checks optionally use cloud SDK credentials
  (AWS/Azure/GCP/Snowflake). Optional: Grype/Syft for container image scanning.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/agent-bom
  source: https://github.com/msaad00/agent-bom
  pypi: https://pypi.org/project/agent-bom/
  scorecard: https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom
  tests: 4449
  install:
    pipx: agent-bom
    pip: agent-bom
    docker: ghcr.io/msaad00/agent-bom:0.68.0
  openclaw:
    requires:
      bins: []
      env: []
      credentials: none
    credential_policy: >-
      Zero credentials required for CVE scanning, blast radius, compliance
      evaluation, SBOM generation, and MCP registry lookups. Optional env vars
      below increase rate limits or enable cloud CIS checks. Env var values in
      discovered config files are replaced with ***REDACTED*** by
      sanitize_env_vars() in the installed code — verify at
      https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/security.py#L159
    optional_env:
      - name: NVD_API_KEY
        purpose: "Increases NVD API rate limit (scanning works without it)"
        required: false
      - name: SNYK_TOKEN
        purpose: "Snyk vulnerability enrichment for code_scan (optional)"
        required: false
      - name: AWS_PROFILE
        purpose: "AWS CIS benchmark checks — uses boto3 with local AWS profile"
        required: false
      - name: AZURE_TENANT_ID
        purpose: "Azure CIS benchmark checks (azure-mgmt-* SDK)"
        required: false
      - name: AZURE_CLIENT_ID
        purpose: "Azure CIS benchmark checks — service principal client ID"
        required: false
      - name: AZURE_CLIENT_SECRET
        purpose: "Azure CIS benchmark checks — service principal secret"
        required: false
      - name: GOOGLE_APPLICATION_CREDENTIALS
        purpose: "GCP CIS benchmark checks (google-cloud-* SDK)"
        required: false
      - name: SNOWFLAKE_ACCOUNT
        purpose: "Snowflake CIS benchmark checks"
        required: false
      - name: SNOWFLAKE_USER
        purpose: "Snowflake CIS benchmark checks"
        required: false
      - name: SNOWFLAKE_PRIVATE_KEY_PATH
        purpose: "Snowflake key-pair auth (CI/CD)"
        required: false
      - name: SNOWFLAKE_AUTHENTICATOR
        purpose: "Snowflake auth method (default: externalbrowser SSO)"
        required: false
    optional_bins:
      - syft
      - grype
      - semgrep
      - kubectl
    emoji: "\U0001F6E1"
    homepage: https://github.com/msaad00/agent-bom
    source: https://github.com/msaad00/agent-bom
    license: Apache-2.0
    os:
      - darwin
      - linux
      - windows
    install_verification: >-
      Before running with sensitive data: (1) pip install agent-bom;
      (2) agent-bom verify agent-bom; (3) review security.py#L159
      (sanitize_env_vars) and discovery/__init__.py to confirm redaction
      behavior.
    credential_handling: >-
      MCP config files are parsed as JSON/TOML/YAML. Only server names,
      commands, args, and URLs are extracted. Env var values are replaced with
      ***REDACTED*** by sanitize_env_vars() in the installed code. Verify at
      https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/security.py#L159
    data_flow: >-
      All scanning is local-first. Only public package names and CVE IDs are
      sent to vulnerability databases (OSV, NVD, EPSS, GitHub Advisories).
      Registry data (427+ MCP server metadata) is bundled in the package —
      lookups are in-memory with zero network calls. CIS benchmark checks call
      cloud provider APIs using locally configured credentials only. No config
      files, credentials, or env var values ever leave the machine.
    file_reads:
      # Claude Desktop
      - "~/Library/Application Support/Claude/claude_desktop_config.json"
      - "~/.config/Claude/claude_desktop_config.json"
      # Claude Code
      - "~/.claude/settings.json"
      - "~/.claude.json"
      # Cursor
      - "~/.cursor/mcp.json"
      - "~/Library/Application Support/Cursor/User/globalStorage/cursor.mcp/mcp.json"
      # Windsurf
      - "~/.windsurf/mcp.json"
      # Cline
      - "~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
      # VS Code Copilot
      - "~/Library/Application Support/Code/User/mcp.json"
      # Codex CLI
      - "~/.codex/config.toml"
      # Gemini CLI
      - "~/.gemini/settings.json"
      # Goose
      - "~/.config/goose/config.yaml"
      # Continue
      - "~/.continue/config.json"
      # Zed
      - "~/.config/zed/settings.json"
      # OpenClaw
      - "~/.openclaw/openclaw.json"
      # Roo Code
      - "~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json"
      # Amazon Q
      - "~/Library/Application Support/Code/User/globalStorage/amazonwebservices.amazon-q-vscode/mcp.json"
      # JetBrains AI
      - "~/Library/Application Support/JetBrains/*/mcp.json"
      - "~/.config/github-copilot/intellij/mcp.json"
      # Junie
      - "~/.junie/mcp/mcp.json"
      # Project-level configs
      - ".mcp.json"
      - ".vscode/mcp.json"
      - ".cursor/mcp.json"
      # User-provided files
      - "user-provided SBOM files (CycloneDX/SPDX JSON)"
      - "user-provided policy files (YAML/JSON policy-as-code)"
      - "user-provided audit log files (JSONL from agent-bom proxy)"
      - "user-provided SKILL.md files (for skill_trust analysis)"
    file_writes: []
    network_endpoints:
      - url: "https://api.osv.dev/v1"
        purpose: "OSV vulnerability database — batch CVE lookup for packages"
        auth: false
      - url: "https://services.nvd.nist.gov/rest/json/cves/2.0"
        purpose: "NVD CVSS v4 enrichment — optional API key increases rate limit"
        auth: false
      - url: "https://api.first.org/data/v1/epss"
        purpose: "EPSS exploit probability scores"
        auth: false
      - url: "https://api.github.com/advisories"
        purpose: "GitHub Security Advisories — supplemental CVE lookup"
        auth: false
      - url: "https://api.snyk.io"
        purpose: "Snyk vulnerability enrichment for code_scan (requires SNYK_TOKEN)"
        auth: true
    telemetry: false
    persistence: false
    privilege_escalation: false
    always: false
    autonomous_invocation: restricted
---

# agent-bom — AI Agent Infrastructure Security Scanner

Discovers MCP clients and servers across 20+ AI tools, scans for CVEs, maps
blast radius, runs cloud CIS benchmarks, checks OWASP/NIST/MITRE compliance,
generates SBOMs, and assesses AI infrastructure against AISVS v1.0 and MAESTRO
framework layers.

## Install

```bash
pipx install agent-bom
agent-bom scan              # auto-discover + scan
agent-bom check langchain   # check a specific package
agent-bom where             # show all discovery paths
```

### As an MCP Server

```json
{
  "mcpServers": {
    "agent-bom": {
      "command": "uvx",
      "args": ["agent-bom", "mcp"]
    }
  }
}
```

## Tools (30)

### Vulnerability Scanning
| Tool | Description |
|------|-------------|
| `scan` | Full discovery + vulnerability scan pipeline |
| `check` | Check a package for CVEs (OSV, NVD, EPSS, KEV) |
| `blast_radius` | Map CVE impact chain across agents, servers, credentials |
| `remediate` | Prioritized remediation plan for vulnerabilities |
| `verify` | Package integrity + SLSA provenance check |
| `diff` | Compare two scan reports (new/resolved/persistent) |
| `where` | Show MCP client config discovery paths |
| `inventory` | List discovered agents, servers, packages |

### Compliance & Policy
| Tool | Description |
|------|-------------|
| `compliance` | OWASP LLM/Agentic Top 10, EU AI Act, MITRE ATLAS, NIST AI RMF |
| `policy_check` | Evaluate results against custom security policy (17 conditions) |
| `cis_benchmark` | CIS benchmark checks (AWS, Azure v3.0, GCP v3.0, Snowflake) |
| `generate_sbom` | Generate SBOM (CycloneDX or SPDX format) |
| `aisvs_benchmark` | OWASP AISVS v1.0 compliance — 9 AI security checks |

### Registry & Trust
| Tool | Description |
|------|-------------|
| `registry_lookup` | Look up MCP server in 427+ server security metadata registry |
| `marketplace_check` | Pre-install trust check with registry cross-reference |
| `fleet_scan` | Batch registry lookup + risk scoring for MCP server inventories |
| `skill_trust` | Assess skill file trust level (5-category analysis) |
| `code_scan` | SAST scanning via Semgrep with CWE-based compliance mapping |

### Runtime & Analytics
| Tool | Description |
|------|-------------|
| `context_graph` | Agent context graph with lateral movement analysis |
| `analytics_query` | Query vulnerability trends, posture history, and runtime events |
| `runtime_correlate` | Cross-reference proxy audit JSONL with CVE findings, risk amplification |
| `vector_db_scan` | Probe Qdrant/Weaviate/Chroma/Milvus for auth and exposure |
| `gpu_infra_scan` | GPU container and K8s node inventory + unauthenticated DCGM probe (MAESTRO KC6) |

### Specialized Scans
| Tool | Description |
|------|-------------|
| `dataset_card_scan` | Scan dataset cards for bias, licensing, and provenance issues |
| `training_pipeline_scan` | Scan training pipeline configs for security risks |
| `browser_extension_scan` | Scan browser extensions for risky permissions and AI domain access |
| `model_provenance_scan` | Verify model provenance and supply chain integrity |
| `prompt_scan` | Scan prompt templates for injection and data leakage risks |
| `model_file_scan` | Scan model files for unsafe serialization (pickle, etc.) |
| `license_compliance_scan` | Full SPDX license catalog scan with copyleft and network-copyleft detection |

### Resources
| Resource | Description |
|----------|-------------|
| `registry://servers` | Browse 427+ MCP server security metadata registry |

## Example Workflows

```
# Check a package before installing
check(package="@modelcontextprotocol/server-filesystem", ecosystem="npm")

# Map blast radius of a CVE
blast_radius(cve_id="CVE-2024-21538")

# Full scan
scan()

# Run CIS benchmark
cis_benchmark(provider="aws")

# Run AISVS v1.0 compliance
aisvs_benchmark()

# Scan vector databases for auth misconfigurations
vector_db_scan()

# Discover GPU containers, K8s GPU nodes, and unauthenticated DCGM endpoints
gpu_infra_scan()

# Assess trust of a skill file
skill_trust(skill_content="<paste SKILL.md content>")
```

## Supported Frameworks

- **OWASP LLM Top 10** (2025) — prompt injection, supply chain, data leakage
- **OWASP Agentic Top 10** — tool poisoning, rug pulls, credential theft
- **OWASP AISVS v1.0** — AI Security Verification Standard (9 checks)
- **MITRE ATLAS** — adversarial ML threat framework
- **MITRE ATT&CK Enterprise** — cloud/infra T-code mapping on CIS failures
- **MAESTRO** — KC1–KC6 layer tagging on all findings
- **EU AI Act** — risk classification, transparency, SBOM requirements
- **NIST AI RMF** — govern, map, measure, manage lifecycle
- **CIS Foundations** — AWS, Azure v3.0, GCP v3.0, Snowflake benchmarks

## Privacy & Data Handling

This skill installs agent-bom from PyPI. The redaction behavior described here
is implemented in the installed package — **verify before running with
sensitive data**:

```bash
# 1. Verify package integrity (Sigstore)
agent-bom verify agent-bom

# 2. Review the redaction code directly
# security.py L159: sanitize_env_vars() — replaces env values with ***REDACTED***
# https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/security.py#L159

# 3. Review config parsing
# https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/discovery/__init__.py
```

Discovery reads local MCP client config files. Only server names, commands,
args, and URLs are extracted. Env var values are replaced with `***REDACTED***`
by `sanitize_env_vars()` in the installed code. Only public package names and
CVE IDs are sent to vulnerability databases. Cloud CIS checks use locally
configured credentials and call only the cloud provider's own APIs.

## Verification

- **Source**: [github.com/msaad00/agent-bom](https://github.com/msaad00/agent-bom) (Apache-2.0)
- **Sigstore signed**: `agent-bom verify agent-bom@0.68.0`
- **4,400+ tests** with CodeQL + OpenSSF Scorecard
- **No telemetry**: Zero tracking, zero analytics
