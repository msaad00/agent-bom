---
name: agent-bom
description: >-
  AI agent infrastructure security scanner — check packages for CVEs, look up MCP servers
  in the 427+ server security metadata registry, assess blast radius, generate SBOMs, enforce
  compliance (OWASP, MITRE ATLAS, EU AI Act, NIST AI RMF). Use when the user
  mentions vulnerability scanning, dependency security, SBOM generation, MCP server
  trust, or AI supply chain risk.
version: 0.59.3
license: Apache-2.0
compatibility: >-
  Requires Python 3.11+. Install via pipx or pip. Optional: Docker for container
  scanning (Grype/Syft). No external API keys required for basic operation.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/agent-bom
  source: https://github.com/msaad00/agent-bom
  pypi: https://pypi.org/project/agent-bom/
  smithery: https://smithery.ai/server/agent-bom/agent-bom
  scorecard: https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom
  tests: 6194
  install:
    pipx: agent-bom
    pip: agent-bom
    docker: ghcr.io/msaad00/agent-bom:0.59.3
  openclaw:
    requires:
      bins: []
      env: []
      credentials: none
    credential_policy: "Zero credentials required for core scanning. All env vars below are strictly optional and only used for specific enterprise features (CIS benchmarks, analytics). They are never auto-discovered, inferred, or transmitted."
    optional_env:
      - name: NVD_API_KEY
        purpose: "Increases NVD API rate limit (scanning works without it)"
        required: false
      - name: SNYK_TOKEN
        purpose: "Snyk vulnerability enrichment (optional additional data source)"
        required: false
      - name: AGENT_BOM_CLICKHOUSE_URL
        purpose: "ClickHouse analytics storage (enterprise only, not needed for scanning)"
        required: false
      - name: AWS_PROFILE
        purpose: "AWS CIS benchmark only — used when user explicitly runs cis_benchmark(provider='aws')"
        required: false
      - name: AWS_DEFAULT_REGION
        purpose: "AWS CIS benchmark only"
        required: false
      - name: SNOWFLAKE_ACCOUNT
        purpose: "Snowflake CIS benchmark only — used when user explicitly runs cis_benchmark(provider='snowflake')"
        required: false
      - name: SNOWFLAKE_USER
        purpose: "Snowflake CIS benchmark only"
        required: false
      - name: SNOWFLAKE_PASSWORD
        purpose: "Snowflake CIS benchmark only"
        required: false
    optional_bins:
      - syft
      - grype
      - kubectl
      - semgrep
      - docker
    emoji: "\U0001F6E1"
    homepage: https://github.com/msaad00/agent-bom
    source: https://github.com/msaad00/agent-bom
    license: Apache-2.0
    os:
      - darwin
      - linux
      - windows
    file_reads_note: "Parses full config files to extract server names and commands. All env var values are redacted via sanitize_env_vars() before inclusion in scan output."
    credential_handling: "Config files are fully parsed as JSON/TOML/YAML, but only server names (mcpServers.*.command, mcpServers.*.args, mcpServers.*.url) are extracted. Env var blocks ARE read but ALL values are replaced with '***REDACTED***' by sanitize_env_vars() before appearing in any output. Additionally, values are scanned for credential patterns (AWS keys, GitHub tokens, JWTs, private keys) and redacted even in custom-named variables. Bearer tokens and Snowflake passwords are also redacted. This is enforced in src/agent_bom/discovery/__init__.py at every parse function. Cloud credentials (AWS, Snowflake) are only used when user explicitly runs cis_benchmark with those providers."
    credential_handling_verification: "Verify directly on GitHub without installing: https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/security.py#L148-L185 (sanitize_env_vars + value credential patterns), https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/discovery/__init__.py#L307-L311 (parse_mcp_config redaction), #L425-L426 (parse_codex_config), #L483-L484 (parse_goose_config), #L528-L535 (parse_snowflake_connections)"
    data_flow: "All scanning is local-first with zero outbound calls by default except public vulnerability databases (OSV, NVD, EPSS, GitHub Advisories). No discovery data, config files, credentials, or environment variables ever leave the machine. Only public package names and CVE IDs are sent to vulnerability databases."
    verification_without_install: "All security-critical code is viewable on GitHub without installing: (1) Credential redaction: https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/security.py (2) Config parsing: https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/discovery/__init__.py (3) 6,100+ tests including security tests: https://github.com/msaad00/agent-bom/tree/main/tests (4) OpenSSF Scorecard: https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom (5) CodeQL + Bandit + pip-audit run on every PR: https://github.com/msaad00/agent-bom/actions"
    supply_chain_verification: "PyPI releases are Sigstore-signed with SLSA provenance attestation. Verify: agent-bom verify agent-bom@0.59.3 (checks SHA-256 + Sigstore signature + SLSA provenance). Source: Apache-2.0 licensed, all code public. No obfuscation, no minification, no binary blobs."
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
      # Cortex Code (Snowflake)
      - "~/.snowflake/cortex/mcp.json"
      - "~/.snowflake/cortex/settings.json"
      - "~/.snowflake/cortex/permissions.json"
      # Codex CLI
      - "~/.codex/config.toml"
      # Gemini CLI
      - "~/.gemini/settings.json"
      # Goose
      - "~/.config/goose/config.yaml"
      # Snowflake CLI
      - "~/.snowflake/connections.toml"
      - "~/.snowflake/config.toml"
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
      # Project-level configs (searched in working directory)
      - ".mcp.json"
      - ".vscode/mcp.json"
      - ".cursor/mcp.json"
      # User-provided files
      - "user-provided SBOM files (CycloneDX/SPDX JSON)"
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
      - url: "https://api.deps.dev/v3alpha"
        purpose: "Google deps.dev — transitive dependency resolution and license enrichment"
        auth: false
      - url: "https://api.github.com/advisories"
        purpose: "GitHub Security Advisories — supplemental CVE lookup for packages"
        auth: false
      - url: "https://api.snyk.io"
        purpose: "Snyk vulnerability enrichment (requires SNYK_TOKEN)"
        auth: true
    telemetry: false
    persistence: false
    privilege_escalation: false
    always: false
    autonomous_invocation: restricted
---

# agent-bom — AI Supply Chain Security Scanner

Scans AI infrastructure for vulnerabilities, generates SBOMs, and enforces
compliance. Discovers MCP clients, servers, and packages across 20 MCP clients.

## Install (Recommended: Local-First)

Local scanning eliminates all third-party trust concerns. All vulnerability
databases (OSV, NVD, EPSS, KEV) are queried directly from your machine.

```bash
pipx install agent-bom
agent-bom scan              # auto-discover 20 MCP clients + scan
agent-bom check langchain   # check a specific package
agent-bom where             # show all discovery paths
```

### As an MCP Server (Local)

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

### As a Docker Container

```bash
docker run --rm ghcr.io/msaad00/agent-bom:0.59.3 scan
```

### Self-Hosted SSE Server

```bash
docker build -f Dockerfile.sse -t agent-bom-sse .
docker run -p 8080:8080 agent-bom-sse
# Connect: { "type": "sse", "url": "http://localhost:8080/sse" }
```

## Available MCP Tools (20 tools)

| Tool | Description |
|------|-------------|
| `scan` | Full discovery + vulnerability scan pipeline |
| `check` | Check a package for CVEs (OSV, NVD, EPSS, KEV) |
| `blast_radius` | Map CVE impact chain across agents, servers, credentials |
| `registry_lookup` | Look up MCP server in 427+ server security metadata registry |
| `compliance` | OWASP LLM/Agentic Top 10, EU AI Act, MITRE ATLAS, NIST AI RMF |
| `remediate` | Prioritized remediation plan for vulnerabilities |
| `verify` | Package integrity + SLSA provenance check |
| `skill_trust` | Assess skill file trust level (5-category analysis) |
| `generate_sbom` | Generate SBOM (CycloneDX or SPDX format) |
| `policy_check` | Evaluate results against security policy |
| `diff` | Compare two scan reports (new/resolved/persistent) |
| `marketplace_check` | Pre-install trust check with registry cross-reference |
| `code_scan` | SAST scanning via Semgrep with CWE-based compliance mapping |
| `where` | Show MCP client config discovery paths |
| `inventory` | List discovered agents, servers, packages |
| `context_graph` | Agent context graph with lateral movement analysis |
| `analytics_query` | Query vulnerability trends, posture history, and runtime events from ClickHouse |
| `cis_benchmark` | Run CIS benchmark checks against AWS or Snowflake accounts |
| `fleet_scan` | Batch registry lookup + risk scoring for MCP server inventories |
| `runtime_correlate` | Cross-reference runtime audit logs with CVE findings |

## MCP Resources

| Resource | Description |
|----------|-------------|
| `registry://servers` | Browse 427+ MCP server security metadata registry |
| `policy://template` | Default security policy template |

## Example Workflows

```
# Check a package before installing
check(package="@modelcontextprotocol/server-filesystem", ecosystem="npm")

# Map blast radius of a CVE
blast_radius(cve_id="CVE-2024-21538")

# Look up a server in the threat registry
registry_lookup(server_name="brave-search")

# Generate an SBOM
generate_sbom(format="cyclonedx")

# Assess trust of a skill file
skill_trust(skill_content="<paste SKILL.md content>")
```

## Privacy & Data Handling

### Config file reads

Discovery reads and **fully parses** local MCP client config files (JSON, TOML,
YAML) to extract server names, command paths, and transport URLs. Environment
variable blocks **are read** during parsing, but **all values are replaced with
`***REDACTED***`** by `sanitize_env_vars()` (`src/agent_bom/security.py:148`)
before appearing in any output. Bearer tokens and passwords are also redacted.
Only env var **names** (not values) appear in reports. The extracted data (e.g.,
"brave-search is configured in Claude Desktop") stays in local memory and is
only included in scan output you explicitly request.

Verify this behavior: `src/agent_bom/security.py` lines 148-175,
`src/agent_bom/discovery/__init__.py` lines 307-311, 425-426, 483-484, 528-535.

### Network behavior

All scanning runs **locally by default** with no outbound connections except
public vulnerability databases (OSV, NVD, EPSS, GitHub Advisories).

Optional tokens (NVD_API_KEY, SNYK_TOKEN, AGENT_BOM_CLICKHOUSE_URL) are only
used when you explicitly set them. They are never auto-discovered or inferred.

### Cloud credentials (CIS benchmarks)

The `cis_benchmark` tool for AWS uses standard AWS SDK credential chain
(AWS_PROFILE, AWS_DEFAULT_REGION) and for Snowflake uses SNOWFLAKE_ACCOUNT,
SNOWFLAKE_USER, SNOWFLAKE_PASSWORD. These are **only used when you explicitly
invoke `cis_benchmark`** with those providers — they are never read during
normal scanning, discovery, or any other tool call. If not set, the tool
returns an error asking you to configure them.

## Security Boundaries

### Safe to send (public data only)

- Public package names + versions (`langchain`, `express@4.18.2`)
- Public CVE IDs (`CVE-2024-21538`)
- Public MCP server names (`brave-search`)
- Ecosystem identifiers (`pypi`, `npm`, `go`)

### Never send

- API keys, tokens, passwords, or `.env` contents
- Full config files (may contain credentials)
- Internal URLs, hostnames, or proprietary package names
- Use `${env:VAR}` references, never literal credential values

## Reproducible Redaction Test

Verify credential redaction without trusting any claims. Create a fake config
with real-looking secrets, run agent-bom, and confirm nothing leaks:

```bash
# 1. Create a temp dir with a fake MCP config containing real-looking secrets
mkdir -p /tmp/agent-bom-test
cat > /tmp/agent-bom-test/.mcp.json << 'EOF'
{
  "mcpServers": {
    "test-server": {
      "command": "node",
      "args": ["server.js"],
      "env": {
        "API_KEY": "sk-live-abc123secretkey456",
        "DATABASE_URL": "postgres://admin:supersecretpassword@db.internal:5432/prod",
        "GITHUB_TOKEN": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh",
        "SAFE_VAR": "this-is-not-a-secret"
      }
    }
  }
}
EOF

# 2. Run scan against ONLY this test directory (isolated from real configs)
agent-bom scan --config-dir /tmp/agent-bom-test -f json -o /tmp/agent-bom-test/output.json

# 3. Verify: grep for ANY secret value — should find NOTHING (exit code 1 = pass)
grep -c "sk-live-abc123\|supersecretpassword\|ghp_ABCDEF" /tmp/agent-bom-test/output.json
# Expected output: 0

# 4. Verify: credential key NAMES are detected (values are never written to output)
grep -c '"API_KEY"\|"GITHUB_TOKEN"\|"AWS_SECRET_ACCESS_KEY"\|"DATABASE_URL"' /tmp/agent-bom-test/output.json
# Expected output: >0 (key names appear in credential_env_vars list)

# 5. Verify: has_credentials is true for our test server
grep -c '"has_credentials": true' /tmp/agent-bom-test/output.json
# Expected output: >0

# 6. Cleanup
rm -rf /tmp/agent-bom-test
```

**How redaction works:** Env var **values** are never written to scan output.
The JSON report only includes credential key **names** in `credential_env_vars`
(e.g., `["API_KEY", "GITHUB_TOKEN"]`) so you can see what's referenced without
exposing secrets. Values are redacted in-memory by `sanitize_env_vars()`
([source](https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/security.py#L148-L187))
before any downstream processing. Both key-name patterns (token, password,
secret, api_key, auth, credential, bearer, jwt) and value patterns (AWS keys,
GitHub tokens, JWTs, Slack tokens, connection strings, private keys) are caught.

## Verification

- **Source**: [github.com/msaad00/agent-bom](https://github.com/msaad00/agent-bom) (Apache-2.0)
- **PyPI**: [pypi.org/project/agent-bom](https://pypi.org/project/agent-bom/)
- **Smithery**: [smithery.ai/server/agent-bom](https://smithery.ai/server/agent-bom/agent-bom)
- **Sigstore signed**: `agent-bom verify agent-bom@0.59.3`
- **6,100+ tests** with automated security scanning (CodeQL + OpenSSF Scorecard)
- **OpenSSF Scorecard**: [securityscorecards.dev](https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom)
- **No telemetry**: Zero tracking, zero analytics
