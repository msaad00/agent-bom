---
name: agent-bom
description: Scan AI agents and MCP servers for CVEs, generate SBOMs, map blast radius, enforce security policies
version: 0.31.6
metadata:
  openclaw:
    requires:
      bins:
        - agent-bom
      optional_bins:
        - docker
        - grype
      env: []
    optional_env:
      - name: NVD_API_KEY
        purpose: "Increases NVD rate limit from 5 to 50 requests per 30 seconds — not required for any functionality"
        sent_only_to: "https://services.nvd.nist.gov"
        required: false
    emoji: "\U0001F6E1"
    homepage: https://github.com/msaad00/agent-bom
    source: https://github.com/msaad00/agent-bom
    pypi: https://pypi.org/project/agent-bom/
    license: Apache-2.0
    os:
      - darwin
      - linux
    install:
      - kind: uv
        package: agent-bom
        bins:
          - agent-bom
      - kind: pip
        package: agent-bom
        bins:
          - agent-bom
      - kind: pipx
        package: agent-bom
        bins:
          - agent-bom
    file_reads:
      - "~/Library/Application Support/Claude/claude_desktop_config.json"
      - "~/.config/Claude/claude_desktop_config.json"
      - "~/.claude/settings.json"
      - "~/.claude.json"
      - "~/Library/Application Support/Cursor/User/globalStorage/cursor.mcp/mcp.json"
      - "~/.config/Cursor/User/globalStorage/cursor.mcp/mcp.json"
      - "~/.cursor/mcp.json"
      - "~/.windsurf/mcp.json"
      - "~/Library/Application Support/Windsurf/User/globalStorage/windsurf.mcp/mcp.json"
      - "~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
      - "~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
      - "~/Library/Application Support/Code/User/mcp.json"
      - "~/.config/Code/User/mcp.json"
      - "~/.continue/config.json"
      - "~/.config/zed/settings.json"
      - "~/.openclaw/openclaw.json"
      - "~/.snowflake/cortex/mcp.json"
      - "~/.docker/mcp/registry.yaml"
      - "~/.docker/mcp/catalogs/docker-mcp.yaml"
      - ".mcp.json"
      - "mcp.json"
      - ".cursor/mcp.json"
      - ".vscode/mcp.json"
      - "docker-compose.yml"
      - "docker-compose.yaml"
      - "compose.yml"
      - "compose.yaml"
    file_reads_justification: |
      These are the standard config file locations for 11 MCP clients.
      Each file is a JSON/YAML config containing MCP server definitions.
      agent-bom reads them to discover which MCP servers are configured,
      then extracts package names for CVE scanning. On any given system,
      only 2-4 of these files typically exist — the rest are silently skipped.
      The 27 paths break down as: 11 MCP clients × ~2 OS variants = ~19 global
      paths + 5 project-level configs + 4 Docker Compose filenames.
      No directory traversal, no glob patterns, no recursive walks.
      Use --dry-run to see exactly which files exist on YOUR system.
    file_writes: []
    network_endpoints:
      - url: "https://api.osv.dev/v1/querybatch"
        purpose: "CVE lookup by package name+version"
        auth: false
      - url: "https://services.nvd.nist.gov/rest/json/cves/2.0"
        purpose: "CVSS score enrichment"
        auth: "optional — NVD_API_KEY increases rate limit from 5 to 50 req/30s, not required"
      - url: "https://api.first.org/data/v1/epss"
        purpose: "Exploit probability scores"
        auth: false
      - url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        purpose: "Known exploited vulnerability status"
        auth: false
      - url: "https://registry.npmjs.org"
        purpose: "npm package metadata"
        auth: false
      - url: "https://pypi.org/pypi"
        purpose: "PyPI package metadata"
        auth: false
    sensitive_data_handling:
      config_files_contain_secrets: true
      what_is_extracted: "server names, commands, arguments, env var NAMES only"
      what_is_never_extracted: "env var VALUES, file contents beyond JSON structure, auth tokens, passwords"
      credential_name_detection: "pattern-match on key names (*KEY*, *TOKEN*, *SECRET*, *PASSWORD*, *AUTH*) — values never read"
      redaction: "all credential-like values shown as ***REDACTED*** in output"
      in_memory_only: true
      written_to_disk: false
    data_sent: "package names and versions only"
    data_not_sent: "file paths, config contents, env var values, hostnames, IP addresses"
    checksums:
      pypi_sha256: "auto-verified at install time via pip"
      sigstore_signed: true
      slsa_provenance: "GitHub Actions OIDC (see release.yml)"
      verify_command: "cosign verify-blob dist/agent_bom-*.whl --bundle dist/agent_bom-*.whl.bundle --certificate-oidc-issuer https://token.actions.githubusercontent.com"
    telemetry: false
    persistence: false
    privilege_escalation: false
---

# agent-bom — AI Supply Chain Security Scanner

## What it does

agent-bom is a **read-only** security scanner for AI agent and MCP server configurations.
It discovers MCP client configs on your system, extracts package dependencies, and queries
public vulnerability databases for known CVEs. It then maps blast radius (which credentials
and tools are exposed if a package is compromised), generates SBOMs, and evaluates security policies.

**Key capabilities:**
- CVE scanning via OSV.dev (no API key required)
- NVD CVSS v4 enrichment, EPSS exploit probability, CISA KEV status
- Blast radius mapping: CVE → package → server → agent → credentials/tools
- SBOM generation: CycloneDX 1.6, SPDX 3.0, SARIF 2.1.0
- Policy-as-code engine for CI/CD security gates
- Threat intelligence registry of 427+ known MCP servers with risk metadata
- Docker image scanning (requires `docker` binary, optional)

## Scope boundaries

agent-bom operates within a **strictly bounded scope**. Every file path, network endpoint,
and data element is enumerated below and in the manifest metadata above.

### Config files read (exhaustive list)

The following paths are the **only** files agent-bom reads. Each is a JSON/YAML MCP client
config. If a file does not exist, it is silently skipped. No directory traversal, no glob
patterns, no recursive walks.

| Client | macOS path | Linux path |
|--------|-----------|------------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` | `~/.config/Claude/claude_desktop_config.json` |
| Claude Code | `~/.claude/settings.json`, `~/.claude.json` | same |
| Cursor | `~/Library/Application Support/Cursor/User/globalStorage/cursor.mcp/mcp.json`, `~/.cursor/mcp.json` | `~/.config/Cursor/User/globalStorage/cursor.mcp/mcp.json`, `~/.cursor/mcp.json` |
| Windsurf | `~/.windsurf/mcp.json`, `~/Library/Application Support/Windsurf/User/globalStorage/windsurf.mcp/mcp.json` | `~/.windsurf/mcp.json` |
| Cline (VS Code) | `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` | `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` |
| VS Code Copilot | `~/Library/Application Support/Code/User/mcp.json` | `~/.config/Code/User/mcp.json` |
| Continue.dev | `~/.continue/config.json` | same |
| Zed | `~/.config/zed/settings.json` | same |
| OpenClaw | `~/.openclaw/openclaw.json` | same |
| Cortex Code | `~/.snowflake/cortex/mcp.json` | same |
| Docker MCP Toolkit | `~/.docker/mcp/registry.yaml`, `~/.docker/mcp/catalogs/docker-mcp.yaml` | same |

**Project-level configs** (current working directory only): `.mcp.json`, `mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`

**Docker Compose files** (current working directory only): `docker-compose.yml`, `docker-compose.yaml`, `compose.yml`, `compose.yaml`

**Total**: 27 specific file paths. All enumerated in `metadata.openclaw.file_reads` above.

### What agent-bom extracts from these files

- Server names, commands, arguments
- Environment variable **names only** (values are never read, stored, or logged)
- Credential-like env var names are flagged: `*KEY*`, `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*CREDENTIAL*`, `*AUTH*`
- Standard system vars (`PATH`, `HOME`, `LANG`) are excluded

### What agent-bom CANNOT access

- **Arbitrary files** — only the 27 paths listed above
- **Environment variable values** — only names are extracted
- **Private networks or internal APIs** — all network calls go to public endpoints only
- **Other processes** — no IPC, no signals, no process inspection
- **System configuration** — no `/etc`, no system services, no kernel parameters
- **Browser data** — no cookies, history, bookmarks, or stored passwords
- **SSH keys, GPG keys, or keychains** — never accessed
- **User documents** — no access to Desktop, Documents, Downloads, or media files

### Network endpoints (exhaustive list)

All network calls are read-only GET/POST to public vulnerability databases.
Only package names and versions are sent. All enumerated in `metadata.openclaw.network_endpoints` above.

| API | URL | Purpose | Auth required |
|-----|-----|---------|---------------|
| OSV.dev | `https://api.osv.dev/v1/querybatch` | CVE lookup by package | No |
| NVD | `https://services.nvd.nist.gov/rest/json/cves/2.0` | CVSS scores | No (API key optional) |
| EPSS | `https://api.first.org/data/v1/epss` | Exploit probability | No |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Known exploited vulns | No |
| npm | `https://registry.npmjs.org/{pkg}/{version}` | Package metadata | No |
| PyPI | `https://pypi.org/pypi/{pkg}/{version}/json` | Package metadata | No |

**No telemetry, analytics, or tracking.** Zero network calls unless scanning for vulnerabilities.
Network calls can be completely disabled with `--no-scan` (inventory-only mode).

### Data flow

```
[Local config files]  →  read server name, command, args, env var NAMES
                          ↓
[Package names+versions]  →  sent to OSV.dev, NVD, EPSS, KEV, npm, PyPI
                          ↓
[CVE results]  →  returned to local process, written to stdout or --output file
```

- **Sent to APIs**: package name + version only (e.g., `express@4.17.1`)
- **Returned from APIs**: CVE IDs, severity scores, advisory URLs
- **Never sent**: file paths, config contents, env var values, scan results, hostnames, IP addresses

### User control over scope

Users can restrict or bypass auto-discovery entirely:

| Flag | Effect |
|------|--------|
| `--dry-run` | Shows exactly which files and APIs would be accessed, then exits without reading anything |
| `--inventory <file>` | Scans only the agents/packages defined in a JSON inventory file — skips all config discovery |
| `--project <dir>` | Scans only MCP configs in a specific project directory |
| `--config-dir <dir>` | Reads MCP configs from a single custom directory only |
| `--no-skill` | Disables skill/instruction file scanning |
| `--skill-only` | Runs only skill scanning, skips all agent/package/CVE analysis |
| `--no-scan` | Inventory-only mode — discovers configs but makes no network calls |

**Recommended first run**: `agent-bom scan --dry-run` to preview the access plan before any actual scanning.

## Environment variables

agent-bom itself optionally uses:
- `NVD_API_KEY` — higher NVD rate limits (optional, never logged or transmitted beyond NVD)

This is declared in `metadata.openclaw.optional_env` above. **No env vars are required.**

## Installation

### Recommended: uv (fastest)
```bash
uv tool install agent-bom
```

### Alternative: pip
```bash
pip install agent-bom
```

### Alternative: pipx (isolated environment)
```bash
pipx install agent-bom
```

### Verify installation
```bash
agent-bom --version
# Should print: agent-bom 0.31.6
```

### Verify source
- **PyPI**: https://pypi.org/project/agent-bom/
- **Source**: https://github.com/msaad00/agent-bom
- **Sigstore signatures**: Each release wheel and sdist is signed with Sigstore OIDC.
  Verify with: `cosign verify-blob dist/agent_bom-*.whl --bundle dist/agent_bom-*.whl.bundle`

## When to use

- Before installing a new MCP server — run a pre-install check
- To audit your current agent setup for vulnerabilities
- To generate compliance documentation (SBOM)
- To understand blast radius of a specific CVE
- To enforce security policy gates in CI/CD

## Workflows

### 1. Quick scan (auto-discover local MCP configs)

```bash
agent-bom scan --format json
```

Discovers all configured MCP clients on your system, extracts package dependencies,
and queries OSV.dev for known CVEs. No API keys required.

### 2. Scan with enrichment (NVD CVSS + EPSS + CISA KEV)

```bash
agent-bom scan --enrich --format json
```

Adds CVSS v4 scores from NVD, exploit probability from EPSS, and CISA Known Exploited
Vulnerability status to each finding. Set `NVD_API_KEY` for higher NVD rate limits (optional).

### 3. Check a specific MCP server before installing

```bash
agent-bom check <package-name>@<version> -e <ecosystem>
```

Example:
```bash
agent-bom check @modelcontextprotocol/server-filesystem@2025.1.14 -e npm
```

### 4. Generate SBOM

```bash
agent-bom scan --format cyclonedx --output sbom.json
```

Supported formats: `cyclonedx` (CycloneDX 1.6), `spdx` (SPDX 3.0), `sarif` (SARIF 2.1.0)

### 5. Scan Docker image (requires `docker` binary)

```bash
agent-bom scan --image nginx:1.25 --format json
```

Uses Grype/Syft if available, otherwise falls back to Docker CLI for package extraction.
**This workflow requires the `docker` binary to be installed.**

### 6. Evaluate security policy

```bash
agent-bom scan --policy policy.json --enrich
```

### 7. Generate remediation plan

```bash
agent-bom scan --enrich --remediate remediation.md
```

## Output interpretation

- **critical/high severity**: Immediate action required — upgrade or remove package
- **blast_radii**: Shows CVE → package → server → agent → credentials/tools chain
- **exposed_credentials**: Env var **names** at risk if CVE is exploited (values are never shown)
- **risk_score**: 0-10 contextual score based on severity + reach + credential exposure
- **owasp_tags/atlas_tags/nist_ai_rmf_tags**: OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF mappings

## Guardrails

- **Read-only**: agent-bom never writes, modifies, or deletes any file on your system
- **No execution**: It never runs MCP servers, spawns processes, or executes discovered commands
- **No credential access**: Only env var **names** appear in reports — values are never read
- **No data exfiltration**: Scan results stay local. Only package names/versions are sent to public APIs
- **No persistence**: No background processes, daemons, cron jobs, or system modifications
- **No privilege escalation**: Runs as current user, no sudo/root required
- **No telemetry**: No analytics, crash reports, or usage tracking of any kind
- **Deterministic**: Same input always produces the same output (modulo upstream API data freshness)
- **Auditable**: Full source code at https://github.com/msaad00/agent-bom (Apache-2.0 license)
- **Signed releases**: Every PyPI release is signed with Sigstore OIDC
- **CI-verified**: Every commit passes 1000+ automated tests including security scanning
- **Docker non-root**: All container images run as unprivileged `abom` user (USER directive in every Dockerfile)

## Verification & provenance

You can independently verify every claim in this manifest:

| What to verify | How |
|---------------|-----|
| Source code | `git clone https://github.com/msaad00/agent-bom && grep -r "requests\|urllib\|httpx" src/` — all network calls use httpx, fully auditable |
| Network endpoints | `grep -n "osv.dev\|nvd.nist\|first.org\|cisa.gov\|npmjs.org\|pypi.org" src/agent_bom/` — exhaustive list of all outbound URLs in source |
| File access | `grep -rn "open(\|Path(" src/agent_bom/discovery/` — all file reads happen in the discovery module only |
| Credential handling | `grep -n "credential_names\|SENSITIVE_PATTERNS\|REDACTED" src/agent_bom/` — values are never stored |
| Signed release | `cosign verify-blob dist/agent_bom-*.whl --bundle dist/agent_bom-*.whl.bundle --certificate-oidc-issuer https://token.actions.githubusercontent.com` |
| CI test count | See [GitHub Actions](https://github.com/msaad00/agent-bom/actions) — every commit runs 1000+ tests including security scanning |
| OpenSSF Scorecard | [Scorecard viewer](https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom) |
| Dry-run audit | `agent-bom scan --dry-run` — shows every file, API, and data element that would be accessed, with a full data audit |

### Source code evidence

The following are actual code excerpts from the agent-bom source that enforce the claims above.
These can be verified at the linked source files.

**Credential names only — values never read** ([models.py:222-233](https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/models.py#L222-L233)):
```python
@property
def credential_names(self) -> list[str]:
    """Return names of env vars that look like credentials."""
    sensitive_patterns = [
        "key", "token", "secret", "password", "credential",
        "api_key", "apikey", "auth", "private",
        "connection", "conn_str", "database_url", "db_url",
    ]
    return [
        k for k in self.env  # self.env is dict of {name: value} but only KEYS are returned
        if any(pat in k.lower() for pat in sensitive_patterns)
    ]
```

**Config parsing extracts structure only** ([discovery/__init__.py:160-167](https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/discovery/__init__.py#L160-L167)):
```python
def parse_mcp_config(config_data: dict, config_path: str) -> list[MCPServer]:
    """Parse MCP server definitions from a config file.
    Supports multiple config formats:
    - Standard: {"mcpServers": {"name": {"command": ..., "args": [...]}}}
    - VS Code:  {"servers": {"name": {"type": "stdio", "command": ...}}}
    """
    # Only extracts: server name, command, args, env var keys
```

**All file reads are enumerated — no dynamic paths** ([discovery/__init__.py:30-107](https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/discovery/__init__.py#L30-L107)):
```python
CONFIG_LOCATIONS: dict[AgentType, dict[str, list[str]]] = {
    AgentType.CLAUDE_DESKTOP: {
        "Darwin": ["~/Library/Application Support/Claude/claude_desktop_config.json"],
        "Linux": ["~/.config/Claude/claude_desktop_config.json"],
    },
    # ... 10 more clients, each with hardcoded paths
}
# No dynamic path construction, no user input in paths, no glob patterns
```

### Binary behavior audit

ClawHub notes that `agent-bom` is an external binary not bundled in the skill. To verify it matches the source:

```bash
# 1. Install from source (not PyPI) to guarantee source-binary match
git clone https://github.com/msaad00/agent-bom && cd agent-bom
pip install -e .

# 2. Compare installed version to source
agent-bom --version  # Should match pyproject.toml version
python -c "import agent_bom; print(agent_bom.__file__)"  # Points to cloned source

# 3. Run dry-run data audit to confirm scope
agent-bom scan --dry-run
```

The `--dry-run` output includes a **Data Audit** section that shows:
- Exactly which data elements are extracted from config files (server names, commands, env var NAMES only)
- Exactly what data is sent to each API (package name + version only)
- What is explicitly NOT sent (file paths, config contents, env var values, hostnames)

## Runtime dependencies

| Feature | Required binary | Notes |
|---------|----------------|-------|
| Core scanning | `agent-bom` only | No external tools needed |
| Docker image scanning | `docker` | Optional — only when user passes `--image` |
| Enhanced image scanning | `grype`, `syft` | Optional — richer results if available |
