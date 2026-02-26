# Permissions & Trust Contract

agent-bom is a **read-only security scanner**. This document is an explicit,
auditable contract of what the tool accesses — and what it never touches.

---

## What We Read

agent-bom reads only what you explicitly ask it to scan:

| Target | How specified | What is read |
|--------|--------------|--------------|
| Agent configs | auto-discovery or `--project` | Config JSON/YAML files (e.g. `claude_desktop_config.json`) |
| Inventory | `--inventory` | Your inventory JSON file |
| Lock files | inferred from project | `package-lock.json`, `requirements.txt`, `Cargo.lock`, etc. |
| Docker images | `--image` | Image filesystem layers (via Grype/Syft subprocess) |
| Kubernetes | `--k8s` | Pod specs via `kubectl get pods -o json` (read-only) |
| Terraform | `--tf-dir` | `.tf` source files (no state files, no `.tfvars`) |
| GitHub Actions | `--gha` | `.github/workflows/*.yml` files |
| SBOM files | `--sbom` | CycloneDX/SPDX JSON you provide |

---

## Auto-Discovery Config Paths (exhaustive list)

**Auto-discovery** reads these specific config paths only. No directory traversal,
no glob patterns, no recursive walks. If a file does not exist, it is silently skipped.

### Global config files

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

### Project-level config files (current working directory only)

- `.mcp.json`
- `mcp.json`
- `.cursor/mcp.json`
- `.vscode/mcp.json`
- `.openclaw/openclaw.json`

### Docker Compose files (current working directory only)

- `docker-compose.yml`
- `docker-compose.yaml`
- `compose.yml`
- `compose.yaml`

**Total**: 27 specific file paths. No other files are ever read during auto-discovery.

Use `--dry-run` to preview exactly which paths would be read before any scan runs.

---

## What We Extract From Config Files

From each MCP client config, agent-bom extracts:

| Data element | Example | Used for |
|-------------|---------|----------|
| Server name | `"filesystem"` | Inventory labeling |
| Command | `"npx"` | Package identification |
| Arguments | `["@modelcontextprotocol/server-filesystem", "/path"]` | Package name + version extraction |
| Env var **names** | `"OPENAI_API_KEY"` | Credential exposure mapping |

### What is NOT extracted

- **Environment variable values** — only names are read, never values
- **File path arguments** — shown in inventory but never traversed or opened
- **Config file contents** — only the structured server definitions are parsed

### Credential name detection

Env var names matching these patterns are flagged as credential-like:

**Flagged**: `*KEY*`, `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*CREDENTIAL*`, `*API_KEY*`, `*APIKEY*`, `*AUTH*`, `*PRIVATE*`, `*CONNECTION*`, `*CONN_STR*`, `*DATABASE_URL*`, `*DB_URL*`

**Excluded** (standard system vars): `PATH`, `HOME`, `LANG`, `SHELL`, `USER`, `TERM`, `EDITOR`, `DISPLAY`, `PWD`, `TMPDIR`

Credential values are **never** read, stored, logged, or transmitted. Only names appear in reports as blast-radius indicators.

---

## What We Never Do

- **Never write** to any config file, lock file, or project file
- **Never execute** MCP servers or agent processes
- **Never store** credential values — only env var _names_ appear in reports
- **Never transmit** your file contents, project structure, or inventory to external services
- **Never cache** any personal data to disk (scan history is opt-in via `--save`)
- **Never require** authentication tokens or API keys (NVD key is optional for rate limits only)
- **Never access** arbitrary files — only the 27 enumerated paths above
- **Never traverse** directories or use glob patterns during auto-discovery
- **Never run** background processes, daemons, cron jobs, or system services

---

## External API Calls (exhaustive list)

All network calls are read-only GET/POST to public vulnerability databases.
Only package names and versions are sent. No user data is included in requests.

| Service | URL | What we send | What we receive | Auth |
|---------|-----|-------------|----------------|------|
| OSV.dev | `https://api.osv.dev/v1/querybatch` | Package names + versions | CVE IDs, advisories | None |
| NVD/NIST | `https://services.nvd.nist.gov/rest/json/cves/2.0` | CVE IDs | CVSS scores, CWE IDs | Optional (NVD_API_KEY for higher rate limits) |
| FIRST EPSS | `https://api.first.org/data/v1/epss` | CVE IDs | Exploit probability scores | None |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | _(none — full download)_ | KEV catalog | None |
| npm registry | `https://registry.npmjs.org/{pkg}/{version}` | Package name + version | Package metadata | None |
| PyPI | `https://pypi.org/pypi/{pkg}/{version}/json` | Package name + version | Package metadata | None |
| OpenSSF Scorecard | `https://api.securityscorecards.dev/projects/github.com/{owner}/{repo}` | GitHub owner/repo | Scorecard scores | None |
| Jira (optional) | `https://{instance}.atlassian.net/rest/api/3/issue` | Finding summaries | Ticket confirmation | API token (`--jira-token`) |
| Slack (optional) | User-provided webhook URL | Finding summaries | Delivery status | Webhook URL (`--slack-webhook`) |
| Vanta (optional) | `https://api.vanta.com/v1/` | Compliance evidence | Upload confirmation | API token (`--vanta-token`) |
| Drata (optional) | `https://public-api.drata.com/` | Compliance evidence | Upload confirmation | API token (`--drata-token`) |

### Data flow

```
[Local config files]  →  extract server name, command, args, env var NAMES
                          ↓
[Package names+versions]  →  sent to OSV.dev, NVD, EPSS, KEV, npm, PyPI, OpenSSF Scorecard
                          ↓
[Findings (optional)]     →  sent to Jira, Slack, Vanta, Drata (only if flags provided)
                          ↓
[CVE results]  →  returned to local process, written to stdout or --output file
```

- **Sent to APIs**: package name + version only (e.g., `express@4.17.1`)
- **Returned from APIs**: CVE IDs, severity scores, advisory URLs
- **Never sent**: file paths, config contents, env var values, scan results, hostnames, IP addresses

All external calls can be completely disabled with `--no-scan` (inventory-only mode).

**No telemetry, analytics, or tracking.** Zero network calls unless scanning for vulnerabilities.

---

## Credential Handling

Environment variables in MCP server configs are **never read for their values**.
Only the _key names_ (e.g. `OPENAI_API_KEY`, `DATABASE_URL`) are inspected to
determine whether credentials are present. Values are always shown as `***REDACTED***`.

agent-bom itself optionally uses one env var:
- `NVD_API_KEY` — increases NVD rate limit from 5 to 50 requests per 30 seconds. This key is sent only to `services.nvd.nist.gov` and is never logged, cached, or transmitted elsewhere.

---

## User Control Over Scope

Users can restrict or bypass auto-discovery entirely:

| Flag | Effect |
|------|--------|
| `--dry-run` | Shows exactly which files, APIs, and data would be accessed, then exits without reading anything |
| `--inventory <file>` | Scans only the agents/packages defined in a JSON inventory file — skips all config discovery |
| `--project <dir>` | Scans only MCP configs in a specific project directory |
| `--config-dir <dir>` | Reads MCP configs from a single custom directory only |
| `--no-skill` | Disables skill/instruction file scanning |
| `--skill-only` | Runs only skill scanning, skips all agent/package/CVE analysis |
| `--no-scan` | Inventory-only mode — discovers configs but makes no network calls |

**Recommended first run**: `agent-bom scan --dry-run` to preview the complete access plan before any actual scanning.

---

## Verifying Our Claims

This is an open-source tool — you can verify every claim above:

| Verification | How |
|---|---|
| Read source code | `src/agent_bom/` — all scanning logic is in plain Python |
| Audit network calls | `grep -rn "osv.dev\|nvd.nist\|first.org\|cisa.gov\|npmjs.org\|pypi.org" src/agent_bom/` — exhaustive list of all outbound URLs |
| Audit file access | `grep -rn "open(\|Path(" src/agent_bom/discovery/` — all file reads in the discovery module |
| Audit credential handling | `src/agent_bom/models.py` — `MCPServer.credential_names` property + `SENSITIVE_PATTERNS` in `security.py` |
| Run in isolation | `--no-scan` skips all network calls; `--dry-run` reads nothing |
| Verify signed releases | `cosign verify-blob dist/agent_bom-*.whl --bundle dist/agent_bom-*.whl.bundle --certificate-oidc-issuer https://token.actions.githubusercontent.com` |
| OpenSSF Scorecard | [![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/msaad00/agent-bom/badge)](https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom) |

---

## Least Privilege — API Server

When running `agent-bom api`, the HTTP server adds these headers to every response:

```
X-Agent-Bom-Read-Only: true
X-Agent-Bom-No-Credential-Storage: true
```

The API server itself runs entirely in-process. No outbound connections are made
unless a scan job explicitly requests enrichment (`"enrich": true` in the request body).

---

## Reporting a Security Issue

See [SECURITY.md](SECURITY.md) for responsible disclosure via GitHub Security Advisories.
