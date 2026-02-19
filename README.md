# agent-bom

[![CI](https://github.com/agent-bom/agent-bom/actions/workflows/ci.yml/badge.svg)](https://github.com/agent-bom/agent-bom/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/agent-bom)](https://pypi.org/project/agent-bom/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Docker Pulls](https://img.shields.io/docker/pulls/agentbom/agent-bom)](https://hub.docker.com/r/agentbom/agent-bom)

**AI Bill of Materials (AI-BOM) generator for AI agents and MCP servers.**

`agent-bom` maps the full trust chain from AI agent → MCP server → packages → known vulnerabilities, with **blast radius analysis**: *"If this package is compromised, which agents are affected, what credentials are exposed, and what tools can an attacker reach?"*

---

## Why agent-bom?

Existing tools scan for prompt injection or inventory AI models. **Nobody maps the full dependency chain from agent to vulnerability.**

Traditional SBOMs stop at the package layer. `agent-bom` goes deeper:

```
Agent (Claude Desktop)
  └── MCP Server (database-server)
        ├── Tool: query_database (read/write)
        ├── Credentials: DB_PASSWORD, API_KEY
        └── Packages:
              ├── express@4.18.2 ← CVE-2024-XXXX (HIGH)
              └── axios@1.6.0   ← CVE-2024-YYYY (CRITICAL)
                    ↑
                    Blast Radius: 3 agents, 2 credentials exposed, 5 tools reachable
```

A vulnerable package means every agent connected to that MCP server inherits the risk — credentials included.

---

## Install

```bash
pip install agent-bom
```

From source:

```bash
git clone https://github.com/agent-bom/agent-bom.git
cd agent-bom
pip install -e .
```

---

## Quick Start

| Command | What it does |
|---------|-------------|
| `agent-bom scan` | Auto-discover agents + extract deps + scan for CVEs |
| `agent-bom scan --inventory agents.json` | Scan agents from a manual inventory file |
| `agent-bom scan --sbom syft-output.json --inventory agents.json` | Ingest existing Syft/Grype/Trivy CycloneDX or SPDX SBOM |
| `agent-bom scan --image nginx:1.25` | Scan a Docker image for packages + CVEs (uses Syft if available, Docker CLI fallback) |
| `agent-bom scan --image myapp:latest --image redis:7` | Scan multiple Docker images in one run |
| `agent-bom scan --k8s` | Discover container images from a Kubernetes cluster (default namespace) |
| `agent-bom scan --k8s --all-namespaces` | Scan all K8s namespaces |
| `agent-bom scan --k8s --namespace prod --context my-cluster` | Scan a specific namespace and context |
| `agent-bom scan --project /path` | Scan a specific project directory |
| `agent-bom scan --config-dir /path` | Scan a custom agent config directory |
| `agent-bom scan --transitive` | Include transitive dependencies |
| `agent-bom scan --transitive --max-depth 5` | Transitive resolution with custom depth |
| `agent-bom scan --enrich` | Add NVD / EPSS / CISA KEV data |
| `agent-bom scan --enrich --nvd-api-key KEY` | Enrich with higher NVD rate limits |
| `agent-bom scan --no-scan` | Inventory only — skip vulnerability scanning |
| `agent-bom scan --no-tree` | Skip dependency tree in console output |
| `agent-bom scan --save` | Save scan to `~/.agent-bom/history/` for diffing |
| `agent-bom scan --baseline report.json` | Diff current scan against a saved baseline |
| `agent-bom scan -f json -o report.json` | Export JSON report |
| `agent-bom scan -f cyclonedx -o bom.cdx.json` | Export CycloneDX 1.6 BOM |
| `agent-bom scan -f sarif -o bom.sarif` | Export SARIF for GitHub Security tab |
| `agent-bom scan -f spdx -o bom.spdx.json` | Export SPDX 3.0 AI-BOM JSON-LD |
| `agent-bom scan -f html -o report.html` | Self-contained HTML report — interactive Cytoscape.js graph, dark theme, blast radius score bars (opens in browser) |
| `agent-bom scan -f prometheus -o metrics.prom` | Prometheus text exposition format — drop into node_exporter textfile dir |
| `agent-bom scan --push-gateway http://localhost:9091` | Push scan metrics directly to Prometheus Pushgateway |
| `agent-bom scan --otel-endpoint http://localhost:4318` | Export via OpenTelemetry OTLP/HTTP (requires `pip install agent-bom[otel]`) |
| `agent-bom scan -f text` | Plain text output (for grep/awk) |
| `agent-bom scan -f json -o - \| jq .` | Pipe clean JSON to stdout |
| `agent-bom scan -q --fail-on-severity high` | CI gate — exit 1 if high+ vulns found |
| `agent-bom scan --fail-on-kev` | CI gate — exit 1 if any CISA KEV finding (use with `--enrich`) |
| `agent-bom scan --fail-if-ai-risk` | CI gate — exit 1 if AI framework has vulns + exposed creds |
| `agent-bom scan --policy policy.json` | CI gate — declarative policy rules (fail/warn conditions) |
| `agent-bom check express@4.18.2 -e npm` | Pre-install check — is this package safe? |
| `agent-bom check "npx @scope/mcp-server"` | Check a package before running with npx |
| `agent-bom history` | List saved scan history |
| `agent-bom diff baseline.json` | Diff latest scan against a baseline |
| `agent-bom diff baseline.json current.json` | Diff any two report files |
| `agent-bom policy-template` | Generate a starter `policy.json` with common rules |
| `agent-bom inventory` | List discovered agents (no vuln scan) |
| `agent-bom inventory -c config.json` | Inventory a specific config file |
| `agent-bom validate agents.json` | Validate an inventory file against the schema |
| `agent-bom where` | Show where configs are looked up |

---

## How It Works

agent-bom operates in two modes: **auto-discovery** and **manual inventory**. Both are agentless — you bring the data, agent-bom scans and generates the BOM.

### Mode 1: Auto-discovery

When you run `agent-bom scan` with no arguments, it scans your machine for known MCP client configurations:

```bash
# Discover all local agents automatically
agent-bom scan

# Discover from a specific project directory
agent-bom scan --project /path/to/my-project
```

agent-bom looks for config files at known paths for each supported client (see `agent-bom where` for locations). It parses the `mcpServers` block in each config to find MCP server definitions.

### Mode 3: Docker image scanning

Scan container images directly — no MCP config needed:

```bash
# Scan a single image (uses Syft if installed, Docker CLI otherwise)
agent-bom scan --image nginx:1.25

# Scan multiple images
agent-bom scan --image myapp:latest --image redis:7 --image postgres:16

# Combine with vulnerability enrichment and CI gate
agent-bom scan --image myapp:latest --enrich --fail-on-severity high -f sarif -o results.sarif
```

Each image becomes a synthetic agent entry in the report. Syft is preferred because it extracts packages from all layers without running the container. The Docker CLI fallback creates a temporary container, exports the filesystem, and scans manifest files (`dist-info`, `node_modules/*/package.json`, `/var/lib/dpkg/status`).

### Mode 4: Kubernetes pod discovery

Enumerate running container images from a cluster and scan each:

```bash
# Scan pods in the default namespace
agent-bom scan --k8s

# Scan all namespaces
agent-bom scan --k8s --all-namespaces

# Target a specific namespace and context
agent-bom scan --k8s --namespace production --context my-prod-cluster

# Full pipeline: discover K8s images → scan → SARIF upload
agent-bom scan --k8s --all-namespaces --enrich -f sarif -o k8s-aibom.sarif
```

`--k8s` calls `kubectl get pods -o json`, extracts unique image references from all container specs (including init and ephemeral containers), deduplicates them, and passes each to the image scanner. Combine with `--image` if you also want to include images not yet running in the cluster.

### Mode 2: Manual inventory

For agents not auto-discovered — custom agents, production deployments, cloud platforms — provide a JSON inventory file:

```bash
agent-bom scan --inventory agents.json
```

**Inventory format** (`agents.json`):

```json
{
  "agents": [
    {
      "name": "my-production-agent",
      "agent_type": "custom",
      "config_path": "/opt/my-agent/config.json",
      "mcp_servers": [
        {
          "name": "database-server",
          "command": "npx",
          "args": ["-y", "@my-org/mcp-database-server"],
          "env": {
            "DATABASE_URL": "postgresql://...",
            "API_KEY": "sk-..."
          },
          "transport": "stdio",
          "tools": [
            {"name": "query_database", "description": "Execute SQL queries"},
            "list_tables"
          ],
          "packages": [
            {"name": "express", "version": "4.18.2", "ecosystem": "npm"},
            "axios@1.6.0"
          ]
        }
      ]
    }
  ]
}
```

| Field | Required | Description |
|-------|:--------:|-------------|
| `agents[].name` | yes | Agent identifier |
| `agents[].agent_type` | no | `claude-desktop`, `claude-code`, `cursor`, `windsurf`, `cline`, or `custom` (default: `custom`) |
| `agents[].config_path` | no | Where the agent config lives — can be a file path, ARN, Snowflake URI, etc. |
| `agents[].version` | no | Agent version string |
| `agents[].mcp_servers[].name` | yes | MCP server identifier |
| `agents[].mcp_servers[].command` | no | Server command (`npx`, `uvx`, `python`, `node`, etc.). Omit for cloud/API-managed servers. |
| `agents[].mcp_servers[].args` | no | Command arguments (array of strings) |
| `agents[].mcp_servers[].env` | no | Environment variables (object). Credential-like keys are flagged automatically |
| `agents[].mcp_servers[].transport` | no | `stdio` (default), `sse`, or `streamable-http` |
| `agents[].mcp_servers[].url` | no | Server URL (for SSE/HTTP transports) |
| `agents[].mcp_servers[].mcp_version` | no | MCP protocol version (e.g. `"2024-11-05"`). Tracked in output for compatibility auditing. |
| `agents[].mcp_servers[].working_dir` | no | Server working directory (for lock file resolution) |
| `agents[].mcp_servers[].tools` | no | Pre-populated tool list — array of objects (`{"name", "description"}`) or strings |
| `agents[].mcp_servers[].packages` | no | Pre-known packages — array of objects (`{"name", "version", "ecosystem"}`) or `"name@version"` strings |
| `agents[].source` | no | Where this inventory entry came from (e.g. `"snowflake"`, `"aws-bedrock"`, `"local"`) |

The inventory format mirrors what auto-discovery finds. Pre-populated packages are merged with any packages agent-bom discovers from lock files, so you can provide what you know and agent-bom fills in the rest.

**Validate before scanning:**

```bash
agent-bom validate agents.json   # exits 0 if valid, 1 with clear errors if not
```

**What you need for each scanning capability:**

| Capability | Required fields |
|-----------|----------------|
| Vulnerability scan | `mcp_servers[].packages[].name` + `.version` + `.ecosystem` |
| Credential detection | `mcp_servers[].env` (key names only — values never logged) |
| Blast radius analysis | Both packages and env above, plus `mcp_servers[].tools[]` |
| SARIF output (finding location) | `config_path` on agent or server |
| Supply chain traceability | `source` on agent or at file root |

**Mapping from platform-specific formats:**

| Your platform | Maps to |
|--------------|---------|
| Claude Desktop `mcpServers.X.command/args/env` | `mcp_servers[].command/args/env` |
| Cursor / VS Code `mcpServers.X` | Same — auto-discovered by `agent-bom scan` |
| Snowflake `CREATE MCP SERVER` tools YAML | `mcp_servers[].tools[]` + `mcp_servers[].packages[]` |
| AWS Bedrock `actionGroupName` / Lambda ARN | Agent name = group name, `config_path` = ARN, packages from Lambda deps |
| EC2 / VM with AI packages installed | `mcp_servers[].packages[]` with ecosystem = pypi/npm |
| OpenAI Assistant function tools | `mcp_servers[].tools[]` with name + description |

**Example inventories for different sources:**

- [examples/snowflake-inventory.json](examples/snowflake-inventory.json) — Snowflake Cortex agents with MCP servers and tools from query history
- [examples/cloud-inventory.json](examples/cloud-inventory.json) — AWS Bedrock agents and EC2-hosted ML pipelines with pre-known packages
- [schemas/inventory.schema.json](schemas/inventory.schema.json) — Full JSON Schema with field documentation

---

## Features

- **Auto-discovery** — Claude Desktop, Claude Code, Cursor, Windsurf, Cline, VS Code Copilot, Snowflake Cortex Code, Continue.dev, Zed, and project-level `.mcp.json`
- **Manual inventory** — scan any agent platform via `--inventory` JSON; validate with `agent-bom validate`
- **Multi-ecosystem** — npm, pip, Go, Cargo (lock files + manifest files)
- **npx / uvx detection** — extracts package names from MCP server command definitions
- **MCP registry lookup** — resolves packages for 25+ known MCP servers by name when no lock file is present (e.g. `@modelcontextprotocol/server-filesystem`, `mcp-server-git`); updated weekly via automated workflow
- **SBOM ingestion** — `--sbom sbom.json` accepts existing CycloneDX 1.x or SPDX 2.x/3.0 output from Syft, Grype, Trivy, or cdxgen; integrates into existing pipelines without replacing them
- **Docker image scanning** — `--image nginx:1.25` extracts packages from container images using Syft (preferred) or Docker CLI filesystem export fallback; repeatable for multiple images in one scan
- **Kubernetes discovery** — `--k8s` queries `kubectl get pods` to enumerate running container images, then scans each via the Docker image scanner; supports `--namespace`, `--all-namespaces`, and `--context`
- **Transitive resolution** — recursively resolves nested deps via npm and PyPI registries with proper semver/PEP 440 range handling (`^`, `~`, `>=`, specifier sets)
- **Vulnerability scanning** — queries [OSV.dev](https://osv.dev) across all ecosystems; GHSA/RUSTSEC aliases automatically mapped to CVE IDs for enrichment
- **CVSS scoring** — computes numeric CVSS 3.x base scores from vector strings (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8`), not just labels
- **Enrichment** — NVD metadata (CWE IDs, dates), EPSS exploit probability, CISA KEV flags (`--enrich`); all CVEs enriched with proper rate limiting (not capped)
- **Blast radius scoring** — risk score boosted by KEV membership (+1.0), high EPSS (+0.5), and AI framework context (+0.5)
- **AI framework risk tagging** — LangChain, OpenAI, transformers, MCP, and 25+ other AI packages flagged with context: *"AI framework runs inside an agent with 3 exposed credentials and 7 reachable tools"*
- **Remediation plan** — grouped upgrade actions ordered by blast radius impact (agents protected × credentials freed × vulns cleared × KEV/AI flags)
- **Pre-install safety check** — `agent-bom check express@4.18.2` queries OSV before you run `npx -y`
- **Scan history** — `--save` persists scans to `~/.agent-bom/history/`; `agent-bom diff` shows new/resolved findings between runs
- **Policy-as-code** — `--policy policy.json` with declarative rules (severity thresholds, KEV, AI risk, credentials, ecosystem filters); `agent-bom policy-template` generates a starter file
- **Policy CI gates** — `--fail-on-severity`, `--fail-on-kev`, `--fail-if-ai-risk` for quick inline enforcement
- **Credential detection** — flags MCP servers exposing API keys, tokens, and secrets in env vars
- **Output formats** — rich console (with severity chart), HTML (interactive browser report with Mermaid dependency graph), JSON, CycloneDX 1.6, SARIF 2.1, SPDX 3.0, plain text
- **CI/CD ready** — `--quiet`, stdout piping (`-o -`), multiple exit code policies

---

## Supported Platforms

### Auto-discovered (local MCP clients)

| Client | macOS | Linux | Windows |
|--------|:-----:|:-----:|:-------:|
| Claude Desktop | ✅ | ✅ | ✅ |
| Claude Code | ✅ | ✅ | ✅ |
| Cursor | ✅ | ✅ | ✅ |
| Windsurf | ✅ | ✅ | ✅ |
| Cline | ✅ | ✅ | ✅ |
| VS Code Copilot (Agent mode) | ✅ | ✅ | ✅ |
| Snowflake Cortex Code CLI | ✅ | ✅ | ✅ |
| Continue.dev | ✅ | ✅ | ✅ |
| Zed | ✅ | ✅ | ✅ |

### Manual scan (any platform)

Use `--inventory` to scan any agent not listed above — including custom agents, OpenAI-based tools, LangChain apps, or anything that uses MCP servers. See [Inventory format](#mode-2-manual-inventory) above.

### Cloud platforms (planned)

| Platform | Status | How it would work |
|----------|:------:|-------------------|
| Snowflake Cortex | Planned | Query `ACCOUNT_USAGE.QUERY_HISTORY` for `CREATE MCP SERVER` / `CREATE OR REPLACE AGENT` |
| AWS Bedrock Agents | Planned | List agents via Bedrock API, extract action group configs |
| Google Vertex AI | Planned | Discover agents + extensions via Vertex API |
| OpenAI Assistants | Planned | List assistants + tool definitions via OpenAI API |

### Package ecosystems scanned

| Ecosystem | Lock files | AI frameworks covered |
|-----------|-----------|----------------------|
| npm | `package-lock.json`, `package.json` | LangChain.js, Vercel AI SDK, etc. |
| pip | `requirements.txt`, `Pipfile.lock`, `pyproject.toml` | LangChain, LlamaIndex, transformers, openai, mistralai, etc. |
| Go | `go.sum` | — |
| Cargo | `Cargo.lock` | — |

AI framework packages (LangChain, transformers, openai, mistralai, etc.) are scanned for CVEs and flagged with AI-specific blast radius context when they run inside an agent with credentials and tools exposed.

---

## Docker

```bash
docker run --rm \
  -v ~/.config:/root/.config:ro \
  -v $(pwd)/reports:/workspace/reports \
  agentbom/agent-bom:latest scan --enrich -o /workspace/reports/ai-bom.json
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for CI/CD, Kubernetes, and remote scanning setups.

---

## Roadmap

**Cloud agent discovery:**
- [ ] Snowflake Cortex — scan `CREATE MCP SERVER` / `CREATE OR REPLACE AGENT` from query history
- [ ] AWS Bedrock — discover agents and action group configurations
- [ ] Google Vertex AI — discover agents and extensions
- [ ] OpenAI — scan assistant tool definitions

**Scanner capabilities:**
- [x] AI framework risk tagging — LangChain, OpenAI, transformers, MCP, and 25+ packages with AI-specific blast radius context
- [x] Full CVSS 3.x base score computation from vector strings
- [x] Proper semver / PEP 440 range resolution for transitive dependency scanning
- [x] All CVEs enriched via NVD with proper rate limiting (not capped at 10)
- [x] Prioritized remediation plan grouped by blast radius impact
- [x] MCP registry lookup — 25+ known MCP servers resolved to packages by name; weekly automated sync
- [x] SBOM ingestion — accept Syft/Grype/Trivy CycloneDX or SPDX output as input (`--sbom`)
- [x] Docker image scanning — extract packages from container images via Syft or Docker CLI (`--image`)
- [x] Kubernetes pod discovery — enumerate running container images via kubectl and scan each (`--k8s`)
- [ ] Live MCP server introspection (enumerate tools/resources dynamically)

**Output & policy:**
- [x] SARIF 2.1 output for GitHub Security tab
- [x] SPDX 3.0 AI-BOM JSON-LD output (`-f spdx`)
- [x] Policy CI gates: `--fail-on-kev`, `--fail-if-ai-risk`, `--fail-on-severity`
- [x] Policy-as-code: declarative rules with `--policy policy.json` + `agent-bom policy-template`
- [x] Scan history and baseline diffing (`--save`, `--baseline`, `agent-bom diff`)
- [x] Severity distribution chart in console output
- [x] HTML report — self-contained browser report with interactive Cytoscape.js dependency graph, dark theme, blast radius score bars, enrichment hint (`-f html`)
- [x] Prometheus metrics output — text exposition format + Pushgateway push + OTel OTLP (`-f prometheus`, `--push-gateway`, `--otel-endpoint`)
- [x] Grafana dashboard — importable JSON in `examples/grafana-dashboard.json`; one-command monitoring stack (`examples/docker-compose-monitoring.yml`)
- [x] Jenkins pipeline — `examples/Jenkinsfile` with scan → SARIF upload → Prometheus push → security gate
- [ ] MITRE ATLAS mapping for AI/ML threats

---

## Observability — Prometheus & Grafana

agent-bom emits Prometheus-format metrics so scan results appear as live Grafana dashboards.

### Option 1 — Push to Prometheus Pushgateway

```bash
# Start the monitoring stack (Prometheus + Pushgateway + Grafana + OTel Collector)
docker compose -f examples/docker-compose-monitoring.yml up -d

# Push metrics after each scan
agent-bom scan --push-gateway http://localhost:9091

# Open Grafana, import examples/grafana-dashboard.json
open http://localhost:3000   # admin / admin
```

### Option 2 — node_exporter textfile collector

```bash
# Write a .prom file — node_exporter scrapes it automatically
agent-bom scan -f prometheus -o /var/lib/node_exporter/textfile/agent-bom.prom
```

### Option 3 — OpenTelemetry OTLP

```bash
pip install agent-bom[otel]   # installs opentelemetry packages

agent-bom scan --otel-endpoint http://localhost:4318   # OTLP/HTTP collector
```

### Metrics emitted

| Metric | Labels | Description |
|--------|--------|-------------|
| `agent_bom_agents_total` | — | Agents discovered |
| `agent_bom_mcp_servers_total` | — | MCP servers |
| `agent_bom_packages_total` | — | Packages scanned |
| `agent_bom_vulnerabilities_total` | `severity` | Vulns by severity |
| `agent_bom_kev_findings_total` | — | CISA KEV count |
| `agent_bom_fixable_vulnerabilities_total` | — | Vulns with a fix |
| `agent_bom_blast_radius_score` | `vuln_id, package, version, severity, ecosystem, kev, fixable` | Risk score 0–10 |
| `agent_bom_vulnerability_cvss_score` | `vuln_id, package, severity` | CVSS base score (with `--enrich`) |
| `agent_bom_vulnerability_epss_score` | `vuln_id, package, severity` | EPSS probability (with `--enrich`) |
| `agent_bom_agent_vulnerabilities_total` | `agent, severity` | Per-agent vuln breakdown |
| `agent_bom_credentials_exposed_total` | `agent` | Credentials exposed per agent |

### Jenkins pipeline

See `examples/Jenkinsfile` for a complete pipeline: scan → SARIF upload → Prometheus push → security gate.

---

## CI Integration

```yaml
# .github/workflows/ai-bom.yml

# Option A: standalone scan
- name: Generate AI-BOM
  run: |
    pip install agent-bom
    agent-bom scan --inventory agents.json --fail-on-severity high -f sarif -o results.sarif

- name: Upload to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif

# Option B: pipe Syft SBOM into agent-bom (for teams already using Syft/Grype)
- name: Generate SBOM with Syft
  uses: anchore/sbom-action@v0
  with:
    image: myapp:latest
    format: cyclonedx-json
    output-file: sbom.cdx.json

- name: Scan SBOM for AI agent blast radius
  run: |
    pip install agent-bom
    agent-bom scan --sbom sbom.cdx.json --inventory agents.json \
      --enrich --fail-on-kev -f sarif -o results.sarif

- name: Upload to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
git clone https://github.com/agent-bom/agent-bom.git
cd agent-bom
pip install -e ".[dev]"
pytest && ruff check src/
```

---

## Security

To report a vulnerability, email **crewnycgiving@gmail.com**. See [SECURITY.md](SECURITY.md) for our responsible disclosure policy.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

Built by [Wagdy Saad](https://linkedin.com/in/wagdy-saad) — Staff Security Engineer specializing in cloud security and AI agent security.

*Not affiliated with Anthropic, Cursor, or any MCP client vendor.*
