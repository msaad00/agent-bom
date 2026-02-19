# agent-bom

[![CI](https://github.com/agent-bom/agent-bom/actions/workflows/ci.yml/badge.svg)](https://github.com/agent-bom/agent-bom/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/agent-bom)](https://pypi.org/project/agent-bom/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/agent-bom/agent-bom/blob/main/LICENSE)
[![Docker Pulls](https://img.shields.io/docker/pulls/agentbom/agent-bom)](https://hub.docker.com/r/agentbom/agent-bom)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/agent-bom/agent-bom/badge)](https://securityscorecards.dev/viewer/?uri=github.com/agent-bom/agent-bom)

**AI Bill of Materials (AI-BOM) — CVE scanning, blast radius, and OWASP LLM Top 10 tagging for AI agents and MCP servers.**

`agent-bom` answers the question no traditional SBOM can:

> *"If this CVE is exploited, which AI agents are compromised, which credentials are exposed, and which tools can an attacker reach?"*

---

## Why agent-bom?

Traditional SBOMs list packages. AI supply chains need more.

| Capability | Traditional SBOM | agent-bom |
|---|---|---|
| Package inventory | ✓ | ✓ |
| Known CVEs | ✓ | ✓ |
| CVSS + EPSS + CISA KEV enrichment | some | ✓ |
| **Blast radius** — which agents are affected | ✗ | ✓ |
| **Credential exposure** — which secrets are reachable | ✗ | ✓ |
| **Tool reachability** — which MCP tools can attackers invoke | ✗ | ✓ |
| **OWASP LLM Top 10 tagging** per finding | ✗ | ✓ |
| MCP server registry (55+ known servers) | ✗ | ✓ |
| AI framework scanning (10 Python frameworks) | ✗ | ✓ |
| Kubernetes pod image scanning | ✗ | ✓ |
| Terraform / IaC AI resource scanning | ✗ | ✓ |
| GitHub Actions workflow scanning | ✗ | ✓ |
| Container image scanning (Grype → Syft → Docker) | ✗ | ✓ |
| SARIF output → GitHub Security tab | ✗ | ✓ |
| CycloneDX 1.6 + SPDX 3.0 AI-BOM output | ✗ | ✓ |
| Prometheus / OTLP observability | ✗ | ✓ |
| REST API + SSE streaming | ✗ | ✓ |
| Read-only, no credentials stored | ✓ | ✓ |

---

## Architecture

```
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                        SOURCES (what you scan)                          │
  │                                                                         │
  │  Local configs   Docker images   Kubernetes pods   Terraform / IaC      │
  │  Python projects GitHub Actions  Existing SBOMs    JSON inventory        │
  └───────────────────────────────┬─────────────────────────────────────────┘
                                  │  agent-bom scan
                                  ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                        DISCOVERY ENGINE                                 │
  │                                                                         │
  │  MCP Config     Grype/Syft      kubectl          HCL parser             │
  │  auto-detect    image layers    pod specs        .tf files              │
  │  (8 clients)    (all ecosys.)   (all ns)         AI resource detection  │
  └───────────────────────────────┬─────────────────────────────────────────┘
                                  │  packages + agents
                                  ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                     INTELLIGENCE LAYER                                  │
  │                                                                         │
  │  OSV.dev batch CVE scan   NVD CVSS v4   EPSS exploit probability        │
  │  CISA KEV catalog         MCP Registry  OWASP LLM Top 10 tagging        │
  └───────────────────────────────┬─────────────────────────────────────────┘
                                  │  enriched vulnerabilities
                                  ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                      BLAST RADIUS ENGINE                                │
  │                                                                         │
  │  CVE-2024-XXXX (CRITICAL, CVSS 9.8, KEV, EPSS 0.94)                    │
  │    ├─ 4 agents affected    (Claude Desktop, Cursor, k8s:prod, ci.yml)   │
  │    ├─ 3 credentials exposed  (OPENAI_API_KEY, DB_PASS, AWS_SECRET)      │
  │    ├─ 7 tools reachable    (query_db, write_file, execute_code…)        │
  │    └─ OWASP tags          [LLM05 LLM06 LLM08]                          │
  └───────────────────────────────┬─────────────────────────────────────────┘
                                  │  structured findings
                                  ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                          OUTPUTS                                        │
  │                                                                         │
  │  Console (rich)   HTML dashboard   JSON          CycloneDX 1.6          │
  │  SPDX 3.0 AI-BOM  SARIF (GitHub)   Prometheus    OTLP (Grafana)         │
  └─────────────────────────────────────────────────────────────────────────┘
```

---

## Get Started in 30 Seconds

```bash
pip install agent-bom

# Scan local AI agents (Claude Desktop, Cursor, Windsurf, Cline, VS Code...)
agent-bom scan

# HTML dashboard — severity donut, blast radius chart, smart risk graph
agent-bom scan -f html -o report.html && open report.html

# CI gate — fail if any critical/high CVE is found
agent-bom scan --fail-on-severity high -q
```

No config needed. Auto-discovers agent configs on macOS, Linux, and Windows.

---

## Install

| Mode | Command |
|------|---------|
| Core CLI + scanner | `pip install agent-bom` |
| REST API server | `pip install agent-bom[api]` |
| Streamlit dashboard | `pip install agent-bom[ui]` |
| OpenTelemetry export | `pip install agent-bom[otel]` |
| All extras | `pip install agent-bom[api,ui,otel]` |

**Docker:**

```bash
docker run --rm -v ~/.config:/root/.config:ro agentbom/agent-bom:latest scan
```

**Kubernetes:**

```bash
helm repo add agent-bom https://agent-bom.github.io/charts
helm install agent-bom agent-bom/agent-bom
```

---

## Deployment Models

| Mode | How to run | Use case |
|------|-----------|----------|
| **CLI** | `pip install agent-bom && agent-bom scan` | Local scanning, developer workflow |
| **CI/CD gate** | `agent-bom scan --fail-on-severity high -q` | Block PRs with critical CVEs |
| **Docker** | `docker run agentbom/agent-bom scan` | Isolated, reproducible scans |
| **REST API** | `agent-bom api` → port 8422 | Dashboards, integrations, scripting |
| **Kubernetes** | Helm chart + CronJob | Continuous cluster monitoring |
| **Streamlit dashboard** | `agent-bom serve` | Team-visible security dashboard |
| **Prometheus / Grafana** | `--push-gateway` or `--otel-endpoint` | Observability stack integration |

---

## What It Scans

| Source | Flag | What's detected |
|--------|------|-----------------|
| Local MCP configs | *(auto)* | Claude Desktop, Cursor, Windsurf, Cline, VS Code, Continue, Zed, Snowflake Cortex Code |
| Manual inventory | `--inventory agents.json` | Any agent/MCP server you describe in JSON |
| Existing SBOM | `--sbom sbom.json` | Ingest CycloneDX / SPDX from Syft, Grype, Trivy, cdxgen |
| Docker image | `--image nginx:1.25` | Packages + CVEs from all layers (Grype preferred, Syft fallback, Docker CLI) |
| Kubernetes pods | `--k8s` | Running container images via `kubectl get pods` — all packages |
| Terraform / IaC | `--tf-dir infra/` | Bedrock, Vertex AI, Azure OpenAI resources; provider CVEs; hardcoded API keys |
| GitHub Actions | `--gha /repo` | AI credentials in `env:`, openai/anthropic/langchain SDK in `run:` steps |
| Python agent project | `--agent-project .` | LangChain, OpenAI Agents SDK, CrewAI, AutoGen, Google ADK, Pydantic AI + 4 more |

All sources produce the same output pipeline: packages → OSV CVE scan → enrichment → blast radius → report.

---

## Start Here — Pick Your Use Case

| I want to scan... | Command | What you get |
|-------------------|---------|--------------|
| My local AI tools (Claude Desktop, Cursor, Windsurf, Cline, VS Code...) | `agent-bom scan` | Auto-discovered MCP servers, packages, CVEs |
| A Python project using LangChain / OpenAI Agents / CrewAI / AutoGen... | `agent-bom scan --agent-project .` | Agent defs, tools, credential refs, CVEs from requirements |
| A Docker image | `agent-bom scan --image myapp:latest` | All packages in image layers → CVE scan |
| All containers running in a Kubernetes cluster | `agent-bom scan --k8s --all-namespaces` | Package inventory of every pod image → CVE scan |
| Terraform infrastructure (Bedrock, Vertex AI, Azure OpenAI...) | `agent-bom scan --tf-dir infra/` | AI resource inventory, provider CVEs, hardcoded secrets |
| GitHub Actions workflows | `agent-bom scan --gha .` | AI credentials in `env:`, SDK usage in `run:` steps |
| An existing Syft / Grype / Trivy SBOM | `agent-bom scan --sbom sbom.cdx.json` | Blast radius on top of existing SBOM |
| A JSON inventory of custom/cloud agents | `agent-bom scan --inventory agents.json` | CVE scan + blast radius for any agent you describe |
| Everything at once | `agent-bom scan --k8s --tf-dir infra/ --gha . --agent-project .` | Full AI supply chain snapshot |

**Common next steps after scanning:**

```bash
agent-bom scan --enrich                          # add NVD CVSS + EPSS + CISA KEV data
agent-bom scan -f html -o report.html            # open dashboard in browser
agent-bom scan -f sarif -o results.sarif         # upload to GitHub Security tab
agent-bom scan --fail-on-severity high -q        # CI gate — exit 1 on high+ CVEs
agent-bom serve                                  # interactive Streamlit dashboard
```

---

## OWASP LLM Top 10 Tagging

Every finding in the blast radius analysis is automatically tagged with applicable
[OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) codes:

| Code | Name | Triggered by |
|------|------|-------------|
| **LLM05** | Supply Chain Vulnerabilities | Any package CVE — always tagged |
| **LLM06** | Sensitive Information Disclosure | Credential env vars exposed alongside vulnerable package |
| **LLM08** | Excessive Agency | Server with >5 tools + CRITICAL/HIGH severity CVE |
| **LLM02** | Insecure Output Handling | Tool with shell/exec semantics + any CVE |
| **LLM07** | System Prompt Leakage | Tool that reads files/prompts + any CVE |
| **LLM04** | Data and Model Poisoning | AI framework package (torch, transformers, langchain…) + HIGH+ CVE |

Tags appear in the blast radius table (`--format console`), in JSON output (`owasp_tags` field), and in SARIF result properties for GitHub Advanced Security.

---

## MCP Server Registry

agent-bom ships with a registry of **55+ known MCP servers** with provenance, risk levels, and package metadata.

| Category | Servers included |
|----------|-----------------|
| Official (modelcontextprotocol) | filesystem, github, gitlab, slack, postgres, sqlite, fetch, memory, puppeteer, google-maps, gdrive, git, sentry, sequential-thinking + more |
| Cloud providers | AWS (core, Bedrock), Cloudflare, Vercel |
| Databases | MongoDB, Supabase, Redis, Elasticsearch, Qdrant, Neo4j |
| Developer tools | Stripe, Linear, Jira, Confluence, GitHub Copilot, JetBrains |
| AI / ML | HuggingFace Hub, LangSmith, Weights & Biases, OpenAI |
| Productivity | Notion, Zapier, Twilio, SendGrid |
| Search & data | Exa, Tavily, Firecrawl, DuckDuckGo, Apify |
| Observability | Grafana, Datadog |

The registry powers risk-level warnings when an unverified MCP server is detected in your agent configs.

View the full registry: [`data/mcp-registry.yaml`](https://github.com/agent-bom/agent-bom/blob/main/data/mcp-registry.yaml)

---

## Observability & Monitoring

```bash
# Prometheus Pushgateway
agent-bom scan --push-gateway http://localhost:9091

# node_exporter textfile collector
agent-bom scan -f prometheus -o /var/lib/node_exporter/textfile/agent-bom.prom

# OpenTelemetry OTLP (Grafana, Jaeger, Honeycomb...)
pip install agent-bom[otel]
agent-bom scan --otel-endpoint http://localhost:4318
```

**One-command monitoring stack** (Prometheus + Pushgateway + Grafana):

```bash
docker compose -f docker-compose-monitoring.yml up -d
agent-bom scan --push-gateway http://localhost:9091
open http://localhost:3000   # import grafana-dashboard.json
```

**Metrics exported:**
- `agent_bom_vulnerabilities_total` — by severity
- `agent_bom_agents_total` — total agents scanned
- `agent_bom_blast_radius_credentials` — exposed credential count
- `agent_bom_blast_radius_tools` — reachable tool count
- `agent_bom_kev_findings_total` — CISA KEV hit count

---

## Key Commands

```bash
# Discovery
agent-bom scan                                          # auto-discover local agents
agent-bom scan --inventory agents.json                  # manual inventory
agent-bom scan --image myapp:latest --image redis:7     # Docker images
agent-bom scan --k8s --all-namespaces                   # Kubernetes cluster
agent-bom scan --tf-dir infra/prod --tf-dir infra/staging
agent-bom scan --gha /path/to/repo
agent-bom scan --agent-project /path/to/python-project  # Python agent frameworks
agent-bom scan --sbom syft-output.cdx.json --inventory agents.json

# Enrichment & CI gates
agent-bom scan --enrich                                 # NVD + EPSS + CISA KEV
agent-bom scan --fail-on-severity high -q               # exit 1 on high+
agent-bom scan --fail-on-kev --enrich                   # exit 1 on KEV findings
agent-bom scan --fail-if-ai-risk                        # exit 1 on AI vuln + creds
agent-bom scan --policy policy.json                     # declarative policy rules

# Output formats
agent-bom scan -f html      -o report.html              # Grafana-style dashboard
agent-bom scan -f json      -o report.json              # machine-readable
agent-bom scan -f cyclonedx -o bom.cdx.json             # CycloneDX 1.6
agent-bom scan -f sarif     -o results.sarif            # GitHub Security tab
agent-bom scan -f spdx      -o bom.spdx.json            # SPDX 3.0 AI-BOM JSON-LD
agent-bom scan -f prometheus -o metrics.prom             # Prometheus / node_exporter

# Trust & transparency
agent-bom scan --dry-run                                # show what would be read, exit 0
agent-bom scan --dry-run --inventory agents.json --enrich  # full access preview

# Dashboard & utilities
agent-bom serve                                         # Streamlit dashboard (pip install agent-bom[ui])
agent-bom api                                           # REST API (pip install agent-bom[api])
agent-bom check express@4.18.2 -e npm                  # pre-install CVE check
agent-bom diff baseline.json                            # diff vs saved baseline
agent-bom inventory                                     # list agents, no CVE scan
agent-bom validate agents.json                          # validate inventory JSON
agent-bom where                                         # show config search paths
```

---

## Trust & Permissions

agent-bom is **read-only**. It never writes to configs, never executes MCP servers,
and never stores credential values. See [PERMISSIONS.md](https://github.com/agent-bom/agent-bom/blob/main/PERMISSIONS.md) for the full trust contract.

Use `--dry-run` to preview exactly which files and APIs would be accessed before any scan runs.

**Three layers of evidence:**
1. `--dry-run` — shows every file path and API call upfront
2. `PERMISSIONS.md` — auditable read-only contract
3. API trust headers — `X-Agent-Bom-Read-Only: true` on every HTTP response
4. Open-source code — all scanning logic is auditable in `src/agent_bom/`

Releases v0.7.0+ are signed via [Sigstore/cosign](https://www.sigstore.dev/). Download the `.bundle` file from the GitHub Release and verify:

```bash
cosign verify-blob agent_bom-0.7.0-py3-none-any.whl \
  --bundle agent_bom-0.7.0-py3-none-any.whl.bundle \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "https://github.com/agent-bom/agent-bom"
```

---

## CI Integration

```yaml
# Option A — standalone AI-BOM scan
- name: Generate AI-BOM
  run: |
    pip install agent-bom
    agent-bom scan --inventory agents.json --enrich --fail-on-severity high \
      -f sarif -o results.sarif

- name: Upload to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif

# Option B — pipe Syft/Grype SBOM into agent-bom
- name: Generate SBOM with Syft
  uses: anchore/sbom-action@v0
  with:
    image: myapp:latest
    format: cyclonedx-json
    output-file: sbom.cdx.json

- name: Blast radius analysis
  run: |
    pip install agent-bom
    agent-bom scan --sbom sbom.cdx.json --inventory agents.json \
      --enrich --fail-on-kev -f sarif -o results.sarif
```

---

## Inventory Format

For agents not auto-discovered, provide a JSON inventory:

```json
{
  "agents": [{
    "name": "my-production-agent",
    "agent_type": "custom",
    "mcp_servers": [{
      "name": "database-server",
      "command": "npx",
      "args": ["-y", "@my-org/mcp-database-server"],
      "env": { "DB_PASSWORD": "...", "API_KEY": "..." },
      "tools": [{"name": "query_database"}, "list_tables"],
      "packages": [
        {"name": "express", "version": "4.18.2", "ecosystem": "npm"},
        "axios@1.6.0"
      ]
    }]
  }]
}
```

```bash
agent-bom validate agents.json   # validate before scanning
agent-bom scan --inventory agents.json --enrich -f html -o report.html
```

See [example-inventory.json](https://github.com/agent-bom/agent-bom/blob/main/example-inventory.json) and [examples/inventory.schema.json](https://github.com/agent-bom/agent-bom/blob/main/examples/inventory.schema.json) for full schema.

---

## REST API

```bash
pip install agent-bom[api]
agent-bom api          # http://127.0.0.1:8422  |  docs at /docs
```

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Liveness probe — returns `X-Agent-Bom-Read-Only: true` |
| `GET /version` | Version info |
| `POST /v1/scan` | Start an async scan (returns `job_id`) |
| `GET /v1/scan/{job_id}` | Poll scan status + results |
| `GET /v1/scan/{job_id}/stream` | SSE — real-time scan progress |
| `GET /v1/agents` | Agent discovery without CVE scan |
| `GET /v1/registry` | Full MCP server registry (55+ entries) |
| `GET /v1/registry/{id}` | Single registry entry |
| `GET /v1/jobs` | List all scan jobs |

---

## Roadmap

- [ ] AWS Bedrock — live agent + action group discovery via boto3
- [ ] Snowflake Cortex — query history scanning for `CREATE MCP SERVER` / `CREATE OR REPLACE AGENT`
- [ ] Google Vertex AI — agent + extension discovery
- [ ] Jupyter notebook scanning — detect AI library usage in `.ipynb` files
- [ ] Live MCP server introspection — enumerate tools/resources dynamically
- [ ] MITRE ATLAS mapping for AI/ML threats
- [ ] MCP registry growth — continuous expansion toward 100+ entries

---

## Contributing

```bash
git clone https://github.com/agent-bom/agent-bom.git && cd agent-bom
pip install -e ".[dev]"
pytest && ruff check src/
```

See [CONTRIBUTING.md](https://github.com/agent-bom/agent-bom/blob/main/CONTRIBUTING.md) for guidelines. To report a vulnerability, see [SECURITY.md](https://github.com/agent-bom/agent-bom/blob/main/SECURITY.md).

---

Apache 2.0 — see [LICENSE](https://github.com/agent-bom/agent-bom/blob/main/LICENSE).

*Not affiliated with Anthropic, Cursor, or any MCP client vendor.*
