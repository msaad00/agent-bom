<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/logo-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/logo-light.svg" alt="agent-bom" width="480" />
  </picture>
</p>

<p align="center">
  <a href="https://github.com/msaad00/agent-bom/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/msaad00/agent-bom/ci.yml?style=flat&logo=github&label=Build" alt="Build"></a>
  <a href="https://pypi.org/project/agent-bom/"><img src="https://img.shields.io/pypi/v/agent-bom?style=flat&label=Latest%20version" alt="PyPI"></a>
  <a href="https://hub.docker.com/r/agentbom/agent-bom"><img src="https://img.shields.io/docker/pulls/agentbom/agent-bom?style=flat&label=Docker%20pulls" alt="Docker"></a>
  <a href="https://github.com/msaad00/agent-bom/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue?style=flat" alt="License"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom"><img src="https://api.securityscorecards.dev/projects/github.com/msaad00/agent-bom/badge" alt="OpenSSF"></a>
  <a href="https://github.com/msaad00/agent-bom/stargazers"><img src="https://img.shields.io/github/stars/msaad00/agent-bom?style=flat&logo=github&label=Stars" alt="Stars"></a>
</p>
<!-- mcp-name: io.github.msaad00/agent-bom -->

<p align="center">
  <b>Security scanner for AI infrastructure. Find CVEs, map blast radius, detect credential exposure across MCP agents, containers, Kubernetes, cloud, and GPU workloads.</b>
</p>

<p align="center">
  <picture>
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/demo.svg" alt="agent-bom demo" width="800" />
  </picture>
</p>

---

## Why agent-bom?

> **Traditional scanners tell you a package has a CVE.**
> **agent-bom tells you which AI agents are compromised, which credentials leak, which tools an attacker reaches, and what the business impact is.**

```
CVE-2025-1234  (CRITICAL . CVSS 9.8 . CISA KEV)
  |-- better-sqlite3@9.0.0  (npm)
       |-- sqlite-mcp  (MCP Server . unverified . root)
            |-- Cursor IDE  (Agent . 4 servers . 12 tools)
            |-- ANTHROPIC_KEY, DB_URL, AWS_SECRET  (Credentials exposed)
            |-- query_db, read_file, write_file, run_shell  (Tools at risk)

 Fix: upgrade better-sqlite3 -> 11.7.0
```

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-light.svg" alt="Blast Radius" width="800" />
  </picture>
</p>

---

## Get started

```bash
pip install agent-bom

agent-bom scan                                     # auto-discover + scan
agent-bom scan --enrich                            # + NVD CVSS + EPSS + CISA KEV
agent-bom scan -f html -o report.html              # HTML dashboard
agent-bom scan --enforce                           # tool poisoning detection
agent-bom scan --fail-on-severity high -q          # CI gate
agent-bom scan --image myapp:latest                # Docker image scanning
agent-bom scan --k8s --all-namespaces              # K8s cluster
agent-bom scan --aws --snowflake --databricks      # Multi-cloud
agent-bom scan --hf-model meta-llama/Llama-3.1-8B  # model provenance
```

Auto-discovers 20 MCP clients: Claude Desktop, Claude Code, Cursor, Windsurf, Cline, VS Code Copilot, Continue, Zed, Cortex Code, Codex CLI, Gemini CLI, Goose, Snowflake CLI, OpenClaw, Roo Code, Amazon Q, ToolHive, Docker MCP Toolkit, JetBrains AI, and Junie.

<details>
<summary><b>Install extras</b></summary>

| Mode | Command |
|------|---------|
| Core CLI | `pip install agent-bom` |
| Cloud (all) | `pip install 'agent-bom[cloud]'` |
| REST API | `pip install 'agent-bom[api]'` |
| MCP server | `pip install 'agent-bom[mcp-server]'` |
| Dashboard | `pip install 'agent-bom[ui]'` |
| Docker | `docker run --rm -v ~/.config:/root/.config:ro agentbom/agent-bom scan` |

</details>

<details>
<summary><b>Upgrade / Uninstall</b></summary>

```bash
pip install --upgrade agent-bom          # upgrade
pip uninstall agent-bom                  # uninstall
rm -rf ~/.agent-bom                      # remove local data
```

</details>

---

## How it works

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/high-level-workflow-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/high-level-workflow-light.svg" alt="How it works" width="800" />
  </picture>
</p>

1. **Discover** -- auto-detect MCP configs, Docker images, K8s pods, cloud resources, model files
2. **Scan** -- send package names + versions to public APIs (OSV.dev, NVD, EPSS, CISA KEV). No secrets leave your machine.
3. **Analyze** -- blast radius mapping, tool poisoning detection, compliance tagging, posture scoring
4. **Report** -- JSON, SARIF, CycloneDX, SPDX, HTML, Mermaid, or console. Alert dispatch to Slack/webhooks.

**Read-only guarantee.** Never writes configs, never runs servers, never stores secrets. `--dry-run` previews everything. Every release is [Sigstore-signed](PERMISSIONS.md).

---

## What it covers

| | Traditional scanners | agent-bom |
|---|---|---|
| Package CVE detection | Yes | Yes (OSV + NVD + EPSS + CISA KEV + GHSA + NVIDIA CSAF) |
| SBOM generation | Yes | Yes (CycloneDX 1.6, SPDX 3.0, SARIF) |
| **AI agent discovery** | -- | 20 MCP clients + Docker Compose |
| **Blast radius mapping** | -- | CVE -> package -> server -> agent -> credentials -> tools |
| **Credential exposure** | -- | Which secrets leak per vulnerability, per agent |
| **Tool poisoning detection** | -- | Description injection, capability combos, drift detection |
| **Privilege detection** | -- | root, shell access, privileged containers, per-tool permissions |
| **6-framework compliance** | -- | OWASP LLM + MCP + Agentic, MITRE ATLAS, NIST AI RMF, EU AI Act |
| **Posture scorecard** | -- | Letter grade (A-F), 6 dimensions, incident correlation (P1-P4) |
| **Policy-as-code** | -- | 16 conditions, CI gate, block unverified servers |
| **Lateral movement analysis** | -- | Agent context graph, shared credentials, BFS attack paths |
| **427+ server MCP registry** | -- | Risk levels, tool inventories, auto-synced weekly |

<details>
<summary><b>What it scans</b></summary>

| Source | How |
|--------|-----|
| MCP configs | Auto-discover (20 clients + Docker Compose) |
| Docker images | Grype / Syft / Docker CLI fallback |
| Kubernetes | kubectl across namespaces |
| Cloud providers | AWS, Azure, GCP, Databricks, Snowflake, Nebius |
| Terraform / GitHub Actions | AI resources + env vars |
| AI platforms | HuggingFace, W&B, MLflow, OpenAI |
| Jupyter notebooks | AI library imports + model refs |
| Model files | 13 formats (.gguf, .safetensors, .pkl, ...) |
| Skill files | CLAUDE.md, .cursorrules, AGENTS.md |
| Existing SBOMs | CycloneDX / SPDX import |

</details>

<details>
<summary><b>What it outputs</b></summary>

Console, HTML dashboard, SARIF, CycloneDX 1.6, SPDX 3.0, Prometheus, OTLP, JSON, Mermaid, Cytoscape graph JSON, REST API.

```bash
agent-bom scan -f cyclonedx -o ai-bom.cdx.json   # CycloneDX 1.6
agent-bom scan -f spdx -o ai-bom.spdx.json       # SPDX 3.0
agent-bom scan -f sarif -o results.sarif           # GitHub Security tab
agent-bom scan -f html -o report.html              # Interactive dashboard
agent-bom scan -f graph -o graph.json              # Cytoscape-compatible
```

</details>

---

## Deployment

| Mode | Command | Best for |
|------|---------|----------|
| CLI | `agent-bom scan` | Local audit |
| GitHub Action | `uses: msaad00/agent-bom@v0.59.1` | CI/CD + SARIF |
| Docker | `docker run agentbom/agent-bom scan` | Isolated scans |
| REST API | `agent-bom api` | Dashboards, SIEM |
| MCP Server | `agent-bom mcp-server` (19 tools) | Inside any MCP client |
| Dashboard | `agent-bom serve` | API + Next.js UI (18 pages) |
| Runtime proxy | `agent-bom proxy` | MCP traffic audit |
| Snowflake | [DEPLOYMENT.md](DEPLOYMENT.md) | Snowpark + SiS |

<details>
<summary><b>GitHub Action</b></summary>

```yaml
- uses: msaad00/agent-bom@v0.59.1
  with:
    severity-threshold: high
    upload-sarif: true
    enrich: true
    fail-on-kev: true
```

</details>

<details>
<summary><b>REST API (14 endpoints)</b></summary>

```bash
pip install agent-bom[api]
agent-bom api --api-key $SECRET --rate-limit 30   # http://127.0.0.1:8422/docs
```

| Endpoint | Description |
|----------|-------------|
| `POST /v1/scan` | Start async scan |
| `GET /v1/scan/{id}` | Results + status |
| `GET /v1/scan/{id}/attack-flow` | Per-CVE blast radius graph |
| `GET /v1/registry` | 427+ server registry |
| `GET /v1/compliance` | Full 6-framework compliance posture |
| `GET /v1/posture` | Enterprise posture scorecard (A-F) |
| `GET /v1/posture/credentials` | Credential risk ranking |
| `GET /v1/posture/incidents` | Incident correlation (P1-P4) |
| `POST /v1/traces` | OpenTelemetry trace ingestion |
| `GET /v1/scan/{id}/context-graph` | Lateral movement paths |
| `GET /v1/malicious/check` | Malicious package check |

</details>

<details>
<summary><b>Cloud providers</b></summary>

| Provider | Depth | Install |
|----------|-------|---------|
| **Snowflake** | Deep (Cortex, MCP, governance, observability) | `pip install 'agent-bom[snowflake]'` |
| **AWS** | Standard (Bedrock, Lambda, EKS, ECS, SageMaker) | `pip install 'agent-bom[aws]'` |
| **Azure** | Standard (OpenAI, Functions, AI Foundry, Container Apps) | `pip install 'agent-bom[azure]'` |
| **GCP** | Standard (Vertex AI, Cloud Functions, GKE, Cloud Run) | `pip install 'agent-bom[gcp]'` |
| **Databricks** | Preview (Cluster packages, model serving) | `pip install 'agent-bom[databricks]'` |
| **Nebius** | Preview (Managed K8s, containers) | `pip install 'agent-bom[nebius]'` |
| **CoreWeave** | Via K8s | `--k8s --context=coreweave-cluster` |

</details>

---

## Ecosystem

| Platform | Link |
|----------|------|
| PyPI | `pip install agent-bom` |
| Docker | `docker run agentbom/agent-bom scan` |
| GitHub Action | `uses: msaad00/agent-bom@v0.59.1` |
| Glama | [glama.ai/mcp/servers/@msaad00/agent-bom](https://glama.ai/mcp/servers/@msaad00/agent-bom) |
| MCP Registry | [server.json](integrations/mcp-registry/server.json) |
| ToolHive | [registry entry](integrations/toolhive/server.json) |
| OpenClaw | [SKILL.md](integrations/openclaw/SKILL.md) |
| Smithery | [smithery.yaml](smithery.yaml) |
| Railway | [Dockerfile.sse](Dockerfile.sse) |

---

## Architecture

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/engine-internals-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/engine-internals-light.svg" alt="Engine internals" width="800" />
  </picture>
</p>

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for full diagrams: data flow pipeline, blast radius propagation, compliance framework mapping, integration architecture, and deployment topology.

---

## Trust & permissions

- **Read-only** -- never writes configs, runs servers, provisions resources, or stores secrets
- **Credential redaction** -- only env var **names** in reports; values never read
- **`--dry-run`** -- preview every file and API URL before access
- **Sigstore signed** -- releases v0.7.0+ signed via cosign OIDC
- **OpenSSF Scorecard** -- [automated supply chain scoring](https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom)
- **[PERMISSIONS.md](PERMISSIONS.md)** -- full auditable trust contract

---

## Roadmap

- [ ] CIS AI benchmarks
- [ ] License compliance engine
- [ ] Workflow engine scanning (n8n, Zapier, Make)

See the full list of [shipped features](https://github.com/msaad00/agent-bom/releases).

---

## Contributing

```bash
git clone https://github.com/msaad00/agent-bom.git && cd agent-bom
pip install -e ".[dev]"
pytest && ruff check src/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) | [SECURITY.md](SECURITY.md) | [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

---

Apache 2.0 -- [LICENSE](LICENSE)
