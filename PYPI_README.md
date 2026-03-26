# agent-bom

**AI security scanner for agents, MCP, containers, cloud, and runtime.**

agent-bom discovers AI agents and MCP servers, maps CVEs into real blast radius from package to server to agent to credentials and tools, scans packages, container images, filesystems, IaC, secrets, and cloud AI infrastructure, and protects MCP traffic at runtime.

![agent-bom demo](https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/demo-latest.gif)

## Quick start

```bash
pip install agent-bom

# AI agent and MCP scan
agent-bom agents

# Workstation posture summary
agent-bom agents --posture

# Pre-install CVE and supply chain gate
agent-bom check flask@2.0.0
```

## What it scans

- **30 MCP client types** across real local developer environments
- **Packages and supply chain** with OSV, NVD, GHSA, EPSS, and CISA KEV
- **Container images and filesystems** with native image and inventory scanning
- **IaC and Kubernetes** including Dockerfile, Terraform, CloudFormation, Helm, and Kubernetes manifests
- **Cloud AI and AI infrastructure** across AWS, Azure, GCP, Databricks, Snowflake, Hugging Face, Ollama, W&B, OpenAI, and vector databases
- **Runtime MCP traffic** with an enforcement proxy, 112 detection patterns, PII redaction, and evidence collection

## How it works

![How agent-bom works](https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/scan-pipeline-light.svg)

## Blast radius

![agent-bom blast radius](https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-light.svg)

## More common commands

```bash
# Container image scan
agent-bom image nginx:latest

# IaC and Kubernetes scan
agent-bom iac Dockerfile k8s/ infra/main.tf

# Cloud AI and infrastructure inventory
agent-bom cloud aws

# AI BOM / SBOM export
agent-bom agents -p . -f cyclonedx -o ai-bom.json

# Runtime proxy
agent-bom proxy "npx @mcp/server-filesystem /tmp"
```

For the full GitHub README, Mermaid diagrams, release history, and live project status, see:

- GitHub: https://github.com/msaad00/agent-bom
- Documentation: https://github.com/msaad00/agent-bom#readme
- Docker Hub: https://hub.docker.com/r/agentbom/agent-bom
