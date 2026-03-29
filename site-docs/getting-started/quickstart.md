# Quick Start

## Install

```bash
pip install agent-bom
```

## Scan your local AI environment

```bash
agent-bom agents
```

This auto-discovers local MCP clients and AI agent configs, extracts configured
servers and packages, and scans for CVEs.

## Scan a project plus local agent context

```bash
agent-bom agents -p .
```

Use this when you want one scan to cover both:
- project manifests and lockfiles in the current repo
- local MCP / agent context on your machine

## Scan instruction and skill files

```bash
agent-bom skills scan .
agent-bom skills verify .
```

This covers `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, and supported `skills/*`
instruction surfaces.

## Check a specific package before installing

```bash
agent-bom check langchain --ecosystem pypi
agent-bom check express --ecosystem npm
agent-bom check tensorflow --ecosystem pypi
```

## Export machine-readable output

```bash
agent-bom agents -f json -o report.json
agent-bom agents -f sarif -o findings.sarif
agent-bom agents -f cyclonedx -o bom.json
```

## Run compliance mapping

```bash
agent-bom agents --compliance owasp-llm
agent-bom agents --compliance eu-ai-act
agent-bom agents --compliance all
```

## Scan a container image

```bash
agent-bom image python:3.12-slim
```

## Scan infrastructure as code

```bash
agent-bom iac Dockerfile k8s/ infra/main.tf
```

`iac` accepts one or more paths in a single run, so the example above scans:
- a Dockerfile
- a Kubernetes directory
- a Terraform file

## Inspect discovery paths

```bash
agent-bom mcp where
agent-bom mcp inventory
```

## Output formats

```bash
agent-bom agents -f table    # terminal table (default)
agent-bom agents -f json     # JSON report
agent-bom agents -f html     # HTML dashboard
agent-bom agents -f sarif    # SARIF for GitHub Code Scanning
agent-bom agents -f csv      # CSV export
```
