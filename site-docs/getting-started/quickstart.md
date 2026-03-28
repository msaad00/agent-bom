# Quick Start

## Scan your environment

```bash
agent-bom scan
```

This auto-discovers MCP clients on your machine (Claude Desktop, Cursor, VS Code, Windsurf, etc.), extracts configured servers and packages, and scans for CVEs.

## Check a specific package

```bash
agent-bom check langchain
agent-bom check express --ecosystem npm
agent-bom check tensorflow --ecosystem pypi
```

## See what was discovered

```bash
agent-bom where    # show all discovery paths
agent-bom scan -f json -o report.json   # full JSON report
```

## Generate an SBOM

```bash
agent-bom scan --sbom cyclonedx -o sbom.json
agent-bom scan --sbom spdx -o sbom.spdx.json
```

## Run compliance checks

```bash
agent-bom scan --compliance owasp-llm
agent-bom scan --compliance eu-ai-act
agent-bom scan --compliance all
```

## Scan a container image

```bash
agent-bom scan --image python:3.12-slim
```

Uses agent-bom's native container scanning path for image analysis.

## Output formats

```bash
agent-bom scan -f table    # terminal table (default)
agent-bom scan -f json     # JSON report
agent-bom scan -f html     # HTML dashboard
agent-bom scan -f sarif    # SARIF for GitHub Code Scanning
agent-bom scan -f csv      # CSV export
```
