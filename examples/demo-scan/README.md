# Demo Scan

Run a vulnerability scan against a bundled inventory of agents with known-vulnerable packages — no setup required.

```bash
agent-bom scan --demo
```

## What it does

The `--demo` flag loads a pre-built inventory containing two agents and three MCP servers with intentionally vulnerable dependencies (e.g. `flask==2.2.0`, `werkzeug==2.2.2`, `requests==2.28.0`). The scan runs with `--enrich` enabled so you see real CVE details, EPSS scores, and blast-radius analysis.

## Output formats

```bash
# Console (default)
agent-bom scan --demo

# JSON
agent-bom scan --demo -f json -o demo-results.json

# CycloneDX SBOM
agent-bom scan --demo -f cyclonedx -o demo-sbom.cdx.json

# SARIF (for GitHub Security tab)
agent-bom scan --demo -f sarif -o demo.sarif
```
