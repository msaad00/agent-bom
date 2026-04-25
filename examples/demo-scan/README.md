# Demo Scan

Run a vulnerability scan against a bundled inventory of agents with known-vulnerable packages — no setup required.

```bash
agent-bom scan --demo
```

## One-shot dashboard import

Start the API/dashboard, then push the bundled synthetic demo into the
dashboard with one command:

```bash
agent-bom serve
```

In another terminal:

```bash
scripts/demo/load-dashboard-demo.sh http://127.0.0.1:8422
```

If your API requires a key, set `AGENT_BOM_API_KEY` or
`AGENT_BOM_PUSH_API_KEY` before running the loader. The script writes the
temporary report under the OS temp directory, pushes it to
`/v1/results/push`, then deletes the temporary file. The bundled data is
synthetic and uses placeholder credential names only.

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
