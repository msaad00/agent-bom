# CLI Debug Guide

## First triage

```bash
agent-bom doctor
agent-bom where
agent-bom agents --dry-run
agent-bom agents -p . --no-scan
```

- `doctor` checks local prerequisites.
- `where` shows the MCP config paths scanned on the current machine.
- `agents --dry-run` shows what would be accessed without performing the scan.
- `agents -p . --no-scan` verifies discovery and package extraction before any CVE lookups.

## Logging and quiet mode

```bash
agent-bom agents --verbose
agent-bom agents --log-level debug --log-file /tmp/agent-bom.log
agent-bom agents --quiet --no-scan
```

- `--quiet` suppresses scan chatter and retry noise. Use it for scripting.
- `--verbose` expands the console view.
- `--log-level debug` and `--log-file` are the fastest way to capture a reproducible failure.

## Output contracts

- `check` supports `--format json` for machine-readable pre-install verdicts.
- `report history` and `report diff` support `--format json` for CI consumption.
- Use `agents` for JSON, SARIF, HTML, PDF, CycloneDX, SPDX, and other report formats.
- Use `agent-bom check requests@2.33.0 -e pypi -f json` for a single-package JSON verdict.
- Use `agent-bom report diff before.json after.json -f json -o diff.json` for machine-readable diff output.
- Use `agent-bom agents -f sarif -o results.sarif` for file output.
- Use `agent-bom agents -f sarif -o -` when you need SARIF JSON on stdout.

## Verification flows

```bash
agent-bom verify
agent-bom verify agent-bom
agent-bom verify requests@2.33.0 -e pypi
agent-bom verify @modelcontextprotocol/server-filesystem@2025.1.14 -e npm
```

- `verify` with no arguments self-verifies the installed `agent-bom`.
- `verify agent-bom` is the same shortcut.
- Other packages require an explicit `name@version`.

## Discovery and command routing

- `agent-bom where` is the top-level shortcut for discovery paths.
- `agent-bom mcp where` remains available when you want the grouped MCP command.
- `agent-bom check` is for one package.
- `agent-bom agents` is for environment, project, SBOM, and export workflows.

## Contributor setup

```bash
pip install -e ".[dev-all]"
pytest tests/ -x -q
```

- `.[dev-all]` is the supported full-suite contributor environment.
- The `graph` extra includes the numeric dependencies required for PageRank and centrality tests.
