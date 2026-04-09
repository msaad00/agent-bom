# CLI Debug Guide

## Fast triage

```bash
agent-bom doctor
agent-bom where
agent-bom agents --dry-run
agent-bom agents -p . --no-scan
```

Use these commands to separate discovery problems from vulnerability-scanning problems before turning on enrichment or exports.

## Quiet, logs, and output

```bash
agent-bom agents --quiet --no-scan
agent-bom agents --log-level debug --log-file /tmp/agent-bom.log
agent-bom agents -f sarif -o results.sarif
agent-bom agents -f sarif -o -
```

- `--quiet` suppresses scan chatter and retry noise for scripting.
- `--log-level debug` with `--log-file` is the quickest way to capture a reproducible issue.
- `-o -` is the stdout form for machine-readable exports.

## Command contracts

- `check` supports `--format json` for machine-readable single-package verdicts.
- `report history` and `report diff` support `--format json` for automation.
- `verify` with no arguments, or `verify agent-bom`, self-verifies the installed package.
- `where` is available both as `agent-bom where` and `agent-bom mcp where`.
- Use `agents` for environment scans, exports, and report generation.

## Package verification

```bash
agent-bom verify
agent-bom verify requests@2.33.0 -e pypi
agent-bom verify @modelcontextprotocol/server-filesystem@2025.1.14 -e npm
```

Explicit `name@version` is required for packages other than the installed `agent-bom`.
