# First Run Guide

This guide gives new users a deterministic path from install to a real
inventory and graph without asking them to scan a private repository first.

## 1. Run the Release-Pinned Demo

```bash
agent-bom agents --demo --offline
```

Use this when you need reproducible output. The package versions are curated
and guarded by tests so screenshots and docs do not depend on fabricated CVEs.

## 2. Inspect the Bundled Sample Project

From any directory after installing `agent-bom`:

```bash
agent-bom samples first-run
cd agent-bom-first-run
agent-bom agents --inventory inventory.json -p . --enrich
```

From a repository checkout, you can also scan the checked-in fixture directly:

```bash
agent-bom agents \
  --inventory examples/first-run-ai-stack/inventory.json \
  --project examples/first-run-ai-stack \
  --enrich
```

This path shows how real inputs fit together without committing vulnerable
fixture dependencies:

- `inventory.json` models agents, MCP servers, credential env var names, and
  tools.
- `services/research-mcp/requirements.txt` contributes Python package
  evidence.
- `services/browser-helper/package-lock.json` contributes npm lockfile
  evidence with safe package versions.
- `prompts/agent-system-prompt.md` is available for instruction and prompt
  scanning workflows.

## 3. Open the Dashboard

```bash
pip install 'agent-bom[ui]'
agent-bom serve
```

For the curated dashboard demo:

```bash
scripts/demo/load-dashboard-demo.sh http://127.0.0.1:8422
```

For the sample project, export JSON and push it through your normal API import
flow:

```bash
agent-bom agents \
  --inventory agent-bom-first-run/inventory.json \
  --project agent-bom-first-run \
  -f json \
  -o /tmp/agent-bom-first-run.json
```

## 4. Move To Your Own Repo

After the sample makes sense, scan your own project:

```bash
agent-bom agents -p .
```

Add `--inventory <file>` when you already have agent/server inventory from a
fleet collector, SIEM export, or manually curated source of truth.
