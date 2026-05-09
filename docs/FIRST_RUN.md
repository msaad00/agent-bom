# First Run Guide

This guide gives new users a deterministic path from install to a real
inventory and graph without asking them to scan a private repository first.

## 1. Run the Release-Pinned Demo

```bash
agent-bom agents --demo --offline
```

Use this when you need reproducible output. The package versions are curated
and guarded by tests so screenshots and docs do not depend on fabricated CVEs.

### Annotated demo output

The demo is intentionally noisy enough to prove value without scanning a
private repo. A current release run starts like this:

```text
Demo mode - curated agent + MCP sample with known-vulnerable packages.
Offline mode - local vulnerability DB only

Discovery
  [ok] 2 agent(s) from curated sample environment

Package Extraction
  12 packages (7 pypi, 5 npm)

Vulnerability Scan
  [ok] Local DB: 57 vulnerabilities found (offline)
  [warn] Found 57 vulnerabilities across 57 findings
  [warn] Scan complete - 2 critical, 19 high, 28 medium, 8 low

agent-bom <installed version>
agents=2 servers=4 packages=12 vulnerabilities=57
```

What to look for:

| Output | Meaning | Why it matters |
|---|---|---|
| `Demo mode` | Uses the bundled curated sample instead of your workstation config. | The first run is reproducible and safe to share in a bug report or sales demo. |
| `Offline mode` | Uses the local vulnerability database only. | The command does not depend on live OSV/GHSA/network availability. |
| `2 agent(s)` | Loads sample agent surfaces such as Cursor and Claude Desktop. | Findings are tied to AI agents, not only package names. |
| `12 packages` | Extracts Python and npm package evidence behind MCP servers. | The scan proves supply-chain inventory before reporting risk. |
| `57 vulnerabilities` | Matches vulnerable demo package versions against real advisories. | The findings are advisory-backed; they are not invented demo rows. |
| severity summary | Groups findings by critical/high/medium/low. | Operators can immediately prioritize the highest-risk fixes. |
| `agents=... servers=...` | Prints a compact inventory summary. | The same evidence can move into JSON, SARIF, SBOM, HTML, graph, or dashboard workflows. |

After the summary, text output lists package rows:

```text
cursor  database-server  pypi  cryptography  39.0.0
cursor  database-server  pypi  pillow        9.0.0
```

Then it lists findings with fix guidance and reach context:

```text
VULN_ID          SEVERITY  PACKAGE              FIX     AGENTS  CREDENTIALS
CVE-2023-50447  critical  pillow@9.0.0         10.2.0  1       2
CVE-2023-0286   high      cryptography@39.0.0  39.0.1  1       2
```

Read the final columns as blast-radius context: `AGENTS` is how many agent
surfaces can reach the vulnerable package instance, and `CREDENTIALS` is how
many credential environment variable names are visible on the associated path.
Those names are environment variable identifiers, not secret values.

The most useful next command is usually a structured export:

```bash
agent-bom agents --demo --offline -f json -o /tmp/agent-bom-demo.json
```

Use that JSON to push the same evidence into a control plane, inspect the graph,
or attach deterministic output to an issue.

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
Add `--inventory-only` when that file is the complete evidence boundary and
you do not want project, cwd, skill, model, dataset, or secret auto-discovery
merged into the result.
