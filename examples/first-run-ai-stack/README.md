# First-Run AI Stack

This is a small, inspectable sample project for first-time `agent-bom`
users. It is also available after install with
`agent-bom samples first-run`. It is intentionally safer than asking users to
scan their own repo first, but it still looks like a real AI workspace:

- one Cursor-style agent and one Claude Code-style agent
- two MCP servers, including a shared server
- credential environment variable names with placeholder values only
- advisory-backed package versions declared in the inventory
- a prompt file so instruction scanning has something concrete to inspect

The sample is for product orientation, screenshots, demos, and local smoke
tests. It does not contain real credentials or installable vulnerable
dependency manifests. The generated `agent-bom samples first-run` project writes
the full Python and npm manifests for local demo scans.

## CLI Walkthrough

From the repository root:

```bash
agent-bom agents \
  --inventory examples/first-run-ai-stack/inventory.json \
  --project examples/first-run-ai-stack \
  --enrich
```

For a network-free run after your local vulnerability DB is available:

```bash
agent-bom agents \
  --inventory examples/first-run-ai-stack/inventory.json \
  --project examples/first-run-ai-stack \
  --offline \
  --no-update-db
```

Export JSON for dashboard import or downstream review:

```bash
agent-bom agents \
  --inventory examples/first-run-ai-stack/inventory.json \
  --project examples/first-run-ai-stack \
  -f json \
  -o /tmp/agent-bom-first-run.json
```

## What To Look For

- **Inventory:** `Cursor First-Run Workspace`, `Claude Review Bot`, and the
  two MCP servers from `inventory.json`.
- **Graph:** the `research-filesystem` MCP server is shared by both agents,
  so package risk and credential exposure should fan out across both.
- **Findings:** the sample uses real vulnerable versions (`flask==2.2.0`,
  `werkzeug==2.2.2`, `requests==2.28.0`, `axios@0.21.1`, and
  `lodash@4.17.20`) so the first scan has advisory-backed evidence.
- **Credentials:** only environment variable names are modeled. Placeholder
  values such as `${OPENAI_API_KEY}` are not secrets.
- **Evidence:** the checked-in fixture keeps package evidence in
  `inventory.json` so repository security gates do not treat demo dependencies
  as installable project dependencies. The generated first-run sample includes
  concrete manifests for local scanning.

## Dashboard Flow

Start the local API and dashboard:

```bash
agent-bom serve
```

Then push the exported JSON through the API, or use the built-in dashboard
demo loader for the fully curated demo:

```bash
scripts/demo/load-dashboard-demo.sh http://127.0.0.1:8422
```

Use this sample when you want to explain how a real repo scan is wired. Use
`agent-bom agents --demo --offline` when you need the release-pinned,
fully reproducible demo output.
