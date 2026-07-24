# How agent-bom works, and why it's different

This is the single canonical overview of the product flow. Other docs link here
instead of re-deriving the stages with their own counts. If you are choosing
what to run, start with [`START_HERE.md`](START_HERE.md); if you are choosing
what to deploy, use the
[deployment decision matrix](../site-docs/deployment/overview.md).

## Why it's different: symbol-level CVE reachability

Most scanners stop at "this package has a CVE." `agent-bom` joins the
CVE-affected symbols from OSV/GHSA advisories to your call graph, so you see the
subset that is actually reachable from your code — typically a fraction of the
raw match count — and then fuses that verdict into the agent graph. A reachable
CVE in a package an MCP server exposes to an agent that holds a credential is a
different risk than the same CVE sitting in dead code, and the product treats it
that way.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/blast-radius-dark.svg">
  <img alt="agent-bom blast radius: one vulnerable package fanning out through finding, MCP server, agent, credentials, and reachable tools" src="images/blast-radius-light.svg">
</picture>

That drilldown — package to finding to MCP server to agent to credentials and
reachable tools — is the product's center of gravity. Everything else exists to
produce and act on it. Function-level de-noising joins OSV/GHSA affected symbols
to Python, npm, Go, Java, Rust, and Ruby call graphs when `--project` AST
analysis is available; the CVE/CWE/CPE identifiers ride along on the
reachability verdict. See [`VULNERABILITY_MATCHING.md`](VULNERABILITY_MATCHING.md)
for the mechanics.

## The three product lanes

Read it as three ways to use the same evidence model: **scan** locally or in CI,
**centralize** evidence in a self-hosted control plane, and **enforce** runtime
tool calls through the optional gateway. Every lane uses `Finding` +
`UnifiedGraph`; sidebar **Findings** is a triage queue inside the control plane,
not a separate product lane.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/how-it-works-dark.svg">
  <img alt="agent-bom three product lanes: local and CI scanning, a self-hosted control plane, and optional runtime gateway enforcement on one Finding and UnifiedGraph model" src="images/how-it-works-light.svg">
</picture>

| Lane | What happens | Key output |
|---|---|---|
| **1. Scan** | Read-only intake from repos, CI, images, IaC, MCP configs, and cloud accounts. Enrichment joins OSV / GHSA / NVD / KEV / EPSS and scores symbol-level CVE reachability. | SARIF, SBOM, HTML, JSON, and graph exports |
| **2. Centralize** | `agent-bom serve` runs the self-hosted dashboard, Findings queue, REST API, fleet inventory, audit evidence, and Postgres-backed shared state. | reviewed posture, evidence history, and exports |
| **3. Enforce** | `agent-bom gateway serve` applies allow / warn / block policy to live MCP tool calls and records signed audit evidence. | runtime decisions and audit trail |

The scan lane computes symbol-level reachability; `UnifiedGraph` turns it into
blast radius across agents, MCP servers, packages, credentials, and tools. The
control plane and gateway consume that same evidence instead of rebuilding it.

## Where to go next

- Deeper module and surface architecture: [`ARCHITECTURE.md`](ARCHITECTURE.md)
- Service lanes and backend choices: [`PRODUCT_MAP.md`](PRODUCT_MAP.md)
- Positioning and shipped-vs-not: [`PRODUCT_BRIEF.md`](PRODUCT_BRIEF.md)
- Lanes and cost posture: [`EDITIONS.md`](EDITIONS.md)
- What to deploy first: [deployment overview](../site-docs/deployment/overview.md)
