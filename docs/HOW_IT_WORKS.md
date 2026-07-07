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

## The five-stage flow

Read it in one direction: read-only **intake**, then **scan**, then normalize
into one **evidence** model, then serve and enforce over it from a self-hosted
**control** plane, then emit **artifacts** in the formats each consumer already
trusts.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/how-it-works-dark.svg">
  <img alt="agent-bom five-stage flow: intake, scan, evidence, control, artifacts" src="images/how-it-works-light.svg">
</picture>

| Stage | What happens | Key output |
|---|---|---|
| **1. Intake** | Read-only collection from repos, CI, lockfiles, SBOMs, container images, IaC, MCP configs, cloud accounts, and runtime events. No writes, no secret values read. | raw evidence sources |
| **2. Scan** | The six-step engine — discover, extract, scan, enrich, analyze, report — runs parsers and advisory scanners, enriches with NVD CVSS / EPSS / KEV / GHSA, and **analyzes symbol-level CVE reachability** against the call graph. | matched, enriched, reachability-scored findings |
| **3. Evidence** | Everything normalizes into one `Finding` model and one `ContextGraph`, so triage never forks per source. Reachable CVEs are fused into the agent/MCP graph to produce the blast radius above. | unified `Finding` + `ContextGraph` |
| **4. Control** | The same evidence is served and enforced through a self-hosted control plane: REST API, dashboard, MCP server, gateway/proxy, fleet — all behind auth, RBAC, tenant scope, and signed audit. | tenant-scoped, audited access + runtime decisions |
| **5. Artifacts** | Decisions leave in the format each consumer trusts: SARIF, CycloneDX, SPDX, OCSF, HTML, PDF, JSON, CSV, webhooks — for humans (CLI, UI) and agents (MCP tools, API) alike. | gates, reports, compliance evidence, runtime blocks |

Stage 2's "analyze" step is where symbol-level reachability is computed; stage 3
is where it becomes a blast radius. That pairing is the differentiator — the
rest of the flow is table stakes done cleanly.

## Where to go next

- Deeper module and surface architecture: [`ARCHITECTURE.md`](ARCHITECTURE.md)
- Service lanes and backend choices: [`PRODUCT_MAP.md`](PRODUCT_MAP.md)
- Positioning and shipped-vs-not: [`PRODUCT_BRIEF.md`](PRODUCT_BRIEF.md)
- Lanes and cost posture: [`EDITIONS.md`](EDITIONS.md)
- What to deploy first: [deployment overview](../site-docs/deployment/overview.md)
</content>
