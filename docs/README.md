# Docs Index

> **Canonical docs tree.** `docs/` is the source of truth for **engineering and
> operator reference** material. The **getting-started / narrative** version of
> the docs is the MkDocs site under [`../site-docs/`](../site-docs/index.md),
> published at <https://msaad00.github.io/agent-bom/>. When a topic appears in
> both, `docs/` is canonical for the reference detail and `site-docs/` is
> canonical for the onboarding walkthrough. See
> [`../PROJECT_STRUCTURE.md#documentation-map`](../PROJECT_STRUCTURE.md#documentation-map).

New here? Start with [`START_HERE.md`](START_HERE.md) (role-based entry paths)
and [`../PROJECT_STRUCTURE.md`](../PROJECT_STRUCTURE.md) (repo map).

Keep top-level `docs/` focused on operator-facing and externally useful
material. The index below groups the canonical docs by audience.

---

## Orientation (start here)

- [`FIRST_RUN.md`](FIRST_RUN.md) — install → first scan → first artifact (canonical first-run path)
- [`START_HERE.md`](START_HERE.md) — role-based entry paths (security engineer / platform-SRE / AI-agent developer)
- [`HOW_IT_WORKS.md`](HOW_IT_WORKS.md) — five-stage evidence flow (canonical product story)
- [`PRODUCT_BRIEF.md`](PRODUCT_BRIEF.md) — positioning and persona contract
- [`PRODUCT_MAP.md`](PRODUCT_MAP.md) — operator chooser: lanes, surfaces, backends
- [`EDITIONS.md`](EDITIONS.md) — lanes + cost posture (canonical editions statement)
- [`PRODUCT_BOUNDARIES.md`](PRODUCT_BOUNDARIES.md) — boundary and copy-rules companion to editions
- [`AGENT_CAPABILITY.md`](AGENT_CAPABILITY.md) — machine-readable capability manifest (MCP/API counts)
- [`TRUST.md`](TRUST.md) — what we store, what we don't, customer boundary
- [`CAPTURE.md`](CAPTURE.md) — product-proof screenshot capture protocol
- [`VISUAL_LANGUAGE.md`](VISUAL_LANGUAGE.md) — brand, media rules, and asset inventory
- [`../PROJECT_STRUCTURE.md`](../PROJECT_STRUCTURE.md) — repo map: where everything lives, which trees are canonical
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — layered stack, data flow, scan pipeline, blast radius, compliance tagging (mermaid)
- [`CLI_MAP.md`](CLI_MAP.md) — all 50 top-level commands grouped by domain + intentional aliases
- [`DATA_SOURCES.md`](DATA_SOURCES.md) — intake diagram → mechanism → permission boundary
- [`SESSION_FLOWS.md`](SESSION_FLOWS.md) — compact who → enforced → lands diagrams for scan push, ingest, MCP, Helm, fleet sync, and API keys

## Security engineers (scan · gate · export)

- [`SUPPLY_CHAIN.md`](SUPPLY_CHAIN.md) — supply-chain scanning model
- [`CONTROL_MAPPING.md`](CONTROL_MAPPING.md) — compliance framework mapping
- [`SECURITY_ARCHITECTURE.md`](SECURITY_ARCHITECTURE.md) — security architecture
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — threat model
- [`PENTEST_READINESS.md`](PENTEST_READINESS.md) — pentest readiness
- [`SCANNER_CONTEXT_CONTRACT.md`](SCANNER_CONTEXT_CONTRACT.md) — IaC `ScanContext` two-gate authorization model

## Platform / SRE (self-host · deploy · operate)

Two hubs cover the clustered material — start at the hub, then follow it to the detail sibling:

- [`DEPLOY_PLATFORM.md`](DEPLOY_PLATFORM.md) — **deployment doc-set hub**: deploy anywhere (Compose · EKS · hosted); indexes `DEPLOYMENT.md`, `DEPLOY_QUICKSTART.md`, `ENTERPRISE_DEPLOYMENT.md`
- [`ENTERPRISE.md`](ENTERPRISE.md) — **enterprise doc-set hub**: controls-to-code map; indexes deployment, security posture, playbook, procurement, operations-evidence, and support siblings
- [`RUNTIME_REFERENCE.md`](RUNTIME_REFERENCE.md) — runtime surface map; indexes `RUNTIME_MONITORING.md` and `RUNTIME_PROXY_AUDIT_JSONL.md`
- [`PERMISSIONS.md`](PERMISSIONS.md) — RBAC roles and permissions
- [`DATABASE_EVIDENCE.md`](DATABASE_EVIDENCE.md) — persistence and evidence stores
- [`RELEASE_VERIFICATION.md`](RELEASE_VERIFICATION.md) — release verification
- [`openapi/v1.json`](openapi/v1.json) — canonical REST contract (299 paths / 356 operations)

## AI / agent developers (MCP · clients · tools)

- [`MCP_SERVER.md`](MCP_SERVER.md) — run the MCP server, 75 tools
- [`MCP_CLIENT_GUIDES.md`](MCP_CLIENT_GUIDES.md) — connect MCP clients
- [`PYTHON_API.md`](PYTHON_API.md) — Python control-plane client
- [`PLUGIN_ENTRYPOINTS.md`](PLUGIN_ENTRYPOINTS.md) — opt-in plugin entry-point loader and author contract

## Graph subsystem

- [`graph/CONTRACT.md`](graph/CONTRACT.md) — graph coverage, accuracy guarantees, scaling boundaries, non-promises, known gaps
- [`graph/SECURITY_GRAPH_UX_RUBRIC.md`](graph/SECURITY_GRAPH_UX_RUBRIC.md) — review rubric for fix-first security graph usability
- [`GRAPH_MIGRATION.md`](GRAPH_MIGRATION.md) — `context_graph.py` (legacy bridge) → `graph/builder.py` (canonical) consolidation note

---

Archived or historical writeups live under [`docs/archive`](archive/README.md).
