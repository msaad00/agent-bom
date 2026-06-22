# Project Structure

A repo-map for `agent-bom`: where things live, which trees are canonical, and
how the `src/agent_bom/` package is organized into subsystems. Start here when
you ask **"where does X live?"**

`agent-bom` is a single pure-Python package (~221K LoC) that exposes one shared
evidence model through many surfaces: CLI/CI, REST API, MCP server, dashboard,
and runtime proxy/gateway. The package is intentionally broad — this map groups
its modules so the breadth reads as a system, not a flat sprawl.

For the layered architecture and data-flow diagrams, see
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). For role-based entry paths, see
[`docs/START_HERE.md`](docs/START_HERE.md).

---

## Top-level layout

| Path | What it is | Canonical? |
|---|---|---|
| `src/agent_bom/` | The product. All scanner, control-plane, MCP, and output code. | **Yes** — the single source of truth for behavior. |
| `tests/` | Test suite (pytest, parallelized with pytest-xdist). | Yes. |
| `docs/` | Operator- and contributor-facing reference docs (this tree). | **Yes** — canonical for engineering/reference docs. |
| `site-docs/` | MkDocs source for the published docs site. | **Yes** — canonical for the *narrative/getting-started* site; see [Documentation map](#documentation-map). |
| `ui/` | Next.js 16 + React 19 + Tailwind 4 dashboard (the human cockpit). | Yes — the active UI. |
| `dashboard/` | Static/build assets and supporting dashboard files. | Build support for the UI. |
| `sdks/` | Client SDKs: `python`, `go`, `typescript`, `typescript-client`, `shared`. | Yes — typed control-plane clients (not scanner SDKs). |
| `deploy/` | Helm chart, docker-compose pilot, EKS reference, deployment manifests. | Yes. |
| `contracts/` | Cross-surface contract fixtures. | Yes. |
| `docs/openapi/v1.json` | Committed OpenAPI spec — the canonical REST contract (230 paths / 271 operations). | **Yes** — SDK + client contract checks read this. |
| `scripts/` | Release, deploy, and consistency tooling (e.g. `check_release_consistency.py`). | Yes. |
| `integrations/` | External tool integrations and examples. | Yes. |
| `examples/`, `config/`, `security/`, `fuzz/` | Samples, config, security policy, fuzz harnesses. | Support material. |
| `AGENTS.md`, `CLAUDE.md` | Contributor/agent operating rules. Read `AGENTS.md` first. | Yes. |
| `README.md`, `PYPI_README.md`, `DOCKER_HUB_README.md`, `DOCKER_HUB_UI_README.md` | Front doors per distribution channel; kept in sync by `scripts/check_release_consistency.py`. | Yes — each is canonical for its channel. |

---

## `src/agent_bom/` subsystems

The package has ~192 top-level modules plus 22 subpackages. Grouped by the role
each plays in the **collect → normalize → serve → enforce** pipeline:

### 1. Scan layer — collect evidence

Turn an input (repo, image, SBOM, MCP config, cloud account) into raw inventory
and findings.

| Subsystem | Path | Responsibility |
|---|---|---|
| Discovery | `discovery/` | Find local AI agents and MCP clients/servers (29 first-class client types plus dynamic/project surfaces). |
| Parsers | `parsers/` | Extract packages from lockfiles/manifests across 15 ecosystems; parse skills, dataset cards, browser extensions, OS packages. |
| Scanners | `scanners/` | OSV batch scan, CVSS, vendor advisories (GHSA/Intel/AMD/NVIDIA/firmware), `blast_radius.py`, risk scoring. |
| Cloud | `cloud/` | Read-only, gated estate inventory + CIS benchmarks (AWS/Azure/GCP) and AI/GPU provider posture. |
| IaC | `iac/` | Terraform, CloudFormation, Helm, Kubernetes, Dockerfile, dbt scanning + ATT&CK/ATLAS mapping. |
| Identity (NHI) | `identity/` | Non-human identity discovery (Okta/Entra, gated). |
| Containers | `oci_parser.py`, `image.py`, `filesystem.py` | Native OCI image + disk-image parsing (no Rust/Go on the scan path). |
| SAST / secrets | `sast.py`, `ast_*.py`, `secret_scanner.py`, `malicious.py`, `model_pickle_scan.py` | Source analysis, secret detection, safe malicious-model disassembly. |

### 2. Enrichment — add intelligence

| Subsystem | Path | Responsibility |
|---|---|---|
| Enrichment | `enrichment.py`, `enrichment_posture.py` | NVD CVSS, EPSS, CISA KEV, GHSA enrichment. |
| Compliance | `compliance_coverage.py`, `owasp*.py`, `nist_*.py`, `atlas.py`, `mitre_*.py`, `eu_ai_act.py`, `iso_27001.py`, `soc2.py`, `cis_controls.py`, `cmmc.py`, `pci_dss.py`, `fedramp.py` | Tag findings against curated framework controls (see ARCHITECTURE §4). |
| Cost (FinOps) | `cost_model.py`, `api/cost_*.py` | LLM spend forecasting, budget runway, chargeback, anomaly detection. |
| Cross-env / correlation | `cross_env_correlation.py`, `correlate.py`, `runtime_correlation.py` | Fuse evidence across environments and runtime logs. |

### 3. Unified Finding + ContextGraph — the convergence point

Every scan path lands on **one** `Finding` model and **one** graph, so blast
radius, attack-path fusion, and exposure scoring all read the same evidence.

| Subsystem | Path | Responsibility |
|---|---|---|
| Models | `models.py`, `finding.py` | Core data models: `Package`, `Vulnerability`, `Agent`, `Finding`, `BlastRadius`. |
| Graph (canonical) | `graph/` | `builder.py` builds the `UnifiedGraph` from serialized report JSON; `node.py`/`edge.py`/`types.py`/`container.py` define the schema; overlays add CNAPP/NHI/governance context; `attack_path_fusion.py` and `blast_reach.py` score exposure. |
| Graph (legacy bridge) | `context_graph.py` | Legacy lateral-movement graph. **In-progress migration** — see [Graph migration](#graph-migration-split-brain). |

### 4. Control plane — serve + enforce

The self-hosted operator surface. Same evidence, multi-tenant, audited.

| Subsystem | Path | Responsibility |
|---|---|---|
| API | `api/` | FastAPI app. `routes/` (30 route modules; 271 REST operations + 2 WebSocket), `middleware.py` (4 layers), and `*_store.py`/`postgres_*.py` persistence (SQLite default, Postgres for clusters, optional Snowflake/ClickHouse). |
| MCP server | `mcp_server*.py`, `mcp_tools/` | FastMCP server advertising 69 tools, 6 resources, 6 prompts (mostly read-only; 3 Shield write actions fail closed). |
| Runtime enforcement | `proxy*.py`, `gateway*.py`, `firewall*.py`, `shield.py`, `runtime/`, `enforcement.py` | MCP traffic proxy, secure-by-default gateway, inline firewall, Shield enforcement. **Spread by design** — see [Runtime enforcement spread](#runtime-enforcement-spread). |
| Auth / tenancy | `rbac.py`, `permissions.py`, `entitlements.py`, `mcp_tenant.py`, `api/auth.py`, `api/oidc.py` | RBAC roles, tenant scoping, API keys, OIDC/SAML/SCIM. |
| Fleet | `fleet/`, `fleet_scan.py` | Endpoint/collector inventory pushed into one control plane. |
| Audit | `audit_integrity.py`, `audit_replay.py`, `api/audit_log.py` | HMAC-chained audit trail + integrity verification. |

### 5. Outputs — decisions and artifacts

| Subsystem | Path | Responsibility |
|---|---|---|
| Output formatters | `output/` | JSON, SARIF, CycloneDX, SPDX, OCSF, HTML, PDF, CSV, Markdown, JUnit, Prometheus, console, plus graph/mermaid/svg/badge renderers. |
| SIEM / connectors | `siem/`, `connectors/`, `integrations/` | OCSF SIEM export; Jira/Slack/ServiceNow/Vanta/Drata. |
| Alerts | `alerts/` | Dedup, dispatch, scan alerts. |
| Evidence | `evidence/`, `compliance_hub*.py`, `database_evidence.py` | Compliance evidence bundles and policy evidence. |

### 6. CLI — the developer/CI entry point

| Subsystem | Path | Responsibility |
|---|---|---|
| CLI | `cli/` | Click entry point. 48 top-level commands (plus an inline `upgrade`) across 7 help categories. See [`docs/CLI_MAP.md`](docs/CLI_MAP.md). |

---

## Graph migration (split-brain)

The graph subsystem is mid-consolidation. Newcomers should know which is the
future:

- **Legacy / bridge:** `src/agent_bom/context_graph.py` — the original
  lateral-movement graph that operates on raw JSON dicts. It still backs some
  CLI/API paths and converts to the canonical model via `to_unified_graph()`.
- **Canonical / target:** `src/agent_bom/graph/builder.py` builds the
  `UnifiedGraph` (`graph/container.py`, `graph/node.py`, `graph/edge.py`,
  `graph/types.py`). New graph features belong here.
- **The bridge:** `src/agent_bom/graph/compat.py` maps legacy node/edge kinds
  (`NODE_KIND_TO_ENTITY`, `EDGE_KIND_TO_RELATIONSHIP`) onto the canonical
  `EntityType`/`RelationshipType` enums so conversion doesn't silently drop
  identity or relationship edges.

**Direction of travel:** add to `graph/`, treat `context_graph.py` as a bridge
that will shrink over time. The graph contract (entity/edge coverage, accuracy
guarantees, scaling tiers, known gaps) is in
[`docs/graph/CONTRACT.md`](docs/graph/CONTRACT.md).

See [`docs/GRAPH_MIGRATION.md`](docs/GRAPH_MIGRATION.md) for the full note.

---

## Runtime enforcement spread

Runtime enforcement is intentionally **not** one module — it is layered across
several so each enforcement point can be adopted independently:

- `proxy.py` + `proxy_*.py` — wrap a target MCP server for traffic inspection,
  inline detectors, and audited policy decisions (optionally Docker/Podman
  sandboxed via `proxy_sandbox.py`).
- `gateway.py` + `gateway_*.py` + `gateway_server.py` — the secure-by-default
  central gateway and its policy templates/upstreams.
- `firewall.py` + `firewall_client.py` — inline inter-agent firewall decisions.
- `shield.py` — Shield enforcement actions (the 3 write actions that fail
  closed without admin role + scope + audit reason).
- `runtime/` — runtime detectors, patterns, and the runtime server.

These share the same policy evaluator and audit sink, so a finding's exposure
path stays explainable across whichever enforcement layer is in use.

---

## Documentation map

`agent-bom` keeps documentation in a few deliberate trees. Use this to know
which is the source of truth for what:

| Tree | Source of truth for | Format |
|---|---|---|
| `docs/` | Engineering + operator reference (architecture, threat model, MCP server, deployment, graph contract, this structure map). | Markdown, read on GitHub. |
| `site-docs/` | The **published docs site** ([msaad00.github.io/agent-bom](https://msaad00.github.io/agent-bom/)) — getting-started, tutorials, narrative walkthroughs. | MkDocs. |
| `README.md` (root) | The repository front door. | Markdown. |
| `PYPI_README.md` / `DOCKER_HUB*.md` | Per-channel front doors, kept consistent by the release-consistency gate. | Markdown. |

When a topic exists in both `docs/` and `site-docs/`, `docs/` is canonical for
the engineering reference and `site-docs/` is canonical for the
narrative/onboarding version. See [`docs/README.md`](docs/README.md) for the
audience-grouped index.
