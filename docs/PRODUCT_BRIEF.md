# Product Brief

`agent-bom` is an open security scanner and AI BOM for the AI stack, with a
self-hosted control plane for teams that need fleet inventory, graph-backed
findings, MCP/runtime enforcement, and governance evidence inside their own
environment.

It is built around a simple thesis: security and visibility for AI infrastructure should be open, transparent, and accessible, not reserved for teams with enterprise budgets.

Package risk is only the start. `agent-bom` follows what it can reach across
MCP servers, agents, credential environment names, tools, runtime behavior, and
trust posture. That reachability-backed AI BOM is the core product value.

`agent-bom` is a released OSS product with a working CLI, GitHub Action, Docker images, authenticated API and MCP deployment paths, report formats, a dashboard, and a growing enterprise-hardening track.

Current repo-derived counts live in [PRODUCT_METRICS.md](PRODUCT_METRICS.md). This brief intentionally keeps volatile metrics out of the main narrative.

## Positioning contract

The product should converge curious users into real adoption by answering four
persona questions quickly:

| Persona | Question they need answered | Product proof |
|---|---|---|
| Product manager | "Is the first run valuable and obvious?" | deterministic demo, fix-first output, clear next step |
| Sales engineer | "Can I prove this in the buyer's environment?" | CLI/Docker/Action smoke, control-plane pilot, gateway/proxy evidence |
| Account executive | "Who buys this and why now?" | AI/MCP supply-chain risk, self-hosted deployment, evidence for governance teams |
| Software/security engineer | "Can I trust and operate it?" | signed releases, tests, strict auth defaults, Postgres tenancy, audit chain, scoped runtime controls |

Do not present the product as ten equal entry points. Present it as one wedge
with three adoption lanes: generate an AI BOM for the stack, send that evidence
to a customer-controlled plane, then enforce selected runtime paths.

```text
agent-bom
├─ generate an AI BOM locally
│  └─ CLI, Docker, GitHub Action -> findings, SARIF, SBOM, HTML, graph exports
├─ send evidence to a control plane
│  └─ fleet sync, REST API, Helm/EKS, UI -> inventory, graph, compliance, governance
└─ enforce runtime behavior
   └─ MCP server, proxy/gateway, Shield SDK -> audit, policy blocks, runtime alerts
```

1. **Generate an AI BOM locally** — CLI, Docker, and GitHub Action produce
   findings, SARIF, SBOMs, HTML reports, and graph exports.
2. **Send evidence to a control plane** — endpoint fleet, REST API, Helm/EKS,
   and the browser UI centralize inventory, graph state, compliance, and
   governance.
3. **Enforce runtime behavior** — MCP server mode, proxy/gateway, and Shield
   SDK turn the same model into agentic workflow controls.

This framing does not narrow the deployment story. It makes "deploy in your
own cloud / infrastructure" the production form of lane 2, with runtime
controls from lane 3 added where the customer needs inline enforcement.

Integrations should be described as distribution and workflow fit, not as a
miscellaneous compatibility list. The strongest story is:

- **coding agents and MCP clients**: Claude, Cursor, Windsurf, VS Code, Cortex
  Code, and similar clients can invoke agent-bom as a read-only security tool
  surface.
- **skills and registries**: OpenClaw skills, Cortex Code skill packaging, MCP
  Registry, Smithery, Glama, and Docker MCP registry make repeatable
  agent-bom workflows available where agent users already discover tools.
- **developer controls**: CLI, Docker, GitHub Action, SARIF, SBOM, and
  pre-install checks make local and CI adoption useful without the dashboard.
- **enterprise data paths**: REST API, fleet sync, Helm/EKS, Postgres,
  ClickHouse, Snowflake paths, OTEL, SIEM/export hooks, and compliance bundles
  let security teams centralize evidence inside their own infrastructure.

## Deployment truth

The product should be framed deployment-first:

- **self-hosted operator plane** in the customer's own infrastructure
- **entry points** through CLI, GitHub Action, fleet ingest, proxy, and gateway
- **pilot** as a narrower rollout profile of the same architecture, not a separate product shape
- **Fortune-500 deployment readiness** as customer-controlled infrastructure,
  explicit auth/tenant/storage choices, and evidence-backed operations, not as
  a hosted SaaS claim

That keeps the repo story aligned with the actual code: one shared graph, one
policy model, multiple entry points, no mandatory hosted control plane.

## Durable thesis

- Agent security is not just software composition analysis. It is context across packages, MCP servers, agent configuration, credentials, tools, and runtime behavior.
- Security for agentic infrastructure should be inspectable and explainable. Findings should show blast radius, not just raw package IDs.
- Strong security and visibility should be available to individual developers and small teams, not only to enterprises with large budgets and long procurement cycles.

## Stable capability brief

### Discovery

`agent-bom` discovers agent and MCP environments from local config, project manifests and lockfiles, container images, cloud surfaces, and supporting config files. It understands mainstream MCP client setups, not just generic manifests.

### Scanning

The scanner covers package risk, malicious or suspicious package indicators, container layers, IaC, cloud AI surfaces, secrets, instruction or skill files, and model or weight supply chain integrity. Project scans surface lockfile-backed inventory, declaration-only manifests, direct-versus-transitive package depth, and explicit advisory-depth coverage so users can tell how much of the scan came from resolved lockfiles versus manifest-only declarations. Findings also carry advisory-source attribution so operators can distinguish primary matches from later enrichment instead of inferring that from references. Model and weight scans surface risky formats, signature presence, bundle manifests, adapter lineage, provenance checks, and first-class CLI hash verification against Hub-backed metadata where available.

### Blast radius

Blast radius is the product center of gravity. `agent-bom` connects vulnerabilities to packages, MCP servers, agents, credential exposure, and reachable tools. Impact is CWE-aware so the reported consequences match the weakness class instead of inflating every issue into full compromise.

### Trust and policy

`agent-bom` scores trust with evidence, not a black-box label. It combines package and registry posture, capability risk, drift, exposed credentials, and related supply-chain signals. Policy and compliance layers can then act on those findings with clearer context.

The shipped policy path is the repo's native JSON policy engine used by the
gateway and proxy surfaces. That should stay the default product framing today.
If enterprise buyers need OPA/Rego, the sensible roadmap is interoperability
through bundle import/export or an external decision hook, not a rewrite of the
core policy engine.

The product also protects its own shipped surfaces with the same discipline: signed releases, provenance, daily dependency monitoring, drift checks, and CI guards for the JavaScript surfaces so accidental source-map leaks or stale npm dependencies do not silently ship.

Model and weight security should be described the same way: not just as file detection, but as a supply-chain contract that surfaces risky formats, signature presence, manifest and lineage evidence, provenance checks, and Hub-backed hash verification where available.

### Runtime protection

The runtime story has two levels:

- a lighter MCP proxy path that inspects live JSON-RPC traffic inline
- a broader runtime protection engine used for deeper protection workflows

The wording matters. The proxy and the broader runtime engine are related, but they are not the same path and should not be described as the same detector surface.

### Observability and OTEL

OpenTelemetry should be described as a first-class product capability, not a
buried add-on. `agent-bom` already:

- preserves W3C trace context across API requests
- exports operator telemetry over OTLP/HTTP when configured
- ingests OTEL traces into the control plane
- uses OTEL traces as runtime evidence, not just as emitted spans

That bidirectional model is a real differentiator and should appear in the main
product narrative.

### Skills and instruction files

`agent-bom` treats skill and instruction files as part of the agent attack surface. It scans common instruction surfaces, builds stable bundle identity for review, and is moving toward stronger trust verdicts and richer behavioral analysis.

### Compliance and evidence

Findings can be mapped into compliance and governance views, but the product should present that as evidence generation and control mapping, not as a substitute for a real security program.

### Cloud, containers, and infrastructure

The product is broader than MCP alone. It includes cloud posture, container scanning, IaC, and fleet or API surfaces. That breadth matters because agent risk rarely stops at a single config file.

## Current posture

`agent-bom` should be described today as:

- a serious open-source product with a clear path to `1.0`
- unusually complete for an open tool in agent and MCP security
- complementary to traditional package and container scanners today, while differentiated by blast radius, runtime, and MCP-aware analysis
- deployable across local development, CI/CD gates, and authenticated self-hosted operator environments

That means public repo copy should emphasize real shipped surfaces, not just aspirations.

## Path to 1.0

The next phase should stay disciplined:

- enterprise hardening: auth defaults, tenant isolation, Helm and deployment defaults, stable operator contracts
- scanner depth: stronger lockfile and package coverage so buyers do not need a second tool for basic SCA depth
- supply chain operations: tighter SBOM import/diff workflows so external vendor BOMs and current scans stay comparable
- MCP and runtime depth: keep improving governance, observability, and remote operation without weakening the low-friction local story
- skills depth: move from strong regex-first analysis toward more semantic analysis while preserving stable output contracts
- contributor scalability: make extension and contribution paths clearer without destabilizing the core product

This is the right path because it improves product trust without diluting the MCP and AI-native advantage.

## Positioning

Good external phrasing:

- Open security scanner and AI BOM for the AI stack
- Generate a reachability-backed AI BOM across agents, MCP, packages, credentials, cloud, and runtime
- Context-aware security for agents, MCP, runtime, and AI supply chain and infrastructure
- Blast radius from package risk to agents, credentials, tools, and runtime

Avoid:

- absolute claims like "nobody else" or "no competitor"
- hand-counted metrics in the main narrative
- mixing historical audit snapshots with current product truth

When comparing the product, prefer language like:

- "unusually complete for an open tool"
- "one of the only open tools combining discovery, blast radius, runtime, and MCP-aware trust in one system"
- "a serious OSS product with a real path to 1.0"

## References

- [README](../README.md)
- [Product metrics](PRODUCT_METRICS.md)
- [Major MCP client guides](MCP_CLIENT_GUIDES.md)
- [Claude Desktop / Claude Code integration](CLAUDE_INTEGRATION.md)
- [Cortex CoCo / Cortex Code integration](CORTEX_CODE.md)
- [Codex CLI integration](CODEX_CLI.md)
- [MCP server mode](MCP_SERVER.md)
- [Runtime monitoring and proxy](RUNTIME_MONITORING.md)
- [MCP security model](MCP_SECURITY_MODEL.md)
- [Architecture](ARCHITECTURE.md)
- [Threat model](THREAT_MODEL.md)
