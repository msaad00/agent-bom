# Deployment Modes and Alignment

Use this page when the question is not "can `agent-bom` do this?" but "how do
we package, deploy, explain, and scale it without making the product feel more
complicated than it is?"

The short answer:

- `agent-bom` is **one product**
- it is a **self-hosted control plane for AI and MCP security**
- it uses **two deployable images**
- proxy and gateway are **optional runtime surfaces**, not mandatory chokepoints

## What Is Already Real

Core security and isolation are already part of the shipped control-plane path:

- tenant isolation across API, store, and export paths
- RBAC on sensitive routes
- OIDC and SAML for operator auth
- API-key auth with tenant propagation and quotas
- auditability and signed or tamper-evident evidence flows

That means the remaining work is mostly productization, operability, and
alignment, not "invent auth" or "add tenant boundaries from scratch."

The honest auth and runtime gaps that still matter are:

- gateway and control-plane API-key rotation / revocation UX
- per-user OAuth2 auth-code / PKCE for laptop to gateway
- clearer deployment-mode UX so operators only see surfaces that apply to their environment

## One Product, Two Images

Keep the image model simple and stable:

| Product concept | Deployable image | Purpose |
|---|---|---|
| **agent-bom API / runtime image** | `agentbom/agent-bom` | CLI, API, scanner jobs, gateway, proxy, MCP server |
| **agent-bom UI companion image** | `agentbom/agent-bom-ui` | Browser UI for the self-hosted control plane |

This is the correct split:

- Python runtime surfaces and the Node UI have different patch cadence, scaling, and blast radius
- separate images are cleaner and safer in customer EKS
- the mistake is not having two images
- the mistake is presenting them like two products

Use this wording everywhere:

- **one product**: `agent-bom`
- **one self-hosted control plane**
- **API / runtime image**
- **UI companion image**
- **optional proxy and gateway surfaces**

## Canonical Deployment Modes

These are the four modes that should drive the product story, navigation, docs,
and packaging.

| Mode | Deploy this | Primary surfaces | Best fit |
|---|---|---|---|
| **local** | CLI only | scan, exports, local posture | individual developer, one-off audit |
| **fleet** | control plane + endpoint pushes | fleet, findings, audit, source/job review | laptops or collectors reporting into a shared plane |
| **cluster** | EKS control plane + scheduled jobs + optional gateway/proxy | scan, API/UI, runtime, traces, cluster inventory | customer-managed EKS rollout |
| **hybrid** | cluster mode plus endpoint proxy/fleet | fleet + runtime + control-plane review | enterprise with laptops and shared runtime surfaces |

The UI should make these modes obvious instead of treating every install as if
it were a fully populated hybrid deployment.

## Customer EKS Story

This is the clean customer-facing deployment story:

> `agent-bom` is one self-hosted control plane for AI and MCP security. It runs
> inside the customer's EKS or VPC, keeps tenant-scoped findings, audit, and
> graph state in customer-owned stores, and uses two deployable images: the
> API/runtime image and the UI companion image. Proxy and gateway are optional
> runtime surfaces, not mandatory chokepoints.

### What the customer actually deploys

| Layer | Runs in customer infra | Why it exists |
|---|---|---|
| **UI** | browser-facing deployment | review, trigger, schedule, export |
| **API / control plane** | FastAPI service | auth, RBAC, tenant scope, orchestration, graph, audit, policy |
| **scanner jobs** | CronJobs, CI runners, one-off jobs | repo, image, IaC, MCP, cloud, and cluster scanning |
| **fleet ingest** | endpoint or collector pushes | workstation and collector inventory without a mandatory daemon product |
| **proxy** | sidecar or laptop wrapper | local enforcement near MCP traffic |
| **gateway** | shared relay and policy surface | central runtime control where shared relay is useful |
| **stores** | Postgres required, ClickHouse optional, Snowflake optional | transactional state, analytics, governance-oriented backends |

### Response to the three practical concerns

| Concern | Honest answer | What still needs polish |
|---|---|---|
| **Tenant isolation** | already enforced at API, store, and export layers | make tenant context more visible in sources, jobs, evidence, fleet, quotas, and gateway audit views |
| **Gateway bottleneck** | proxy remains edge enforcement; not every workload must hairpin through one relay | document HPA, PDB, policy cache behavior, fail-open/fail-closed choices, and per-tenant or per-upstream limits more explicitly |
| **Deployment complexity** | the control plane, jobs, proxy, and gateway already map to code-backed surfaces | reduce mode sprawl, unify wording, simplify install docs, and keep one canonical operator story |

## End-to-End Alignment Matrix

These are the surfaces that need to stay aligned in wording, docs, packaging,
and UX.

| Surface | Canonical story |
|---|---|
| **Commands** | CLI for local work, jobs, proxy, gateway, and MCP server all stay under `agent-bom` |
| **API routes** | API owns auth, RBAC, tenant scope, orchestration, graph, audit, policy, and exports |
| **UI screens** | UI drives workflows and review; it never collects privileged data directly |
| **Helm values** | one chart, one operator plane, optional runtime surfaces |
| **Docker images** | `agentbom/agent-bom` + `agentbom/agent-bom-ui` under one product |
| **Compose examples** | local-built image names are examples, not a separate product taxonomy |
| **README and docs** | one deployment/offering matrix, one deployment-mode vocabulary |
| **Docker Hub descriptions** | explicitly describe the two-image model as one product |
| **Offering language** | local, fleet, cluster, and hybrid should be the only primary deployment modes |

## Track 1: `#1520` Product-Surface Alignment

Issue: `#1520 feat: deployment-context-aware navigation (local / fleet / cluster / hybrid)`

Implementation checklist:

- extend posture/counts to return `deployment_mode`
- add granular booleans for `has_local_scan`, `has_fleet_ingest`, `has_cluster_scan`, `has_mesh`, `has_gateway`, `has_proxy`, `has_traces`, and `has_registry`
- hide nav items that are not meaningful for the current mode
- add direct-link empty states that explain what enables the page
- make `/sources`, `/jobs`, `/fleet`, `/gateway`, `/proxy`, `/traces`, `/mesh`, and `/context` mode-aware
- make tenant context visible on source, job, evidence, fleet, audit, and quota views

Acceptance fixtures:

- `local`
- `fleet`
- `cluster`
- `hybrid`

## Track 2: Packaging, Docs, and Image Alignment

Checklist:

- keep the product name as `agent-bom` everywhere
- keep the image split as API/runtime image plus UI companion image
- remove wording that makes the UI sound like a separate product
- distinguish local-built compose image names from published Docker Hub names
- add one canonical install and deployment matrix across CLI, control plane, proxy, gateway, fleet, and backends
- keep Docker Hub, PyPI, README, compose, Helm, and release notes using the same deployment-mode vocabulary
- keep charts and released image tags aligned with the active release branch

## Track 3: Customer EKS Operability Hardening

Checklist:

- gateway API-key rotation and revocation UX
- gateway per-tenant runtime rate limiting
- chart appVersion and published artifact alignment
- chart or install validation as a first-class CI path
- clearer MDM-friendly endpoint proxy install story
- optional sidecar auto-injection later, but not required for the core control-plane cleanup

## What To Say In The Product Pitch

Use the strongest claim that is true today:

> `agent-bom` gives teams one self-hosted control plane for AI and MCP
> security: scan, fleet, graph, audit, proxy, and gateway under one operator
> story, inside the customer's EKS or VPC, with tenant-scoped state in their
> own stores and no mandatory vendor control plane.

Avoid overstating:

- do not imply the gateway must be the only path for every workload
- do not imply the UI is its own product
- do not imply deployment requires every surface at once
- do not imply API-key lifecycle UX is finished when rotation and revocation are still being productized
