# Deployment Overview

Use this page when the question is not "how do I install `agent-bom`?" but
"what should I deploy first, what does that give me, and when do I add runtime
enforcement?"

Treat this as the primary deployment chooser. The rest of the deployment docs
either deepen one of these supported paths or act as reference material for
teams intentionally diverging from them.

`agent-bom` is one product with two deployable images:

- `agentbom/agent-bom` for scanner, API, jobs, gateway, proxy, and other non-browser runtimes
- `agentbom/agent-bom-ui` for the browser dashboard

Pilot on one workstation:

```bash
curl -fsSL https://raw.githubusercontent.com/msaad00/agent-bom/main/deploy/docker-compose.pilot.yml -o docker-compose.pilot.yml
docker compose -f docker-compose.pilot.yml up -d
# Dashboard -> http://localhost:3000
```

Production in your own cluster from a checked-out repo:

```bash
export AWS_REGION="<your-aws-region>"
scripts/deploy/install-eks-reference.sh \
  --cluster-name corp-ai \
  --region "$AWS_REGION" \
  --hostname agent-bom.internal.example.com \
  --enable-gateway
```

Advanced/manual chart install from a checked-out repo:

```bash
helm upgrade --install agent-bom deploy/helm/agent-bom \
  --namespace agent-bom --create-namespace \
  -f deploy/helm/agent-bom/examples/eks-production-values.yaml
```

## Read This Way

Do not read every deployment page. Pick one path, then open reference pages only
when your platform team needs that specific detail.

| You are trying to... | Start with | Stop there unless... |
|---|---|---|
| run a local pilot | [Docker](docker.md) | you need EKS, SSO, or fleet sync |
| deploy in vanilla EKS | [Vanilla EKS Quickstart](eks-vanilla-quickstart.md) | you need service mesh, ESO, or cert-manager |
| deploy in hardened AWS / EKS | [Your Own AWS / EKS](own-infra-eks.md) | you need a lower-level Helm or Terraform reference |
| run a Snowflake POV | [Snowflake POV](snowflake-pov.md) | you need backend-parity details |
| choose proxy vs gateway vs fleet | [Proxy vs Gateway vs Fleet](proxy-vs-gateway-vs-fleet.md) | you need runtime operations or gateway discovery |

Everything else in the deployment section is reference material.

## Product Surfaces

| Surface | Deploy when | What it gives you |
|---|---|---|
| **Scan** | day 1 | discovery, package/image/IaC/cloud checks, findings, blast radius |
| **Fleet** | day 1 for teams | endpoint and collector inventory without inline traffic control |
| **API + UI** | self-hosted pilots and production | auth, RBAC, tenant scope, graph, remediation, audit, policy |
| **Proxy** | selected local or sidecar MCPs | inline local MCP inspection, policy decisions, signed audit events |
| **Gateway** | shared remote MCP traffic | central remote MCP relay, policy distribution, audit events |
| **MCP server mode** | agent-invoked scanning | exposes `agent-bom` as read-only MCP tools, resources, and prompts |

Default rollout: deploy API + UI with Postgres, add scans and fleet sync, then
add proxy or gateway only where runtime enforcement is worth the extra operating
surface.

## Deployment Defaults

| Decision | Default |
|---|---|
| **first pilot** | `deploy/docker-compose.pilot.yml` |
| **production installer** | `scripts/deploy/install-eks-reference.sh` |
| **system of record** | Postgres |
| **analytics/lake** | optional ClickHouse, Snowflake, OTEL, or S3 exports |
| **runtime enforcement** | selected proxy or gateway, not all traffic by default |

## Enterprise Deployment Promise

This self-hosted shape is designed around a few explicit operating principles:

- **Customer-controlled hosting**: no mandatory vendor control plane and no mandatory SaaS dependency
- **Zero-trust access**: OIDC, SAML, API keys, RBAC, tenant propagation, quotas, and signed audit trails
- **Least privilege**: read-only discovery roles where possible, selected proxy enforcement only where needed
- **Low latency**: runtime inspection stays close to the MCP workloads instead of hairpinning through a global gateway
- **Cheap by default**: scan workers scale to zero, offline vuln DB reduces repeated network lookups, ClickHouse stays optional
- **Interoperable**: one shared graph and policy model spans scanner, proxy, gateway, fleet, and API/UI

## Self-hosted now, provider track later

The supported strength today is the self-hosted enterprise path:

- one organization running `agent-bom` in its own infrastructure
- strong tenant-aware auth, RBAC, audit, fleet, graph, and gateway routing
- customer-owned storage, telemetry, and support-sharing decisions

That should not be read as a hidden claim of turnkey MSSP maturity. Provider
surfaces such as tenant lifecycle automation, richer delegation templates, and
provider-style admin operations remain a separate product track.

## Enterprise Self-Hosted Diagrams

Use three single-concern diagrams instead of one overloaded graph:

- **Topology** answers who runs what, where.
- **Auth + Ingress Flow** answers how operators get in.
- **Inventory & Runtime Evidence Flow** answers how data and policy move.

In the diagrams below, every box prefixed with `agent-bom` is code from this
project running in the customer's environment. The browser, IdP, cloud APIs,
remote MCPs, and storage systems are customer-owned dependencies or optional
destinations; they are not an agent-bom hosted control plane.

### Topology — Who Runs What, Where

```mermaid
flowchart TB
    classDef ab fill:#0f172a,stroke:#6366f1,color:#e0e7ff
    classDef cust fill:#0b1220,stroke:#475569,color:#cbd5e1,stroke-dasharray:3 3

    subgraph Customer["Customer VPC / EKS / self-hosted cluster"]
      direction TB
      Platform["agent-bom platform<br/>UI + API + scan workers"]:::ab
      Runtime["agent-bom runtime<br/>proxy + gateway"]:::ab
      Postgres[("Postgres<br/>system of record")]:::ab
      Sinks[("Optional sinks<br/>ClickHouse · Snowflake · S3 · OTEL")]:::cust
    end

    subgraph External["Customer-owned external"]
      direction TB
      IdP["Corporate IdP"]:::cust
      Cloud["Cloud APIs"]:::cust
      Remote["Remote MCPs"]:::cust
      Endpoints["Endpoints / browser"]:::cust
    end

    Platform --> Postgres
    Platform -. optional export .-> Sinks
    Runtime --> Platform
```

Truth block:
- `agent-bom` is the UI, API, scan workers, proxy, gateway, and optional endpoint
  CLI/collector. It is not a hidden SaaS dependency in this topology.
- Postgres is the required system of record; ClickHouse, Snowflake, S3, and OTEL
  remain optional sinks.
- IdP, cloud APIs, remote MCPs, and operator endpoints stay customer-owned.
  agent-bom integrates with them; it does not host them.

### Auth + Ingress Flow

```mermaid
flowchart LR
    classDef ab fill:#0f172a,stroke:#6366f1,color:#e0e7ff
    classDef cust fill:#0b1220,stroke:#475569,color:#cbd5e1,stroke-dasharray:3 3

    Browser["Operator browser"]:::cust
    IdP["Corporate IdP"]:::cust
    Ingress["Ingress / TLS"]:::ab
    UI["agent-bom UI"]:::ab
    API["agent-bom API<br/>auth · RBAC · tenant scope"]:::ab
    Secrets["Secrets / Vault / IRSA"]:::cust

    Browser --> Ingress
    IdP -. OIDC / SAML .-> Ingress
    Ingress --> UI
    UI --> API
    Secrets --> API
```

Truth block:
- Operators enter through the customer's ingress and TLS; the UI never short-circuits the API.
- The API remains the single control-plane authority for auth, RBAC, and tenant scope.
- Corporate IdP and secret stores stay customer-owned; agent-bom reads from them, it does not replace them.

### Inventory & Runtime Evidence Flow

```mermaid
flowchart LR
    classDef src fill:#0b1220,stroke:#475569,color:#cbd5e1,stroke-dasharray:3 3
    classDef proc fill:#0f172a,stroke:#6366f1,color:#e0e7ff
    classDef run fill:#0f172a,stroke:#10b981,color:#d1fae5
    classDef data fill:#0f172a,stroke:#f59e0b,color:#fef3c7

    subgraph Inventory["Inventory and scan data"]
      direction TB
      Direct["Direct scan<br/>CLI / worker"]:::src
      Pushed["Pushed inventory<br/>adapter / CI / skill"]:::src
      Fleet["Fleet sync<br/>endpoint CLI / collector"]:::src
      Normalize["validate · redact · normalize"]:::proc
      Direct --> Normalize
      Pushed --> Normalize
      Fleet --> Normalize
    end

    subgraph RuntimeFlow["Runtime evidence"]
      direction TB
      LocalMCP["Selected local MCP traffic"]:::src
      RemoteMCP["Shared remote MCP traffic"]:::src
      Proxy["agent-bom proxy<br/>local enforcement"]:::run
      Gateway["agent-bom gateway<br/>remote enforcement"]:::run
      RuntimeEvents["policy decisions + audit events"]:::proc
      LocalMCP --> Proxy
      RemoteMCP --> Gateway
      Proxy --> RuntimeEvents
      Gateway --> RuntimeEvents
    end

    API["agent-bom API<br/>auth · RBAC · tenant scope"]:::proc
    Evidence["Canonical evidence<br/>inventory · findings · graph · remediation"]:::proc
    Postgres[("Postgres<br/>system of record")]:::data
    Export["Optional exports<br/>OTEL · SIEM · Snowflake · ClickHouse · S3"]:::data

    Normalize --> API
    RuntimeEvents --> API
    API --> Evidence
    Evidence --> Postgres
    API -. export / analytics .-> Export
```

Truth block:
- Inventory sources converge through validation, redaction, and normalization
  before they become graph or finding evidence.
- Proxy and gateway are optional runtime surfaces. They add policy decisions and
  audit events; they are not required to get inventory, findings, or graph state.
- The API is the authority for auth, RBAC, tenant scope, policy distribution,
  audit intake, and export decisions.

## Best Self-Hosted Path

If you want the best current self-hosted rollout in your own infrastructure,
start with this shape:

1. Deploy the packaged API + UI control plane with Postgres.
2. Add scheduled scan jobs for cluster, container, and MCP discovery.
3. Add endpoint fleet sync for developer laptops and workstations.
4. Add `agent-bom proxy` only to the MCP workloads that need inline runtime
   enforcement.
5. Use the gateway surface to manage policy centrally and front shared remote
   MCPs, while proxies pull the same policies and push audit events back.

For managed endpoint rollout, `agent-bom proxy-bootstrap` now generates a
single onboarding bundle that can be:

- pushed directly as shell / PowerShell bootstrap assets
- wrapped into Jamf, Kandji, or Intune rollout scripts
- assembled into `.pkg` and `.msi` installers from the same generated bundle
- published into a Homebrew tap via the shipped formula renderer

That gives you one operator story without pretending every workload needs the
same runtime path.

For the post-install maintenance path around proxy policy-signing key rotation
and cert-manager-backed webhook certificate renewal, see
[Runtime Operations](runtime-operations.md).

For the default self-hosted data-ownership and support-sharing boundary, see
[Customer Data and Support Boundary](customer-data-and-support-boundary.md).

## How the surfaces connect

| Path | Starts from | Ends at | Purpose |
|---|---|---|---|
| **Inventory** | scan jobs, CI, `agent-bom agents`, fleet sync | API + UI + Postgres | discover what is installed, configured, risky, and reachable |
| **Proxy runtime** | endpoint or sidecar workload | local MCP + control-plane audit/policy | workload-local stdio/runtime enforcement |
| **Gateway runtime** | shared remote MCP client | remote MCP + control-plane audit/policy | central remote MCP traffic plane |
| **Analytics / archive** | control plane | ClickHouse, S3, SIEM, OTEL | optional longer retention, analytics, and exports |

This is the product split to keep in mind:

- **UI** drives workflows and review
- **API** owns auth, RBAC, graph, audit, and policy
- **workers** do scans and normalization
- **fleet** persists endpoint inventory
- **proxy and gateway** are runtime surfaces deployed where they fit

By default, the control plane, job results, fleet inventory, graph snapshots,
remediation output, and proxy audit data stay inside the customer's
infrastructure. External egress only happens when the operator explicitly enables
it for catalog refresh, enrichment, registry lookups, SIEM export, OTLP, or
webhooks.

That same self-hosted boundary also means `agent-bom` maintainers do not get
silent access to tenant data. For the full operator-facing contract, see
[Customer Data and Support Boundary](customer-data-and-support-boundary.md).

## Which Service Does What

| Surface | Deploy it when | What it owns | What it is not |
|---|---|---|---|
| **Scan** | you need discovery, CVE analysis, Kubernetes inventory, CI gates, or scheduled audits | package, container, IaC, MCP, cloud, and cluster scanning | a live enforcement layer |
| **Fleet** | you want laptops, workstations, or other collectors to persist inventory into one control plane | endpoint and collector push into `/v1/fleet/sync`, review in `/fleet` | an always-on endpoint agent or MDM product |
| **Proxy / runtime** | you need inline MCP inspection or policy enforcement on live tool traffic | `agent-bom proxy`, audit push, selected blocks/warns, local or sidecar enforcement | a generic shared network gateway for every workload |
| **Gateway** | you want central policy authoring and optional shared remote MCP traffic | `/gateway`, `/v1/gateway/policies`, policy pull for proxies, `agent-bom gateway serve` | a replacement for the proxy itself |
| **API + UI** | you want one operator control plane | findings, graph, remediation, fleet review, audit, policy management | a hosted vendor control plane |
| **MCP server** | you want `agent-bom` exposed as tools to assistants or remote clients | `agent-bom mcp server` tool surface | the same thing as the runtime proxy |

## Hosted product checklist

For the packaged product to feel end to end, the UI should drive the control
plane instead of collecting data itself.

| Operator action in UI | Backend/API owner | Data actually comes from |
|---|---|---|
| Create a scan job | `POST /v1/scan` | worker jobs that scan repos, images, IaC, MCP configs, or cloud targets |
| Poll progress / stream status | `GET /v1/scan/{job_id}`, `GET /v1/scan/{job_id}/stream`, `GET /v1/jobs` | control-plane job state |
| Export graph / licenses / VEX / reports | `GET /v1/scan/{job_id}/graph-export`, `/licenses`, `/vex`, `/skill-audit`; `GET /v1/compliance/{framework}/report` | normalized findings and graph state already stored in the control plane |
| Schedule recurring collection | `POST /v1/schedules`, `GET /v1/schedules`, `PUT /v1/schedules/{id}/toggle`, `DELETE /v1/schedules/{id}` | scheduled worker execution |
| Review fleet and endpoint inventory | `GET /v1/fleet`, `GET /v1/fleet/stats`, `GET /v1/fleet/{agent_id}` | endpoint or collector pushes to `POST /v1/fleet/sync` |
| Review traces and pushed results | `POST /v1/traces`, `POST /v1/results/push`, `GET /v1/activity`, `GET /v1/governance` | OTLP, event collectors, or customer-owned push paths |
| Manage runtime policy | `GET/POST/PUT/DELETE /v1/gateway/policies`, `POST /v1/gateway/evaluate` | proxy and gateway policy pull/evaluation |
| Review runtime audit and health | `GET /v1/proxy/status`, `GET /v1/proxy/alerts`, `GET /v1/gateway/audit`, `GET /v1/gateway/stats` | `agent-bom proxy` and gateway audit push to `/v1/proxy/audit` |
| Manage auth, keys, and audit export | `/v1/auth/*`, `/v1/audit*`, `/v1/exceptions*` | control-plane auth, RBAC, audit, and policy state |
| Review graph, findings, posture, and compliance | `/v1/graph*`, `/v1/assets*`, `/v1/compliance*`, `/v1/posture*`, `/v1/governance*` | canonical entities, findings, events, and graph state in the control plane |

That is the intended split:

- `UI` = configure, trigger, schedule, review, export
- `API / control plane` = auth, RBAC, tenant scope, orchestration, graph, persistence, audit, policy
- `workers / connectors` = do the privileged read or collection work
- `proxy / gateway` = enforce and audit runtime MCP traffic

For the concrete backend and UI rollout plan behind this split, see [Hosted
Product Control-Plane Spec](../architecture/hosted-product-spec.md).

## Approved intake paths today

“Approved” here means explicit, customer-controlled backend intake paths. The
Node UI is not one of them.

| Intake path | Code-backed today | How it enters `agent-bom` |
|---|---|---|
| Direct scan | yes | CLI, CI, or API-triggered worker job reads repos, lockfiles, images, IaC, MCP configs, and selected cloud targets |
| Read-only integration | partial, source-dependent | backend connector or worker reads customer-approved cloud or warehouse APIs with customer-managed credentials |
| Pushed ingest | yes | `POST /v1/fleet/sync`, `POST /v1/traces`, `POST /v1/results/push`, `POST /v1/proxy/audit` |
| Imported artifact | yes | uploaded or provided SBOMs, inventories, and external scanner JSON are parsed by the backend |
| Proxy enforcement | yes | `agent-bom proxy` sidecar or local wrapper inspects MCP traffic and pushes audit to the API |
| Central gateway traffic plane | present, still maturing operationally | `agent-bom gateway serve` fronts remote MCP upstreams and pushes the same audit/policy signals back to the control plane |

Covered source categories today:

- repos, packages, and lockfiles
- container images
- IaC: Terraform, Kubernetes, Helm, CloudFormation, Dockerfile
- agents, MCP servers, tools, skills, and instruction files
- runtime traces and proxy/gateway audit events
- fleet inventory pushed by endpoints or collectors
- exported SBOMs and third-party scanner artifacts
- selected cloud and AI infrastructure surfaces where the scanner or connector exists

## What is live now vs still maturing

The self-hosted control-plane pattern is live now. The rough edges are mostly
operator polish, not the core trust boundary.

| Area | Live now | Still maturing |
|---|---|---|
| API + UI control plane | findings, graph, remediation, fleet, audit, compliance, auth | source/connector UX should become more explicit in the UI |
| Direct scans | repo, image, IaC, package, MCP, cloud-backed scan jobs | broader one-click source onboarding in the UI |
| Pushed ingest | fleet sync, traces, proxy audit, pushed results | clearer product-level “data sources” management surface |
| Proxy runtime path | sidecar and local wrapper deployment docs, metrics, audit, enforcement | more turnkey rollout guidance by workload type |
| Gateway | central policy and audit are real; traffic-plane shape and docs exist | still more design/runbook than a single polished operator guide |
| Hosted packaging | self-hosted API/UI and Helm control plane are real | release-path polish for every artifact path should stay under CI guard |

## Security and Data-Flow Boundaries

The deployment model is intentionally split by trust boundary:

1. **Discovery and scan paths** read from repos, images, manifests, cloud APIs, or local configs and write findings into the control plane.
2. **Fleet ingest** persists workstation and collector inventory without requiring a shared privileged daemon across every endpoint.
3. **Proxy/runtime** stays near the MCP servers so enforcement is low-latency and least-privilege.
4. **Gateway** centralizes policy definition and auditability, and can also
   front shared remote MCP traffic when that is the better fit.
5. **Control plane** owns storage, graph views, remediation, audit review, and operator workflows.

That keeps request latency low, avoids a single giant runtime chokepoint, and
lets customers adopt only the surfaces they actually need.

## Recommended Deployment Choices

| Need | Recommended path |
|---|---|
| Run one scan locally | CLI |
| Gate pull requests and releases | GitHub Action |
| Keep runtime isolated for a single job | Docker |
| Self-host the operator plane for a team | API + UI + Postgres |
| Deploy in your own AWS / EKS | Helm control plane + scheduled scan jobs + selected proxy sidecars |
| Bring developer endpoints into the same plane | Fleet sync |
| Add live MCP enforcement | Proxy + gateway policy pull |
| Expose agent-bom as a tool server | MCP server |
| Add event-scale analytics | ClickHouse alongside the control plane |
| Use warehouse-native governance workflows | Snowflake with explicit backend parity limits |

## What Operators See After Deploy

The deployment story should end in usable operator surfaces, not just pods and
YAML.

**Risk overview**

![agent-bom dashboard](https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/dashboard-live.png)

**Fleet and graph visibility**

![agent-bom agent mesh](https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/mesh-live.png)

**Remediation workflow**

![agent-bom remediation view](https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/remediation-live.png)

## Start Here

- [AWS Company Rollout](aws-company-rollout.md)
- [Your Own AWS / EKS](own-infra-eks.md)
- [Enterprise MCP / Endpoint Pilot](enterprise-pilot.md)
- [Endpoint Fleet](endpoint-fleet.md)
- [When To Use Proxy vs Gateway vs Fleet](proxy-vs-gateway-vs-fleet.md)
- [Focused EKS MCP Pilot](eks-mcp-pilot.md)
- [Packaged API + UI Control Plane](control-plane-helm.md)
- [Snowflake POV Deployment Runbook](snowflake-pov.md)
- [Performance, Sizing, and Benchmarks](performance-and-sizing.md)
- [Visual Leak Detection](visual-leak-detection.md)
- [Worker and Scheduler Concurrency](worker-and-scheduler-concurrency.md)
- [Gateway Auto-Discovery From the Control Plane](gateway-auto-discovery.md)
- [Backend Parity](backend-parity.md)

## Hosting and Storage Boundaries

`agent-bom` is deployable in multiple honest ways:

- **Local laptop / workstation**: CLI or `agent-bom serve` with SQLite
- **Self-hosted VM / container**: `agent-bom api` or `agent-bom serve` behind
  your ingress and auth
- **Docker Compose / container platforms**: packaged API, proxy, or MCP server
- **Kubernetes / Helm**: control plane, scanner, optional runtime monitor, and
  operator surfaces
- **Postgres / Supabase**: primary transactional backend
- **ClickHouse**: analytics add-on
- **Snowflake**: warehouse-native governance surface with explicit parity
  limits, not the default full hosting contract

Default guidance:

- **Postgres** is the normal self-hosted control-plane answer
- **ClickHouse** is the first analytics add-on when event volume grows
- **Snowflake** is an explicit advanced path, not the default production recommendation

For the detailed backend matrix, see [Backend Parity Matrix](backend-parity.md).
