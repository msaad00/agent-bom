# Deployment Overview

Use this page when the question is not "how do I install `agent-bom`?" but
"what do I actually deploy in my own infrastructure, and what data path does it
create?"

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
helm upgrade --install agent-bom deploy/helm/agent-bom \
  --namespace agent-bom --create-namespace \
  -f deploy/helm/agent-bom/examples/eks-production-values.yaml
```

`agent-bom` is intentionally packaged as interoperable surfaces, not a forced
monolith:

- **scan** for discovery, inventory, CVE analysis, IaC, image, and cloud checks
- **fleet** for persisted endpoint and collector inventory
- **proxy / runtime** for inline MCP inspection and enforcement
- **gateway** for central runtime policy distribution and evaluation
- **API + UI** for operator review, audit, graph, remediation, and control-plane workflows
- **MCP server mode** when you want `agent-bom` itself exposed as tools

The published container split follows the same model:

- `agentbom/agent-bom` is the main runtime image for CLI, API, jobs, gateway,
  proxy-related entrypoints, and MCP server mode
- `agentbom/agent-bom-ui` is only the standalone browser UI image used when the
  control plane runs the UI separately from the API

## What You Can Offer In Customer-Controlled Infra

This is the current code-backed self-hosted story:

| Surface | What the customer deploys | What it does |
|---|---|---|
| **agent-bom Scan** | CronJobs, CI runners, one-off jobs, endpoint CLI runs | Discovers agents, MCP servers, packages, images, IaC, Kubernetes, and cloud assets; writes findings and graph state |
| **agent-bom Fleet** | Endpoint collectors or workstation CLI pushes | Persists inventory and scan history into the control plane without requiring a separate endpoint daemon product |
| **agent-bom Proxy** | Sidecar or local wrapper near selected MCP servers | Enforces allow/warn/deny policy, detects credential exposure, blocks undeclared tools, emits signed audit logs, and can fail closed on tampered cached policy bundles |
| **agent-bom Gateway** | Shared remote MCP traffic plane plus policy/audit surface | Stores, serves, and audits the policies consumed by proxies and managed runtime paths |
| **agent-bom Runtime** | Proxy + audit + policy pull + event persistence | Gives runtime visibility without forcing all traffic through one shared chokepoint |
| **agent-bom Control Plane** | API + UI + Postgres, with optional ClickHouse | Presents findings, graph, remediation, fleet review, audit, and policy management from one operator-owned plane |

## Enterprise Deployment Promise

This self-hosted shape is designed around a few explicit operating principles:

- **Customer-controlled hosting**: no mandatory vendor control plane and no mandatory SaaS dependency
- **Zero-trust access**: OIDC, SAML, API keys, RBAC, tenant propagation, quotas, and signed audit trails
- **Least privilege**: read-only discovery roles where possible, selected proxy enforcement only where needed
- **Low latency**: runtime inspection stays close to the MCP workloads instead of hairpinning through a global gateway
- **Cheap by default**: scan workers scale to zero, offline vuln DB reduces repeated network lookups, ClickHouse stays optional
- **Interoperable**: one shared graph and policy model spans scanner, proxy, gateway, fleet, and API/UI

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

```mermaid
flowchart LR
    subgraph Customer["Customer-controlled infrastructure"]
      subgraph Sources["Scan and runtime surfaces"]
        CI["CI / scheduled scan jobs"]
        Endpoints["Developer laptops / workstations"]
        Proxy["agent-bom proxy<br/>local wrapper or sidecar"]
        LocalMCP["Selected local or in-cluster MCPs"]
        Gateway["agent-bom gateway<br/>shared remote MCP traffic"]
      end

      subgraph Plane["agent-bom control plane"]
        API["API + UI"]
        Fleet["Fleet inventory"]
        Policy["Gateway policy + audit"]
        Findings["Findings / graph / remediation"]
        PG["Postgres"]
        CH["ClickHouse optional"]
      end
    end

    subgraph Optional["Optional operator-enabled egress"]
      Remote["Remote MCPs"]
      Vuln["Vulnerability DB refresh"]
      Enrich["Enrichment / package metadata / webhooks / SIEM"]
    end

    CI -->|scan output| Findings
    Endpoints -->|fleet or results push| Fleet
    Proxy -->|inline runtime path| LocalMCP
    Proxy -->|policy pull + audit push| Policy
    Gateway -->|policy pull + audit push| Policy
    Gateway -->|shared remote MCP traffic| Remote
    Findings --> API
    Fleet --> API
    Policy --> API
    API --> PG
    API --> CH
    Findings -. optional .-> Vuln
    API -. optional .-> Enrich
```

By default, the control plane, job results, fleet inventory, graph snapshots,
remediation output, and proxy audit data stay inside the customer's
infrastructure. External egress only happens when the operator explicitly enables
it for catalog refresh, enrichment, registry lookups, SIEM export, OTLP, or
webhooks.

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
- [Focused EKS MCP Pilot](eks-mcp-pilot.md)
- [Packaged API + UI Control Plane](control-plane-helm.md)
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

For the detailed backend matrix, see [Backend Parity Matrix](backend-parity.md).
