# agent-bom

**Open security scanner for AI supply chain — agents, MCP servers, packages, containers, cloud, GPU, and runtime.**

Every CVE in your AI stack is a credential leak waiting to happen. `agent-bom`
follows the chain end-to-end and tells you which fix collapses it first.

Blast radius is the core idea:

```text
CVE -> package -> MCP server -> agent -> credentials -> tools
```

This container is the quickest way to run the same scanner, runtime surfaces,
and self-hosted operator path described in the main repository README.

## Image Model

`agent-bom` is one product with two deployable container images:

- **`agentbom/agent-bom`** — API/runtime image for CLI, API, scanner jobs, gateway, proxy, and MCP server mode
- **`agentbom/agent-bom-ui`** — UI companion image for the self-hosted control plane

Keep the split. The Python runtime surfaces and the Node UI have different
runtime, patch cadence, and scaling characteristics. They are companion images,
not separate products.

## Run This First

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

References:

- GitHub README: https://github.com/msaad00/agent-bom/blob/main/README.md
- Product brief: https://github.com/msaad00/agent-bom/blob/main/docs/PRODUCT_BRIEF.md
- Verified metrics: https://github.com/msaad00/agent-bom/blob/main/docs/PRODUCT_METRICS.md

## CLI And Runtime Quick Start

**Discover and scan your AI agent environment**

```bash
docker run --rm agentbom/agent-bom:latest agents
```

**Workstation posture summary**

```bash
docker run --rm agentbom/agent-bom:latest agents --posture
```

**Pre-install CVE check**

```bash
docker run --rm agentbom/agent-bom:latest check flask@2.0.0
```

**Scan a project directory**

```bash
docker run --rm -v "$(pwd):/workspace" agentbom/agent-bom:latest agents -p /workspace
```

**Export AI BOM (CycloneDX / SPDX)**

```bash
docker run --rm -v "$(pwd):/workspace" agentbom/agent-bom:latest agents -p /workspace -f cyclonedx -o /workspace/ai-bom.json
```

**IaC misconfiguration scan**

```bash
docker run --rm -v "$(pwd):/workspace" agentbom/agent-bom:latest iac /workspace
```

## What You Get

- Blast radius from package to server to agent to credentials and tools
- AI-native coverage across agents, MCP, runtime, containers, cloud, IaC, and GPU
- One operator path across CLI, CI, API, dashboard, remediation, and MCP tools
- Runtime MCP protection plus broader review and tamper-evident evidence exports

## Product Surfaces

The promoted self-hosted rollout is a scoped operator stack, not one forced
runtime monolith. Teams typically deploy only the surfaces they need:

- **scan**: discovery, inventory, CVE, image, IaC, Kubernetes, and cloud analysis
- **fleet**: endpoint and collector inventory pushed into the control plane
- **proxy / runtime**: inline MCP enforcement near selected workloads
- **gateway**: central policy management for those runtime paths
- **API + UI**: the operator plane for findings, graph, remediation, audit, and policy workflows

## Control-Plane Contract

The API is the source of truth for auth, tenant resolution, RBAC, quotas,
SCIM posture, fleet inventory, graph selectors, policy, secret posture, and
audit. UI displays that posture from the API instead of inventing a parallel
role or tenant model. MCP Gateway consumes the same tenant, policy, audit,
secret-manager, and lifecycle posture model as the API. CLI and local MCP
modes stay low-friction, but label local/dev behavior clearly when they are not
enterprise-controlled.

Helm, EKS examples, Docker metadata, and GitHub Actions should expose the same
environment variable names, fail-closed defaults, and required checks. The
runtime image and UI image are separate deployment units for scaling and patch
cadence, not separate security products.

## OTEL and Policy

`agent-bom` already supports OpenTelemetry as a real interoperability surface:

- API request tracing with W3C trace context
- OTLP export for operator telemetry
- OTEL trace ingest through `/v1/traces`
- runtime workflows that consume OTEL traces as evidence

Policy is native by default. The shipped gateway and proxy use the repo's JSON
policy engine, not an embedded OPA/Rego runtime. That is intentional: one
shared policy model across scan, gateway, proxy, and runtime, without adding an
extra policy binary to the operator stack.

The right enterprise story is:

- OTEL is first-class today
- native JSON policy remains the default
- OPA/Rego is an optional future interoperability path, not the core engine

## Deploy In Your Own Infra

`agent-bom` is designed to run inside your own AWS account, VPC, EKS cluster,
IAM boundary, databases, and SSO stack.

Recommended shape:

- stateless API + UI deployments behind your ingress
- Postgres for transactional state and graph metadata
- optional ClickHouse only when audit and analytics volume justifies it
- scheduled scan jobs for cluster, image, and discovery work
- endpoint fleet sync for laptops and collectors
- selected `agent-bom proxy` sidecars or local wrappers for the MCP workloads that need inline enforcement
- gateway-backed policy pull so runtime controls stay centralized without hairpinning all traffic through one shared chokepoint

Everything stays in your infrastructure by default; optional egress for DB
refresh, enrichment, SIEM, OTLP, and webhooks is operator-controlled.

## Security Posture

- HTTPS for every external hop
- private in-cluster traffic or service-mesh mTLS for internal hops
- auth on every non-loopback control-plane surface
- production profiles set `AGENT_BOM_DISABLE_DOCS=1` so `/docs`, `/redoc`, and `/openapi.json` are not exposed as unauthenticated helper routes
- shared control-plane profiles set `AGENT_BOM_API_LOCAL_PATH_SCANS=disabled`; enable API-local filesystem scans only for an explicit single-tenant mounted workspace
- RBAC and tenant scoping on sensitive routes
- rate limiting, audit trails, and signed release artifacts
- HMAC-backed tamper evidence for exported bundles

## Dashboard Views

Dashboard overview:

![agent-bom dashboard overview](https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/dashboard-live.png)

Attack paths and exposure:

![agent-bom dashboard attack paths and exposure](https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/dashboard-paths-live.png)

Focused graph:

![agent-bom focused graph](https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/mesh-live.png)

## Tags

| Tag | Description |
|-----|-------------|
| `latest` | Most recent stable release |
| `0.82.3` | Current stable version (pinned) |

Published images:

- `agentbom/agent-bom` — main runtime image for CLI scans, API/control-plane
  jobs, gateway, proxy-adjacent entrypoints, and MCP server mode
- `agentbom/agent-bom-ui` — standalone Next.js browser UI image for
  self-hosted deployments that run the UI separately from the API

For local Docker Compose examples, the repo may use local-built image aliases
such as `agent-bom:latest` and `agent-bom-ui:latest`. Those are compose-facing
names for local builds from this repo, not a second published product line.

## Links

- GitHub: https://github.com/msaad00/agent-bom
- PyPI: https://pypi.org/project/agent-bom/
- Docs: https://msaad00.github.io/agent-bom/
- GitHub Action: https://github.com/marketplace/actions/agent-bom
