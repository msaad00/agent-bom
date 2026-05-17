# Product Boundaries

This page defines the current `agent-bom` product lanes so public docs, demos,
PRs, and buyer conversations use the same vocabulary.

The short version:

- **OSS** is the open scanner, CLI, reports, MCP tools, API, and local control
  plane components in this repository.
- **Self-hosted enterprise** is the same product operated in the customer's
  infrastructure with Postgres/Supabase, Helm, auth, tenant isolation, audit,
  fleet, graph, and selected runtime controls.
- **Snowflake** is a warehouse-native governance and deployment lane for
  customers who already govern data in Snowflake. It is not the default
  transactional control-plane backend for every feature.
- **Managed agent-bom Cloud is not shipped in this repository today.**

## Lane Matrix

| Lane | First command | Artifact | Current boundary |
|---|---|---|---|
| OSS local scanner | `agent-bom agents --demo --offline` | terminal findings, JSON/HTML/SARIF/SBOM, graph exports | runs locally or in CI; no hosted service required |
| OSS MCP tools | `agent-bom mcp server` | strict-args read-only tools for agents | agent-callable security surface; no remote control plane required |
| OSS API/UI pilot | `agent-bom serve --host 127.0.0.1 --port 8000` | local API and browser cockpit | single-node pilot or demo; use auth for non-loopback binds |
| Self-hosted enterprise | `helm template agent-bom deploy/helm/agent-bom -f deploy/helm/agent-bom/examples/eks-production-values.yaml` | production-shaped Kubernetes manifests | customer VPC/Kubernetes/database/IdP/audit boundary |
| Snowflake POV | `agent-bom agents --snowflake` | Snowflake inventory and posture evidence visible to the configured role | read-only Snowflake discovery, governance, and selected backend paths |
| Snowflake Native App | follow `docs/snowflake-native-app/INSTALL.md` | customer-account Snowflake deployment package | Snowflake-account deployment lane; not a replacement for every API/UI store |

## OSS

OSS is the default adoption path and should remain useful without a hosted
service.

What is shipped:

- CLI scans, local reports, SARIF, SBOM, HTML, JSON, and graph exports
- GitHub Action and Docker entry points
- read-only MCP tool server with strict argument validation
- local API/UI pilot mode
- skills scanning and policy-aware CI gates
- graph-backed `ExposurePath` output for humans and agents

What is not implied:

- no managed `agent-bom Cloud` account is created by installing the package
- no vendor telemetry is required for local scans
- no dashboard is required for CI or MCP use

## Self-Hosted Enterprise

Self-hosted enterprise is the production control-plane lane for customers that
need central inventory, graph state, audit, auth, governance, and runtime
controls inside their own boundary.

What is shipped:

- API and dashboard deployment paths
- Helm profiles and Docker Compose pilot profiles
- Postgres/Supabase transactional stores for broad control-plane coverage
- auth, RBAC, tenant scope, audit, evidence, fleet, graph, and policy surfaces
- runtime proxy/gateway patterns for selected MCP enforcement paths
- local entitlement metadata hooks for support/SLA and future commercial
  feature visibility

Recommended first proof:

```bash
helm template agent-bom deploy/helm/agent-bom \
  -f deploy/helm/agent-bom/examples/eks-production-values.yaml
```

Artifact:

- rendered Kubernetes manifests that show the API/UI, database, auth, runtime,
  and operational settings that would be applied in the customer's cluster

Next step:

- bind the deployment to the customer's IdP, Postgres/Supabase, ingress, audit
  log retention, and selected scan or runtime sources

What is not implied:

- the repo does not ship a managed multi-tenant vendor cloud service today
- SQLite is not the recommended clustered enterprise store
- API-local filesystem scans should stay disabled in shared EKS-style control
  planes unless an explicit tenant workspace is mounted
- local entitlement metadata does not make outbound licensing calls and does
  not gate current OSS scanner or control-plane functionality

### Local Entitlement Metadata

Self-hosted packages can set `AGENT_BOM_ENTITLEMENT_FILE` to a local JSON file
so admins and health checks can see support/SLA and enabled commercial metadata
without contacting a vendor service.

Example:

```json
{
  "lane": "self-hosted-enterprise",
  "features": ["support.sla", "retention.extended"],
  "support": {
    "tier": "enterprise",
    "sla": "business-hours"
  },
  "expires_at": "2027-01-01T00:00:00Z"
}
```

Operator surfaces:

- `GET /health` includes an entitlement summary.
- `GET /v1/entitlements` returns the full local metadata state for admins.
- `GET /v1/entitlements/check/{feature}` evaluates one feature and appends an
  audit entry.

Boundary:

- Missing metadata returns `status: missing` and keeps OSS paths usable.
- Invalid or expired metadata returns `status: invalid` or `status: expired`
  and disables only commercial metadata features.
- The current implementation is metadata-only. It is not hosted billing,
  telemetry, or a mandatory license check.

## Snowflake

Snowflake is a lane for organizations that already use Snowflake as a
governance, evidence, or security-lake boundary.

What is shipped:

- Snowflake discovery from the CLI when credentials are configured
- Snowflake CIS and posture evidence surfaces
- Snowflake Native App packaging and deployment guidance
- selected Snowflake-backed store paths where the code and backend parity docs
  say parity exists

Recommended first proof:

```bash
agent-bom agents --snowflake --format json --output snowflake-inventory.json
```

Artifact:

- a local JSON evidence file for the account, role, warehouse, and schemas
  visible to the configured read-only Snowflake role

Next step:

- for a customer-account deployment, follow
  `docs/snowflake-native-app/INSTALL.md` and validate the exact enabled
  features against `site-docs/deployment/backend-parity.md`

What is not implied:

- Snowflake is not the default transactional backend for every API/UI workflow
- Snowflake Native App does not remove the need to document role grants,
  warehouse boundaries, and customer-owned retention
- Snowflake support does not mean `agent-bom` claims full CNAPP parity with a
  proprietary cloud platform

## Managed Cloud Boundary

Managed `agent-bom Cloud` is a roadmap lane, not a shipped repository feature.

It is acceptable to describe a future managed lane as:

- managed operations for the same scanner and graph primitives
- optional hosted scale for teams that do not want to run the control plane
- customer-controlled data and explicit telemetry boundaries

It is not acceptable to describe it as shipped until there is code, deployment
evidence, billing or tenant isolation evidence, and release documentation for
that lane.

## Copy Rules

Use these phrases:

- "open security scanner and self-hosted control plane"
- "open security data plane for AI-era infrastructure"
- "deploys in the customer's infrastructure"
- "Snowflake Native App lane" or "Snowflake-backed selected paths"
- "managed cloud is not shipped today"

Avoid these phrases unless a future release proves them:

- "agent-bom Cloud is available"
- "Snowflake is the full control-plane backend"
- "drop-in Wiz replacement"
- "complete CNAPP"
- "all UI workflows are fully persisted"
- "all cloud identity providers have live ingestion parity"

## Release Checklist

Before a release or demo repeats product-lane claims, verify:

- README and Docker Hub README mention the same lane boundaries
- `site-docs/deployment/backend-parity.md` still matches the backend claim
- Helm, Docker, CLI, and Snowflake first commands still work or have a stated
  reason they were not rerun
- screenshots use the shipped UI and current real or fixture-backed data
- roadmap items remain labeled as roadmap items
