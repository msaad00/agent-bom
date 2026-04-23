# Enterprise MCP / Endpoint Pilot

This is the canonical `agent-bom` pilot shape for a company that wants one
open-source control plane for:

- employee endpoint fleet visibility
- server-side MCP visibility in EKS
- gateway policy management
- selected inline proxy enforcement

If you still need to choose between pilot and production rollout paths, start
with [Deployment Overview](overview.md). This page is the narrower pilot guide
once you have already chosen that shape.

It is intentionally not an EDR-style managed agent product. The current
contract is opt-in endpoint scans plus self-hosted control-plane and proxy
surfaces.

## Scope

This pilot keeps the product surface narrow on purpose:

- employee endpoints push fleet and discovery state into the control plane
- scheduled scan jobs cover cluster, package, image, and MCP discovery
- selected MCP workloads get `agent-bom proxy` sidecars or local wrappers
- the control plane hosts API, UI, findings, audit, and gateway policy
- Postgres is required; ClickHouse stays optional

## Enterprise deployment topology

The canonical self-hosted topology and runtime/data-flow diagrams now live in
[Deployment Overview](overview.md#enterprise-self-hosted-diagrams).

Use that page first when you need the high-level shape:

- what runs in the customer VPC / EKS environment
- how scans, fleet, proxy, and gateway feed the control plane
- where auth, tenant scope, and audit are enforced

This pilot page stays focused on the narrower pilot contract:

- what is in scope for the endpoint + MCP pilot
- what is intentionally out of scope
- which rollout steps and security properties matter for a focused first deployment

## What is in scope

| Surface | Included in the pilot | Why |
|---|---|---|
| Endpoint fleet | Yes | Employee laptops push MCP and agent discovery into the shared control plane |
| Runtime fleet | Yes | EKS scanner + selected sidecars cover server-side MCPs |
| Gateway policies | Yes | Control-plane policy management is now linked to proxy pull |
| Proxy audit push | Yes | SOC sees blocks and warnings centrally |
| Same-origin UI | Yes | One ingress, one internal control plane |
| Postgres | Yes | Primary transactional backend for multi-replica pilots |
| ClickHouse | Optional | Bring it in once pilot event volume justifies it |
| Snowflake backend | No | Not part of the focused pilot contract |
| Managed endpoint agent | No | Still roadmap, not current product contract |
| MDM integration | No | Still roadmap |

## Security properties

- self-hosted API, UI, audit log, and Postgres stay in the company's infra
- OIDC, API keys, RBAC, and Postgres RLS are the control-plane boundary
- proxy policy pull and audit push are now real, not cosmetic
- gateway can now require an incoming bearer/API-key token for remote MCP clients
- screenshot OCR enforcement now fails closed when explicitly enabled without the visual runtime
- `AGENT_BOM_AUDIT_HMAC_KEY` is required for pilot sign-off
- the EKS pilot path assumes Pod Security Admission `restricted`
- focused pilot values lock ingress down instead of leaving it wide open

## Scale properties

- API is horizontally scalable behind Postgres-backed state
- scheduler leader election uses Postgres advisory locking
- endpoint fleet is batch-driven and scales to pilot size without a managed agent
- ClickHouse is available when pilot volume grows beyond what Postgres should carry for analytics
- sidecar proxy rollout stays workload-by-workload instead of forcing universal inline routing

For concrete sizing, autoscaling, and load-test guidance, use
[Performance, Sizing, and Benchmarks](performance-and-sizing.md).

## Required rollout steps

1. Run Postgres migrations.
2. Install the Helm control plane with the focused pilot values.
3. Label the namespace for Pod Security Admission `restricted`.
4. Start endpoint fleet scan-and-push on employee workstations.
5. Add proxy sidecars only to the MCP workloads you want inline enforcement on.

## Migration contract

Long-lived control-plane databases now have an Alembic baseline:

```bash
alembic -c deploy/supabase/postgres/alembic.ini upgrade head
```

If a database was already initialized from
[deploy/supabase/postgres/init.sql](https://github.com/msaad00/agent-bom/blob/main/deploy/supabase/postgres/init.sql),
stamp it once before future changes:

```bash
alembic -c deploy/supabase/postgres/alembic.ini stamp 20260416_01
```

Use `init.sql` for disposable bootstrap paths and local compose; use Alembic as
the authoritative migration path for long-lived enterprise control planes.
