# Enterprise MCP / Endpoint Pilot

This is the canonical `agent-bom` pilot shape for a company that wants one
open-source control plane for:

- employee endpoint fleet visibility
- server-side MCP visibility in EKS
- gateway policy management
- selected inline proxy enforcement

It is intentionally not an EDR-style managed agent product. The current
contract is opt-in endpoint scans plus self-hosted control-plane and proxy
surfaces.

## Scope

```mermaid
flowchart LR
    subgraph EndpointFleet["Endpoint fleet"]
      Cursor["Cursor / Windsurf / Cline"]
      Claude["Claude Desktop / Claude Code"]
      VSCode["VS Code / Copilot / Continue / Roo / Amazon Q / Cortex Code"]
      Scan["agent-bom agents --preset enterprise --introspect --push-url .../v1/fleet/sync"]
      Cursor --> Scan
      Claude --> Scan
      VSCode --> Scan
    end

    subgraph RuntimeFleet["Runtime fleet on EKS"]
      Cron["Scanner CronJob"]
      Sidecars["Selected MCP sidecars"]
      Workloads["In-cluster MCP workloads"]
      Workloads --> Cron
      Workloads --> Sidecars
    end

    subgraph ControlPlane["Self-hosted control plane"]
      API["FastAPI API"]
      UI["Next.js UI"]
      Gateway["Gateway policy UI/API"]
      Audit["Audit + findings + fleet stores"]
      API --> Gateway
      API --> Audit
      UI --> API
    end

    subgraph DataPlane["Persistence"]
      PG["Postgres / Supabase"]
      CH["ClickHouse (optional analytics)"]
    end

    Scan --> API
    Cron --> API
    Sidecars --> API
    API --> PG
    API --> CH
```

## Enterprise deployment topology

Everything agent-bom ships runs inside one trust boundary — the customer's
VPC, EKS account, or self-managed cluster. The only arrows that cross that
boundary are OIDC (inbound, terminated at ingress) and policy-audited MCP
upstream calls (outbound). Enrichment to OSV/NVD is optional and
allow-listable.

| Layer | Lives in | Scales via | Talks to |
|---|---|---|---|
| **Ingress + auth** | ALB / Istio Gateway + OIDC | — | Corporate IdP (Okta / Entra / Google) |
| **Runtime MCP plane** | `gateway` + selected `proxy` sidecars / local wrappers | HPA + PDB | Remote MCPs, `/v1/proxy/audit` |
| **Control plane** | `api`, `ui`, `jobs`, `backup` (Helm) | HPA + CronJob | Data plane, OTEL, Prometheus |
| **Data plane** | Customer-owned Postgres (+ optional ClickHouse, S3) | Operator-managed | — |
| **Platform glue** | ExternalSecrets, ServiceMonitor, OTEL collector | Operator-managed | AWS Secrets Manager / Vault / Grafana |

```mermaid
flowchart LR
    subgraph outside["Outside customer-owned infrastructure"]
      idp["Corporate IdP<br/>Okta · Entra · Google"]
      ci["CI / scheduled jobs"]
      remote["Approved remote MCPs"]
      osv["OSV / NVD / GHSA<br/>optional enrichment"]
    end

    subgraph customer["Customer VPC / cluster / account"]
      ingress["Ingress + TLS + SSO"]

      subgraph control["Agent-BOM control plane"]
        ui["UI"]
        api["API"]
        jobs["Scan / ingest jobs"]
        backup["Backup / scheduler"]
      end

      subgraph runtime["Runtime MCP plane"]
        proxy["agent-bom proxy<br/>sidecar or local wrapper"]
        gateway["agent-bom gateway"]
      end

      subgraph data["Customer-owned data stores"]
        pg["Postgres"]
        ch["ClickHouse<br/>optional analytics"]
        s3["Object storage<br/>optional backups / archive"]
      end

      subgraph ops["Platform glue"]
        secrets["Secrets manager"]
        metrics["Telemetry / monitoring"]
      end
    end

    idp -. OIDC .-> ingress
    ingress --> ui
    ingress --> api
    ingress -. optional shared runtime URL .-> gateway
    ci --> jobs
    jobs --> api
    proxy --> gateway
    gateway --> api
    gateway --> remote
    api --> pg
    api -. analytics .-> ch
    backup --> s3
    secrets --> api
    secrets --> gateway
    api --> metrics
    gateway --> metrics
    api -. enrichment .-> osv
```

*Everything inside the customer boundary runs in the customer's account. The
default cross-boundary paths are inbound OIDC and outbound, policy-audited MCP
upstream calls.*

### Runtime MCP flow in customer infra

```mermaid
flowchart LR
    dev["Developer client or MCP-enabled workload"]
    proxy["Local / sidecar<br/>agent-bom proxy"]
    gateway["In-cluster<br/>agent-bom gateway"]
    api["Control-plane API"]
    store["Postgres / audit store"]
    remote["Approved remote MCP"]

    dev -->|"MCP JSON-RPC"| proxy
    proxy -->|"inspect + local policy"| gateway
    gateway -->|"shared policy + relay"| remote
    remote --> gateway
    gateway -->|"response"| proxy
    proxy -->|"safe response"| dev
    gateway -->|"POST /v1/proxy/audit"| api
    api --> store
```

1. Developer client speaks MCP JSON-RPC to the local `agent-bom proxy`.
2. The proxy inspects and audits the call, enforces local policy, and relays
   to the central `agent-bom gateway`.
3. The gateway applies shared policy, records audit to `/v1/proxy/audit`, and
   forwards to the remote MCP upstream.
4. Responses come back on the same path; image responses can run through the
   visual leak detector before they reach the developer.
5. The control plane persists audit, findings, and graph state for the UI,
   exports, and compliance surfaces.

## Control flow

```mermaid
sequenceDiagram
    participant Admin as Security admin
    participant UI as /gateway UI
    participant API as Control-plane API
    participant Proxy as agent-bom proxy
    participant MCP as MCP server

    Admin->>UI: Create / update policy
    UI->>API: POST /v1/gateway/policies
    API-->>UI: ETag + persisted policy
    Proxy->>API: GET /v1/gateway/policies?enabled=true
    API-->>Proxy: Cached policy bundle
    Proxy->>MCP: Forward allowed JSON-RPC
    Proxy-->>API: POST /v1/proxy/audit
    API-->>UI: Fleet / findings / audit visible
```

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
