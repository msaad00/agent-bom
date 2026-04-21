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
| **MCP traffic plane** | `gateway` + `proxy` Deployments | HPA + PDB | Remote MCPs, `/v1/proxy/audit` |
| **Control plane** | `api`, `ui`, `jobs`, `backup` (Helm) | HPA + CronJob | Data plane, OTEL, Prometheus |
| **Data plane** | Customer-owned Postgres (+ optional ClickHouse, S3) | Operator-managed | — |
| **Platform glue** | ExternalSecrets, ServiceMonitor, OTEL collector | Operator-managed | AWS Secrets Manager / Vault / Grafana |

```mermaid
flowchart TB
    subgraph outside["Outside customer trust boundary"]
      idp["Corporate IdP<br/>Okta · Entra · Google"]
      dev["Developer laptop<br/>Claude Desktop · Cursor · Claude Code"]
      gh["GitHub Actions / CI runner"]
      remote["Remote MCPs<br/>SaaS + partner tools"]
      osv["OSV / NVD / GHSA<br/>optional egress, allow-listable"]
    end

    subgraph vpc["Customer VPC / EKS account"]
      ingress["Ingress + TLS<br/>ALB / Istio Gateway"]

      subgraph traffic["Agent-Bom traffic plane in your EKS cluster"]
        px["MCP proxy<br/>sidecar or laptop wrapper<br/>stdio · SSE · HTTP"]
        gw["MCP gateway<br/>agent-bom gateway serve<br/>Deployment + HPA"]
      end

      subgraph control["Agent-Bom control plane in your EKS cluster"]
        ui["UI<br/>same-origin browser app"]
        api["API<br/>fleet · policy · audit · findings"]
        jobs["Scan + ingest workers<br/>CronJob + Job"]
        backup["Backup CronJob<br/>pg_dump -> S3"]
      end

      subgraph data["Customer-owned data plane"]
        pg["Postgres / Supabase<br/>jobs · fleet · graph · audit"]
        ch["ClickHouse (optional)<br/>analytics + long-retention"]
        s3["S3 (optional)<br/>backups + SBOM archive"]
      end

      subgraph platform["Platform integration in your account"]
        es["ExternalSecrets<br/>AWS SM / Vault"]
        otel["OTEL collector<br/>traces + metrics"]
        prom["Prometheus / ServiceMonitor"]
      end
    end

    idp -. OIDC .-> ingress
    ingress -->|"browser traffic"| ui
    ingress -->|"API + WS"| api
    ingress -->|"optional shared MCP URL"| gw

    dev -->|"MCP JSON-RPC"| px
    px -->|"audited relay"| gw
    gw -->|"policy-audited upstream call"| remote
    px -->|"/v1/proxy/audit"| api
    gw -->|"/v1/proxy/audit"| api

    gh -->|"SARIF + findings"| api
    jobs -->|"scan results + inventory"| api

    api -->|"transactional state"| pg
    api -. "optional analytics" .-> ch
    backup -->|"backup archive"| s3

    es -->|"runtime secrets"| api
    es -->|"runtime secrets"| gw
    api -->|"telemetry"| otel
    gw -->|"telemetry"| otel
    api -->|"metrics"| prom
    gw -->|"metrics"| prom
    api -. "optional enrichment egress" .-> osv
```

*Everything in the boundary runs in your account. Only OIDC (inbound) and
MCP upstream calls (outbound, policy-audited) cross it.*

### How an MCP call actually flows

1. Developer client (Claude Desktop / Cursor / Claude Code) speaks MCP
   JSON-RPC to the local `agent-bom proxy` (stdio or SSE).
2. The proxy inspects and audits the call, enforces policy, then relays to
   the central `agent-bom gateway` inside your cluster.
3. The gateway applies shared policy, records the audit event to
   `/v1/proxy/audit`, and forwards to the remote MCP upstream.
4. Responses flow back on the same path; screenshot/image responses run
   through the `VisualLeakDetector` for OCR-based redaction before the
   developer sees them.
5. Every hop emits OTEL spans with a W3C trace context, so a single trace
   ties developer → proxy → gateway → remote MCP → back.

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
