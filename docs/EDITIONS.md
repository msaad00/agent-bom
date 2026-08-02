# Deployment lanes

This is the single canonical statement of which lanes exist and how to run them.
It folds together what used to be scattered across
[`PRODUCT_BOUNDARIES.md`](PRODUCT_BOUNDARIES.md),
[`DEPLOY_QUICKSTART.md`](DEPLOY_QUICKSTART.md), and
[`HOSTED_POC.md`](HOSTED_POC.md). For what to deploy in each lane, use the
[deployment decision matrix](../site-docs/deployment/overview.md).

## How it runs

**agent-bom is free and open source (Apache-2.0).** You run it in your own
boundary — laptop, cluster, or Snowflake account — and you pay only for the
infrastructure you already own.

## The lanes

| Lane | What ships | Boundary |
|---|---|---|
| **OSS** | CLI, Docker, GitHub Action, reports, SBOM/SARIF/HTML/JSON, graph exports, MCP tools, local API/UI pilot | no external service or vendor telemetry required |
| **Self-hosted** | API/UI, Helm, Postgres/Supabase, auth/RBAC, tenant isolation, audit, graph, fleet, selected runtime proxy/gateway controls | operated in your own infrastructure |
| **Snowflake** | Snowflake discovery, CIS/posture evidence, Native App packaging, selected backend paths | governance and warehouse-native lane, not full transactional parity for every feature |

## First proof per lane

**OSS local scanner** — free, no account:

```bash
agent-bom scan --demo --offline
```

**Self-hosted control plane** — one workstation pilot, free:

```bash
curl -fsSL https://raw.githubusercontent.com/msaad00/agent-bom/main/deploy/docker-compose.pilot.yml -o docker-compose.pilot.yml
docker compose -f docker-compose.pilot.yml up -d
# Dashboard -> http://localhost:3000
```

For production self-hosting (Helm / EKS Terraform), see the
[deployment decision matrix](../site-docs/deployment/overview.md).

**Snowflake** — read-only evidence in the customer's account:

```bash
agent-bom scan --snowflake --format json --output snowflake-inventory.json
```

## How this maps to deployment

| If you are... | Lane | Deploy |
|---|---|---|
| scanning a laptop or repo | OSS | `pip install agent-bom` |
| running a team demo | Self-hosted | docker compose pilot |
| going to production | Self-hosted | Helm / EKS Terraform |
| a Snowflake shop | Snowflake | SPCS / Native App |

## Related

- Boundary table and copy rules: [`PRODUCT_BOUNDARIES.md`](PRODUCT_BOUNDARIES.md)
- Connect-and-scan onboarding: [`DEPLOY_QUICKSTART.md`](DEPLOY_QUICKSTART.md)
- Product flow and differentiator: [`HOW_IT_WORKS.md`](HOW_IT_WORKS.md)
- Deployment decision matrix: [deployment overview](../site-docs/deployment/overview.md)
</content>
