# Editions and cost posture

This is the single canonical statement of which lanes exist and what they cost.
It folds together what used to be scattered across
[`PRODUCT_BOUNDARIES.md`](PRODUCT_BOUNDARIES.md),
[`DEPLOY_QUICKSTART.md`](DEPLOY_QUICKSTART.md), and
[`HOSTED_POC.md`](HOSTED_POC.md). For what to deploy in each lane, use the
[deployment decision matrix](../site-docs/deployment/overview.md).

## Cost posture, stated plainly

**Every lane that ships in this repository is free to run.** There is no
managed public SaaS and no paid tier in this repo yet. You run agent-bom in your
own boundary — laptop, cluster, or Snowflake account — and you pay only for the
infrastructure you already own.

This page describes cost *posture*, not prices. Where a lane's licensing is not
yet finalized, that is called out below rather than guessed.

## The lanes

| Lane | Cost today | What ships | Boundary |
|---|---|---|---|
| **OSS** | Free (open source) | CLI, Docker, GitHub Action, reports, SBOM/SARIF/HTML/JSON, graph exports, MCP tools, local API/UI pilot | no hosted service or vendor telemetry required |
| **Self-hosted** | Free to run today; a licensed enterprise tier is roadmap, not shipped | API/UI, Helm, Postgres/Supabase, auth/RBAC, tenant isolation, audit, graph, fleet, selected runtime proxy/gateway controls | operated in the customer's own infrastructure |
| **Gated hosted POC** | Free but access-gated (operator-run, invite only) | a small operator-run demo environment for customer-0 proof | limited-access evaluation only; not generally available managed SaaS |
| **Snowflake** | Free to run in the customer's account (customer pays Snowflake for compute) | Snowflake discovery, CIS/posture evidence, Native App packaging, selected backend paths | governance and warehouse-native lane, not full transactional parity for every feature |

Managed `agent-bom Cloud` is **not shipped in this repository today**. It can be
discussed as a roadmap lane only when labeled that way. Echoing the repo's own
language: OSS CLI, self-hosted API/UI, gated hosted POC, or optional
Snowflake-native lane — no managed public SaaS in this repo yet.

## First proof per lane

**OSS local scanner** — free, no account:

```bash
agent-bom agents --demo --offline
```

**Self-hosted control plane** — one workstation pilot, free:

```bash
curl -fsSL https://raw.githubusercontent.com/msaad00/agent-bom/main/deploy/docker-compose.pilot.yml -o docker-compose.pilot.yml
docker compose -f docker-compose.pilot.yml up -d
# Dashboard -> http://localhost:3000
```

For production self-hosting (Helm / EKS Terraform), see the
[deployment decision matrix](../site-docs/deployment/overview.md).

**Gated hosted POC** — operator-run, invite only. See
[`HOSTED_POC.md`](HOSTED_POC.md) for the runbook.

**Snowflake** — read-only evidence in the customer's account:

```bash
agent-bom agents --snowflake --format json --output snowflake-inventory.json
```

## How this maps to deployment

| If you are... | Lane | Deploy |
|---|---|---|
| scanning a laptop or repo | OSS | `pip install agent-bom` |
| running a team demo | Self-hosted | docker compose pilot |
| going to production | Self-hosted | Helm / EKS Terraform |
| a Snowflake shop | Snowflake | SPCS / Native App |
| evaluating a live URL without operating it | Gated hosted POC | request access |

## Related

- Boundary table and copy rules: [`PRODUCT_BOUNDARIES.md`](PRODUCT_BOUNDARIES.md)
- Connect-and-scan onboarding: [`DEPLOY_QUICKSTART.md`](DEPLOY_QUICKSTART.md)
- Product flow and differentiator: [`HOW_IT_WORKS.md`](HOW_IT_WORKS.md)
- Deployment decision matrix: [deployment overview](../site-docs/deployment/overview.md)
</content>
