# Product Boundaries

This is the GitHub-facing companion to
`site-docs/deployment/product-boundaries.md`. For the lanes stated together with
their cost posture, see [EDITIONS.md](EDITIONS.md) — the canonical editions page.
This page is the boundary and copy-rules reference.

`agent-bom` has three current product lanes:

| Lane | Shipped today | Boundary |
|---|---|---|
| OSS | CLI, Docker, GitHub Action, reports, SBOM/SARIF/HTML/JSON, graph exports, MCP tools, local API/UI pilot | no hosted service or vendor telemetry required |
| Self-hosted enterprise | API/UI, Helm, Postgres/Supabase, auth/RBAC, tenant isolation, audit, graph, fleet, selected runtime proxy/gateway controls | operated in the customer's infrastructure |
| Snowflake | Snowflake discovery, CIS/posture evidence, Native App packaging, selected backend paths | governance and warehouse-native lane, not full transactional parity for every feature |
| Gated hosted POC | A small operator-run demo environment for customer-0 proof | limited-access evaluation only; not generally available managed SaaS |

Managed `agent-bom Cloud` is not shipped in this repository today. It can be
discussed as a roadmap lane only when labeled that way.

Current detection positioning:

- CSPM/CIS, vuln/SCA, compliance evidence, IaC posture, scheduled connected
  account scans, and graph-backed attack paths are demo-ready.
- Scheduled scans are cadence-bound polling. They are not real-time provider
  event streaming.
- DSPM is real only where the configured source exposes data governance
  metadata, grants, tags, and lineage today, with Snowflake as the strongest
  lane. Full DSPM across cloud object stores and databases still requires
  classifier-backed content inspection and access-to-data mapping.

## First Proofs

OSS local scanner:

```bash
agent-bom scan --demo --offline
```

Artifact: terminal findings and graph-ready inventory.

Self-hosted enterprise:

```bash
helm template agent-bom deploy/helm/agent-bom \
  -f deploy/helm/agent-bom/examples/eks-production-values.yaml
```

Artifact: production-shaped Kubernetes manifests for the customer boundary.

Snowflake:

```bash
agent-bom scan --snowflake --format json --output snowflake-inventory.json
```

Artifact: read-only Snowflake evidence visible to the configured role.

## Copy Rules

Use:

- "open security scanner and self-hosted control plane"
- "open security data plane for AI-era infrastructure"
- "customer-owned infrastructure and data boundary"
- "scheduled posture monitoring"
- "Snowflake-depth data governance evidence"
- "Snowflake Native App lane"
- "gated hosted POC"
- "managed cloud is not shipped today"

Avoid unless a future release proves it:

- "managed agent-bom Cloud is available"
- "Snowflake is the full control-plane backend"
- "drop-in commercial CNAPP replacement"
- "complete CNAPP"
- "full DSPM across every cloud"
- "real-time cloud event detection" unless event ingestion is enabled
- "all cloud identity providers have live ingestion parity"

See the site-docs page for the full lane matrix and release checklist.

Trust boundary and verification hooks: [`TRUST.md`](TRUST.md).
Publication and operator-private custody: [`PUBLICATION_POLICY.md`](PUBLICATION_POLICY.md).
