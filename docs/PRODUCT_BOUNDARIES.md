# Product Boundaries

This is the GitHub-facing companion to
`site-docs/deployment/product-boundaries.md`.

`agent-bom` has three current product lanes:

| Lane | Shipped today | Boundary |
|---|---|---|
| OSS | CLI, Docker, GitHub Action, reports, SBOM/SARIF/HTML/JSON, graph exports, MCP tools, local API/UI pilot | no hosted service or vendor telemetry required |
| Self-hosted enterprise | API/UI, Helm, Postgres/Supabase, auth/RBAC, tenant isolation, audit, graph, fleet, selected runtime proxy/gateway controls | operated in the customer's infrastructure |
| Snowflake | Snowflake discovery, CIS/posture evidence, Native App packaging, selected backend paths | governance and warehouse-native lane, not full transactional parity for every feature |

Managed `agent-bom Cloud` is not shipped in this repository today. It can be
discussed as a roadmap lane only when labeled that way.

## First Proofs

OSS local scanner:

```bash
agent-bom agents --demo --offline
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
agent-bom agents --snowflake --format json --output snowflake-inventory.json
```

Artifact: read-only Snowflake evidence visible to the configured role.

## Copy Rules

Use:

- "open security scanner and self-hosted control plane"
- "open security data plane for AI-era infrastructure"
- "customer-owned infrastructure and data boundary"
- "Snowflake Native App lane"
- "managed cloud is not shipped today"

Avoid unless a future release proves it:

- "managed agent-bom Cloud is available"
- "Snowflake is the full control-plane backend"
- "drop-in commercial CNAPP replacement"
- "complete CNAPP"
- "all cloud identity providers have live ingestion parity"

See the site-docs page for the full lane matrix and release checklist.
