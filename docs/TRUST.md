# Trust and deployment boundary

One-page reference for buyers and operators evaluating **agent-bom** in their
own environment. For product lanes and hosted POC limits see
[`PRODUCT_BOUNDARIES.md`](PRODUCT_BOUNDARIES.md).

## What runs where

| Component | Default location | Customer control |
|---|---|---|
| CLI scanner | Workstation / CI runner | Customer executes; no hosted dependency |
| Control plane API + UI | Customer VPC / cluster / laptop | Self-hosted Helm, Docker, or local `agent-bom api` |
| Graph + findings store | Customer SQLite or Postgres | Data never leaves the configured boundary |
| Runtime proxy / gateway | Customer network path | Optional enforcement lane; fail-closed by policy |
| Vulnerability intel | OSV/GHSA/NVD when online; bundled demo DB offline | Network egress is operator-controlled |

Managed multi-tenant SaaS is **not** shipped from this repository. Gated hosted
POC environments exist only for limited evaluation and are labeled as demo
estate data.

## Tenant isolation

- Every API request resolves a **tenant id** (header, session, or trusted-proxy
  binding). Cross-tenant reads and writes are rejected.
- Postgres deployments can enable row-level security policies; SQLite pilots use
  separate files per environment.
- API keys, OIDC sessions, SAML assertions, and SCIM tokens are validated
  before route handlers run. Anonymous access is opt-in for local development
  only.
- Audit log entries are append-only and can be signed for tamper evidence
  (see compliance export paths).

## What we store (and do not)

**Stored:** inventory metadata, advisory-backed findings, graph nodes/edges,
credential **names** and refs, compliance control mappings, runtime event
metadata, audit actions.

**Not stored by default:** plaintext secrets, cloud API secret values, raw model
weights, or buyer source code (unless explicitly scanned from a path the
operator provides).

Redaction and `sanitize_error` / `sanitize_text` guards apply on API and log
paths so raw exceptions do not leak paths, ARNs, or connection strings.

## How evidence is derived

1. **Discovery** — agents, MCP servers, packages, cloud connectors, fleet
   heartbeats.
2. **Reachability** — symbol/graph reach, effective reach bands, runtime
   observed/blocked tool calls.
3. **Posture** — CNAPP-style overlays, IAM effective permissions, governance
   drift.
4. **Export** — JSON, CSV, Parquet, SARIF, CycloneDX, and signed compliance
   bundles share the same underlying finding rows (`framework_tags` parity on
   API/CSV/Parquet).

The finding drawer **Why it matters** block summarizes reach, runtime state,
blast radius, and compliance tags so operators do not have to read four screens
to prioritize.

## First proof commands

```bash
# Local scanner (no network)
agent-bom agents --demo --offline

# Release smoke (install → scan → export)
./scripts/release_smoke.sh

# Labeled control plane estate
agent-bom api --demo-estate --allow-insecure-no-auth
```

Artifact: terminal findings, dashboard queue/graph/runtime surfaces, exportable
reports. Demo estates are watermarked **Demo data — simulated estate** in the UI.

## Verification hooks

| Check | Command |
|---|---|
| Release smoke | `./scripts/release_smoke.sh` |
| Pre-tag consistency | `scripts/preflight_release.sh` |
| Pilot install | `scripts/pilot-verify.sh <url> <api-key>` |
| Product screenshots | `cd ui && npm run capture:product-proof` |

## Questions this page answers

| Question | Answer |
|---|---|
| Is inventory accurate? | Advisory-backed CVE matching + reproducible `--demo --offline` path with regression tests |
| Is data isolated? | Tenant-scoped stores; auth-by-default API |
| What runs in my cloud? | Everything except optional external intel fetches you enable |
| Can I export for audit? | CSV/Parquet/SARIF/compliance bundles from the same finding model |

For step-by-step onboarding see [`FIRST_RUN.md`](FIRST_RUN.md).

## Related docs

- [`TRUST.md`](TRUST.md) — tenant boundary, evidence derivation, verification hooks
- [`PRODUCT_BOUNDARIES.md`](PRODUCT_BOUNDARIES.md) — OSS vs self-hosted vs hosted POC lanes
