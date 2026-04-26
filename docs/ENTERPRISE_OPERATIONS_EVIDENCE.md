# Enterprise Operations and Procurement Evidence

This page is the release-facing evidence index for self-hosted enterprise
operations reviews. It connects the procurement packet to the concrete
deployment, backup, restore, air-gap, upgrade, support, and key-custody
evidence already shipped in the repo.

It is not a managed-service control claim. For self-hosted deployments, the
customer owns the cloud account, cluster, database, object store, IdP, KMS,
SIEM, incident process, DPA, and retention policy.

## Deployment Evidence Matrix

| Review question | Current answer | Evidence |
|---|---|---|
| What deployment modes are supported? | CLI, Docker, Compose, Helm/EKS, GitHub Action, endpoint rollout, and Snowflake-supported slices | `docs/ENTERPRISE_DEPLOYMENT.md`, `docs/DEPLOYMENT.md`, `deploy/docker-compose.yml`, `deploy/helm/agent-bom/` |
| Is the production path multi-replica capable? | Yes for Postgres-backed control planes; multi-replica API, UI, HPA, PDB, topology spread, and anti-affinity are packaged in Helm examples | `site-docs/deployment/control-plane-helm.md`, `deploy/helm/agent-bom/examples/eks-production-values.yaml` |
| Does the app fail closed for unsafe clustered state? | Yes for shared rate limiting, SCIM storage, browser session signing, and static-key clustered use | `docs/ENTERPRISE_DEPLOYMENT.md`, `tests/test_api_hardening.py` |
| Is mTLS supported? | Delegated ingress/sidecar/service-mesh mTLS posture is documented and reported; native app-terminated mTLS is tracked separately | `docs/ENTERPRISE_DEPLOYMENT.md`, `docs/ENTERPRISE_SECURITY_PLAYBOOK.md` |
| Are network boundaries packaged? | Helm chart includes NetworkPolicy and restricted pod settings; mesh hardening example adds Istio and Kyverno overlays | `deploy/helm/agent-bom/templates/networkpolicy.yaml`, `deploy/helm/agent-bom/examples/eks-istio-kyverno-values.yaml` |
| Is backup and restore tested? | Yes, Postgres dump, S3-compatible object store upload, restore script, disaster simulation, row-count verification, and tenant distribution check run in CI | `.github/workflows/backup-restore.yml`, `site-docs/deployment/backup-restore.md`, `deploy/ops/restore-postgres-backup.sh` |
| Is air-gapped import documented? | Yes, release images can be bundled, checksumed, loaded, and pushed to an internal registry | `.github/workflows/airgap-image-bundle.yml`, `site-docs/deployment/airgapped-image-bundle.md`, `scripts/release/build-airgap-image-bundle.sh` |
| Are release artifacts verifiable? | Yes, release verification covers signatures, provenance, SBOMs, and digest checks | `docs/RELEASE_VERIFICATION.md`, `docs/SUPPLY_CHAIN.md`, `.github/workflows/release.yml` |
| Are benchmark claims evidence-backed? | Target SLOs and harness scaffolding exist; published 1k/5k/10k results remain a separate issue | `docs/PERFORMANCE_BENCHMARKS.md`, `docs/perf/` |

## Trust Boundary and Data Flow Summary

| Boundary | Data entering agent-bom | Data leaving agent-bom | Primary controls |
|---|---|---|---|
| CLI scanner | local manifests, MCP configs, lockfiles, optional IaC and image metadata | reports selected by the operator | read-only scan behavior, path validation, output redaction |
| GitHub Action | repository manifests, configs, and generated SBOMs | SARIF, summaries, artifacts | pinned action, CI policy thresholds, dependency review, self-scan |
| Control-plane API | scan submissions, fleet sync, graph snapshots, policies, audit events | API responses, audit exports, compliance bundles | API key/OIDC/SAML/trusted-proxy auth, RBAC, scopes, tenant scoping |
| Runtime proxy and gateway | MCP tool calls, policy decisions, sandbox posture evidence | audit records, allow/block decisions, upstream MCP calls | inline detectors, policy engine, sandbox isolation, egress posture |
| Persistence layer | scan jobs, graph rows, fleet inventory, policy/audit state | tenant-scoped reads and exports | Postgres RLS, tenant filters, HMAC audit chain |
| External enrichment | package names, versions, advisory identifiers | OSV/NVD/EPSS/KEV responses | optional offline mode, cache TTLs, circuit breakers |
| Evidence exports | audit events, compliance findings, SBOMs, release metadata | signed bundles and report files | HMAC/Ed25519 signing posture, release provenance, operator retention |

## Encryption and Key Custody Matrix

| Material | Storage or transit path | Encryption and custody model |
|---|---|---|
| API traffic | ingress to control plane | operator TLS terminates at ingress, sidecar, or service mesh |
| Proxy identity headers | proxy to control-plane HTTP hop | trusted-proxy HMAC attestation plus optional delegated mTLS posture |
| Browser sessions | httpOnly cookies | `AGENT_BOM_BROWSER_SESSION_SIGNING_KEY`; clustered deployments fail closed without a persistent signing key |
| API keys | control-plane store | scrypt-hashed keys; plaintext key material is shown only at creation time |
| Audit chain | audit store and exports | `AGENT_BOM_AUDIT_HMAC_KEY`; optional require-HMAC mode and rotation posture |
| Compliance bundles | generated evidence bundle | HMAC fallback or Ed25519 signer when configured |
| Postgres data | customer database | customer-owned database encryption, backup encryption, and KMS policy |
| Backup archives | S3-compatible object store | Helm values support SSE or SSE-KMS; bucket retention/object lock are customer-owned |
| Container and release artifacts | registries and GitHub releases | image digests, Sigstore/cosign, SLSA, SBOM, checksum verification |
| OIDC/SAML/SCIM secrets | env vars or external secret manager | customer-owned KMS, Vault, Secrets Manager, External Secrets, or CSI driver |

## Backup, Restore, and DR Evidence

The packaged Postgres backup path is evidence-backed by a workflow that:

1. Starts Postgres and an S3-compatible object store.
2. Seeds tenant-bearing scan, finding, and audit rows.
3. Dumps the database with the same `pg_dump --format=custom` shape used by
   the Helm backup CronJob.
4. Uploads the dump to the object store.
5. Drops the tenant tables to simulate disaster.
6. Restores through `deploy/ops/restore-postgres-backup.sh`.
7. Verifies row counts and tenant distribution after restore.

Operational evidence to attach to a customer review:

- latest successful `Backup restore round-trip` workflow run
- configured backup bucket, region, prefix, encryption mode, and KMS key id
- restore-drill record with backup URI, start/end time, operator, approver, and
  measured data-loss window
- Postgres HA or managed database failover policy
- bucket versioning, lifecycle, object-lock, and retention policy
- incident approval record before restoring over production

The product supplies the CronJob, restore script, workflow proof, and runbook.
The customer supplies RPO/RTO targets, backup retention, object lock, failover
topology, and disaster-recovery approval process.

## Upgrade and Rollback Evidence

| Step | Evidence to collect |
|---|---|
| Pre-upgrade | release tag, commit SHA, image digests, Helm values diff, database backup URI |
| Schema readiness | Alembic target or schema-version posture where applicable |
| Rollout | Helm release history, deployment status, API `/health`, `/readyz`, `/v1/auth/policy` |
| Smoke test | tenant-scoped scan, graph read, audit export, browser/auth mode check |
| Rollback trigger | failed health checks, failed auth posture, failed tenant smoke test, or unacceptable SLO regression |
| Rollback action | `helm rollback`, database restore if schema changes require it, restart API/UI/gateway workers |
| Post-rollback | repeated smoke test, audit export, incident record, root-cause link |

For long-lived Postgres control planes, run migrations explicitly and keep the
pre-upgrade backup URI in the change ticket. Do not treat image rollback as a
database rollback when schema changes were applied.

## Air-Gap Evidence

For disconnected deployments, attach:

- source release tag and commit SHA
- `cosign verify` output for API and UI images
- bundle platform, filename, and checksum
- `manifests/images.txt`
- `manifests/sha256sums.txt`
- internal registry repository and post-push digest
- receiving operator, approver, import time, and target environment

The air-gap workflow produces transfer artifacts. The receiving environment
must still verify checksums before import and must apply its own registry
retention and access policy.

## Procurement Questionnaire Answers

| Question | Current answer |
|---|---|
| Is agent-bom a hosted SaaS today? | No. The current enterprise posture is self-hosted software operated by the customer. |
| Who owns customer data? | The operator/customer owns deployment data, cloud accounts, databases, object stores, logs, SIEM routing, and retention policy. |
| Does agent-bom store secrets? | It stores hashes or references where needed; secret values should live in customer-managed secret stores. Scanner output redacts credential values. |
| Does agent-bom support tenant isolation? | Yes, through tenant-aware API middleware, scoped stores, Postgres RLS posture, tenant-scoped audit/compliance exports, and cross-tenant regression tests. |
| Is there a public pentest report? | Not yet. `docs/PENTEST_READINESS.md` defines the scope and exit criteria for third-party validation. |
| Is SOC 2 complete? | No. The repo provides evidence mappings and technical controls, not a completed SOC 2 attestation. |
| Can a customer use its own KMS or Vault? | Yes for deployment custody through Kubernetes secrets, External Secrets, CSI, Vault, Secrets Manager, and database/object-store encryption; app-native rotation adapters remain tracked separately. |
| Are support SLAs included in OSS? | No. The support model documents vulnerability disclosure, patch intent, community support boundaries, and enterprise-support handoff points. |
| Are subprocessors listed? | For self-hosted use, infrastructure subprocessors are customer-owned. Product external calls are optional enrichment and registry sources documented in the trust model and supply-chain docs. |
| Are benchmark numbers published? | Harnesses and target SLOs exist; formal 1k/5k/10k results remain pending and should not be cited as completed evidence. |

## Release Packet Checklist

Before posting a release or sending a procurement packet, attach:

1. Exact release tag, commit SHA, image digests, and Helm chart version.
2. Release verification output for signatures, provenance, SBOMs, and checksums.
3. CI summary for CodeQL, gitleaks, dependency review, pip-audit, OSV, container scanning,
   self-scan, tests, and UI validation.
4. Backup/restore workflow run and latest customer restore drill.
5. Air-gap bundle output if disconnected import is in scope.
6. Auth posture output from `/v1/auth/policy`.
7. Secret lifecycle posture from `/v1/auth/secrets/lifecycle` and
   `/v1/auth/secrets/rotation-plan`.
8. Tenant-scoped audit export and compliance bundle for the release candidate.
9. Customer-owned IdP, KMS, SIEM, backup retention, DPA, and incident-response
   evidence.
10. Residual-risk statement naming any missing third-party attestation,
    benchmark, or managed-service control.
