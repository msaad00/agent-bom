# Enterprise Control Mapping

This page maps common procurement and audit questions to implemented
`agent-bom` controls. It is an evidence index, not a certification claim.
Auditors should validate the linked code, tests, workflows, and deployment
settings in the customer environment.

## How To Use This Map

1. Confirm the deployed mode: scan-only, API/UI control plane, gateway, proxy,
   or full self-hosted EKS.
2. Collect the evidence links listed below from the exact release tag in use.
3. Export tenant-scoped evidence from the API when applicable.
4. Attach operator-owned controls such as IdP policy, cloud KMS policy,
   network policy, backup retention, and support process.

## Evidence Collection

| Evidence | Product path | Primary implementation |
|---|---|---|
| Tenant-scoped audit export | `GET /v1/audit/export` | `src/agent_bom/api/routes/enterprise.py`, `src/agent_bom/api/audit_log.py` |
| Audit chain verification | `POST /v1/audit/verify` | `src/agent_bom/api/audit_log.py` |
| Compliance report | `GET /v1/compliance/{framework}/report` | `src/agent_bom/api/routes/compliance.py` |
| Evidence bundle signing posture | `GET /v1/compliance/signing/status` | `src/agent_bom/api/compliance_signing.py` |
| Auth and secret posture | `GET /v1/auth/policy` | `src/agent_bom/api/routes/auth.py`, `src/agent_bom/api/audit_log.py` |
| Release artifact verification | GitHub Release assets | `docs/RELEASE_VERIFICATION.md`, `.github/workflows/release.yml` |
| Dependency and image audit | CI artifacts and release SBOM | `docs/SUPPLY_CHAIN.md`, `.github/workflows/pr-security-gate.yml`, `.github/workflows/extras-audit.yml` |
| Backup restore proof | CI workflow and operator runbook | `.github/workflows/backup-restore.yml`, `deploy/ops/restore-postgres-backup.sh` |

## SOC 2 Common Criteria

| Control family | How agent-bom supports it | Evidence |
|---|---|---|
| CC6.1 logical access | API keys, OIDC, SAML metadata, trusted proxy mode, route-level RBAC | `src/agent_bom/api/middleware.py`, `src/agent_bom/rbac.py`, `docs/ENTERPRISE.md` |
| CC6.2 least privilege | Admin, analyst, and viewer capabilities are enforced by middleware before route handlers | `src/agent_bom/rbac.py`, `tests/test_api_operator_policy.py`, `tests/test_rbac.py` |
| CC6.3 access changes | API key creation, revocation, and rotation are explicit API operations with audit events | `src/agent_bom/api/auth.py`, `src/agent_bom/api/routes/auth.py` |
| CC6.6 transmission boundaries | TLS terminates at customer ingress; gateway/proxy policy can fail closed for runtime traffic | `deploy/helm/agent-bom/templates/controlplane-ingress.yaml`, `src/agent_bom/gateway_server.py` |
| CC6.7 data access restriction | Tenant propagation, Postgres RLS, ClickHouse tenant filters, and cross-tenant tests | `src/agent_bom/api/middleware.py`, `src/agent_bom/api/postgres_common.py`, `tests/test_cross_tenant_leakage.py` |
| CC7.2 monitoring | Prometheus metrics, client error telemetry, audit events, and SIEM integration | `src/agent_bom/api/routes/observability.py`, `site-docs/deployment/siem-integration.md` |
| CC7.3 incident response | Private security advisory intake, disclosure SLA, pentest scope, and runtime break-glass guidance | `SECURITY.md`, `docs/PENTEST_READINESS.md`, `site-docs/deployment/runtime-operations.md` |
| CC8.1 change management | Release consistency checks, pinned actions, lockfiles, dependency review, and release provenance | `scripts/check_release_consistency.py`, `docs/SUPPLY_CHAIN.md`, `.github/workflows/release.yml` |

## ISO 27001:2022 Annex A

| Annex A control | How agent-bom supports it | Evidence |
|---|---|---|
| A.5.15 Access control | RBAC, OIDC tenant claims, API-key lifecycle, trusted proxy headers | `src/agent_bom/api/middleware.py`, `src/agent_bom/api/oidc.py`, `src/agent_bom/api/auth.py` |
| A.5.16 Identity management | External IdP integration, SAML metadata, tenant-bound OIDC providers | `src/agent_bom/api/oidc.py`, `src/agent_bom/api/saml.py` |
| A.5.17 Authentication information | API-key hashing, bearer-token verification, browser cookie signing, CSRF protection | `src/agent_bom/api/auth.py`, `src/agent_bom/api/browser_session.py` |
| A.5.23 Cloud services | Self-hosted deployment guidance, customer-managed storage, cloud read-only roles | `site-docs/deployment/own-infra-eks.md`, `scripts/provision/README.md` |
| A.5.30 ICT readiness | Backup restore workflow, HPA/PDB chart controls, runtime operations runbook | `.github/workflows/backup-restore.yml`, `deploy/helm/agent-bom/templates/controlplane-pdb.yaml` |
| A.8.8 Technical vulnerabilities | OSV, NVD, EPSS, CISA KEV enrichment, dependency scans, image scans | `src/agent_bom/enrichment.py`, `.github/workflows/pr-security-gate.yml`, `.github/workflows/container-rescan.yml` |
| A.8.9 Configuration management | Helm values, pinned deployment examples, release consistency guard | `deploy/helm/agent-bom/values.yaml`, `scripts/check_release_consistency.py` |
| A.8.12 Data leakage prevention | Credential and PII detectors in proxy, gateway, Shield, and visual leak detection | `src/agent_bom/runtime/detectors.py`, `src/agent_bom/runtime/visual_leak_detector.py` |
| A.8.15 Logging | HMAC-chained audit log and tenant-scoped export | `src/agent_bom/api/audit_log.py`, `src/agent_bom/api/postgres_audit.py` |
| A.8.24 Cryptography | HMAC audit chains, Ed25519 evidence signing, KMS-backed backup encryption | `src/agent_bom/api/compliance_signing.py`, `deploy/helm/agent-bom/templates/controlplane-backup-cronjob.yaml` |

## CIS Controls v8

| CIS control | How agent-bom supports it | Evidence |
|---|---|---|
| 1 Inventory and control of enterprise assets | Fleet sync and endpoint inventory | `src/agent_bom/api/routes/fleet.py`, `site-docs/deployment/endpoint-fleet.md` |
| 2 Inventory and control of software assets | Package, MCP, container, OS package, and SBOM scanning | `src/agent_bom/discovery`, `src/agent_bom/parsers`, `src/agent_bom/scanners` |
| 3 Data protection | Tenant-scoped data model, signed evidence bundles, backup encryption knobs | `docs/DATA_MODEL.md`, `docs/COMPLIANCE_SIGNING.md`, `deploy/helm/agent-bom/values.yaml` |
| 4 Secure configuration | IaC and cloud benchmark scanning, Kubernetes and Helm guidance | `src/agent_bom/iac`, `src/agent_bom/cloud`, `site-docs/deployment/kubernetes.md` |
| 5 Account management | API-key expiry, rotation overlap, revocation, and OIDC/SAML integrations | `src/agent_bom/api/auth.py`, `src/agent_bom/api/routes/auth.py` |
| 6 Access control management | RBAC matrix and middleware-enforced route permissions | `src/agent_bom/rbac.py`, `docs/ENTERPRISE.md` |
| 7 Continuous vulnerability management | Dependency audits, CVE freshness, image rescans, Dependabot | `.github/workflows/cve-freshness.yml`, `.github/workflows/extras-audit.yml` |
| 8 Audit log management | HMAC chain, export, verification, SIEM push | `src/agent_bom/api/audit_log.py`, `site-docs/deployment/siem-integration.md` |
| 12 Network infrastructure management | Gateway/proxy egress controls and SSRF hardening | `src/agent_bom/security.py`, `src/agent_bom/gateway_upstreams.py` |
| 16 Application software security | CodeQL, fuzzing, dependency review, release provenance | `.github/workflows/codeql.yml`, `.github/workflows/cflite-pr.yml`, `.github/workflows/release.yml` |

## Customer-Owned Evidence

These controls depend on the operator's environment and should be attached by
the customer during procurement review:

- IdP MFA policy and conditional access rules
- ingress TLS certificate policy and private DNS design
- KMS key policy, rotation evidence, and separation of duties
- S3 object-lock, retention, versioning, replication, and lifecycle policy
- Postgres backup retention and restore drill records
- SIEM routing, alert ownership, and incident response records
- DPA, subprocessor, and support-access procedures
