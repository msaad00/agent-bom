# Enterprise Procurement Evidence Packet

This packet is an evidence index for enterprise security, platform, legal, and
procurement review of self-hosted `agent-bom`. It is not a certification claim.
Validate every linked control against the exact release tag and deployment mode
in use.

## Readiness Summary

`agent-bom` is ready for self-hosted enterprise pilots operated behind the
customer's identity, network, storage, monitoring, and secret-management
controls. The product should not be represented as turnkey Fortune-500 SaaS
procurement-ready until the remaining customer/legal evidence and hosted-service
controls are complete.

| Review area | Current posture | Primary evidence |
|---|---|---|
| Trust boundaries | documented for browser, API, stores, scanner, gateway, egress, and release artifacts | `docs/ENTERPRISE_SECURITY_POSTURE.md`, `docs/SECURITY_ARCHITECTURE.md`, `docs/THREAT_MODEL.md` |
| Control mapping | mapped to SOC 2, ISO 27001, and CIS as an evidence index | `docs/CONTROL_MAPPING.md` |
| Identity and access | API keys, OIDC, SAML metadata, trusted proxy auth, SCIM lifecycle, RBAC, tenant quotas | `docs/ENTERPRISE.md`, `docs/ENTERPRISE_DEPLOYMENT.md`, `tests/test_api_operator_policy.py`, `tests/test_api_scim_lifecycle.py` |
| Secrets lifecycle | non-secret posture and rotation planning; customer retains secret custody | `docs/ENTERPRISE_SECURITY_POSTURE.md`, `src/agent_bom/api/secret_lifecycle.py` |
| Tenant isolation | tenant propagation, scoped stores, audit export, and cross-tenant tests | `docs/DATA_MODEL.md`, `tests/test_cross_tenant_leakage.py` |
| Supply chain | lockfiles, dependency review, self-scan, SBOM, Sigstore, SLSA provenance | `docs/SUPPLY_CHAIN.md`, `docs/RELEASE_VERIFICATION.md`, `.github/workflows/release.yml` |
| Security testing | CodeQL, gitleaks, dependency review, pip audit, fuzzing, SSRF/authz/tenant tests | `docs/PENTEST_READINESS.md`, `.github/workflows/codeql.yml`, `.github/workflows/pr-security-gate.yml` |
| Operations | Helm profiles, backup/restore, airgap bundle, runtime operations, upgrade/rollback evidence, and procurement questionnaire answers | `docs/ENTERPRISE_OPERATIONS_EVIDENCE.md`, `site-docs/deployment/control-plane-helm.md`, `site-docs/deployment/backup-restore.md`, `site-docs/deployment/airgapped-image-bundle.md` |
| Scale | fleet/graph pagination and benchmark targets documented; larger enterprise evidence still expanding | `docs/PERFORMANCE_BENCHMARKS.md`, `site-docs/deployment/performance-and-sizing.md` |
| Support and disclosure | product vulnerability disclosure, patch cadence, support boundaries, and customer incident ownership documented | `SECURITY.md`, `docs/ENTERPRISE_SUPPORT_MODEL.md`, `docs/ENTERPRISE_SECURITY_POSTURE.md` |

## Customer-Owned Evidence

Procurement packets for regulated deployments should include these operator-owned
artifacts alongside the product evidence above:

- IdP MFA, conditional access, group-to-role mapping, and SCIM assignment policy
- ingress TLS, private DNS, network policy, WAF, and egress policy
- KMS, Vault, Secrets Manager, or External Secrets configuration and rotation
  evidence
- Postgres HA, backup retention, restore drill records, and object-lock policy
- SIEM routing, alert ownership, incident response, and escalation contacts
- data retention schedule, DPA, subprocessor review, and support-access policy
- release approval record for the exact tag deployed
- internal escalation contacts for platform, security, IdP, cloud, and database
  owners

## Evidence Collection Checklist

1. Record the release tag, commit SHA, image digests, Helm chart version, and
   deployment mode.
2. Download the GitHub Release assets and verify Sigstore bundles, SLSA
   provenance, and SBOMs using `docs/RELEASE_VERIFICATION.md`.
3. Attach the CI check summary for CodeQL, dependency review, gitleaks, PR
   self-scan, package tests, UI validation, and release consistency checks.
4. Export tenant-scoped audit evidence with `GET /v1/audit/export` when the
   control plane is deployed.
5. Export or screenshot non-secret posture from `GET /v1/auth/policy`,
   `GET /v1/auth/secrets/lifecycle`, and `GET /v1/auth/secrets/rotation-plan`.
6. Attach restore-drill evidence from the backup/restore workflow or the
   customer's latest production restore exercise.
7. Attach customer-owned IdP, KMS, network, retention, and incident-response
   evidence.
8. Attach the self-hosted support boundary and escalation record from
   `docs/ENTERPRISE_SUPPORT_MODEL.md`, plus any customer-owned support contract
   or internal incident workflow.

## Current Gaps Before Fortune-500 Procurement Claims

These tracks are intentionally explicit so the release does not overclaim:

- deeper SOC 2 / ISO / CIS / NIST mapping from each control to exact tests,
  logs, and exported evidence
- procurement-ready legal templates such as customer-owned DPA and
  subprocessors; support boundaries are documented, but paid support terms
  remain separate from the OSS project
- real Vault/KMS/Secrets Manager rotation adapters beyond posture and operator
  planning
- published IdP compatibility evidence for Okta, Microsoft Entra, and Google
  Workspace
- larger fleet/graph benchmark evidence for 1k, 5k, and 10k agent estates
- complete hosted-service controls for any future external multi-tenant SaaS
  deployment

The operational evidence matrix, customer-owned key-custody boundaries,
backup/restore proof, air-gap import record, upgrade/rollback checklist, and
procurement questionnaire answers live in
[`docs/ENTERPRISE_OPERATIONS_EVIDENCE.md`](ENTERPRISE_OPERATIONS_EVIDENCE.md).

## Procurement Positioning

Use this wording for the current release:

> `agent-bom` is ready for self-hosted enterprise pilots where the customer
> operates identity, network, storage, monitoring, and secret management. It
> provides AI agent, MCP, package, vulnerability, fleet, and graph visibility
> with tenant-aware control-plane foundations and verifiable release artifacts.

Do not claim turnkey Fortune-500 SaaS procurement readiness until the open gaps
above are closed with evidence.
