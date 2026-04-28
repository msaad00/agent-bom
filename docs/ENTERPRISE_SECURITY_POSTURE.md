# Enterprise Security Posture

This is the procurement-facing security posture for self-hosted `agent-bom`.
It summarizes what the product does, where trust boundaries sit, and what an
enterprise buyer must configure in its own environment.

## Executive Summary

`agent-bom` is designed for customer-controlled deployment. The recommended
enterprise posture runs the API, UI, jobs, gateway, Postgres, optional
ClickHouse, and backup archive inside the customer's infrastructure. There is
no mandatory vendor-hosted control plane and no mandatory telemetry path.

The product security model is defense in depth:

- read-only discovery by default
- explicit runtime enforcement only where proxy or gateway is deployed
- API authentication through API keys, OIDC, SAML metadata, or trusted proxy
  headers
- middleware-enforced RBAC and tenant propagation
- tenant-scoped stores and export paths
- HMAC-chained audit logs and Ed25519-signed compliance evidence
- pinned release artifacts, lockfiles, dependency review, and image scanning
- restore-tested Postgres backup path for the packaged control plane

## Trust Boundaries

| Boundary | Trust level | Controls |
|---|---|---|
| Browser to UI/API | authenticated enterprise user | ingress TLS, OIDC/proxy auth, httpOnly same-origin session cookie, CSRF protection |
| API to stores | trusted service path | tenant propagation, Postgres RLS, parameterized stores, bounded connection pools |
| Scanner to local files | local user trust boundary | read-only config parsing, path validation, redaction of credential values |
| Scanner to public vuln APIs | untrusted external data | HTTPS, defensive parsers, no code execution from responses |
| Gateway/proxy to upstream MCPs | untrusted upstream | policy evaluation, credential/PII leak detectors, SSRF/private egress blocking |
| API to SIEM/webhook/export targets | operator-approved egress | scheme and private-network validation before outbound push |
| Release artifacts to operator | public supply chain | Sigstore, SLSA provenance, SBOMs, dependency review, image scan gates |

## Data Classification

| Data class | Examples | Default handling |
|---|---|---|
| Inventory metadata | packages, MCP server names, tool names, endpoint IDs | stored in customer-owned Postgres or export files |
| Findings | CVEs, risky permissions, policy hits, blast radius | tenant-scoped API and store paths |
| Audit records | actor, action, resource, tenant, details digest | HMAC-chained per tenant, exportable and verifiable |
| Credentials | API keys, OAuth client secrets, cloud tokens | values are not stored in scan output; deployment secrets live in operator secret stores |
| Compliance evidence | signed bundles, verification keys, audit export | Ed25519 preferred for auditor-distributable verification |
| Telemetry | Prometheus metrics, traces, client error reports | self-hosted endpoints; no mandatory vendor telemetry |

## Encryption And Signing Matrix

| Surface | In transit | At rest | Integrity |
|---|---|---|---|
| Browser/API traffic | customer ingress TLS | Postgres/customer store | request ID, audit entry |
| API keys | HTTPS/TLS at ingress | scrypt-hashed or stored key metadata only | rotation and revocation audit |
| Browser session cookie | same-origin secure cookie in production | signed token payload, no JS-readable bearer token needed | HMAC signature with configured or ephemeral key |
| Audit log | API transport | Postgres or configured audit store | per-tenant HMAC chain |
| Compliance bundle | API transport | operator archive | Ed25519 signature, HMAC fallback |
| Postgres backup | S3/TLS | S3 SSE-S3 or SSE-KMS | restore drill and checksum verification |
| Release artifacts | GitHub/Docker registry TLS | operator artifact store | Sigstore, SLSA, SBOM, image signatures |

## Identity And Access

The self-hosted control plane supports:

- API keys with expiry, rotation overlap, and revocation
- OIDC bearer validation with tenant claim enforcement
- SAML SP metadata for enterprise IdP wiring
- trusted reverse-proxy identity headers when a customer-owned proxy handles
  authentication
- admin, analyst, and viewer RBAC enforced in API middleware

Browser authentication can use same-origin httpOnly cookies for the dashboard
while keeping bearer-token support for CLI and service clients.

## Vulnerability Enrichment Posture

The scanner can enrich findings with OSV, NVD, EPSS, CISA KEV, and GHSA data.
Those sources are treated as untrusted external inputs and are fetched over
HTTPS with defensive parsing. `GET /v1/posture/enrichment` exposes a non-secret
runtime posture for each source: latest success, latest failure, cache hits,
configured SLO, and whether the current process sees the source as `ok`,
`stale`, `degraded`, or `unknown`. Operators should review this surface before
treating KEV, EPSS, or NVD-derived risk scoring as complete.

## Tenant Isolation

Tenant isolation is enforced across API middleware, stores, audit export,
fleet routes, ClickHouse analytics, and shared gateway routing. The control
plane test suite includes cross-tenant matrix and concurrent-write leakage
coverage. Operators should still deploy separate environments for separate
legal entities when regulatory or contractual requirements prohibit shared
infrastructure.

## Secrets Lifecycle

Recommended production posture:

- source API, OIDC, OAuth2, audit HMAC, Ed25519, Postgres, and webhook secrets
  from the customer's secret manager
- mount Kubernetes secrets through External Secrets or equivalent CSI/IRSA
  controls
- set `AGENT_BOM_SECRET_PROVIDER` and `AGENT_BOM_EXTERNAL_SECRETS_ENABLED=1`
  when the deployment is backed by AWS Secrets Manager, Vault, External
  Secrets, or an equivalent customer secret manager
- set rotation timestamps for audit HMAC, compliance signing, SCIM bearer, and
  browser-session signing keys so posture endpoints can expose key age
- rotate API keys through the API rather than replacing all clients at once
- restart API/gateway workloads after rotating mounted signing or OAuth client
  secrets

`GET /v1/auth/secrets/lifecycle` and `GET /v1/auth/policy` expose a non-secret
summary of this posture. They report configured sources, key IDs when supplied,
rotation age, missing required secrets, and whether the deployment has declared
an external secret-manager authority. These endpoints never return secret
values.

`GET /v1/auth/secrets/rotation-plan` turns that posture into a non-secret
operator change plan. It prioritizes due, unknown-age, ephemeral, and required
missing secrets; includes AWS Secrets Manager, Vault, External Secrets/CSI, or
generic secret-manager command templates; and lists rollout, verification, and
timestamp-recording steps. The response is designed for change tickets and does
not automate custody-sensitive secret generation.

The rotation-plan response now exposes an explicit `rotation_adapter` object
for the configured `AGENT_BOM_SECRET_PROVIDER`. Supported adapters are:

| Provider value | Custody boundary | Rotation model |
| --- | --- | --- |
| `aws_secrets_manager` | Customer AWS account | `put-secret-value`, rollout restart, lifecycle verification |
| `hashicorp_vault` | Customer Vault cluster | `vault kv put`, rollout restart, lifecycle verification |
| `external_secrets` / `csi` | Customer upstream provider | Rotate upstream, wait for Kubernetes Secret sync, rollout restart |
| `kubernetes_secret` | Customer Kubernetes Secret | Apply a rotated env-file secret manifest, rollout restart |
| `operator_secret_manager` | Customer secret manager | Generic operator-owned change ticket and rollout |

Every adapter response sets `secret_values_included=false`, names the expected
secret-manager audit evidence, and includes a timestamp-recording command for
the matching `*_LAST_ROTATED` metadata. `agent-bom` never fetches or returns the
secret material.

`agent-bom` does not replace the customer's KMS, Vault, IdP, or privileged
access management system. The product exposes posture and supports rotation
paths; the operator owns secret authority, approval workflow, and key custody.

## SCIM And Revocation Boundary

SCIM is the provisioned identity lifecycle store. User and group resources
include tenant-bound Agent BOM role metadata, but the tenant is still assigned
server-side from `AGENT_BOM_SCIM_TENANT_ID`; tenant fields in IdP payloads are
ignored for routing. Runtime authentication continues to come from API keys,
OIDC, SAML, browser sessions, or trusted reverse-proxy headers. A SCIM
deactivation records the lifecycle event and removes the provisioned active
membership view, but live OIDC/SAML/proxy sessions must be terminated at the
upstream IdP or proxy, and API keys must be revoked through the key lifecycle
API.

## Logging, Monitoring, And Incident Response

Relevant security signals:

- authenticated `/metrics` for Prometheus scraping
- SIEM integration for audit and finding export
- client error telemetry for dashboard failures
- HMAC audit export and verification endpoints
- PrometheusRule defaults for high-risk runtime and control-plane alerts
- private vulnerability reporting through GitHub Security Advisories

Incident response ownership remains with the self-hosting organization. The
published security policy defines maintainer disclosure SLAs for product
vulnerabilities; customer deployment incidents follow customer process.
`docs/ENTERPRISE_SUPPORT_MODEL.md` defines the supported-version window, patch
cadence, escalation paths, and the boundary between product vulnerabilities and
customer-operated incidents.

## Security Header Posture

Control-plane responses emit HSTS, CSP, frame, content-type, referrer, and
permissions-policy headers. HSTS defaults to
`max-age=31536000; includeSubDomains`; preload enrollment is intentionally
operator opt-in through `AGENT_BOM_HSTS_PRELOAD=1` because browser preload is a
domain-level commitment. Operators can also set
`AGENT_BOM_HSTS_MAX_AGE_SECONDS` when a shorter staged rollout is required.

`GET /v1/auth/policy` exposes the non-secret effective header posture under
`security_headers` so change windows can record whether preload is enabled and
which CSP mode is active.

Packaged self-hosted dashboard builds generate `ui_dist/csp-hashes.json` during
`scripts/build-ui.sh` and release packaging. When that manifest is present, the
API serves dashboard HTML with hash-based `script-src` entries instead of
`script-src 'unsafe-inline'`. If the manifest is absent, the dashboard posture
reports `inline_compat` so operators can see that the static export is using the
compatibility fallback.

## Availability, Backup, And Restore

The Helm chart includes an optional Postgres backup CronJob that writes custom
format `pg_dump` artifacts to S3-compatible storage. The restore script is
tested in CI through a MinIO-backed round trip. Production deployments should
set real RPO/RTO targets, bucket retention, KMS keys, object lock where needed,
and restore-drill cadence.

See `site-docs/deployment/backup-restore.md` for the operator runbook.

## Storage Schema And Upgrade Readiness

The control plane exposes a non-secret storage schema manifest in
`GET /v1/auth/policy` under `storage_schema`. SQLite and Postgres control-plane
stores record component versions in `control_plane_schema_versions`; graph
storage keeps its legacy `graph_schema_version` marker and is also listed in
the manifest; ClickHouse analytics creates the same schema-version table for
analytics readiness checks. Operators should capture this surface before and
after rolling upgrades so schema drift is visible alongside release, Helm, and
container version checks.

## Procurement Package

A procurement packet should include:

- this security posture
- `docs/ENTERPRISE_PROCUREMENT_PACKET.md`
- `docs/CONTROL_MAPPING.md`
- `docs/SECURITY_ARCHITECTURE.md`
- `docs/THREAT_MODEL.md`
- `docs/SUPPLY_CHAIN.md`
- `docs/RELEASE_VERIFICATION.md`
- `docs/ENTERPRISE_SUPPORT_MODEL.md`
- `docs/PENTEST_READINESS.md`
- `site-docs/deployment/customer-data-and-support-boundary.md`
- customer-owned DPA, subprocessors, support-access policy, and retention
  schedule

## Current Boundaries

The self-hosted enterprise posture is ready for teams operating the product
behind their own identity, network, storage, and monitoring controls. Turnkey
external multi-tenant SaaS procurement still needs separate hosted-service
controls such as data-subject automation, provider-style tenant lifecycle
operations, and formal legal templates owned by the service provider.
