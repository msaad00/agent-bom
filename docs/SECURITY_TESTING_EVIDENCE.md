# Security Testing and Pentest Evidence Index

This page maps `agent-bom` security controls to the repo-managed tests,
workflows, artifacts, and residual-risk notes that an operator can attach to a
release review or third-party pentest preparation packet.

It is an evidence index, not a claim that a third-party penetration test has
already completed. External validation remains tracked separately in
`docs/PENTEST_READINESS.md`.

## CI Security Gates

| Control | Evidence path | Artifact / result |
|---|---|---|
| CodeQL static analysis | `.github/workflows/codeql.yml` | Code scanning results for Python and GitHub Actions |
| Code-scanning config placeholders | `.github/workflows/pr-security-gate.yml` | Stable PR categories for `agent-bom`, dependency self-scan, and SAST self-scan |
| Secret scanning | `.github/workflows/gitleaks.yml` | Gitleaks PR and push scans |
| Dependency review | `.github/workflows/dependency-review.yml` | GitHub dependency review on PRs |
| pip-audit PR gate | `.github/workflows/pr-security-gate.yml` | JSON-gated `pip-audit` report artifact |
| agent-bom self-scan PR gate | `.github/workflows/pr-security-gate.yml` | SARIF upload plus JSON scan summary |
| OSV lockfile scans | `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `osv-scanner.toml` | SHA-verified OSV scanner binary and lockfile scan logs |
| Container image scan | `.github/workflows/ci.yml`, `.github/workflows/container-rescan.yml`, `.image-scan-ignore` | Container scanner table and SARIF artifacts |
| Fuzzing | `.github/workflows/cflite-pr.yml` | ClusterFuzzLite PR fuzzing for parser/ingest crash coverage |
| Release provenance | `.github/workflows/release.yml` | Sigstore, SLSA, SBOM, and release self-scan artifacts |
| Backup / restore drill | `.github/workflows/backup-restore.yml` | Postgres restore and tenant-aware integrity checks |

Recommended release-review commands:

```bash
gh pr checks <pr-number> --repo msaad00/agent-bom
gh run view <run-id> --repo msaad00/agent-bom --log-failed
uv run pytest tests/test_api_hardening.py tests/test_api_privacy.py tests/test_api_cross_tenant_matrix.py -q
uv run pytest tests/test_proxy_sandbox.py tests/test_proxy_scanner.py tests/test_runtime_detectors.py -q
```

## Product Security Regression Matrix

| Surface | Main controls | Regression evidence |
|---|---|---|
| API authentication | API-key hashing, browser-session signing, OIDC/SAML/trusted-proxy auth, CSRF checks | `tests/test_api_hardening.py`, `tests/test_api_operator_policy.py`, `tests/test_api_oidc.py`, `tests/test_api_saml.py` |
| Authorization and scopes | route role rules, scope rules, tenant-aware request state | `tests/test_api_operator_policy.py`, `tests/test_gateway_auth_tenant_e2e.py` |
| Tenant isolation | same-tenant enforcement, cross-tenant rejection, tenant-scoped exports | `tests/test_api_cross_tenant_matrix.py`, `tests/test_cross_tenant_leakage.py`, `tests/test_api_privacy.py` |
| Audit integrity | HMAC chaining, restart hydration, signed audit export, tamper rejection | `tests/test_audit_chain.py`, `tests/test_api_enterprise_tenant.py`, `tests/test_compliance_report.py` |
| Runtime proxy detection | prompt/tool-call detectors, Unicode-normalized payload handling, audit records | `tests/test_proxy_scanner.py`, `tests/test_runtime_detectors.py`, `tests/test_proxy_audit.py` |
| MCP sandbox | isolated Docker/Podman runtime, sensitive mount rejection, caps, egress posture, digest-aware images | `tests/test_proxy_sandbox.py`, `src/agent_bom/proxy_sandbox.py` |
| SSRF and private egress | URL validation, redirect checks, private IP denial, allowlist behavior | `tests/test_security.py`, `tests/test_gateway_upstreams.py` |
| Container and external scanner ingest | External scanner normalization, decompression, and argv guards | `tests/test_external_scanners.py`, `tests/test_image_scanner.py`, `tests/test_container_limits.py` |
| Compliance evidence | tenant-filtered bundles, nonces, signatures, audit export links | `tests/test_compliance_report.py`, `docs/COMPLIANCE_SIGNING.md` |
| Supply-chain policy | dependency freshness, transitive pins, action SHA pins, self-scan | `docs/SUPPLY_CHAIN.md`, `.github/workflows/pr-security-gate.yml`, `.github/workflows/release.yml` |

## Pentest Preparation Evidence

Before a third-party assessment, prepare:

1. The target commit SHA and release tag.
2. The completed PR check page for that SHA.
3. CodeQL, gitleaks, dependency-review, pip-audit, OSV, container scanning, and self-scan
   artifacts for the release candidate.
4. The control-plane auth mode enabled for the test environment: API key,
   OIDC/SAML, trusted proxy, or browser session.
5. Tenant fixtures for at least two tenants with distinct API keys, policies,
   graph snapshots, audit trails, and compliance exports.
6. Runtime proxy and MCP sandbox configuration, including isolation mode,
   resource limits, egress mode, and image digest policy.
7. Audit export before and after runtime policy tests.
8. Known limitations from `docs/PENTEST_READINESS.md`, `docs/THREAT_MODEL.md`,
   and this page.

## Current Non-Claims and Residual Risks

- No public third-party pentest report is published yet.
- Delegated ingress, sidecar, or service-mesh mTLS remains the recommended
  production pattern. App-native uvicorn mTLS is available for non-mesh
  deployments and is reported through `/v1/auth/policy`.
- Real Postgres integration testing is limited to named workflow drills and
  contract coverage; a broader always-on testcontainers suite is a separate
  hardening item.
- Published 1k/5k/10k benchmark numbers are not filled in until the benchmark
  evidence issue lands.
- CI evidence proves repo-managed checks for the tested commit. It does not
  prove an operator's downstream SIEM, object-lock, backup, KMS, IdP, or
  service-mesh configuration.

## Evidence Collection Checklist

For each release candidate, attach:

1. `gh pr checks` output for the release PR or final merge commit.
2. Links to CodeQL, gitleaks, dependency-review, pip-audit, OSV, container scanning,
   ClusterFuzzLite, and agent-bom self-scan runs.
3. The release SBOM and provenance artifacts.
4. Tenant-isolation and auth regression test output.
5. Runtime proxy and sandbox regression test output.
6. Signed audit or compliance export generated from the release candidate.
7. A residual-risk note that names any skipped checks, accepted advisories, or
   operator-owned controls.
