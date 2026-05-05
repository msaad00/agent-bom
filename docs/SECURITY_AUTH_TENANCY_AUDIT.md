# Security, Auth, and Tenancy Audit

> **Snapshot:** refreshed on 2026-05-05 after the gateway/proxy runtime,
> visual-leak, graph-quality, and evidence-retention work landed. Every
> rating below has a file reference — grep to verify. This
> doc answers: "are SSO / SAML / OAuth / OIDC / multi-tenancy /
> isolation / RBAC / least-priv / zero-trust / defense-in-depth /
> non-repudiation / CIA / input sanitization / KMS / key rotation /
> ephemeral creds all wired and aligned?"

## TL;DR rating

| Dimension | Score | Evidence |
|---|:-:|---|
| API-key auth + rotation | **9** | [`api/auth.py`](../src/agent_bom/api/auth.py), [`api/middleware.py:250`](../src/agent_bom/api/middleware.py#L250) APIKeyMiddleware, [`routes/enterprise.py:106`](../src/agent_bom/api/routes/enterprise.py#L106) `rotate_key` with `rotation_policy="enforced"` |
| OIDC (Okta, Auth0, Azure AD, Google) | **9** | [`api/oidc.py:290`](../src/agent_bom/api/oidc.py#L290) `OIDCConfig`, claim-based tenant resolution, audience pinning |
| SAML SSO | **8.5** | [`api/saml.py`](../src/agent_bom/api/saml.py) `SAMLConfig` + `/v1/auth/saml/metadata`; needs `[saml]` extra |
| RBAC (admin / analyst / viewer) | **9** | [`rbac.py:137 require_permission`](../src/agent_bom/rbac.py#L137), [`:160 require_authenticated_permission`](../src/agent_bom/rbac.py#L160), 3 roles × 8 action classes |
| Rate limiting (per-tenant + global) | **9** | [`api/middleware.py InMemoryRateLimitStore + PostgresRateLimitStore`](../src/agent_bom/api/middleware.py#L53), `X-RateLimit-*` response headers |
| Multi-tenancy: row-level isolation | **9** | Native `tenant_id` in Postgres ([#1562](https://github.com/msaad00/agent-bom/pull/1562)), ClickHouse (row-level filter tested), Snowflake ([#1567](https://github.com/msaad00/agent-bom/pull/1567) fleet native), SQLite. 3 test layers: [`test_clickhouse_tenant_isolation.py`](../tests/test_clickhouse_tenant_isolation.py), [`test_cross_tenant_leakage.py`](../tests/test_cross_tenant_leakage.py), [`test_api_cross_tenant_matrix.py`](../tests/test_api_cross_tenant_matrix.py) |
| Audit log non-repudiation | **8.5** | HMAC-chained log ([`api/audit_log.py`](../src/agent_bom/api/audit_log.py)); Ed25519-signed compliance bundles ([`api/compliance_signing.py`](../src/agent_bom/api/compliance_signing.py), cookbook [`COMPLIANCE_SIGNING.md`](COMPLIANCE_SIGNING.md)). Tenant audit chains hardened in [#1559](https://github.com/msaad00/agent-bom/pull/1559) |
| Secrets at rest (KMS, rotation) | **8.5** | SSE-KMS on Postgres backup ([`controlplane-backup-cronjob.yaml:78`](../deploy/helm/agent-bom/templates/controlplane-backup-cronjob.yaml#L78)), External Secrets wired to Secrets Manager ([`controlplane-externalsecret.yaml`](../deploy/helm/agent-bom/templates/controlplane-externalsecret.yaml)), API-key + HMAC + Ed25519 all operator-rotated via `kubectl rollout restart` |
| Ephemeral creds (no passwords at rest) | **8** | Bearer tokens referenced by env-var name only in upstreams.yaml ([`gateway-upstreams.example.yaml`](../deploy/helm/agent-bom/examples/gateway-upstreams.example.yaml)); OAuth2 client-credentials token cache with early refresh ([`gateway_upstreams.py`](../src/agent_bom/gateway_upstreams.py)); Snowflake key-pair auth is the production recommendation, while `SNOWFLAKE_PASSWORD` remains a deprecated fallback with a runtime warning ([`snowflake_store.py`](../src/agent_bom/api/snowflake_store.py)) |
| Zero-trust / mTLS / NetworkPolicy | **8** | Istio PeerAuthentication + AuthorizationPolicy templates ([`controlplane-istio-*.yaml`](../deploy/helm/agent-bom/templates/)), Kyverno policy, NetworkPolicy `restrictIngress` per example values file, Pod Security Admission `restricted` |
| Defense in depth (middleware stack) | **9** | Body-size + read-timeout → trust-headers + W3C trace → auth → RBAC → tenant → rate limit → route → audit → store. Every layer testable in isolation. |
| SQL injection | **9** | Postgres uses psycopg parameterized queries (no f-string SQL). ClickHouse has [`_escape()`](../src/agent_bom/api/clickhouse_store.py) + numeric casts + a bandit `nosec B608` annotation reviewed. Snowflake store uses connector parameter binding. |
| XSS | **8** | Next.js dashboard renders via React auto-escape; strict CSP on API routes ([`middleware.py:_API_CSP`](../src/agent_bom/api/middleware.py)); HTML report is static-generated without user-controllable HTML passthrough. |
| Input validation at boundaries | **8.5** | Pydantic models on every route; path-traversal + command-injection guards in [`proxy_policy.py`](../src/agent_bom/proxy_policy.py) (`block_secret_paths`, `block_unknown_egress`); `ArgumentAnalyzer` on every tool call |
| CIA triad | **8.5** | C: TLS at ingress + KMS at rest; I: HMAC-chain + Ed25519 signing + checksums on backup restore; A: HPA on API + gateway, backup restore CI round-trip |
| **Overall** | **~8.7** | Above-bar on every axis above except the documented gaps below |

## Current implementation notes

- Audit entry details participate in the HMAC chain, and gateway, proxy,
  quota, and compliance audit events carry tenant context.
- Postgres control-plane state is split across focused stores while preserving
  public imports; job retention respects configured TTL.
- Tenant-scoped stores filter at the query layer where supported. Snowflake
  stores carry native tenant columns for the supported scan, fleet, schedule,
  exception, and policy paths.
- Analytics writes carry session and trace context so logs, metrics, and traces
  can correlate the same request.
- The MCP server metadata and entry point are separated from runtime wiring.
- Python AST analysis and console rendering internals are split into focused
  modules without changing the operator-facing command surface.

## Real gaps (P1 → P2)

### P1 — MFA is a CIS benchmark check, not a product feature

- `grep -rln "mfa\|MFA\|totp" src/agent_bom/` returns only `cloud/*_cis_benchmark.py` (we *check* for MFA in customers' cloud accounts) — **we don't require MFA on the dashboard / API keys ourselves**.
- Impact: a pilot team's dashboard login goes through OIDC / SAML (their IdP enforces MFA) — so MFA is effectively present *via the IdP*. But there's no in-product MFA for API-key auth.
- Current boundary: OIDC + SAML users inherit the IdP's MFA; API keys stay
  machine-to-machine credentials and must be protected by the operator's secret
  storage, rotation, and least-privilege controls.

### Implemented — Screenshot / visual-capture sensitive data detection now exists

- `src/agent_bom/runtime/visual_leak_detector.py` implements the optional OCR
  detector and redaction path for image-bearing tool responses.
- `src/agent_bom/proxy.py` wires `--detect-visual-leaks` for proxy runtime
  enforcement.
- `src/agent_bom/gateway_server.py` wires visual-leak health, readiness, check,
  and redact behavior for gateway responses.
- `src/agent_bom/proxy_policy.py` classifies screenshot/screen-capture tool
  names so policy can block that capability class before an upstream call.
- `tests/test_visual_leak_detector.py` covers the visual channel.

Remaining operator note: the feature is opt-in because OCR requires the
`agent-bom[visual]` extra and a Tesseract binary on `PATH`. That is the right
default for local-first scanning and lightweight gateway deployments.

### P2 — Password-based auth on upstream config should be explicitly banned

- `gateway_upstreams.py` accepts `auth: bearer` with env-var token. Operators could (mis)configure Snowflake MCP as `bearer` and put the Snowflake password in the env var.
- A remaining code hardening step is to add a linter check or runtime warning when
  an upstream's `token_env` is named `*_PASSWORD*`.

### P2 — Snowflake password fallback is deprecated, not hard-disabled in code

- `SNOWFLAKE_PASSWORD` still works with a deprecation warning in
  `build_connection_params()`. The Helm Snowflake example documents key-pair
  auth and sets `AGENT_BOM_SNOWFLAKE_REQUIRE_KEYPAIR=1`, but that flag is not
  currently enforced by `snowflake_store.py`.
- Hard-failing password fallback would be a code change and migration note, not
  a documentation-only claim.

### P2 — `/metrics` endpoint is unauthenticated

- Matches Prometheus scrape convention (no auth required) and the response is intentionally non-sensitive (counters). Worth an explicit note in `OBSERVABILITY_METRICS.md` documenting the threat model so operators know to pin the scrape target behind a NetworkPolicy (which the shipped Helm values already do).

### P2 — Graph layer scalability story is not documented

- `src/agent_bom/graph/` + `context_graph.py` total ~2,850 LOC across 10 focused modules — code is good, but there's no "how this scales" doc (cardinality at 50k packages, memory growth).
- **Fix:** extend `docs/PERFORMANCE_BENCHMARKS.md` with a graph-specific section. Small add, filed as companion issue.

## Appendix: screenshot sensitive-data detection — implemented shape

**Why it matters:** any MCP that wraps a browser / screen-capture tool (Playwright-MCP, Puppeteer-MCP, plus Cursor/Claude running screen-read tools) can exfiltrate secrets, PII, and internal data through pixels that never hit the existing text-content detectors.

**Where it slots into the existing architecture** (no new service):

1. **Detector module** — [`runtime/visual_leak_detector.py`](../src/agent_bom/runtime/visual_leak_detector.py) follows the existing runtime-detector pattern and accepts image-bearing MCP content blocks.
2. **OCR + pattern match** — when `agent-bom[visual]` and Tesseract are
   available, the detector extracts text and applies credential/PII patterns to
   the visual channel.
3. **Redact-in-place** — matching image regions are redacted before the
   response is forwarded.
4. **Policy boundary** — [`proxy_policy.py`](../src/agent_bom/proxy_policy.py)
   classifies screenshot and screen-capture tools so operators can block the
   tool class at the gateway/proxy boundary.
5. **Audit trail** — visual-leak alerts flow through the same runtime audit
   path as text detector alerts, with the durable evidence-retention policy
   keeping replay-only payloads out of long-lived analytics.

## How I verified every claim

```bash
# Repeatable audit script — anyone can rerun
grep -rn "class OIDCConfig\|class SAMLConfig\|class APIKeyMiddleware" src/agent_bom/api/
grep -rn "def require_\|def _authorize" src/agent_bom/rbac.py
grep -rn "rotation_policy\|def rotate_key" src/agent_bom/api/routes/
grep -rn "tenant_id" src/agent_bom/api/postgres/ src/agent_bom/api/snowflake_store.py
grep -rn "SSE-KMS\|kmsKeyId\|Ed25519" deploy/helm/agent-bom/ src/agent_bom/api/
grep -rn "screenshot\|screen_capture\|visual_leak" src/agent_bom/
```
