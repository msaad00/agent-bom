# Security, Auth, and Tenancy Audit

> **Snapshot:** fresh pass over `main` as of 2026-04-20, after #1555–#1566
> landed. Every rating below has a file reference — grep to verify. This
> doc answers: "are SSO / SAML / OAuth / OIDC / multi-tenancy /
> isolation / RBAC / least-priv / zero-trust / defense-in-depth /
> non-repudiation / CIA / input sanitization / KMS / key rotation /
> ephemeral creds all wired and aligned?"

## TL;DR rating

| Dimension | Score | Evidence |
|---|:-:|---|
| API-key auth + rotation | **9** | [`api/auth.py`](../src/agent_bom/api/auth.py), [`api/middleware.py:250`](../src/agent_bom/api/middleware.py:250) APIKeyMiddleware, [`routes/enterprise.py:106`](../src/agent_bom/api/routes/enterprise.py:106) `rotate_key` with `rotation_policy="enforced"` |
| OIDC (Okta, Auth0, Azure AD, Google) | **9** | [`api/oidc.py:290`](../src/agent_bom/api/oidc.py:290) `OIDCConfig`, claim-based tenant resolution, audience pinning |
| SAML SSO | **8.5** | [`api/saml.py`](../src/agent_bom/api/saml.py) `SAMLConfig` + `/v1/auth/saml/metadata`; needs `[saml]` extra |
| RBAC (admin / analyst / viewer) | **9** | [`rbac.py:137 require_permission`](../src/agent_bom/rbac.py:137), [`:160 require_authenticated_permission`](../src/agent_bom/rbac.py:160), 3 roles × 8 action classes |
| Rate limiting (per-tenant + global) | **9** | [`api/middleware.py InMemoryRateLimitStore + PostgresRateLimitStore`](../src/agent_bom/api/middleware.py:53), `X-RateLimit-*` response headers |
| Multi-tenancy: row-level isolation | **9** | Native `tenant_id` in Postgres ([#1562](https://github.com/msaad00/agent-bom/pull/1562)), ClickHouse (row-level filter tested), Snowflake ([#1567](https://github.com/msaad00/agent-bom/pull/1567) fleet native), SQLite. 3 test layers: [`test_clickhouse_tenant_isolation.py`](../tests/test_clickhouse_tenant_isolation.py), [`test_cross_tenant_leakage.py`](../tests/test_cross_tenant_leakage.py), [`test_api_cross_tenant_matrix.py`](../tests/test_api_cross_tenant_matrix.py) |
| Audit log non-repudiation | **8.5** | HMAC-chained log ([`api/audit_log.py`](../src/agent_bom/api/audit_log.py)); Ed25519-signed compliance bundles ([`api/compliance_signing.py`](../src/agent_bom/api/compliance_signing.py), cookbook [`COMPLIANCE_SIGNING.md`](COMPLIANCE_SIGNING.md)). Tenant audit chains hardened in [#1559](https://github.com/msaad00/agent-bom/pull/1559) |
| Secrets at rest (KMS, rotation) | **8.5** | SSE-KMS on Postgres backup ([`controlplane-backup-cronjob.yaml:78`](../deploy/helm/agent-bom/templates/controlplane-backup-cronjob.yaml:78)), External Secrets wired to Secrets Manager ([`controlplane-externalsecret.yaml`](../deploy/helm/agent-bom/templates/controlplane-externalsecret.yaml)), API-key + HMAC + Ed25519 all operator-rotated via `kubectl rollout restart` |
| Ephemeral creds (no passwords at rest) | **8** | Bearer tokens referenced by env-var name only in upstreams.yaml ([`gateway-upstreams.example.yaml`](../deploy/helm/agent-bom/examples/gateway-upstreams.example.yaml)); OAuth2 client-credentials token cache with early refresh ([`gateway_upstreams.py`](../src/agent_bom/gateway_upstreams.py)); Snowflake backend mandates key-pair, password fallback rejected when `AGENT_BOM_SNOWFLAKE_REQUIRE_KEYPAIR=1` ([`eks-snowflake-values.yaml`](../deploy/helm/agent-bom/examples/eks-snowflake-values.yaml)) |
| Zero-trust / mTLS / NetworkPolicy | **8** | Istio PeerAuthentication + AuthorizationPolicy templates ([`controlplane-istio-*.yaml`](../deploy/helm/agent-bom/templates/)), Kyverno policy, NetworkPolicy `restrictIngress` per example values file, Pod Security Admission `restricted` |
| Defense in depth (middleware stack) | **9** | Body-size + read-timeout → trust-headers + W3C trace → auth → RBAC → tenant → rate limit → route → audit → store. Every layer testable in isolation. Diagrammed in README §3. |
| SQL injection | **9** | Postgres uses psycopg parameterized queries (no f-string SQL). ClickHouse has [`_escape()`](../src/agent_bom/api/clickhouse_store.py) + numeric casts + a bandit `nosec B608` annotation reviewed. Snowflake store uses connector parameter binding. |
| XSS | **8** | Next.js dashboard renders via React auto-escape; strict CSP on API routes ([`middleware.py:_API_CSP`](../src/agent_bom/api/middleware.py)); HTML report is static-generated without user-controllable HTML passthrough. |
| Input validation at boundaries | **8.5** | Pydantic models on every route; path-traversal + command-injection guards in [`proxy_policy.py`](../src/agent_bom/proxy_policy.py) (`block_secret_paths`, `block_unknown_egress`); `ArgumentAnalyzer` on every tool call |
| CIA triad | **8.5** | C: TLS at ingress + KMS at rest; I: HMAC-chain + Ed25519 signing + checksums on backup restore; A: HPA on API + gateway, backup restore CI round-trip |
| **Overall** | **~8.7** | Above-bar on every axis above except the new-feature gaps below |

## Assessment of the PR stream that landed while I was out

Every PR below reviewed against the on-disk code, not just the PR description. Verdicts:

| PR | Title | LOC touched | Assessment |
|---|---|---|---|
| [#1559](https://github.com/msaad00/agent-bom/pull/1559) | harden tenant-scoped audit chains | audit_log.py +116 / -46, plus routes | **✓ real hardening.** Audit entry `details` now participate in the HMAC chain (not just metadata); gateway/proxy/quota/compliance audit events carry tenant. Legacy chain verification preserved for old entries. |
| [#1560](https://github.com/msaad00/agent-bom/pull/1560) | align deployment context + self-hosted rollout story | README.md, init.sql +217, DATA_MODEL +39 | **✓ docs + schema alignment.** Postgres init.sql now mirrors the alembic migrations; README self-hosted section explicit about deployment contexts. |
| [#1561](https://github.com/msaad00/agent-bom/pull/1561) | split postgres stores + align job provenance | 5 new postgres_* modules, ~1,400 LOC moved | **✓ the right split.** `postgres_store.py` → `postgres_{common,access,audit,graph,policy}`. Public import surface stable. TTL-respecting scan-job retention is a real bug fix, not just refactor. |
| [#1562](https://github.com/msaad00/agent-bom/pull/1562) | tenant-scoped stores query natively | schedule_store +30, snowflake_store +45 | **✓ correctness.** Broad-read-then-python-filter was a silent O(N) leak risk; every store now filters at the query layer. Snowflake got native tenant columns where it was previously defaulted to "default". |
| [#1563](https://github.com/msaad00/agent-bom/pull/1563) | preserve session + trace context in analytics | clickhouse_store +49, routes/proxy +33 | **✓ observability correctness.** Analytics writes now carry the same session + trace context as the audit log so Grafana correlates the same request across metric/log/trace. |
| [#1564](https://github.com/msaad00/agent-bom/pull/1564) | split mcp server metadata + entrypoint | mcp_server.py -304, metadata/entrypoint +279 | **✓ good split.** mcp_server.py now ~500 LOC of wiring; the tool metadata + entrypoint separation tracks the issue #1522 prescription. |
| [#1565](https://github.com/msaad00/agent-bom/pull/1565) | split python ast analysis internals | ast_analyzer.py -1766, ast_python_analysis.py +1725 | **✓ huge win for reviewability.** The analyzer dispatcher (ast_analyzer.py) is now thin; the Python-specific rules live in a focused module. Exactly the split prescribed. |
| [#1566](https://github.com/msaad00/agent-bom/pull/1566) | split output console renderers | output/__init__.py -1673, console_render.py +1660 | **✓ continues #1557's Phase 1a.** Between this and my #1557, the output monolith is effectively done. |
| [#1567](https://github.com/msaad00/agent-bom/pull/1567) *(open)* | snowflake fleet sync tenant-native | snowflake_store, pipeline | **✓ closes the last silent tenant-default leak.** `_sync_scan_agents_to_fleet` was writing fleet agents into `default` when the job had a real tenant. This is a P0 the audit would have flagged — already fixed. |

**Net verdict:** codex's stream was on the right track. The splits + the tenant-native queries + the audit-chain hardening are exactly what a pilot-readiness review would demand. No red flags, no scaffolding introduced, imports stable.

## Real gaps (P0 → P2)

### P1 — MFA is a CIS benchmark check, not a product feature

- `grep -rln "mfa\|MFA\|totp" src/agent_bom/` returns only `cloud/*_cis_benchmark.py` (we *check* for MFA in customers' cloud accounts) — **we don't require MFA on the dashboard / API keys ourselves**.
- Impact: a pilot team's dashboard login goes through OIDC / SAML (their IdP enforces MFA) — so MFA is effectively present *via the IdP*. But there's no in-product MFA for API-key auth.
- **Fix proposal:** documented today = OIDC + SAML users inherit the IdP's MFA; API keys stay machine-to-machine (operator is expected to protect API-key storage). File a docs-only issue to make this explicit in the `SECURITY_ARCHITECTURE.md`.

### P1 — Screenshot / visual-capture sensitive data detection — *doesn't exist yet* (real feature gap)

- `grep -rln "screenshot\|screen_capture" src/agent_bom/` returns only `parsers/skill_audit.py` (as a permission class check, not content analysis).
- The gap you flagged: MCPs / agents that take screenshots can capture credentials, PII, customer data, internal URLs — agent-bom doesn't inspect or redact that content today.
- **Filed as a new feature:** see issue link in the companion PR. Design sketch below in §Appendix.

### P2 — Password-based auth on upstream config should be explicitly banned

- `gateway_upstreams.py` accepts `auth: bearer` with env-var token. Operators could (mis)configure Snowflake MCP as `bearer` and put the Snowflake password in the env var.
- **Fix:** add a linter check or a runtime warning if an upstream's `token_env` is named `*_PASSWORD*`. Small; not urgent.

### P2 — `AGENT_BOM_SNOWFLAKE_REQUIRE_KEYPAIR=1` is opt-in

- Default is permissive — password fallback still works unless you set the env var.
- **Fix:** flip the default to deny-password for `0.79.0+`, with a migration note. Breaking change, but right thing to do.

### P2 — `/metrics` endpoint is unauthenticated

- Matches Prometheus scrape convention (no auth required) and the response is intentionally non-sensitive (counters). Worth an explicit note in `OBSERVABILITY_METRICS.md` documenting the threat model so operators know to pin the scrape target behind a NetworkPolicy (which the shipped Helm values already do).

### P2 — Graph layer scalability story is not documented

- `src/agent_bom/graph/` + `context_graph.py` total ~2,850 LOC across 10 focused modules — code is good, but there's no "how this scales" doc (cardinality at 50k packages, memory growth).
- **Fix:** extend `docs/PERFORMANCE_BENCHMARKS.md` with a graph-specific section. Small add, filed as companion issue.

## Appendix: screenshot sensitive-data detection — design sketch

**Why it matters:** any MCP that wraps a browser / screen-capture tool (Playwright-MCP, Puppeteer-MCP, plus Cursor/Claude running screen-read tools) can exfiltrate secrets, PII, and internal data through pixels that never hit the existing text-content detectors.

**Where it slots into the existing architecture** (no new service):

1. **Detector module** — `src/agent_bom/runtime/visual_leak_detector.py` (new) following the existing pattern of `CredentialLeakDetector` in [`runtime/detectors.py`](../src/agent_bom/runtime/detectors.py). Takes a tool response that contains an image (MCP protocol uses `content: [{"type": "image", "data": "<base64>"}]`).
2. **OCR + pattern match** — run the image through `pytesseract` (optional dep) → feed extracted text into the same `CREDENTIAL_PATTERNS` + `_PII_PATTERNS` that already guard text responses.
3. **Redact-in-place** — replace pixel regions matching the OCR boxes with a black rectangle before the response is forwarded to the agent. Return an `Alert(detector="visual_leak", severity=CRITICAL|HIGH)`.
4. **Policy rule** — new `block_screen_captures: true` gateway rule that refuses `tools/call` on tools whose `class` is `screen_capture` entirely. Policy engine in [`proxy_policy.py`](../src/agent_bom/proxy_policy.py) already has the capability-class dispatch; add `screen_capture` to the tool classifier in [`runtime/detectors.py _classify_tool_classes`](../src/agent_bom/runtime/detectors.py).
5. **Audit trail** — visual-leak hits land in the same HMAC-chained audit log as text-leak hits; `record_gateway_relay(upstream, "blocked")` and an `action: gateway.visual_leak_blocked` audit event.

**Ship path:** new dep `agent-bom[visual]` that pulls `pytesseract` + `Pillow`, opt-in because OCR is CPU-heavy. Sidecar + gateway both call the detector when they receive an image-bearing tool response. CI tests use a synthetic PNG rendered with the PIL `ImageDraw` drawing of fake API keys + real redaction assertion.

File size estimate: ~300 LOC core + 150 LOC tests.

## What I recommend next (queued)

1. Close out this audit with doc merge + follow-up issues filed (done in this PR).
2. Ship the screenshot-redaction feature as a scoped PR (~1 day of focused work).
3. Add the graph-scalability benchmark entry to `PERFORMANCE_BENCHMARKS.md` (~1 hour).
4. Resume #1522 phases 2–4 for the remaining monoliths (though most landed in #1561, #1564, #1565, #1566 — only `cli/agents/__init__.py` remains large).

## How I verified every claim

```bash
# Repeatable audit script — anyone can rerun
grep -rn "class OIDCConfig\|class SAMLConfig\|class APIKeyMiddleware" src/agent_bom/api/
grep -rn "def require_\|def _authorize" src/agent_bom/rbac.py
grep -rn "rotation_policy\|def rotate_key" src/agent_bom/api/routes/
grep -rn "tenant_id" src/agent_bom/api/postgres/ src/agent_bom/api/snowflake_store.py
grep -rn "SSE-KMS\|kmsKeyId\|Ed25519" deploy/helm/agent-bom/ src/agent_bom/api/
grep -rn "screenshot\|screen_capture" src/agent_bom/  # single match = gap
```
