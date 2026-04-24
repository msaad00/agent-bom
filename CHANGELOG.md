# Changelog

All notable changes to agent-bom are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

Work targeting the next release.

---

## [0.81.3] – 2026-04-23

### Changed
- **Deployment and runtime guidance** — the README, self-hosted EKS guide, endpoint fleet guide, and proxy-vs-gateway-vs-fleet guide now surface the current graph scale boundary, recommended self-hosted defaults, runtime deployment matrix, and discovery-confidence boundaries where operators actually make rollout decisions.

### Fixed
- **Graph overview regression guardrail** — the graph API test suite now locks the default `/v1/graph` overview path to the store-backed `page_nodes` / `edges_for_node_ids` / `snapshot_stats` flow so filtered paging cannot silently fall back to full `load_graph()` materialization.
- **Docker Hub release sync** — the release workflow now uses a Docker Hub short description that stays under the registry API byte limit, preventing the `Publish to Docker Hub` job from failing after image push.

---

## [0.81.2] – 2026-04-23

### Added
- **UI session and capability contract** — `/v1/auth/me` now exposes authenticated actor, tenant, backend role, UI-facing capability summaries, and explicit `can_see` / `can_do` guidance so the browser shell can reflect the real backend auth model instead of inferring permissions ad hoc.
- **Endpoint enrollment identity contract** — managed endpoint onboarding bundles now emit stable `source_id`, `enrollment_name`, owner, environment, tag, and MDM metadata so fleet inventory can preserve one explicit endpoint identity model across Jamf, Intune, Kandji, and local rollout paths.

### Changed
- **Release-managed version surfaces** — the bump/check scripts now manage compose and runtime version pins as first-class release surfaces so image/version drift fails fast in CI instead of leaking into post-tag cleanup.
- **Snowflake schedule parity** — warehouse-native deployments now persist recurring scan schedules in Snowflake and wire `/v1/schedules*` through the same backend-selection path as jobs, fleet, and gateway policy stores.
- **Snowflake exception parity** — exception workflows now persist through the Snowflake backend too, extending the warehouse-native control-plane boundary without overclaiming full Postgres parity.
- **Snowflake tenant-scoped store lookups** — job, fleet, schedule, and exception lookups/deletes now carry tenant scope into the Snowflake store layer instead of relying only on post-hoc route checks, keeping the warehouse path aligned with the platform’s defense-in-depth tenant model.
- **Graph search and slice filtering** — the control plane now uses indexed graph-node search paths with server-side entity, severity, compliance-prefix, and data-source filters so larger tenant snapshots do not fall back to broad client-side graph scans.
- **Graph overview pagination** — the default `/v1/graph` overview path now pages nodes and page-local edges from the store instead of materializing whole snapshots in memory before pagination.
- **Endpoint onboarding bundles** — managed endpoint rollout bundles now carry a machine-readable enrollment manifest plus optional stable fleet `source_id` wiring so Jamf, Intune, and Kandji pushes can keep one explicit endpoint identity contract instead of only raw install scripts.
- **Deployment and product framing** — README, deployment docs, self-hosted diagrams, trust-boundary docs, and Snowflake-parity guidance now align around `AI supply chain and infrastructure`, one obvious pilot path, one obvious production path, and explicit self-hosted vs MSSP boundaries.
- **MCP server modularization** — the monolith split continued with extracted shared scan pipeline, resource/prompt catalog, FastMCP bootstrap helpers, and runtime catalog tool registration while keeping `create_mcp_server()` behavior and public imports stable.

### Fixed
- **Shield concurrency and API rate limiting** — shield now reuses a bounded async bridge instead of spinning up unbounded executor paths, and the in-memory API rate limiter is explicitly thread-safe.
- **Platform record invariants** — persisted fleet and MCP observation records now normalize tenant identity and UTC ISO-8601 timestamps consistently on read/write so graph, fleet, runtime, and audit correlation work from the same canonical model.
- **Audit and graph query hardening** — exception approval/revocation no longer allow actor spoofing, graph routes move sync store calls off the event loop, SQLite graph search falls back cleanly when FTS `MATCH` expressions error, and audit replay rejects malformed short HMAC values instead of truncating them into a false compare.

### Security
- **Gateway hardening** — scoped API keys are now enforced on the routes that already advertise scoped auth behavior, and gateway 404 responses no longer leak tenant-specific upstream details.
- **Runtime monitor defaults** — the optional monitor DaemonSet now uses a dedicated service-account path, disables automounted service-account tokens, and is documented as an explicit zero-trust, off-by-default runtime surface rather than an assumed deployment requirement.

---

## [0.81.1] – 2026-04-22

### Added
- **Inventory-first MCP visibility** — the control plane now surfaces MCP command/URL, auth mode, credential-backed configuration, fleet timing, and provenance across scans, fleet sync, gateway discovery, and persisted observations instead of forcing operators to infer source context from summary badges.
- **Operator feedback surface** — the shipped UI now includes in-product `Share feedback` and `Report bug` entry points with a copyable support bundle instead of relying on out-of-band issue filing alone.
- **Runtime rollout packaging** — endpoint proxy bundles can now be rendered as `.pkg`, `.msi`, Homebrew, and MDM-oriented rollout assets, and Kubernetes deployments can opt into proxy sidecar auto-injection through the packaged mutating webhook path.

### Changed
- **Self-hosted runtime model clarity** — the product now documents `fleet`, `proxy`, and `gateway` as peer surfaces with explicit deployment/use guidance, tighter EKS rollout docs, clearer entrypoints, and an honest retention/security-lake model that matches the current code and storage backends.
- **Security graph semantics** — the UI and docs now make snapshot identity, scope, timestamps, pagination, node identifiers, and blast-radius semantics explicit so graph investigation scales without inventing a second graph model in the operator workflow.
- **Release-caveat guidance** — graph/load boundaries, screenshot-redaction scope, centralized managed-connection limits, and the contributor workflow around GitHub’s `Update branch` synthetic-head problem are now explicit in the shipped docs instead of living as tribal knowledge.

### Fixed
- **AWS/EKS operator path** — the reference installer now includes preflight checks and post-deploy verification so self-hosted rollout is not "install and guess" anymore.
- **Skill-audit correlation gap** — skill-audit findings now feed the graph instead of landing as an orphan analysis surface outside the main inventory and blast-radius model.
- **Runtime contract coverage** — gateway rate-limit behavior and inbound OCSF normalization now have explicit contract tests instead of relying on indirect coverage only.

### Security
- **Runtime hardening sweep** — middleware RBAC write-route coverage is closed, cached proxy policy bundles are Ed25519-signed and fail closed on mismatch, gateway policies can hot-reload without redeploy, and replay detection now uses a bounded long-window design instead of a short-lived exact-only cache.
- **Deploy-time hardening** — the AWS/EKS rollout path now validates control-plane inputs before install, and packaged runtime operations document policy-signing rotation and cert-manager-backed webhook certificate renewal instead of leaving those as tribal knowledge.

---

## [0.81.0] – 2026-04-21

### Added
- **Hosted control-plane source workflows** — first-class source records and source-linked jobs are now joined by persisted schedule controls on `/sources`, so operators can create recurring runs against real `source_id` records instead of reading static guidance (#1602, #1606).

### Changed
- **Blast-radius scoring semantics** — EPSS percentile tiers now influence blast-radius scoring directly, and the previous 35-point deduction ceiling has been removed so high-reach critical exposure does not flatten into the same score band (#1605).
- **Package lookup hot path** — version parsing is cached and package presence checks are batched, cutting repeated database round-trips on larger scan inventories (#1605).
- **Traceability on hot paths** — the API, graph builder, DB lookup path, and runtime proxy now emit OTEL spans with W3C trace propagation so control-plane and proxy activity share one trace context (#1605).

### Fixed
- **Release-managed surface alignment** — package metadata, Dockerfiles, Helm values, runtime examples, registry manifests, and marketplace-facing version pins now align on `0.81.0` instead of leaving post-release drift for operators to discover manually.

### Security
- **Tenant-scoped control-plane reads** — asset routes now enforce tenant scope directly instead of trusting caller-provided tenant context, closing the highest-risk cross-tenant read gap from the post-release audit (#1603).
- **Fail-closed OIDC and audit integrity** — OIDC discovery now refuses unsafe tenant/JWKS combinations, audit records are chained instead of independently HMACed, and gateway requests validate API keys against control-plane state before relay (#1603).
- **Per-tenant runtime fairness** — scan concurrency and operator policy surfaces now expose tenant-specific quota enforcement instead of relying on one global in-process ceiling (#1605).

---

## [0.80.1] – 2026-04-21

### Fixed
- **Standalone UI image release path** — the Next.js container build now emits the `.next/standalone` output expected by the published `agent-bom-ui` image, and CI smoke-tests that path before release.
- **Version-surface coherence** — Helm examples, runtime sidecar manifests, release verification docs, and product metrics now align on `0.80.1` so the public release surfaces match the shipped tag.

### Security
- **Tenant and gateway auth hardening** — Postgres-backed API key verification can now resolve non-default tenant keys during auth and gateway relay paths, instead of silently falling back to default-tenant visibility under RLS.

---

## [0.80.0] – 2026-04-21

### Added
- **Control-plane auth for the shipped UI** — OIDC, trusted-proxy browser auth, session API-key fallback, and runtime auth introspection now let the dashboard operate as a real operator surface instead of a same-origin-only shell.
- **Hosted-product source registry baseline** — the API and UI now expose first-class source records, source-linked jobs, and persisted schedule state as the first slice of the hosted control-plane model.
- **Signed release surfaces** — Helm OCI publish, UI image release wiring, and stronger release verification/docs were added to the productized deployment path.

### Changed
- **P0/P1 audit closure** — visual leak detector races, timeout audit gaps, resolver/VEX strictness, ServiceMonitor/operator defaults, CSP documentation, and UI dependency/release guardrails were tightened across the release lane.
- **Deployment docs and diagrams** — self-hosted operator guidance, EKS rollout docs, and enterprise topology explanations were rewritten to match the actual control-plane/runtime split in code.

### Fixed
- **Gateway and runtime audit integrity** — timeout paths now audit correctly, OCR runs once per response instead of once per image block, and the control plane/runtime surfaces agree on the operator deployment contract.
- **UI packaging accuracy** — README and deployment copy now describe the Python image and standalone UI image honestly instead of implying a single bundled live dashboard path.

---

## [0.79.0] – 2026-04-20

### Added
- **Multi-MCP gateway and rollout path** — central `agent-bom gateway serve`, fleet-driven upstream discovery, focused EKS pilot guidance, and deployment-first docs for self-hosted operator environments (#1551, #1552, #1554, #1555, #1560).
- **Visual leak runtime enforcement** — `VisualLeakDetector` is now wired into gateway and proxy protection paths so screenshot and image tool responses can be redacted or blocked as part of the runtime policy surface (#1572, #1575).
- **Bidirectional OTEL product surface** — OTLP export, W3C trace context, `/v1/traces` ingest, and runtime OTEL evidence are now called out as first-class operator capabilities in the shipped product surfaces (#1583).

### Changed
- **Tenant-native persistence and parity** — fleet, policy, audit, baseline, trends, analytics, and Snowflake/Postgres-backed stores now query natively by tenant rather than relying on broad reads plus in-memory filtering (#1558, #1559, #1561, #1562, #1567, #1569).
- **RBAC and control-plane hardening** — enterprise/compliance/auth-policy surfaces align on the current `admin` / `analyst` / `viewer` model with route-level and middleware-level enforcement kept in sync (#1576).
- **Monolith reduction in core surfaces** — `mcp_server`, `ast_analyzer`, Postgres stores, and console output were split into focused modules while preserving CLI/API behavior and published contracts (#1561, #1564, #1565, #1566).

### Fixed
- **Graph blast-radius hot path** — vuln-to-server edge resolution now uses indexed lookups instead of the prior nested agent×server cross-product in the graph builder (#1581).
- **HTTP retry behavior under load** — outbound retry backoff now adds positive jitter so concurrent OSV and HTTP clients do not back off in lockstep (#1582).
- **Tenant-blind enterprise reads** — baseline compare, trends, audit export, and related enterprise/operator surfaces now honor tenant scope consistently across backends (#1559, #1569).
- **Write-route audit coverage** — exception deletion, SIEM test, schedule mutation, fleet sync/state updates, and related operator write paths now emit audit entries with actor and tenant context.
- **Ignore-file error handling** — malformed YAML/JSON ignore files now fail through narrow parse errors instead of broad exception swallowing (#1582).

### Security
- **Hardened audit evidence chain** — audit HMAC coverage now includes payload `details`, routes fetch tenant-scoped audit entries at the store layer, and exported evidence stays tamper-evident across backends (#1559).
- **Transport and operator posture clarified** — HTTPS-external / trusted-boundary-internal deployment guidance, OTEL/OPA positioning, and current auth/RBAC behavior now match the live product and deployment docs (#1583).

### Docs
- **Release and deployment alignment** — README, Docker Hub README, product brief, EKS guidance, backend matrix, and release-managed version surfaces are aligned on `0.79.0`.

---

## [0.77.1] – 2026-04-18

### Fixed
- **Release metadata alignment** (#1498) — corrected 0.77.0 follow-up: brought `pyproject.toml`, `uv.lock`, and integration listings to a consistent 0.77.1 after an intermediate packaging drift

---

## [0.77.0] – 2026-04-18

### Added
- **Live Kubernetes posture scanning** (#1489) — cluster-scoped scan path walks live API-server objects, correlates pod specs with image/CVE inventory, and emits findings through the unified pipeline
- **Control-plane enterprise auth** — SAML SSO assertion exchange (#1487), API key rotation policy with audit trail (#1492), tenant quotas (#1486), and tenant-scoped rate limiting with Postgres tuning (#1493)
- **Proxy & fleet durability** — idempotent fleet/proxy ingest (#1473), circuit breaker + DLQ for proxy audit delivery (#1494), service-mesh + policy-controller templates for EKS (#1495)
- **Helm packaging for the control plane** (#1453) — end-to-end Helm chart with production operator defaults (#1458), operator observability + backups (#1472), encrypted backup restore path (#1485)
- **MCP agent mesh surface** — agent context graph with lateral movement analysis, IaC findings stitched into the unified graph (#1426), programmable graph query traversal (#1427), mesh cleanup polish (#1470)
- **Findings as first-class UI surface** (#1423) — unified, deep-linkable findings view across vulnerability, policy, and compliance sources with one-click drill into the security graph (#1395, #1397, #1399, #1400, #1401)
- **Snowflake CIS password policy coverage** (#1429) and Snowflake storage backend parity (#1408)
- **Live UI configurability** — runtime-configurable API endpoint (#1452), dashboard posture card unification (#1447), theme support across dashboard and graph surfaces (#1404, #1407, #1411, #1413)
- **Data-sources product surface** (#1421), how-agent-bom-works explainer (#1440), and deployment/hosting guidance (#1444)

### Changed
- **AST analyzer modularization** — JS/TS (#1424), Go (#1425), and shared models (#1420) extracted into focused helpers; SAST helper-chain findings reframed for clearer attribution (#1488)
- **MCP server modularization** — specialized tool registrations (#1439) and runtime helpers (#1438) split out of the main server module
- **Scanner modularization** — OSV helpers (#1418), runtime state helpers (#1417), risk/blast-radius helpers (#1416) split into dedicated modules
- **CLI modularization** — option groups split into helper modules (#1434); wayfinding and doctor output polished (#1394)
- **Proxy policy & audit split** (#1436) for cleaner policy boundaries
- **Remediation scoring anchored to blast-radius risk** (#1443), not CVSS alone
- **Prompt-injection analyzer signals tightened** (#1490)
- **Analytics ingest batched** for flagged trace events (#1428)

### Fixed
- **Operator drilldown UX** (#1496), pilot UI reliability (#1471), mesh UI cleanup + README visuals (#1470)
- **Pilot rate limiting + control-plane HA hardening** (#1460), pilot hardening follow-ups (#1457), pilot auth + endpoint fleet path (#1456)

### Security
- **Gateway policy RBAC hardened** (#1451)
- **Marketplace publishing surfaces hardened** (#1442)
- **Supply-chain trust + extras audit made explicit** (#1441)
- **UI dependency + validation contract hardened** (#1446)

### Docs
- **Enterprise scale guidance + benchmark harness published** (#1459)
- **Data ingestion + security model documented** (#1437)
- **Docs rebuilt on release tags** (#1419)
- **Sidebar IA clarified** (#1412), scan page product surfaces clarified (#1415)

### Infra
- **mypy phase 2 body checking enabled** (#1433)
- **Cloud normalization coverage with fixtures** (#1410)
- **Storage backend contract exposed on health** (#1409)
- **Backend parity + Snowflake modes documented** (#1408)

---

## [0.76.4] – 2026-04-13

### Added
- **Release-surface refresh** — README, PyPI, and Docker Hub now show the current product path with real screenshots, tightened copy, clearer architecture/graph visuals, and a shorter demo flow
- **CVE and graph drilldowns** — vulnerability rows and graph detail panels now provide richer fix, impact, compliance, and evidence context instead of acting like dead text

### Changed
- **Summary-first loading** — dashboard, jobs, activity, vulnerabilities, mesh, context, and insights now unlock from lightweight job summaries first and only hydrate deeper scan data when the active panel needs it
- **Graph defaults and fallbacks** — focused graph views, empty states, findings fallbacks, and posture labels now favor scoped, readable investigation paths over dumping full topology state at once
- **Docker freshness operations** — release automation now includes an explicit Docker `latest` refresh path so base-image fixes can be rebuilt and republished without waiting for a feature release

### Fixed
- **Snowflake SQL hardening** — notebook identifier quoting and `days` coercion now validate and escape values before SQL interpolation
- **Jobs summary contract** — pushed and completed scan rows now keep `completed_at`, `error`, and summary metadata aligned across API, dashboard, and jobs surfaces
- **App-router release build stability** — release pages that rely on search params now render safely under `Suspense`, fixing the current Next.js app-router build path
- **AST/SAST depth wave** — validator-aware guards, transformed-return sanitizers, JS/TS early exits, and cross-file helper modeling reduce false positives while improving Python, JS/TS, and Go parity

### Security
- **Container rebuild response** — Docker refresh and rescan wiring now close the loop for newly published Alpine fixes instead of relying on manual Docker Hub inspection
- **Snowflake query validation** — user-controlled notebook and date inputs are now coerced or quoted before execution, removing the identified injection and query-shape risks

---

## [0.76.2] – 2026-04-09

### Changed
- **Patch release alignment** — managed release/version surfaces are now aligned on `0.76.2` for the next patch cut

### Fixed
- **Alpine package visibility** — local vulnerability DB sync now ingests Alpine secdb in addition to OSV, so Alpine package advisories like the recent `openssl` and `util-linux` fixes are detected without waiting on OSV lag
- **Alpine scanner coverage** — Alpine OS-package fallback queries now include `v3.23`, matching the current container base branch
- **Container hardening** — the Docker build now upgrades installed Alpine packages during both builder and runtime stages instead of only bumping `zlib`
- **Release image gating** — CI and release image scans now fail on fixable `MEDIUM+` and `UNKNOWN` image vulnerabilities while ignoring upstream-unfixed image findings

### Security
- **Container CVE response** — the patch release closes the fixable Alpine `openssl` and `util-linux` image findings and adds stronger pre-release guardrails to stop similar Docker regressions from shipping unnoticed

---

## [0.76.1] – 2026-04-09

### Added
- **CLI output parity for reporting commands** — `check`, `report diff`, and `report history` now have clearer machine-readable behavior, and reporting surfaces that were still missing `--quiet` now support quiet scripting flows
- **CLI troubleshooting coverage** — the shipped docs now include a dedicated debug guide for quiet mode, stdout vs file output, discovery triage, and verification workflows

### Changed
- **Patch release alignment** — release-managed files, Docker/Helm metadata, OpenClaw skills metadata, docs, registry surfaces, and action examples are now aligned on `0.76.1`
- **Verification status wording** — package provenance verification now distinguishes missing attestations from service unavailability instead of collapsing both into a generic unknown state

### Fixed
- **Quiet mode consistency** — reporting and analysis commands now suppress headings/export chatter when `--quiet` is requested
- **Verify JSON output** — `agent-bom verify --json` no longer prepends human console banners before the JSON payload
- **Graph contributor install contract** — graph centrality dependencies and contributor install paths were aligned so graph analysis works in a clean optional-extra install
- **Live MITRE/STIX parsing** — ATT&CK/CAPEC runtime parsing now handles the current upstream payload shape and restores live CWE→ATT&CK mapping
- **Docker Hub release hardening** — release sync, cleanup retention, and version-alignment checks now match the real Docker tag contract and fail loudly on drift
- **Release bump automation** — stale version-bump patterns were removed so dry-run and check mode only flag real managed release surfaces

### Security
- **Supply-chain verification clarity** — provenance verification now reports whether attestations are absent or temporarily unavailable, reducing ambiguous release-audit results for package verification

---

## [0.76.0] – 2026-04-09

### Added
- **Unified graph product path** — persisted snapshots, current-state and diff views, attack-path drilldown, search, impact, delta alert delivery, and Postgres-backed graph persistence are now part of the shipped CLI/API/dashboard flow
- **Multi-language AST/SAST depth** — Python, JS/TS, and Go analysis now include stronger cross-file and taint-aware coverage, plus SARIF import and cleaner custom-rule handling
- **Container layer attribution** — image findings now retain per-layer package provenance so output can show which layer introduced a vulnerable package
- **PDF report export** — `agent-bom scan -f pdf -o report.pdf` now renders the existing HTML report through an optional WeasyPrint-backed export path

### Changed
- **README and architecture visuals** — product positioning, hero commands, and architecture diagrams were shortened and tightened to match the current shipped path without overflowing cards or stale counts
- **Demo CLI polish** — demo and offline copy are shorter, and the scan path no longer prints redundant inner vulnerability banners when the outer progress bar is already rendering the step
- **Release-managed versioning** — docs, deployment files, Helm, OpenClaw, registry metadata, and action examples now align on `0.76.0`

### Fixed
- **Graph correctness and scale** — snapshot isolation, tenant propagation, search escaping, delta dispatch semantics, and direction-aware traversal/reporting were hardened across the recent graph lane
- **Scanner concurrency** — shared cache and scanner-global thread-safety issues were fixed and regression-tested
- **Container evidence depth** — package metadata now tracks layer/package occurrences instead of flattening away provenance
- **Release automation drift** — CodeQL SARIF upload is on v4 and no longer fails when a SARIF file was not actually produced

### Security
- **Release dependency refresh** — cryptography was bumped to `46.0.7`, clearing the active moderate buffer-overflow advisory on the locked release path
- **Graph delta delivery** — delta alerts now flow through the existing dispatcher/webhook surfaces instead of only being computed/export-ready

---

## [0.75.15] – 2026-04-04

### Added
- **API distributed tracing** — request-level `traceparent` propagation, `X-Trace-ID` headers, OTLP/HTTP export, and collector/reverse-proxy contract docs
- **Postgres-backed API rate limiting** — shared throttle state across replicas via `api_rate_limits`, keeping `429` and `Retry-After` semantics consistent
- **Skills AST-aware analysis** — fenced Python and JS/TS code blocks in skill/instruction files now get semantic risk detection for dynamic execution, shell/process execution, and file mutation
- **Skills output schemas** — `skills scan` and `skills rescan` now ship explicit versioned JSON schemas for stable downstream consumption
- **Helm monitoring surfaces** — readiness/startup probes, optional metrics service, optional `ServiceMonitor`, and runtime `/metrics` wiring for Prometheus-friendly deployments
- **Postgres enterprise persistence** — audit log and trend history now have Postgres backends with tenant-aware persistence

### Changed
- **Demo wording** — the built-in `--demo` path is now presented as a curated sample agent + MCP environment, while real local/project scans remain the primary product story
- **Tenant isolation posture** — enterprise stores, gateway policy surfaces, audit/trend history, and shared rate-limit state now align under the same tenant-boundary model
- **Security automation** — daily preventive workflows, deployment freshness checks, and authenticated Railway verification now better reflect real release state

### Fixed
- **GitHub Action enterprise networking** — proxy and custom-CA environment variables now pass through consistently during install and scan steps
- **OpenClaw packaging metadata** — stale skills test-count references were updated to current repo reality
- **Postgres schema drift** — schema summaries, RLS coverage assertions, and table counts now match the current tenant-bearing model

### Security
- **Postgres RLS completion** — all tenant-bearing Postgres tables now enforce row-level security, with shared caches and infra-only tables explicitly excluded from that boundary
- **Enterprise auth maturity** — RBAC route enforcement, OIDC tenant-claim scoping, authenticated request tracing, and shared rate-limiting now operate together as the production API contract

---

## [0.75.14] – 2026-04-03

### Added
- **Next.js Insights page** (`/insights`) — SupplyChainTreemap, BlastRadiusRadial, PipelineFlow, EpssVsCvssChart, VulnTrendChart wired to real scan data; treemap cells are clickable and drill down to `/vulns`
- **Gateway enforcement chart** — audit tab shows stacked bar of blocked/alerted/allowed actions per tool
- **Governance findings chart** — stacked bar of finding severity by governance category
- **Activity query chart** — bar chart of agent query pattern frequency
- **Fleet lifecycle chart** — bar chart of agents by lifecycle state
- **Jobs status donut** — pie chart summarising job queue by status
- **`ui/components/empty-state.tsx`** — reusable `EmptyState` + `ErrorBanner` components used across pages
- **Retry buttons** — Activity and Governance error states now include a Retry button
- **SECURITY.md** expanded — response SLA, known limitations, API security model, disclosure timeline
- **PR template** — added Related Issues, TypeScript check, breaking changes, checklist sections
- **pre-commit hooks** — added `check-yaml`, `check-json`, `check-toml`, `end-of-file-fixer`, `trailing-whitespace`, `detect-private-key`, `check-merge-conflict`, `mixed-line-ending`
- **`agent-bom mcp scan`** — focused MCP server package audit path for pre-install checks
- **Compliance narrative CLI** — auditor-facing narrative export from saved scan reports via `agent-bom report compliance-narrative`
- **MCP caller governance** — per-caller rate limiting, request tracing, and richer tool metrics now flow through the MCP server metrics surface
- **Remote MCP startup contract** — Railway/remote deployments now use an explicit bearer-token contract instead of accidental anonymous exposure

### Fixed
- **JSON report import** — file upload now validates size (10 MB), schema, prototype-pollution keys, and finite numeric values before use (`ui/lib/validators.ts`)
- **`generated_at` TypeScript error** — `ScanResult` does not have `generated_at`; use `scan_timestamp` instead
- **JetBrains claim** — removed from active integrations; filed as issue #412 for proper implementation
- **`skills scan` path handling** — bundle identity now supports referenced files outside the primary file directory, fixing repo-local scans against shared security assets
- **`check` ecosystem ambiguity** — pre-install checks now fail closed on genuinely ambiguous package names and use version-aware registry detection to avoid cross-registry false positives
- **`skills scan --verbose`** — added parity with other CLI surfaces for easier debugging
- **Runtime CLI warning noise** — async proxy tests now use async-aware mocks, removing unawaited coroutine warnings from that path
- **Frontend/backend scan contracts** — UI API types now model `scan_performance`, richer `scorecard_summary`, `posture_scorecard`, and remediation metadata consistently with backend JSON output
- **GitHub Action execution contract** — hardened argv handling, severity validation, pip caching, step summaries, and sanitized PR comment/report generation now match the documented Action behavior
- **Runtime image provenance** — runtime Docker image now builds from repo source instead of reinstalling from PyPI, aligning image behavior with source and release verification
- **MCP execution envelope** — sync and async tools now share bounded concurrency, timeout, metrics, path safety, and sanitized error handling
- **Snowpark enterprise networking** — Snowpark image now supports enterprise proxy and custom-CA configuration like the other maintained image families

### Security
- **JSON file upload** — `ui/lib/validators.ts` guards against DoS via oversized files, prototype pollution, and schema-invalid payloads (no new npm dependencies)
- **API and remote MCP fail closed** — non-loopback API and remote MCP transports now refuse to start without explicit auth unless an insecure override is deliberately supplied
- **Dependency security refresh** — LiteLLM was bumped to `1.83.0`, clearing the active 2026 GitHub security advisories on `main`

---

## [0.75.13] – 2026-04-01

### Added
- **Focused MCP server review** — `agent-bom mcp scan <server>` adds a narrower audit path for a single MCP server or command before adoption
- **Compliance narrative CLI** — compliance narrative export is now reachable from the CLI for release and audit workflows

### Changed
- **Release surfaces aligned** — README, PyPI, Docker Hub, site docs, Helm, OCI metadata, and publishing surfaces now share the same product description and release references
- **Canonical product story** — product positioning, Claude/Cortex integration references, and repo-derived metrics now point back to the canonical brief and generated metrics appendix
- **First-run guidance** — empty-state discovery help now shows concrete Claude, Cursor, Codex CLI, and Cortex CoCo config paths instead of circular retry suggestions
- **SARIF defaults** — SARIF export now auto-enables enrichment when online so severity context lands in GitHub and downstream scanners by default

### Fixed
- **Offline safety boundary** — offline scans now fail closed when the local vulnerability database is missing or incomplete instead of producing a false clean result
- **Incomplete result visibility** — critical scanner and enrichment failures now surface warning summaries instead of silently degrading to partial output
- **Skills scanning** — `agent-bom skills scan .` no longer crashes on repo-local path validation, and the command now supports `-v` / `--verbose`
- **Package checks** — `agent-bom check` now resolves ambiguous package names more safely and avoids cross-ecosystem false positives
- **Output format handling** — unknown output extensions now fail loudly instead of silently falling back to JSON
- **ClickHouse query hardening** — analytics escaping was tightened and the associated tests expanded
- **Release quality gates** — follow-up CodeQL, lint, mypy, FastAPI response-model, and regression issues from the stabilization lane were fixed before release

### Security
- The `0.75.13` release closes the remaining pre-release P0/P1 safety issues from the final audit lane, including offline false-clean behavior, incomplete scan signaling, and ClickHouse query hardening

---

## [0.75.12] – 2026-03-29

### Added
- **First-class skills scanning** — `agent-bom skills scan` and `agent-bom skills verify` are now top-level CLI surfaces for instruction-file trust, provenance, and findings
- **Live MCP tool capability scoring** — added capability-based tool/server risk assessment from `tools/list` introspection, surfaced through MCP and scan outputs
- **Release demo refresh** — updated hero demo and release surfaces for `v0.75.12`

### Changed
- **MCP tool surface** — docs and public surfaces now reflect the current 36-tool MCP server accurately
- **Quickstart alignment** — CLI/docs/demo flows now point to the grouped first-class commands (`agents`, `skills`, `image`, `iac`)
- **Advisory labeling** — unscored vulnerabilities are presented as advisories/pending severity instead of ambiguous unknowns
- **Resolver continuity** — npm version resolution now prefers cached/bundled continuity under rate limiting instead of repeated blocking retries
- **Supply-chain enrichment** — `--enrich` resolves package source metadata before OpenSSF Scorecard lookup and reports explicit enrichment coverage state

### Fixed
- **Blast radius serialization** — package name/version/stable ID now propagate correctly in filesystem and JSON outputs
- **Filesystem posture credibility** — fs/project scans no longer get penalized for missing MCP-only config context; posture and framework mapping now reflect the actual scan mode
- **Framework tagging** — intrinsic vulnerability findings now carry framework tags in both agents and fs modes
- **Remediation output** — remediation JSON now includes populated priority and action fields
- **UI dependency hygiene** — aligned UI eslint peer range with Next.js-supported versions to remove install drift
- **Scorecard source resolution** — npm/PyPI direct dependencies now fall back to source metadata resolution paths so repo URLs, homepages, and Scorecard repos populate end to end

### Security
- No new release-blocking regressions introduced across the `0.75.12` stabilization lane; focused regression suites, UI tests, build checks, and release consistency checks remained green

---

## [0.75.0] – 2026-03-23

### Added
- **Dashboard UX** — posture grade (A-F) hero, top 5 attack path cards, security graph page with interactive React Flow, insight layer toggle (risk/credentials/default), 14-framework compliance heatmap
- **Remediation page** — priority table sorted by blast radius impact, Jira ticket creation per finding, compliance impact summary, severity/framework filters, JSON export
- **Compliance narratives** — `GET /v1/compliance/narrative` generates review-ready text per framework with control-level detail and remediation-compliance bridge
- **`--posture` flag** — 5-line workstation posture summary for solo developers
- **`--fixable-only` flag** — show only vulnerabilities with available fixes
- **`agent-bom doctor`** — preflight diagnostic (Python, DB, network, Docker, MCP configs, API keys)
- **Cross-agent behavioral detection** — `CrossAgentCorrelator` detects lateral movement (3+ agents same tool in 5min), anomaly baseline per agent
- **SSE proxy transport** — `agent-bom proxy --url` for remote SSE/HTTP MCP servers
- **SBOM multi-hop graph** — dependency depth tracking (A→B→C) + CycloneDX `vulnerabilities[]` ingest
- **API rate-limit headers** — `X-RateLimit-Limit/Remaining/Reset` on all responses, `X-API-Version: v1`
- **Jira API endpoint** — `POST /v1/findings/jira` with ephemeral credentials, SSRF-validated
- **False positive feedback** — `POST/GET/DELETE /v1/findings/false-positive` with tenant-scoped persistence
- **Break-glass endpoint** — `POST /v1/shield/break-glass` with admin RBAC + audit logging
- **Prometheus `/metrics`** — fleet_total and fleet_quarantined gauges
- **75 UI component tests** (Vitest + @testing-library/react)
- **8 intent-based OpenClaw skills** — discover, scan, scan-infra, enforce, comply, monitor, analyze, troubleshoot
- **CONTRIBUTING.md** — contributor onboarding guide
- **Enterprise Deployment guide** — MDM push, fleet API, zero-credential architecture

### Changed
- **Homepage reworked** — posture grade + blast radius chains at top, stats compressed to one row
- **Compliance page** — now shows all 14 frameworks (was 6)
- **Security graph** — uses pre-computed blast_radius scores (risk_score, is_kev, epss_score)
- **All dashboard pages** — consistent Loader2 spinners, overflow-x-auto tables, confirmation dialogs on destructive actions, Snowflake-only banners in error state
- **Vulns page** — pagination (50/page), search, FP feedback button, confidence scores
- **Jobs page** — status filter tabs, search, pagination (25/page), JSON export
- **Fleet page** — search, JSON export, confirmation on state transitions
- **Agents page** — search by name
- **CLI output** — severity text labels alongside colors (accessibility)
- **CycloneDX** — `formulation` field identifies agent-bom as generator
- **GitHub Action** — `exclude-unfixable` input for CI gating
- **Architecture diagram** — compact horizontal layout (LR)
- **Count alignment** — release surfaces were brought back to a single source of truth for that release's framework, rule, pattern, page, tool, and format totals

### Fixed
- **Full-stack alignment** — `severity_source`, `confidence`, `nist_800_53_tags`, `fedramp_tags`, `automation_settings`, `vector_db_scan`, `gpu_infra` now serialized in JSON output (were silently dropped)
- **Compliance router** — `/v1/compliance/narrative` no longer shadowed by `/{framework}` wildcard
- **UI field names** — `risk_score ?? blast_score`, `summary ?? description`, `is_kev ?? cisa_kev` with backward compat
- **Offline mode strict** — no silent network fallback when `--offline` set
- **AST prompt detector** — `description`, `help`, `title` fields no longer misclassified as system prompts
- **CodeQL SSRF** — defense-in-depth `validate_url()` at transport layer
- **HSTS header** — `Strict-Transport-Security` added to all API responses
- **OIDC SSRF** — `validate_url()` on discovery URL
- **ECS/EKS test mocks** — updated to paginator pattern
- **Protection engine** — `stop()` persists cleared kill-switch state, semaphore cache bounded to 8 entries
- **Chain-hashed audit log** — each entry includes previous entry's HMAC for tamper-evidence
- **Multi-tenancy isolation** — tenant_id enforced at middleware level
- **Quarantine enforcement** — quarantined agents excluded from fleet list by default
- **Log file permissions** — 0o600 on audit DB, fleet DB, log files
- **Node.js 20 deprecation** — `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24` on dependency-review
- **Local fonts** — Inter + JetBrains Mono bundled (no Google Fonts network dependency)

### Security
- 10/10 OWASP web categories PROTECTED (verified by code audit)
- SLSA L3 provenance on releases, Sigstore signing on PyPI
- 91 SHA-pinned GitHub Actions, 0 npm/Python vulnerabilities
- scrypt KDF for API keys, HMAC constant-time comparison, parameterized SQL everywhere

## [0.74.1] – 2026-03-22

### Security
- **Runtime**: Fix threat level comparison — `ThreatLevel` enum uses ordinal comparison; previously `CRITICAL > HIGH` was `False` (lexicographic), so escalations were never detected
- **Runtime**: Per-session shield engine isolation — zero trust, no cross-session threat contamination
- **Runtime**: Rate limiter now blocks (HIGH/CRITICAL severity) instead of alert-only (MEDIUM)
- **Runtime**: HTTP protection server auth via `AGENT_BOM_PROTECTION_API_KEY` with constant-time comparison
- **Runtime**: Single zero-width space now detected (was requiring 3+ consecutive chars, bypass fixed)
- **Runtime**: Unicode path traversal (`\u002e\u002e`) detection added
- **Runtime**: 3 new credential patterns (HashiCorp Vault, AWS session tokens, PagerDuty) — 112 total
- **Runtime**: Drift baseline persisted to disk, survives engine restarts in shield mode
- **Supply chain**: Go module provenance verification via sum.golang.org checksum database
- **Supply chain**: Provenance results persisted in Package model (integrity_verified, provenance_attested)

### Fixed
- **Compliance**: Wire NIST 800-53 Rev 5 tags in scanner pipeline (was defined but never called)
- **Compliance**: Wire FedRAMP Moderate baseline tags in scanner pipeline
- **Policy**: Add 9 missing framework tag fields to policy engine expressions (all 14 frameworks now accessible)
- **Scanner**: Surface non-OSV ecosystem skips to users with per-ecosystem breakdown
- **Scanner**: Track per-package CVE lookup errors and report at scan completion
- **Scanner**: Add severity_source field for audit trail (cvss, osv_database, ghsa_heuristic)
- **Scanner**: Bound semaphore cache to 8 entries (prevents memory leak in long-running API servers)
- **Scanner**: Kill-switch state now persisted on stop() (was leaving stale blocked state on disk)
- **Cloud**: ECS/EKS/SageMaker discovery uses boto3 paginators (was missing results beyond page 1)
- **MITRE ATLAS**: Expanded from 8 to 30+ technique mappings across all tactic categories

### Added
- `make dev` — starts API server + Next.js dashboard in parallel
- `make install-all` — installs all development extras (dev + ui + mcp-server)
- `dev-all` extra in pyproject.toml for one-command setup
- `AGENT_BOM_CLOUD_DISCOVERY_TIMEOUT` config (default 45s)
- Portable `.claude/launch.json` for dev server configs
- Mermaid blast radius diagram in README
- Mermaid architecture diagram in README
- Compliance frameworks table in README

### Changed
- README: ecosystem count 11 → 15, credential patterns 31 → 34, compliance frameworks 14 → 16
- MITRE ATLAS coverage documented accurately (30+ observable techniques)

---

## [0.74.0] – 2026-03-21

### Dashboard & HTML Report

- **Sidebar navigation** — collapsible left sidebar replaces top nav across Next.js dashboard (18 pages) and HTML report, with 5 grouped sections, command palette (Cmd+K), active link highlighting, mobile drawer (#993)
- **React Flow edge fix** — topology graph nodes now connect properly with Handle components, eliminating all "null handle id" errors (#993)
- **Topology enhancements** — nodes show server count, vuln count, credential indicators; animated edges for vulnerable connections; zoom controls; empty state (#993)
- **HTML report sidebar** — fixed 220px sidebar with IntersectionObserver active section tracking, mobile responsive hamburger toggle, print-friendly layout (#993)

### Security

- **Dependency CVE fixes** — pillow ≥12.1.1 (CVE-2026-25990 PSD OOB write), protobuf ≥6.33.5 (CVE-2026-0994 ParseDict DoS), pyjwt ≥2.12.0 (CVE-2026-32597 crit header bypass), tornado ≥6.5.5 (CVE-2026-31958 multipart DoS, GHSA-78cv-mqj4-43f7 cookie injection)
- **CI/CD hardening** — all GitHub Actions pinned to SHA digests, no `@master` refs, scoped permissions

### Fixed

- **Dashboard layout** — wider content area (1400px), CSS page transitions, thin scrollbar, card hover effects
- **HTML report unused variables** — removed dead nav link variables (ruff F841)

---

## [0.73.0] – 2026-03-19

### Architecture

- **5-product CLI** — `agent-bom`, `agent-shield`, `agent-cloud`, `agent-iac`, `agent-claw` — one package, five entry points, zero duplication (#967)
  - `agent-bom` — BOM generation + vulnerability scanning
  - `agent-shield` — runtime protection (proxy, protect, guard, watch, audit)
  - `agent-cloud` — cloud infrastructure (aws, azure, gcp, snowflake, databricks, huggingface, ollama, posture)
  - `agent-iac` — IaC security (scan, policy, validate)
  - `agent-claw` — fleet governance (fleet, serve, api, schedule, report, connectors)
- **Shared entry point factory** (`_entry.py`) — consistent error handling + update check across all 5 products
- **Parameterized help categories** — each product shows relevant command groups in `--help`
- **Full backward compat** — `agent-bom runtime proxy`, `agent-bom cloud aws`, etc. still work

### Added

- **CycloneDX 1.6 ML BOM extensions** — native `modelCard`, `data` components, `machine-learning-model` type with `quantitativeAnalysis` for training metrics (#967)
- **Agent-shield deep defense mode** (`--shield`) — correlated multi-detector threat scoring, `ThreatLevel` escalation (NORMAL→ELEVATED→HIGH→CRITICAL), automatic kill-switch on CRITICAL (#967)
- **Graph-native AIBOM export** — `to_graphml()` for yEd/Gephi/NetworkX, `to_cypher()` for Neo4j with AIBOM node labels (AIAgent, MCPServer, Package, Vulnerability) (#967)
- **CLI graph formats** — `agent-bom graph --format graphml|cypher` alongside existing json/dot/mermaid (#968)
- **CLI shield flags** — `agent-shield protect --shield --correlation-window 30` (#968)
- **API: graph export** — `GET /v1/scan/{job_id}/graph-export?format=graphml|cypher|dot|mermaid|json` (#970)
- **API: shield control** — `POST /v1/shield/start`, `GET /v1/shield/status`, `POST /v1/shield/unblock` (#970)
- **MCP graph tool** — `graph_export` MCP tool for graphml/cypher/dot/mermaid from scan results (#972)
- **agent-cloud new commands** — `snowflake`, `databricks`, `huggingface`, `ollama`, `posture` (#967)
- **agent-claw fleet** — `fleet sync|list|stats` commands + `connectors` command (#967)

### Fixed

- **Fleet min_trust Python 3.14** — explicit `float()` coercion + defensive `(trust_score or 0.0)` (#969)
- **API test noise** — mock `_run_scan_sync` with pytest `monkeypatch` fixture scoped to test file only (#970)
- **flatted 3.4.1→3.4.2** — GHSA-rf6f-7fwh-wjgh prototype pollution in `/ui` (#970)
- **CVE-2026-33231 suppression** — nltk wordnet_app remote shutdown (not reachable — never imported) (#971)
- **Stale test name** — `test_total_agent_types_is_18` → `is_31` (#967)

---

## [0.72.0] – 2026-03-19

### Added

- **30 MCP clients** — added Pieces, mcp-cli, Trae, Aide, Void, Replit Agent, Aider, Sourcegraph Cody, Tabnine, Copilot CLI, Junie, JetBrains AI
- **AI BOM tools** — 32 MCP tools for scanning, compliance, runtime, cloud in the `0.72.0` release
- **Version accuracy** — all surfaces updated with correct version and client counts
- **Compliance noise reduction** — actionable findings only in default output

---

## [0.71.4] – 2026-03-18

### Fixed
- **SARIF output**: paths were absolute (`/Users/.../Agent-Bom`) causing GitHub Security tab to show "No summary of scanned files". Now relative paths pointing to manifest files (#945)
- **Scanner accuracy**: git commit SHAs in `fixed_version` from OSV data no longer generate false positive "assuming affected" warnings — silently skipped as non-version data (#946)
- **Docker pip CVEs**: upgraded pip in all 6 Docker images — fixes CVE-2025-8869 (5.9M) and CVE-2026-1703 (2.0L) (#947)
- **Release pipeline**: self-scan gate now blocks ALL publish jobs (PyPI, Docker, GHCR, Sigstore, SLSA). No release ships with HIGH+ CVEs (#944)
- **Self-scan noise**: post-merge scan now only uploads HIGH+ findings to GitHub Security tab (was uploading all severities, flooding with 78 low-severity base-image CVEs) (#945)

## [0.71.3] – 2026-03-18

### Fixed
- **Scanner accuracy**: empty string versions no longer silently bypass OSV queries — now logged as unresolvable (#933)
- **HTTP reliability**: all 19 `urllib.request.urlopen` callers migrated to httpx with exponential backoff, Retry-After handling, and configurable timeouts (#878, #932)
- **Context graph OOM**: BFS queue bounded at 10,000 entries + O(1) cycle check via frozenset to prevent memory explosion on dense deployments (#877, #930)
- **Docker Hub token leak**: `release.yml` now masks API token with `::add-mask::`, validates before use (#929)
- **CI self-scan gap**: added `agent-bom scan --os-packages` inside built Docker image to catch base-image CVEs (glibc, sqlite3, dpkg) that Docker Hub found but CI missed (#931)
- **Alpine CI image**: pinned `python:3.12-alpine` by SHA256 digest (#929)
- **Glama Dockerfile**: added missing HEALTHCHECK (#929)
- **Container rescan**: weekly container image rescan escalated from informational to exit-code 1 with warning annotation (#931)
- **action.yml**: shortened description to 91 chars (was 141, GitHub Marketplace truncates at 125) (#933)

### Added
- **CMMC 2.0 in REST API**: wired 17 CMMC practices into `/v1/compliance` endpoint — 14 frameworks now accessible via API (#933)
- **Sync HTTP client**: `create_sync_client()`, `sync_request_with_retry()`, `fetch_bytes()`, `fetch_json()` in `http_client.py` (#932)

## [0.71.2] – 2026-03-16

### Fixed
- **Symlink cycle in parser walk** — `_walk()` now tracks visited real paths via `os.path.realpath()` to prevent the same directory being scanned up to 5× through symlinks (#876)
- **Transitive dep fetch failures now logged** — silent `except (ValueError, KeyError): pass` in npm/PyPI fetch functions replaced with `_logger.warning()`; gather exceptions also routed through logger in addition to console (#879)

### Docs
- ARCHITECTURE.md — added `agent-bom run` node to CLI Commands subgraph wired to Runtime Proxy
- SKILL.md — bumped version, Docker tag, Sigstore reference, and test count to current values

---

## [0.71.1] – 2026-03-15

### Fixed
- **GHSA false positives (authlib, pyjwt)** — GitHub Advisory API now returns `patched_versions=null`; `vulnerable_version_range` is the authoritative field. Added `_installed_version_is_affected()` helper parsing compound constraints (`<=`, `<`, `>=`, `>`). Fixed packages already past the vulnerable window no longer flagged (#895)
- **Empty-version packages passed to scanners** — packages with `version=""` were unconditionally matched against all advisories. Added `""` to the scannable exclusion filter in `scanners/__init__.py`
- **NVIDIA scanner unconditional matches** — CSAF vulns with a `fixed_version` now call `compare_versions()` before appending; unversioned packages skipped
- **Proxy credential detection in error responses** — `check_credentials` was only applied to `"result"` fields; JSON-RPC `"error"` objects can carry exception messages with API keys. Now applies to both (#896)
- **Rate limit advisory-only** — `--rate-limit` logged alerts but never blocked. Enforcement block path added matching replay-detection pattern (#896)
- **Audit log rotation silent failure** — `except OSError: pass` replaced with `logger.warning()` to surface disk-full/permission errors (#896)

---

## [0.70.4] – 2026-03-11

### Added
- **Cloud provisioning scripts** — read-only, least-privilege provisioning for all 11 providers (AWS IAM + EKS RBAC, Azure Managed Identity, GCP Workload Identity, Snowflake key-pair JWT, Databricks PAT/OAuth, HuggingFace fine-grained token, W&B Viewer service account, Nebius IAM, CoreWeave namespace RBAC, NVIDIA NGC Viewer key) in `scripts/provision/`
- **Nebius pagination** — cursor-based pagination with `nextPageToken`/`next_page_token` wired into all 3 discovery functions
- **Post-merge self-scan** — GitHub Actions workflow scans agent-bom with agent-bom on every merge; blocks release on critical CVE (#648)
- **Two-tier severity gate** — `--warn-on` for CI warning gates, `--fail-on-severity` for hard failures (#625)
- **External scanner JSON ingestion** — import supported scanner JSON output with blast radius enrichment (#624)
- **Delta scanning** — `--delta` flag reports only new findings since last scan; exit code based on new-only (#630)
- **Local embedded vulnerability database** — SQLite schema, OSV/EPSS/KEV sync, fast lookup (#631)
- **Bun, NuGet (.NET), pip-compile parsers** (#660)
- **Gradle and conda parsers** for AI/ML ecosystems (#659)
- **go.sum integrity verification** + GOPROXY version resolution (#658)
- **Maven Central and crates.io** version resolution for unpinned deps (#661)
- **GHSA and NVD local DB sync** sources (#653)
- **Multi-source asset deduplication** — cross-cloud dedup with stable IDs (#654)
- **Deterministic UUID v5 stable IDs** for assets and findings (#655)
- **Auto-refresh stale vuln DB flag** — `--auto-refresh-db`, NIM/NeMo/NemoClaw NVIDIA tracking
- **Production-quality Go/Maven/RPM** parser improvements (#656)

### Fixed
- **Credential security** — URL validation (jira.py, slack.py), timing-safe metrics token compare (proxy.py), API key sanitization from exception messages (vector_db.py) (#662)
- **Databricks enum bug** — `EndpointStateReady.value` fix; `str(enum)` returned full name not value, causing all serving endpoints to be skipped (#664)
- **CoreWeave/NVIDIA provisioning** — kubeconfig + namespace RBAC, NGC Viewer key, DCGM exposure detection (#664)
- **Normalization gaps** — CLI check, scan_agents, rescan, postgres cache (#615)
- **GHSA PEP 503 normalization** — advisory matching + resolver debug logging (#619)
- **Multi-arch container rescan** — arm64 support, SARIF to Security tab (#650)
- **OTel hardening** — schema validation, file size cap, framework expansion (#642)
- **Stale DB warning** on outdated local cache (#642)
- **Local vuln DB security** — chmod 0600, HTTPS-only sync, path validation, integrity check (#634)
- **HTML report** — delta/warn-gate banners, vendor_severity display (#632)
- **Silent exception handlers** — logging added to all bare `except` blocks (#620)
- **Documentation accuracy** — detector count (6→7), architecture client and tool counts (#657)
- **MCP tool count** — replaced hardcoded counts with dynamic assertions (#626)

### Changed
- **`cli/scan.py` refactored** — 3,079L monolith → modular `scan/` package (#651)
- **Unified Finding model Phase 1** — core dataclasses, BlastRadius migration shim, dual-write (#628)
- **PEP 503 name normalization** — configurable batch size, unresolved package warnings (#614)
- **server.py routes extracted** — scan, discovery, connectors, governance, enterprise, schedules, observability, assets (#612, #613)

---

## [0.60.1] – 2026-03-08

### Fixed
- **P0: Ecosystem case normalization** — packages with ecosystem `"PyPI"` (uppercase) were silently returning 0 vulnerabilities. Fixed with `.lower()` normalization at every `ECOSYSTEM_MAP` lookup in `query_osv_batch` and `scan_packages`.
- **P0: OSV detail enrichment** — OSV `/v1/querybatch` returns only `{id, modified}` per vuln (no summary, CVSS, aliases). Added parallel detail fetching via `/v1/vulns/{id}` (semaphore=10), called at every return path including cache-hit early returns.
- **P0: Cache blocking I/O** — SQLite cache writes now run off the event loop via `asyncio.to_thread` + batched `put_many()` transaction, preventing event loop stalls on large scans.
- **Zero test failures** — `test_accuracy_baseline.py` fully fixed: lowercase ecosystem, `asyncio.run()`, correct `Severity` enum values.

### Added
- **Update notifications** — background daemon thread checks PyPI on startup, 24-hour file cache at `~/.cache/agent-bom/`, non-blocking notice shown on clean exit.
- **Improved `--version` output** — shows Python version, platform, and external scanner install status.
- **Better first-run UX** — zero-config scan shows actionable quick-start commands.

### Changed
- `CONTRIBUTING.md` rewritten — Quick start (5 min), good-first-issue guide, architecture table, DCO, security report path.

---

## [0.60.0] – 2026-03-07

### Added
- OpenSSF Best Practices passing badge (100% criteria met)
- ClusterFuzzLite integration for continuous fuzz testing
- ARCHITECTURE.md for contributor orientation
- SAST CWE map expanded from 10 → 52 entries
- 11 GitHub area labels for issue triage
- Good-first-issue and help-wanted issues for new contributors

### Changed
- Split OpenClaw monolith SKILL.md into 4 focused skills (scan, compliance, registry, runtime)
- Reduced SKILL.md surface area for better OpenClaw trust score

### Fixed
- ResponseInspector detector for cloaking and payload detection (wired into proxy)

---

## [0.59.3] – 2026-03-07

### Added
- Redesigned SVG diagrams: architecture, blast radius, topology, scan pipeline, compliance heatmap — dark and light variants
- Animated demo SVG
- Simplified README
- Dashboard charts and compliance matrix (Next.js)
- Grafana template
- MkDocs documentation site
- GitHub issue and PR templates
- Roadmap accuracy fixes

### Fixed
- Credential pattern detection improvements
- Policy conditions corrected to 17

---

## [0.59.2] – 2026-03-07

### Added
- Value-based credential scanning
- Smithery/ClawHub/MCP Registry retry logic
- Fleet scan and CIS benchmark input bounds
- NVD cache 90-day TTL
- Docker health check hardening
- ClawHub SKILL.md trust transparency

---

## [0.59.1] – 2026-03-06

### Added
- MCP tool reachability and capability scanning via `mcp_introspect.py`
- VEX (OpenVEX) support: load, generate, apply, export
- SBOM ingest: CycloneDX 1.x and SPDX 2.x/3.0 JSON
- OpenSSF Scorecard → risk boost integration
- OTel trace ingestion and CVE cross-reference

---

## [0.59.0] – 2026-03-06

### Added
- Runtime proxy with 7 detectors: ToolDrift, ArgumentAnalyzer, CredentialLeak, RateLimit, SequenceAnalyzer, ResponseInspector, VectorDBInjectionDetector
- Snowflake Native App integration
- Fleet scan across multiple agent inventories
- CIS benchmark checks (AWS)
- Policy-as-code: 17 conditions (16 declarative + expression engine)
- Prometheus metrics export from proxy
- JSONL audit log from proxy

---

[Unreleased]: https://github.com/msaad00/agent-bom/compare/v0.81.1...HEAD
[0.76.4]: https://github.com/msaad00/agent-bom/compare/v0.76.2...v0.76.4
[0.76.2]: https://github.com/msaad00/agent-bom/compare/v0.76.1...v0.76.2
[0.76.1]: https://github.com/msaad00/agent-bom/compare/v0.76.0...v0.76.1
[0.76.0]: https://github.com/msaad00/agent-bom/compare/v0.75.15...v0.76.0
[0.75.15]: https://github.com/msaad00/agent-bom/compare/v0.75.14...v0.75.15
[0.75.14]: https://github.com/msaad00/agent-bom/compare/v0.75.13...v0.75.14
[0.75.13]: https://github.com/msaad00/agent-bom/compare/v0.75.12...v0.75.13
[0.75.12]: https://github.com/msaad00/agent-bom/compare/v0.75.0...v0.75.12
[0.75.0]: https://github.com/msaad00/agent-bom/compare/v0.72.0...v0.75.0
[0.74.1]: https://github.com/msaad00/agent-bom/compare/v0.74.0...v0.74.1
[0.74.0]: https://github.com/msaad00/agent-bom/compare/v0.73.0...v0.74.0
[0.73.0]: https://github.com/msaad00/agent-bom/compare/v0.72.0...v0.73.0
[0.72.0]: https://github.com/msaad00/agent-bom/compare/v0.71.4...v0.72.0
[0.71.4]: https://github.com/msaad00/agent-bom/compare/v0.71.3...v0.71.4
[0.71.3]: https://github.com/msaad00/agent-bom/compare/v0.71.2...v0.71.3
[0.71.2]: https://github.com/msaad00/agent-bom/compare/v0.71.1...v0.71.2
[0.71.1]: https://github.com/msaad00/agent-bom/compare/v0.70.4...v0.71.1
[0.70.4]: https://github.com/msaad00/agent-bom/compare/v0.60.1...v0.70.4
[0.60.1]: https://github.com/msaad00/agent-bom/compare/v0.60.0...v0.60.1
[0.60.0]: https://github.com/msaad00/agent-bom/compare/v0.59.3...v0.60.0
[0.59.3]: https://github.com/msaad00/agent-bom/compare/v0.59.2...v0.59.3
[0.59.2]: https://github.com/msaad00/agent-bom/compare/v0.59.1...v0.59.2
[0.59.1]: https://github.com/msaad00/agent-bom/compare/v0.59.0...v0.59.1
[0.59.0]: https://github.com/msaad00/agent-bom/releases/tag/v0.59.0
