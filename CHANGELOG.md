# Changelog

All notable changes to agent-bom are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

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
- **Compliance narratives** — `GET /v1/compliance/narrative` generates auditor-ready text per framework with control-level detail and remediation-compliance bridge
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

[Unreleased]: https://github.com/msaad00/agent-bom/compare/v0.75.14...HEAD
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
