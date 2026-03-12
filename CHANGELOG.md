# Changelog

All notable changes to agent-bom are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

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

### Fixed
- **JSON report import** — file upload now validates size (10 MB), schema, prototype-pollution keys, and finite numeric values before use (`ui/lib/validators.ts`)
- **`generated_at` TypeScript error** — `ScanResult` does not have `generated_at`; use `scan_timestamp` instead
- **JetBrains claim** — removed from active integrations; filed as issue #412 for proper implementation

### Security
- **JSON file upload** — `ui/lib/validators.ts` guards against DoS via oversized files, prototype pollution, and schema-invalid payloads (no new npm dependencies)

---

## [0.70.4] – 2026-03-11

### Added
- **Cloud provisioning scripts** — read-only, least-privilege provisioning for all 11 providers (AWS IAM + EKS RBAC, Azure Managed Identity, GCP Workload Identity, Snowflake key-pair JWT, Databricks PAT/OAuth, HuggingFace fine-grained token, W&B Viewer service account, Nebius IAM, CoreWeave namespace RBAC, NVIDIA NGC Viewer key) in `scripts/provision/`
- **Nebius pagination** — cursor-based pagination with `nextPageToken`/`next_page_token` wired into all 3 discovery functions
- **Post-merge self-scan** — GitHub Actions workflow scans agent-bom with agent-bom on every merge; blocks release on critical CVE (#648)
- **Two-tier severity gate** — `--warn-on` for CI warning gates, `--fail-on-severity` for hard failures (#625)
- **Trivy/Grype/Syft ingestion** — import external scanner JSON output with blast radius enrichment (#624)
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
- **Improved `--version` output** — shows Python version, platform, Syft/Grype install status.
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

[0.60.1]: https://github.com/msaad00/agent-bom/compare/v0.60.0...v0.60.1
[0.60.0]: https://github.com/msaad00/agent-bom/compare/v0.59.3...v0.60.0
[0.59.3]: https://github.com/msaad00/agent-bom/compare/v0.59.2...v0.59.3
[0.59.2]: https://github.com/msaad00/agent-bom/compare/v0.59.1...v0.59.2
[0.59.1]: https://github.com/msaad00/agent-bom/compare/v0.59.0...v0.59.1
[0.59.0]: https://github.com/msaad00/agent-bom/releases/tag/v0.59.0
