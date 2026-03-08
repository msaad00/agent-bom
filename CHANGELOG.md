# Changelog

All notable changes to agent-bom are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

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
