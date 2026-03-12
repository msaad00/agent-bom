# agent-bom v0.70.0 Audit Report

**Date**: 2026-03-11
**Auditor**: Automated code audit
**Scope**: Codebase statistics, scanner robustness, v0.60.0-v0.70.0 delta, competitive analysis

---

## 1. Codebase Statistics (from code, verified)

| Metric | Count | Source |
|--------|-------|--------|
| Python modules (`src/agent_bom/`) | 222 | `find -name "*.py"` |
| Test files (`tests/`) | 228 | `find -name "*.py"` |
| Test functions (`def test_`) | 5,457 | `grep -r "def test_"` |
| Pytest-collected tests | 5,555 | `pytest --collect-only` |
| Source LOC (`src/agent_bom/`) | 79,853 | `wc -l` |
| Test LOC (`tests/`) | 74,193 | `wc -l` |
| Total LOC (src + tests) | 154,046 | |
| MCP tools (`@mcp.tool`) | 30 | `mcp_server.py` |
| MCP client types (AgentType enum) | 23 (22 named + CUSTOM) | `models.py` |
| CLI commands (registered) | 27 | `cli/__init__.py add_command` |
| API endpoints | 84 | `@router.get/post/put/delete` across 13 route files + server.py |
| Compliance frameworks | 11 | scanners/__init__.py tag_ calls |
| Cloud providers | 12 | `cloud/__init__.py _PROVIDERS` |
| Runtime detectors | 7 | `runtime/detectors.py` classes |

### Key Module LOC

| Module | Lines |
|--------|-------|
| `scanners/__init__.py` | 867 |
| `enrichment.py` | 539 |
| `models.py` | 502 |
| `api/server.py` | 400 (post-refactor, down from ~2,500+) |
| `mcp_server.py` | 1,571 |
| `proxy.py` | 1,114 |
| `resolver.py` | 275 |

---

## 2. Scanner Robustness Assessment

### a) Name Normalization — 8.5/10

**What exists**: `normalize_package_name()` in `models.py` is the single source of truth. PEP 503 for PyPI (collapses `-`, `_`, `.` to `-`, lowercases). Other ecosystems: lowercase only.

**Usage**: 15 call sites across `scanners/__init__.py`, `scan_cache.py`, `cli/_check.py`, `cli/_history.py`, `api/postgres_store.py`. All key construction paths (`ecosystem:name@version`) use normalized names.

**Gaps found**:
- `parse_fixed_version()` at line 279 uses `pkg.get("name", "").lower() == package_name.lower()` -- this is a **simple lowercase comparison**, not PEP 503 normalized. If OSV returns `Requests_OAuthlib` and input is `requests-oauthlib`, the `.lower()` comparison would fail because underscores vs hyphens aren't collapsed. **This is a real false-negative path** for PyPI packages with mixed separators in OSV affected data.
- `check_typosquat(pkg.name, ...)` at line 619 receives the already-normalized `pkg.name` (good -- normalization happens at line 537 in `scan_packages`).

**Verdict**: Strong coverage. One gap in `parse_fixed_version()` that could miss fix version extraction for packages with underscore/hyphen variants.

### b) False Positive Rate — 8/10

**Dedup logic**:
- `build_vulnerabilities()` deduplicates by `seen_ids` set (line 481-487) -- prevents same CVE appearing twice per package.
- Package deduplication in `scan_agents()` via `_pkg_key()` -- prevents scanning the same package multiple times.
- Credential and tool deduplication in blast radius construction (lines 730-738).
- CVE alias canonicalization: GHSA IDs are remapped to CVE IDs when available (lines 496-498), preventing CVE-123 and GHSA-xxx from appearing as separate findings for the same issue.

**Ecosystem validation**: `ECOSYSTEM_MAP` (7 ecosystems + conda->PyPI alias) gates what gets sent to OSV. Packages with unknown ecosystems are silently dropped (no false positives from bad ecosystem matching).

**Gaps**:
- No version range validation before sending to OSV -- relies entirely on OSV API to filter non-affected versions.
- GHSA supplemental check (`check_github_advisories`) could theoretically return vulns already found by OSV. No explicit cross-dedup between OSV and GHSA results at the package level.

### c) False Negative Prevention — 7.5/10

**Multi-source approach**:
1. OSV (primary) -- batch query with proper ecosystem mapping
2. GHSA (supplemental) -- catches advisories not yet in OSV
3. NVIDIA advisory (supplemental) -- catches NVIDIA-specific CVEs for AI framework packages
4. Typosquat detection -- flags potential malicious packages

**Cache key normalization**: Consistent across `scan_cache.py` (uses `normalize_package_name` in `_key()`), `scanners/__init__.py`, and `postgres_store.py`.

**Gaps**:
- `parse_fixed_version()` name matching gap (see 2a) could cause missed fix version attribution, though the CVE itself is still reported.
- Packages with `version == "unknown"` or `"latest"` are skipped after resolution attempt. If resolver fails (network error), real vulns are missed. Warning is logged (line 554-564) -- not silent, but not blocking either.
- NVIDIA advisory filter checks `_AI_FRAMEWORK_PACKAGES` which requires the constant list to stay current. If a new AI framework package isn't in the list, NVIDIA advisories won't be checked for it.
- OSV batch response length mismatch (line 432-435) logs a warning but continues processing -- could misattribute vulns if OSV returns fewer results than queries.

### d) Batch Handling — 9/10

**Configuration**: All three knobs are env-configurable via `config.py`:
- `AGENT_BOM_SCANNER_BATCH_SIZE` (default 1000, clamped to OSV API max of 1000)
- `AGENT_BOM_SCANNER_MAX_CONCURRENT` (default 10, semaphore-based)
- `AGENT_BOM_SCANNER_BATCH_DELAY` (default 0.5s between batches)

**>1000 packages**: Handled correctly. `batch_size = min(_BATCH_SIZE, 1000)` clamps to API max, then loops in chunks (line 416: `for batch_start in range(0, len(queries), batch_size)`).

**Gap**: No backoff on 429/rate-limit responses. `request_with_retry` handles retries but the batch delay is fixed, not adaptive.

### e) Cache Integrity — 8.5/10

**SQLite WAL mode**: Enabled (line 41 in `scan_cache.py`).
**Thread safety**: `check_same_thread=False` (line 40).
**Key normalization**: Uses `normalize_package_name` in `_key()` method.
**TTL**: 24-hour default, configurable. Expired entries cleaned on read and via `cleanup_expired()`.
**Batch writes**: `put_many()` uses single transaction (`executemany`).
**Eviction**: `evict()`, `evict_many()`, `clear()` all available.
**Max cache size**: Enrichment cache has `ENRICHMENT_MAX_CACHE_ENTRIES` eviction. Scan cache has **no size limit** -- could grow unbounded on long-running instances.

**Gap**: No explicit mutex/lock for concurrent `put_many` calls from multiple async tasks. SQLite WAL handles concurrent reads well, but concurrent writes from different threads could contend. In practice, `asyncio.to_thread(cache.put_many, ...)` serializes writes through the thread pool.

### f) Error Handling — 8/10

**Exception inventory** (13 except blocks in `scanners/__init__.py`):
- Lines 171, 226: `except Exception: return None` -- CVSS vector parse failures. Acceptable: bad vector returns None, severity falls back to MEDIUM. Not logged.
- Line 244: `except ValueError:` -- CVSS score parse. Falls through to vector parsing. Acceptable.
- Line 293: `except Exception: return fixed` -- Version parse failure returns raw string. Acceptable.
- Line 317: `except (ValueError, KeyError):` -- OSV response detail parse. `pass` falls through. Detail enrichment is best-effort.
- Line 345: `except Exception as exc:` -- Detail enrichment failure logged at debug level. Acceptable.
- Line 448: `except (ValueError, KeyError) as e:` -- OSV batch response parse error. Logged to console. Good.
- Lines 548, 601, 613, 634: All use `except Exception as exc:` with console warnings. No silent swallowing. Good.
- Line 850: `except Exception as exc:` with `_logger.warning`. Good.

**Verdict**: No truly silent failures in the scanner path. The two `return None` handlers for CVSS parsing are acceptable (defense against malformed vectors). All security-critical paths log or display warnings.

### g) Version Resolution — 8/10

**Handling of "unknown"/"latest"/empty**:
- Auto-resolution attempted via `resolver.py` for npm and PyPI (line 540-549).
- If resolution fails, packages are excluded from OSV query with explicit warning (line 554-564).
- Warning includes first 10 package names + count of remaining.
- `_logger.warning()` also fires for structured logging.

**Gap**: Resolution only covers npm and PyPI. Go, Cargo, Maven packages with unknown versions are silently excluded from scanning. The warning covers them but there's no resolution attempt.

### h) Enrichment Pipeline — 9/10

**All four sources wired**:
1. NVD (90-day disk cache, API key optional, rate-limited) -- CWE IDs, published/modified dates, status
2. EPSS (30-day disk cache, batch pagination fixed in #538) -- exploit probability + percentile
3. CISA KEV (24-hour cache, disk-persisted) -- active exploitation flag + due dates
4. OpenSSF Scorecard -- supply chain quality signal, 3-tier risk boost in `calculate_risk_score()`

**Post-enrichment**: Compliance tags are refreshed after enrichment (line 827-832). Risk scores recalculated with new data (line 854-855).

**Gap**: deps.dev enrichment exists (`deps_dev_resolved` field on Package) but is not called in the main scan pipeline -- only available as explicit opt-in.

---

## 3. v0.60.0 to v0.70.0 Delta

### Summary

| Metric | Value |
|--------|-------|
| Commits | 179 |
| Files changed | 349 |
| Insertions | +58,480 |
| Deletions | -4,333 |
| Net growth | +54,147 lines |

### By category (conventional commit prefixes)

| Type | Count | % |
|------|-------|---|
| feat: | 63 | 35% |
| fix: | 41 | 23% |
| refactor: | 1 (pre-v0.69.1 was minimal, 16 in v0.69.1-v0.70.0) | |
| chore/docs/test/release: | 37 | 21% |
| Other | 38 | 21% |

**Note**: The refactor count in the commit log shows 1 for the v0.60-v0.69.1 range because the massive refactoring work (16 refactor PRs) landed in the v0.69.1-v0.70.0 range on the current branch.

### Key Changes by Category

#### Scanner Improvements
- PEP 503 name normalization across all key construction (#614, #615)
- Configurable batch size with OSV API max clamping (#614)
- Unresolved version warnings -- no more silent skips (#614)
- EPSS batch pagination fix (#538)
- Silent failure elimination across security-critical paths (#537)
- Scanner depth audit: 6 accuracy fixes (#444)
- AI boost, double penalty, word boundary, additive amplification fixes (#445)
- NVIDIA advisory filter expansion to cover torch/vllm/triton
- Runtime version resolvers and drift detection (#601)

#### Refactoring (v0.69.1 to v0.70.0)
- `api/server.py` decomposed from ~2,500+ lines to 400 lines across 13 route modules
- `cli.py` (6,262 lines) split into `cli/` package with 12 focused modules (#536)
- `parsers/__init__.py` split into `python_parsers.py`, `node_parsers.py`, `compiled_parsers.py`
- `discovery/__init__.py` split out config_parsers.py (#593)
- `output/__init__.py` split into format-specific modules (#592)
- `mcp_server.py` tool logic extracted to `mcp_tools/` package (#572)
- 166 click options extracted to `cli/options.py` (#591)

#### New Features (selected highlights)
- Browser extension discovery (#422)
- Training pipeline lineage + dataset cards (#474)
- SBOM vendor metadata + supply chain enrichment (#473)
- Full SPDX license engine (#500)
- Multi-vendor GPU detection (AMD ROCm, Intel, WDDM) (#499)
- Dedicated REST API endpoints for 6 scan types (#494)
- CIS benchmark expansion 46 -> 67 checks (#535)
- Evidence-based MCP server trust scoring (#513)
- OpenSSF Silver badge (100%, 55/55 criteria) (#557)
- Copilot CLI + Tabnine MCP client discovery (#559)
- Snowflake Notebook discovery (#550)
- SQL injection detection in proxy (#553)
- ADR documentation structure (#501, #600)

#### Bug Fixes (selected)
- EPSS batch pagination + KEV stale cache (#538)
- Exception swallowers, SBOM transitives, policy dry-run (#532)
- mypy 172/172 enforced, zero exceptions (#534)
- HMAC proxy signing order (#446)
- Toxic combos word boundary normalization (#448)
- URL/domain validation hardening (CodeQL) (#475)
- Atomic writes, cache eviction, TOCTOU mitigation (#440)

#### Test Coverage Growth
- v0.60.0 baseline: ~3,000 tests (estimated)
- v0.69.1: 5,534 tests, 73% -> 79% coverage (#569: 904 new tests)
- v0.70.0 (HEAD): 5,555 tests collected
- Scanner-specific tests: 73 (test_scanners.py: 36, test_scanner_robustness.py: 23, test_scanner_ecosystems.py: 14)
- Enrichment tests: 8 (test_enrichment.py)
- Hardening tests: 15 (test_hardening.py)

---

## 4. Competitive Comparison Matrix

### Vulnerability Scanning

| Capability | agent-bom v0.70.0 | Trivy | Grype | Snyk | Wiz |
|-----------|-------------------|-------|-------|------|-----|
| **OSV database** | Primary source | Yes | Yes | No (proprietary) | No (proprietary) |
| **NVD enrichment** | Yes (90d cache, CWE, dates) | Yes (built-in) | Yes (via DB sync) | Yes | Yes |
| **GHSA supplemental** | Yes | Yes | Yes (primary) | Yes | Yes |
| **EPSS scoring** | Yes (batch, paginated) | Yes (since v0.48) | No | Yes (paid) | Yes |
| **CISA KEV** | Yes (24h cache) | Yes | No native | Yes | Yes |
| **NVIDIA advisories** | Yes (AI-specific) | No | No | No | No |
| **Proprietary vuln DB** | No | No | No | Yes (deep) | Yes (deep) |
| **CVSS v3.1 vector parsing** | Yes (in-house) | Yes | Yes | Yes | Yes |
| **CVSS v4.0 vector parsing** | Yes (approximate) | Yes | Partial | Yes | Yes |

**Honest assessment**: Snyk and Wiz have proprietary vulnerability databases with deeper coverage (especially for 0-days and pre-disclosure). agent-bom compensates with multi-source aggregation (OSV + GHSA + NVIDIA + NVD) but lacks proprietary research teams. Trivy and Grype are closest peers in the open-source space. agent-bom's NVIDIA advisory integration for AI packages is unique.

### AI/MCP-Specific Scanning (agent-bom's differentiator)

| Capability | agent-bom v0.70.0 | Trivy | Grype | Snyk | Wiz |
|-----------|-------------------|-------|-------|------|-----|
| **MCP server discovery** | 22 client types | No | No | No | No |
| **MCP tool enumeration** | Yes (introspect) | No | No | No | No |
| **Blast radius analysis** | Yes (cred+tool exposure) | No | No | No | No |
| **AI risk context** | Yes (framework-aware) | No | No | No | No |
| **Credential exposure mapping** | Yes (env var pattern matching) | No | No | No | No |
| **Tool poisoning detection** | Yes (enforcement.py) | No | No | No | No |
| **Prompt injection scanning** | Yes (6 scan types) | No | No | No | No |
| **SKILL.md/instruction file audit** | Yes (85 tests) | No | No | No | No |
| **Browser extension AI analysis** | Yes (27 tests) | No | No | No | No |
| **Training pipeline lineage** | Yes | No | No | No | No |
| **Runtime proxy enforcement** | Yes (7 detectors) | No | No | No | Partial (agent gateway) |

**Honest assessment**: This is agent-bom's moat. No competitor has MCP-native scanning, AI agent discovery, or blast radius analysis. Wiz has some agent monitoring capabilities but not at the MCP protocol level. This category is uncontested.

### SBOM

| Capability | agent-bom v0.70.0 | Trivy | Grype | Snyk | Wiz |
|-----------|-------------------|-------|-------|------|-----|
| **SBOM generation** | CycloneDX | CycloneDX, SPDX | No (Syft does) | CycloneDX, SPDX | CycloneDX |
| **SBOM ingestion** | CycloneDX 1.x, SPDX 2.x/3.0 | Yes | Yes (via Syft) | Yes | Yes |
| **VEX support** | OpenVEX (generate/apply/export) | VEX Hub, OpenVEX | No | No | No |

**Honest assessment**: Trivy leads in SBOM format breadth. agent-bom's VEX support is strong. Grype delegates SBOM to Syft.

### Policy-as-Code

| Capability | agent-bom v0.70.0 | Trivy | Grype | Snyk | Wiz |
|-----------|-------------------|-------|-------|------|-----|
| **Policy engine** | Custom JSON (17 conditions) | Rego (OPA) | No native | Snyk policies | Wiz policies |
| **Condition types** | 16 declarative + expression engine | Full Rego | N/A | GUI-based | GUI + API |
| **Jira integration** | Yes (policy action) | No native | No | Yes | Yes |
| **Dry-run mode** | Yes | Yes (Rego eval) | N/A | Yes | Yes |

**Honest assessment**: Trivy's OPA/Rego integration is more powerful and industry-standard. agent-bom's custom engine is simpler but less expressive. Snyk and Wiz have enterprise-grade policy management with GUI. agent-bom's 17-condition engine covers common cases but can't express arbitrary logic.

### Runtime Protection

| Capability | agent-bom v0.70.0 | Trivy | Grype | Snyk | Wiz |
|-----------|-------------------|-------|-------|------|-----|
| **MCP proxy** | Yes (STDIO intercept) | No | No | No | No |
| **7 runtime detectors** | ToolDrift, ArgumentAnalyzer, CredentialLeak, RateLimit, SequenceAnalyzer, ResponseInspector, VectorDBInjection | No | No | No | Agent gateway (limited) |
| **Config watch** | Yes (filesystem watchers) | No | No | No | No |
| **HMAC response signing** | Yes | No | No | No | No |
| **JWKS signature verify** | Yes | No | No | No | No |
| **Audit logging (JSONL)** | Yes | No | No | No | Yes (cloud-native) |
| **Runtime-CVE correlation** | Yes | No | No | No | Partial |

**Honest assessment**: agent-bom's runtime protection is unique in the MCP space. Wiz has broader cloud runtime monitoring. In the AI agent domain specifically, agent-bom is the only tool with protocol-level interception and enforcement.

### Cloud Infrastructure Scanning

| Capability | agent-bom v0.70.0 | Trivy | Grype | Snyk | Wiz |
|-----------|-------------------|-------|-------|------|-----|
| **Cloud providers** | 12 (AWS, Azure, GCP, CoreWeave, Databricks, Snowflake, Nebius, HuggingFace, W&B, MLflow, OpenAI, Ollama) | AWS, Azure, GCP | No | AWS, Azure, GCP | 30+ |
| **CIS Benchmarks** | 67 checks (AWS/Azure/GCP) | 1,400+ checks | No | Limited | 1,000+ |
| **GPU/AI compute** | Yes (Docker, K8s, multi-vendor) | No | No | No | Partial |
| **Vector DB scanning** | Yes (Pinecone) | No | No | No | No |

**Honest assessment**: Wiz dominates cloud security with breadth and depth. Trivy has strong CIS coverage. agent-bom's 67 CIS checks vs Trivy's 1,400+ is a significant gap. However, agent-bom's AI infrastructure scanning (GPU, vector DB, ML platforms) is unique and covers providers none of the competitors touch (CoreWeave, Nebius, HuggingFace, W&B, MLflow).

### Container Scanning

| Capability | agent-bom v0.70.0 | Trivy | Grype | Snyk | Wiz |
|-----------|-------------------|-------|-------|------|-----|
| **OCI layer parsing** | Yes (native, no Docker/Syft required) | Yes (native) | Yes (via Syft) | Yes | Yes |
| **Ecosystem parsers** | Java JARs, Go, Ruby, .NET, RPM, dpkg, pip | All major | All major (Syft) | All major | All major |
| **Multi-arch** | Yes (arm64 + amd64) | Yes | Yes | Yes | Yes |
| **Rootless scanning** | Yes | Yes | Yes | Partial | Yes |

**Honest assessment**: Trivy is the gold standard for container scanning. agent-bom's native OCI parser is a solid foundation but ecosystem parser depth is thinner than Trivy's comprehensive catalogers.

### Compliance Frameworks

| Framework | agent-bom v0.70.0 | Trivy | Grype | Snyk | Wiz |
|-----------|-------------------|-------|-------|------|-----|
| OWASP LLM Top 10 | Yes | No | No | No | No |
| OWASP MCP Top 10 | Yes | No | No | No | No |
| OWASP Agentic Top 10 | Yes | No | No | No | No |
| MITRE ATLAS | Yes | No | No | No | Partial |
| MITRE ATT&CK | Yes (dynamic STIX) | No | No | No | Yes |
| NIST AI RMF | Yes | No | No | No | No |
| EU AI Act | Yes | No | No | No | Partial |
| NIST CSF 2.0 | Yes | No | No | Yes | Yes |
| ISO 27001:2022 | Yes | No | No | Yes | Yes |
| SOC 2 TSC | Yes | No | No | Yes | Yes |
| CIS Controls v8 | Yes | Yes | No | Partial | Yes |

**Honest assessment**: agent-bom has the broadest AI-specific compliance coverage (6 AI-native frameworks that no competitor tags). For traditional frameworks (NIST CSF, ISO 27001, SOC 2), Snyk and Wiz have deeper mapping with actionable remediation guidance. agent-bom's compliance tagging is automated from vulnerability context, not manually curated.

### CI/CD Integration

| Capability | agent-bom v0.70.0 | Trivy | Grype | Snyk | Wiz |
|-----------|-------------------|-------|-------|------|-----|
| **GitHub Action** | Yes (Marketplace) | Yes | Yes | Yes | Yes |
| **SARIF output** | Yes | Yes | Yes | Yes | Yes |
| **Exit code gating** | Yes | Yes | Yes | Yes | Yes |
| **GitLab CI** | Docker-based | Native template | Docker-based | Native | Native |
| **IDE plugins** | No native | VS Code | No | VS Code, IntelliJ | VS Code |

**Honest assessment**: All tools have adequate CI/CD integration. Snyk's IDE plugins give it a developer experience advantage. agent-bom's MCP server mode provides a different integration path through AI assistants (Claude, Cursor) that no competitor offers.

### Package Name Normalization

| Capability | agent-bom v0.70.0 | Trivy | Grype | Snyk | Wiz |
|-----------|-------------------|-------|-------|------|-----|
| **PEP 503** | Yes (centralized) | Yes | Yes (Syft) | Yes | Yes |
| **npm scope handling** | Lowercase only | Yes | Yes | Yes | Yes |
| **Cache key normalized** | Yes | Yes | Yes | N/A | N/A |
| **Cross-source consistency** | 15 call sites verified | Built-in | Built-in | Built-in | Built-in |

### Enterprise Features

| Capability | agent-bom v0.70.0 | Trivy | Grype | Snyk | Wiz |
|-----------|-------------------|-------|-------|------|-----|
| **SSO/OIDC** | Yes (JWT Bearer) | No | No | Yes | Yes |
| **RBAC** | Basic (claims_to_role) | No | No | Yes (enterprise) | Yes (enterprise) |
| **Multi-tenant** | Supabase schema | No | No | Yes | Yes |
| **SIEM integration** | Splunk, Datadog, Elasticsearch | No | No | Yes | Yes |
| **Dashboard** | Next.js (15 pages) | No (Aqua Platform) | No | Web UI | Full cloud platform |
| **API** | FastAPI (84 endpoints) | No REST API | No | REST API | REST + GraphQL |
| **Pricing** | Free (Apache 2.0) | Free (Apache 2.0) | Free (Apache 2.0) | Freemium | Enterprise only |

---

## 5. Gaps and Next Priorities

### Priority 1: Scanner Accuracy (to reach 9.5/10)

1. **Fix `parse_fixed_version()` name matching** -- Use `normalize_package_name()` instead of `.lower()` comparison at line 279 of `scanners/__init__.py`. This is a real false-negative path for PyPI packages with mixed separators.
   - Effort: 1 hour
   - Impact: Eliminates fix-version misattribution for PEP 503 edge cases

2. **GHSA-OSV cross-dedup** -- When `check_github_advisories` returns supplemental vulns, verify they aren't already reported by OSV (via alias matching). Currently, a CVE found by both OSV and GHSA could appear twice if the canonical ID differs.
   - Effort: 4 hours
   - Impact: Reduces potential false positives in multi-source scanning

3. **Adaptive batch backoff** -- If OSV returns 429, increase `BATCH_DELAY_SECONDS` dynamically instead of fixed 0.5s delay. Currently, rapid scanning of large dependency trees could hit rate limits.
   - Effort: 2 hours
   - Impact: Reliability for large-scale scans (>5,000 packages)

4. **Scan cache size limit** -- Add `AGENT_BOM_SCAN_CACHE_MAX_ENTRIES` with eviction policy (LRU or oldest). Currently unbounded. On long-running API servers, this could consume significant disk.
   - Effort: 2 hours
   - Impact: Production reliability

### Priority 2: Coverage Depth

5. **Version resolution for Go/Maven/Cargo** -- Currently only npm and PyPI get auto-resolution. Go and Maven packages with unknown versions are silently excluded. Add `go list` and Maven Central resolution.
   - Effort: 8 hours
   - Impact: Closes a detection gap for compiled-language ecosystems

6. **CIS Benchmark expansion** -- 67 checks vs Trivy's 1,400+. Focus on the most impactful 50 additional checks (IAM, encryption, logging) for AWS/Azure/GCP.
   - Effort: 40 hours
   - Impact: Competitive parity for cloud security posture

7. **Enrichment cache normalization audit** -- Verify that NVD and EPSS disk caches also use normalized keys. The scan cache is confirmed normalized, but enrichment caches index by CVE ID which should be consistent but hasn't been verified.
   - Effort: 2 hours
   - Impact: Cache correctness

### Priority 3: Enterprise Readiness

8. **Connection pooling for scan cache** -- `check_same_thread=False` with WAL is adequate for moderate concurrency but a proper connection pool (or `aiosqlite`) would handle high-throughput API scenarios better.
   - Effort: 4 hours
   - Impact: API server scalability

9. **IDE plugin** -- Snyk's VS Code plugin is a competitive advantage. An MCP-based integration partially fills this gap (since Claude/Cursor users get scanning through MCP), but a dedicated VS Code extension would broaden reach.
   - Effort: 40+ hours
   - Impact: Developer experience parity

10. **Structured logging** -- Most logging uses `_logger.warning/debug` which is good, but the two `except Exception: return None` blocks in CVSS parsing (lines 171, 226) should at least log at debug level for troubleshooting.
    - Effort: 30 minutes
    - Impact: Debuggability

### Scorecard Summary

| Dimension | Rating | Key Strength | Key Gap |
|-----------|--------|-------------|---------|
| Name normalization | 8.5/10 | Centralized PEP 503, 15 call sites | `parse_fixed_version` uses `.lower()` not PEP 503 |
| False positive rate | 8.0/10 | Multi-level dedup, alias canonicalization | No GHSA-OSV cross-dedup |
| False negative prevention | 7.5/10 | 3 supplemental sources, typosquat | Go/Maven resolution missing |
| Batch handling | 9.0/10 | Configurable, clamped, paginated | No adaptive backoff on 429 |
| Cache integrity | 8.5/10 | WAL, normalized keys, TTL | No size limit |
| Error handling | 8.0/10 | No silent failures in critical paths | 2 bare `return None` in CVSS parsing |
| Version resolution | 8.0/10 | Auto-resolve + explicit warnings | npm/PyPI only |
| Enrichment pipeline | 9.0/10 | 4 sources, post-enrichment refresh | deps.dev not in main pipeline |
| **Overall scanner** | **8.3/10** | | |

### Competitive Position Summary

- **Unique and uncontested**: AI/MCP scanning, blast radius analysis, runtime proxy, 6 AI compliance frameworks, AI infrastructure scanning (GPU, vector DB, ML platforms)
- **Competitive**: SBOM, VEX, policy-as-code, multi-source vuln scanning, CI/CD integration
- **Behind**: CIS benchmark depth (vs Trivy), cloud provider breadth (vs Wiz), proprietary vuln research (vs Snyk/Wiz), IDE plugins (vs Snyk), policy expressiveness (vs Trivy OPA)
- **Strategic advantage**: Only open-source tool that bridges traditional vulnerability scanning with AI agent security. The MCP protocol-level integration is a structural moat that competitors would need to build from scratch.

---

*Report generated from agent-bom v0.70.0 codebase on branch `feat/refactor-api-stores`, commit `e97ee8c`.*
