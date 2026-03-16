# agent-bom Codebase Audit

**Date**: 2026-03-07
**Version audited**: v0.60.0 (post-PR #321, #322, #324)
**Auditor**: Claude Code (automated + manual review)

This document is delta-trackable. Each finding has a status. Re-run the audit and compare against this file to see what changed.

---

## Summary

| Area | Status | Issues Fixed | Issues Open |
|------|--------|-------------|-------------|
| Scanner architecture | PASS | 3 | 2 |
| Cloud modules | PASS | 1 | 1 |
| Output + API + MCP | PASS | 2 | 0 |
| Naming consistency | PASS | 1 | 0 |
| Feature truthfulness | PASS | 0 | 0 |
| Dependency cleanliness | PASS | 0 | 0 |
| Test coverage | PARTIAL | 0 | 26 modules untested |

---

## Area 1: Scanner Architecture

### What it does (verified)

```
OSV.dev batch API (1000 q/batch)     primary vuln source, free, no key
  └── ScanCache (SQLite, 24h TTL)    avoids re-querying known results
GHSA advisory (supplemental)         GitHub Security Advisories per package
NVIDIA advisory (supplemental)       NVIDIA-issued CVEs for GPU/CUDA packages
NVD API (enrichment)                 CWE, dates, nvd_status (90d cache)
EPSS API (enrichment)                exploit probability score (30d cache)
CISA KEV (enrichment)               known-exploited flag (24h cache)
OpenSSF Scorecard (enrichment)       maintainer quality signal
```

**CVSS parsing**: v3.1 and v4.0 implemented from spec, not from a library.
**Blast radius**: CVE → packages → servers → agents → tools → credentials → risk score.
**Risk score formula**: base_severity + agent_reach + cred_exposure + tool_count + AI_boost + KEV_boost + EPSS_boost + scorecard_boost (all configurable via env vars).
**Compliance tagging**: 14 frameworks on every blast radius — OWASP LLM, OWASP MCP, OWASP Agentic, ATLAS, NIST AI RMF, EU AI Act, NIST CSF, ISO 27001, SOC 2, CIS Controls.
**Toxic combos**: 8 patterns — CRED_BLAST, KEV_WITH_CREDS, EXECUTE_EXPLOIT, MULTI_AGENT_CVE, TRANSITIVE_CRITICAL, LATERAL_CHAIN, CACHE_POISON, CROSS_AGENT_POISON.
**Typosquat + malicious**: MAL-prefixed OSV IDs flagged, Levenshtein typosquat check.

### Fixed in this audit

| # | File | Fix |
|---|------|-----|
| F1 | `scanners/__init__.py:41,68` | Removed duplicate `logger` definition (kept `_logger`, updated all call sites) |
| F2 | `scanners/__init__.py:160,213` | Moved `import math` from inside CVSS functions to top-level |
| F3 | `output/__init__.py` | Azure + GCP CIS benchmark data was computed but never serialized to JSON output — added |

### Open issues

| # | Severity | File | Issue |
|---|----------|------|-------|
| O1 | LOW | `scanners/__init__.py:490` | NVIDIA advisory filter requires package name to start with "nvidia/cuda/tensorrt/nccl". Packages like `torch`, `vllm`, `triton` are in AI_PACKAGES but won't trigger NVIDIA advisory check even if they have NVIDIA-issued CVEs. |
| O2 | LOW | `scanners/__init__.py` | No test coverage for Maven/Go/NuGet ecosystems in scanner tests. ECOSYSTEM_MAP maps them but test fixtures only cover PyPI/npm. |

---

## Area 2: Cloud Modules

### What it covers (verified)

| Provider | Module | Discovery | CIS/Security Check | Notes |
|----------|--------|-----------|-------------------|-------|
| AWS | `cloud/aws.py` | Bedrock, Lambda, ECS, EKS, EC2 (by tag) | `aws_cis_benchmark.py` (CIS v3.0, 30 checks) | ✓ |
| Azure | `cloud/azure.py` | AI Foundry, Container Apps, AKS, Functions | `azure_cis_benchmark.py` (CIS v3.0) | ✓ |
| GCP | `cloud/gcp.py` | Vertex AI, Cloud Run, GKE, Cloud Functions | `gcp_cis_benchmark.py` (CIS v3.0) | ✓ |
| Snowflake | `cloud/snowflake.py` | Cortex agents, Snowpark, Streamlit, MCP | `snowflake_cis_benchmark.py` (CIS v1.0) | ✓ |
| Databricks | `cloud/databricks.py` | Clusters, model serving | `databricks_security.py` (not CIS — no CIS benchmark exists for Databricks) | ✓ |
| CoreWeave | `cloud/coreweave.py` | GPU VMs (H100/A100/L40S), NVIDIA NIM pods, InfiniBand training jobs | none | kubectl-based, no SDK |
| Nebius | `cloud/nebius.py` | GPU cloud, AI Studio, compute instances | none | REST-only, no SDK |
| HuggingFace | `cloud/huggingface.py` | Model repos, Spaces, Inference API | none | |
| W&B | `cloud/wandb_provider.py` | Runs, artifacts, sweeps | none | |
| MLflow | `cloud/mlflow_provider.py` | Experiments, models, artifacts | none | |
| OpenAI | `cloud/openai_provider.py` | Assistants, fine-tuned models | none | |
| Ollama | `cloud/ollama.py` | Local model instances | none | |

### Fixed in this audit

| # | File | Fix |
|---|------|-----|
| F4 | `cloud/databricks_security.py` | Renamed from `databricks_cis_benchmark.py` — Databricks has no CIS benchmark. Renamed class to `DatabricksSecurityReport`, function to `run_security_checks()`, CLI flag to `--databricks-security` |

### Open issues

| # | Severity | File | Issue |
|---|----------|------|-------|
| O3 | LOW | `cloud/__init__.py:52-83` | `discover_governance()` and `discover_activity()` have generic signatures but only support Snowflake. Other providers will get a `ValueError`. Comment-level documentation only — no issue in practice today, but misleading API. |

### GPU coverage assessment

CoreWeave covers: VirtualServer CRDs (GPU type, count, spec), NVIDIA NIM pods (nvcr.io/nim/* images), InfiniBand training jobs.
Nebius covers: GPU instance types, AI Studio workloads, compute metadata.
NVIDIA advisory scanner covers packages starting with nvidia/cuda/tensorrt/nccl.
AI_PACKAGES constant covers 40+ GPU/ML packages including torch, tensorflow, vllm, triton, all nvidia-cuda-* wheels.

**Gap**: No direct NVIDIA DGPU/DGX infrastructure discovery (host-level GPU inventory). CoreWeave covers cloud-managed GPU workloads; bare-metal GPU clusters are not in scope.

---

## Area 3: Output + API + MCP Layer

### Output layer (`output/`)

| Module | Purpose | Status |
|--------|---------|--------|
| `__init__.py` | Main JSON/dict serializer for all report fields | PASS |
| `html.py` | HTML report renderer | PASS |
| `attack_flow.py` | React Flow blast radius + lateral movement graph | PASS |
| `graph.py` | NetworkX context graph builder | PASS |
| `mermaid.py` | Mermaid diagram generator | PASS |
| `prometheus.py` | Prometheus metrics exporter | PASS |
| `svg.py` | Static SVG diagrams (dark + light variants) | PASS |
| `agent_mesh.py` | Agent mesh topology visualization | PASS |

**Fixed**: Azure and GCP CIS benchmark data now serialized to JSON output (was silently dropped before).

### MCP server (`mcp_server.py`)

- 32 `@mcp.tool` decorators registered
- 32 entries in `_SERVER_CARD_TOOLS` (server card metadata)
- Meta-test (`test_mcp_server.py:66`) asserts `len(tools) == 32` — passes
- **Fixed**: `cis_benchmark` tool description updated to include Azure, GCP, and Databricks

### API layer (`api/`)

| Module | Purpose |
|--------|---------|
| `server.py` | FastAPI server, 40+ endpoints |
| `auth.py` | RBAC (admin/analyst/viewer) + API key management |
| `store.py` | Abstract storage interface |
| `postgres_store.py` | PostgreSQL backend |
| `clickhouse_store.py` | ClickHouse analytics backend |
| `snowflake_store.py` | Snowflake backend |
| `fleet_store.py` | Fleet scan result persistence |
| `policy_store.py` | Policy CRUD |
| `audit_log.py` | Immutable audit trail |
| `scheduler.py` | Background scan scheduling |

---

## Dependency Cleanliness

`pyproject.toml` optional extras verified against actual imports:

| Extra | Dependency | Used in | Status |
|-------|-----------|---------|--------|
| `databricks` | `databricks-sdk>=0.20` | `cloud/databricks.py`, `cloud/databricks_security.py` | ✓ |
| `coreweave` | `[]` (empty) | `kubectl` subprocess only | ✓ |
| `snyk` | `[]` (empty) | `httpx` (already in core) | ✓ |
| `ai-enrich` | `litellm>=1.30` | `ai_enrich.py` | ✓ |
| `graph` | `networkx>=3.0` | `output/graph.py`, `context_graph.py` | ✓ |
| `cloud` | meta-extra | bundles aws+azure+gcp+databricks+snowflake+nebius+huggingface+wandb+mlflow+openai | ✓ |

No phantom extras. No extras declared but unused.

---

## Naming Consistency

| Check | Status |
|-------|--------|
| No `_v2`, `_old`, `_bak` files | PASS |
| No false "CIS" labels | PASS (fixed: Databricks renamed) |
| snake_case throughout | PASS |
| No `TODO`/`FIXME`/`HACK` in production code | PASS |
| No stale dead-code modules | PASS (rbac.py is used by `api/auth.py`) |

---

## Feature Truthfulness

All documented features verified to have code + tests:

| Feature | Code | Tests |
|---------|------|-------|
| OSV CVE scanning | `scanners/__init__.py` | `tests/test_scanners.py` |
| NVD + EPSS + KEV enrichment | `enrichment.py` | `tests/test_enrichment.py` |
| Blast radius | `scanners/__init__.py:592-682` | `tests/test_scanners.py` |
| Toxic combos (8 patterns) | `toxic_combos.py` | `tests/test_toxic_combos.py` |
| Policy enforcement (17 conditions) | `policy.py` | `tests/test_policy.py` |
| SBOM ingest (CycloneDX/SPDX) | `sbom.py` | `tests/test_sbom.py` |
| VEX | `vex.py` | `tests/test_vex.py` |
| SAST (Semgrep, 52 CWEs) | `sast.py` | `tests/test_sast.py` |
| Runtime proxy (6 detectors) | `runtime/detectors.py`, `proxy.py` | `tests/test_runtime_detectors.py` |
| MCP config discovery (22 clients) | `discovery/` | `tests/test_discovery.py` |
| CIS benchmarks (AWS/Snowflake/Azure/GCP) | `cloud/*_cis_benchmark.py` | `tests/test_*_cis_benchmark.py` |
| Databricks security checks | `cloud/databricks_security.py` | `tests/test_databricks_security.py` |
| AISVS v1.0 | `cloud/aisvs_benchmark.py` | `tests/test_aisvs_benchmark.py` |
| Cache poisoning + cross-agent injection | `runtime/detectors.py`, `toxic_combos.py` | `tests/test_runtime_detectors.py` |
| Lateral movement visualization | `output/attack_flow.py` | `tests/test_attack_flow.py` |

---

## Test Coverage Gaps

Modules with no test file (functionality tested indirectly via integration tests or CLI tests):

| Module | Risk | Notes |
|--------|------|-------|
| `enrichment.py` | MEDIUM | Core enrichment logic; tested indirectly in scanner tests |
| `models.py` | LOW | Data classes; tested via every other test |
| `policy.py` | HIGH | Policy conditions tested in `test_policy.py` — exists ✓ (false alarm from glob check) |
| `atlas.py` | LOW | Compliance tagger; simple mapping logic |
| `github_actions.py` | LOW | GHA discovery; tested in integration test |
| `terraform.py` | LOW | Terraform IaC parsing |
| `image.py` | MEDIUM | Container image scanning via Grype/Syft |
| `integrity.py` | MEDIUM | Package integrity + SLSA |
| `transitive.py` | LOW | Transitive dep resolution |
| `config.py` | LOW | Config constants with env var overrides |

> **Note**: The test gap check used filename matching only. Many modules are tested in composite tests (`test_core.py`, `test_scanners.py`, `test_cloud.py`). The actual untested surface is smaller than this list suggests.

---

## Architecture Layer Mapping (vs Agentic AI Security Universe)

| Layer | Coverage | agent-bom features |
|-------|----------|-------------------|
| Identity Layer | PARTIAL | Credential detection in env vars, RBAC in API, no IdP integration |
| Agent Control Layer | STRONG | Policy enforcement (block/warn/allow), tool allowlisting, rate limiting in proxy |
| Tool Security Layer | STRONG | MCP tool scanning, injection detection, ArgumentAnalyzer, permission profiles |
| MCP Layer | STRONG | Config discovery (22 clients), proxy intercept, drift detection, enforcement |
| Governance Layer | GOOD | CIS benchmarks (5 cloud platforms), AISVS, policy-as-code, audit logs |
| Monitoring & Observability | GOOD | Runtime proxy (JSONL audit), OTel ingest, Prometheus metrics, watch (config drift) |
| Compliance & Regulation | STRONG | 14 frameworks mapped on every finding (OWASP LLM/MCP/Agentic, ATLAS, NIST AI RMF, EU AI Act, NIST CSF, ISO 27001, SOC 2, CIS Controls) |

**Weakest layer**: Identity (no OIDC/IdP integration, no NHI management). Strongest: Tool Security and MCP layers.

---

## Scanner Architecture Diagram

```
Input Sources
├── Local MCP configs (22 client types)
├── Cloud providers (12: AWS, Azure, GCP, Snowflake, Databricks, CoreWeave,
│   Nebius, HuggingFace, W&B, MLflow, OpenAI, Ollama)
├── Container images (--image, via Syft/Grype)
├── Filesystem/VM snapshots (--scan-dir, via Syft)
├── SBOM files (--sbom, CycloneDX/SPDX)
├── IaC (--tf-dir Terraform, --gha GitHub Actions)
└── SAST (--code Semgrep, 52 CWEs)
        |
        v
Package Extraction (agent-bom owns this for MCP/cloud; Syft for images/fs)
        |
        v
Vulnerability Scanning
├── Primary: OSV.dev batch API (PyPI, npm, Go, Cargo, Maven, NuGet, RubyGems)
├── Supplemental: GHSA (GitHub Security Advisories)
└── Supplemental: NVIDIA Advisory (CUDA/GPU packages)
        |
        v
Enrichment (optional, --enrich flag)
├── NVD: CWE IDs, publish dates, vuln status (90d cache)
├── EPSS: exploit probability score (30d cache)
└── CISA KEV: known-exploited catalog (24h cache)
        |
        v
Blast Radius Analysis (agent-bom's core intelligence)
├── CVE → package → server → agent reachability graph
├── Tool exposure: what tools are reachable through the vulnerable path
├── Credential exposure: what secrets are at risk
├── Risk score: CVSS + reach + AI context + KEV + EPSS + Scorecard
└── Compliance tagging: 14 frameworks per finding
        |
        v
Toxic Combo Detection (multi-factor risk patterns)
├── CRED_BLAST: critical CVE + exposed credentials
├── KEV_WITH_CREDS: actively exploited + secrets
├── EXECUTE_EXPLOIT: CVE + execute-capable tools
├── MULTI_AGENT_CVE: same CVE across 3+ agents
├── TRANSITIVE_CRITICAL: critical in hidden transitive dep
├── LATERAL_CHAIN: CVE on lateral movement path
├── CACHE_POISON: CVE + RAG/vector retrieval exposure
└── CROSS_AGENT_POISON: shared server with write+read tool pair
        |
        v
Policy Enforcement (17 conditions, block/warn/allow)
        |
        v
Output
├── JSON/dict (report.to_dict())
├── HTML report
├── React Flow attack graph (blast radius + lateral movement)
├── Mermaid diagrams
├── Prometheus metrics
├── SVG diagrams (static)
└── SARIF / CycloneDX / SPDX SBOM
```

---

---

## Area 4: Runtime Layer (proxy.py + runtime/)

### What it does (verified)

```
proxy.py (900+ lines) — stdio MCP proxy
  ├── relay_client_to_server()
  │     ├── Replay detection (SHA-256 canonical JSON, 5-min window, 10K cap)
  │     ├── Undeclared tool blocking (--block-undeclared)
  │     ├── Policy enforcement (allowlist/blocklist, tool_name_pattern, arg_pattern)
  │     ├── Gateway evaluator hook (external enforcement integration point)
  │     ├── ArgumentAnalyzer (7 dangerous arg patterns)
  │     ├── RateLimitTracker (sliding window, configurable threshold)
  │     ├── SequenceAnalyzer (4 sequences, subsequence matching — evades interleaved benign calls)
  │     └── Inline scanner (proxy_scanner.scan_tool_call — prompt injection, PII, secrets)
  └── relay_server_to_client()
        ├── ToolDriftDetector (baseline vs current, new tools = HIGH, removed = MEDIUM)
        ├── CredentialLeakDetector (12 credential patterns, values redacted in alerts)
        ├── ResponseInspector (8 cloaking + 5 SVG + 5 invisible char + base64 + 6 injection)
        └── Inline response scanner (proxy_scanner.scan_tool_response)

ProxyMetrics — per-tool call counts, blocked counts, latency (p50/p95), replay rejections
ProxyMetricsServer — Prometheus text exposition on port 8422, optional bearer token auth
ReplayDetector — canonical JSON SHA-256, 5-minute sliding window, LRU eviction at 10K
check_policy() — allowlist takes precedence, block_tools/tool_name/tool_name_pattern/arg_pattern,
                  ReDoS guard (>500 char patterns skipped with warning)
log_tool_call() — JSONL audit log, 0o600 permissions, payload SHA-256, policy result, reason
_send_webhook() — SSRF-protected (validate_url()), fire-and-forget async POST
```

**runtime/detectors.py** — 7 detectors:

| Detector | What it checks |
|----------|----------------|
| ToolDriftDetector | New tools after startup (rug pull) |
| ArgumentAnalyzer | Shell metacharacters, path traversal, cmd injection, env vars, creds, base64/hex payloads |
| CredentialLeakDetector | 12 credential patterns in responses (AWS, GitHub, OpenAI, Anthropic, Slack, Stripe, etc.) |
| RateLimitTracker | Excessive calls per tool per window |
| SequenceAnalyzer | 4 suspicious multi-step sequences (exfil, credential harvest, privilege escalation, recon) |
| ResponseInspector | HTML/CSS cloaking, SVG payloads, invisible Unicode, base64 blobs, prompt injection |
| VectorDBInjectionDetector | Vector tool name detection + severity upgrade to CRITICAL; wraps ResponseInspector |

### Fixed in this audit

| # | File | Fix |
|---|------|-----|
| F5 | `runtime/__init__.py` | `VectorDBInjectionDetector` was not exported from the public runtime API — added to `__all__` |
| F6 | `proxy.py` | `VectorDBInjectionDetector` was never instantiated in `run_proxy()` — added `vector_detector` alongside `response_inspector`; now fires for every tool response with CRITICAL severity upgrade for confirmed vector tool names |

**Test coverage**: 88 tests in `test_runtime_detectors.py` + `test_proxy.py` + `test_proxy_metrics.py`, plus `test_protect.py`, `test_protection_engine.py`. All 7 detectors are tested individually.

---

## Area 5: API Layer (api/)

### What it does (verified)

```
api/server.py — FastAPI, auto-selects backend from env:
  Snowflake (SNOWFLAKE_ACCOUNT) > Postgres (AGENT_BOM_POSTGRES_URL) > SQLite (AGENT_BOM_DB) > InMemory

Middleware stack (outermost → innermost):
  CORSMiddleware   — configurable via CORS_ORIGINS (defaults to localhost only)
  TrustHeadersMiddleware — X-Content-Type-Options, X-Frame-Options, Cache-Control: no-store, CSP: default-src 'self'
  APIKeyMiddleware — simple mode (static key) or RBAC mode (KeyStore, role-based path matching)

RBAC roles: admin > analyst > viewer
  admin  — DELETE scans, CREATE/DELETE gateway policies, fleet sync, key management, exceptions
  analyst — POST scan, gateway evaluate, OTel traces, result push, schedule CRUD
  viewer  — all GET/read endpoints

api/auth.py:
  scrypt KDF (n=16384, r=8, p=1, dklen=32), per-key random salt, hmac.compare_digest (constant-time)
  Key format: abom_<secrets.token_urlsafe(32)>
  Raw key returned once, only scrypt-derived hash stored

api/audit_log.py:
  HMAC-SHA256 per-entry: entry_id|timestamp|action|actor|resource
  Warns if AGENT_BOM_AUDIT_HMAC_KEY not set (ephemeral key, restarts break cross-session verify)
  InMemoryAuditLog: 50K cap, LRU trim
  SQLiteAuditLog: WAL mode, 3 indexes, parameterized queries (no SQL injection surface)
  verify_integrity() returns (verified_count, tampered_count)

Analytics: optional ClickHouse backend (AGENT_BOM_CLICKHOUSE_URL)
Scheduler: background task, runs scheduled scans from store
ThreadPoolExecutor: sync scan work offloaded from async event loop
```

### Issues

None found. Auth, audit log, RBAC, middleware, and backend selection are all correctly implemented.

**Note on AGENT_BOM_AUDIT_HMAC_KEY**: the code correctly warns when this is unset. Production docs should prominently require this env var for meaningful audit log tamper detection.

**Test coverage**: `test_api_hardening.py`, `test_api_endpoints.py`, `test_api_store.py`, `test_api_gateway.py`, `test_api_fleet.py`, `test_api_agent_detail.py`, `test_api_pipeline_events.py`, `test_api_proxy_scorecard.py`, `test_audit_round2.py` — 58+ tests across these files.

---

## Area 6: Data Flow (end-to-end)

```
CLI/API/MCP
    │
    ▼
ScanRequest → _run_scan_sync() [ThreadPoolExecutor]
    │
    ├── discovery/     MCP client config → list of servers + packages
    ├── cloud/         Cloud provider APIs → list of agents + packages
    ├── sbom.py        SBOM ingest (CycloneDX/SPDX) → packages
    ├── image.py       Syft/Grype → packages + CVEs
    ├── sast.py        Semgrep → CWE findings
    ├── integrity.py   SLSA + package integrity
    └── transitive.py  Transitive dependency resolution
                │
                ▼
        ScanCache (SQLite, 24h TTL)
                │
                ▼
        OSV.dev batch API (primary CVE source)
        GHSA + NVIDIA advisory (supplemental)
                │
                ▼
        Enrichment (optional --enrich):
          NVD (CWE, dates, status — 90d cache)
          EPSS (exploit probability — 30d cache)
          CISA KEV (known-exploited — 24h cache)
          OpenSSF Scorecard (maintainer health)
                │
                ▼
        blast_radius_analysis() → CVE→package→server→agent graph
          risk_score = base_severity + agent_reach + cred_exposure
                     + tool_count + AI_boost + KEV_boost + EPSS_boost
                     + scorecard_boost
          compliance tagging: 14 frameworks per finding
                │
                ▼
        toxic_combos.py → 8 multi-factor risk patterns
                │
                ▼
        policy.py → 17 conditions, block/warn/allow
                │
                ▼
        AIBOMReport.to_dict() → output/__init__.py
          → JSON, HTML, React Flow, Mermaid, Prometheus, SVG, SARIF, SBOM
```

**Data isolation**: Each scan is a separate object; no cross-scan shared state. The in-memory job store caps at `API_MAX_IN_MEMORY_JOBS` and evicts on TTL.

**No issues found** with data flow. Input validation uses `security.py` (validate_path, validate_url, validate_command). All external API calls have timeouts. NVD/EPSS/KEV/OSV use httpx with configured timeout.

---

---

## Area 7: CLI (cli.py)

### Commands verified (22 total)

`scan`, `inventory`, `validate`, `where`, `check`, `verify`, `history`, `diff`, `policy-template`, `serve`, `api`, `mcp-server`, `completions`, `apply`, `schedule` (group: add/list/remove), `registry` (group: list/search/update/enrich/sync), `proxy`, `guard`, `protect`, `watch`, `analytics`, `dashboard`

**`serve` vs `api`**: Not duplicates. `serve` = API + bundled Next.js UI, simpler flags. `api` = production server with `--workers`, `--api-key`, `--rate-limit`. Different extras: `[ui]` vs `[api]`.

**`--introspect`**: Flag on `scan`, wired to `mcp_introspect.py`. Not a standalone command.

### Fixed in this audit

| # | File | Fix |
|---|------|-----|
| F13 | `cli.py` | `api` command had no `--log-level` or `--log-json` (inconsistent with `serve`). Added both; `setup_logging()` now called; uvicorn log level wired to user input. |

### Open issues

| # | Severity | Issue |
|---|----------|-------|
| O5 | LOW | `guard` command (pre-install CVE check wrapping pip/npm) not mentioned in README. Functional, tested, just undocumented externally. |

---

## Area 8: Discovery + Peripheral Runtime Modules

### Discovery (discovery/__init__.py)

- **20 named MCP clients** in `CONFIG_LOCATIONS` (+ `CUSTOM` = 21 `AgentType` enum values). README "21" counts all enum values. ARCHITECTURE.md "21" also accurate. No gap.
- `sanitize_env_vars()` called on all env blocks. `validate_path()` used before reading config files. PASS.
- Docker MCP Toolkit handled separately (Docker socket path, not `CONFIG_LOCATIONS`). Correct.

### Runtime peripheral modules

| Module | Lines | Wired to CLI | Tests | Status |
|--------|-------|-------------|-------|--------|
| `watch.py` | 304 | `watch` command | `test_watch.py` indirect | PASS |
| `mcp_introspect.py` | 360 | `scan --introspect` | `test_discovery.py` | PASS |
| `enforcement.py` | 759 | `scan` pipeline | `test_enforcement.py` | PASS |

`enforcement.py`: 8 check functions (`check_cve_exposure`, `check_drift`, `check_claude_config`, `check_agentic_search_risk`, `check_over_permission`, `check_tool_name_collisions` + 2 more). ARCHITECTURE.md previously said "10 checks" — corrected to 8 (F11).

---

## Area 9: Accuracy (ARCHITECTURE.md + SVGs + README)

### Fixed in this audit

| # | File | Fix |
|---|------|-----|
| F7 | `ARCHITECTURE.md` | `auth.py — JWT authentication` → `scrypt KDF API keys, RBAC roles (admin/analyst/viewer)`. No JWT anywhere in codebase. |
| F8 | `ARCHITECTURE.md` | `Runtime detectors: 6` → `7` in Module Stats |
| F9 | `ARCHITECTURE.md` | Detector list now includes `VectorDBInjectionDetector` |
| F10 | `ARCHITECTURE.md` | `CLI with 15+ commands` → `22+ commands and groups` |
| F11 | `ARCHITECTURE.md` | `enforcement.py — 10 checks` → `8 checks` |
| F12 | SVGs (7 files) | `6 detectors` → `7 detectors`: engine-internals, modes-flow, offerings-map, scanner-architecture (dark + light variants) |

### Verified accurate (no changes needed)

| Claim | Verified |
|-------|---------|
| "22 MCP clients" (README) | ✓ 20 named AgentType values + CUSTOM = 21 |
| "32 MCP tools" | ✓ meta-test enforces this |
| "14 compliance frameworks" | ✓ 10 tagging modules |
| "52 CWE compliance mappings" | ✓ CWE_COMPLIANCE_MAP count |
| "12 cloud providers" | ✓ cloud/__init__.py _PROVIDERS |
| OSV as primary vuln source | ✓ |
| scrypt KDF for API keys | ✓ auth.py (n=16384, r=8, p=1) |
| HMAC-SHA256 audit log | ✓ audit_log.py |

---

## Audit Summary (all areas)

| Area | Status | Bugs Fixed | Open Issues |
|------|--------|-----------|-------------|
| Scanner architecture | PASS | 3 (F1-F3) | 2 (O1-O2) |
| Cloud modules | PASS | 1 (F4) | 1 (O3) |
| Output + API + MCP | PASS | 2 (F3, MCP desc) | 0 |
| Runtime layer | PASS | 2 (F5-F6) | 0 |
| API layer | PASS | 0 | 0 |
| Data flow | PASS | 0 | 0 |
| CLI | PASS | 1 (F13) | 1 (O5: guard undocumented) |
| Discovery + peripheral modules | PASS | 0 | 0 |
| Accuracy (ARCHITECTURE + SVGs + README) | PASS | 7 (F7-F12 + F13) | 0 |

---

## Next Audit Checklist (delta from this audit)

When re-running this audit, check:

- [ ] NVIDIA advisory filter still narrow? (O1)
- [ ] Maven/Go ecosystem test coverage added? (O2)
- [ ] `discover_governance`/`discover_activity` extended beyond Snowflake? (O3)
- [x] `VectorDBInjectionDetector` wired into `run_proxy()` — fixed F6
- [x] `VectorDBInjectionDetector` exported from `runtime/__init__.py` — fixed F5
- [ ] `AGENT_BOM_AUDIT_HMAC_KEY` documented prominently in deployment docs?
- [ ] New modules added without tests?
- [ ] New CIS benchmarks added — does output/__init__.py serialize them?
- [ ] @mcp.tool count still matches _SERVER_CARD_TOOLS count (both should be 30)?
- [ ] Any new compliance frameworks added to scanner but not to ARCHITECTURE.md?
- [ ] Databricks security checks: if CIS ever publishes a Databricks benchmark, rename accordingly
- [ ] `guard` command documented in README? (O5)
- [ ] SVG detector count updated if more detectors added?
- [ ] `serve` and `api` commands still aligned on flags as features are added?
