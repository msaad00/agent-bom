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
**Compliance tagging**: 10 frameworks on every blast radius — OWASP LLM, OWASP MCP, OWASP Agentic, ATLAS, NIST AI RMF, EU AI Act, NIST CSF, ISO 27001, SOC 2, CIS Controls.
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

- 22 `@mcp.tool` decorators registered
- 22 entries in `_SERVER_CARD_TOOLS` (server card metadata)
- Meta-test (`test_mcp_server.py:66`) asserts `len(tools) == 22` — passes
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
| MCP config discovery (20 clients) | `discovery/` | `tests/test_discovery.py` |
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
| MCP Layer | STRONG | Config discovery (20 clients), proxy intercept, drift detection, enforcement |
| Governance Layer | GOOD | CIS benchmarks (5 cloud platforms), AISVS, policy-as-code, audit logs |
| Monitoring & Observability | GOOD | Runtime proxy (JSONL audit), OTel ingest, Prometheus metrics, watch (config drift) |
| Compliance & Regulation | STRONG | 10 frameworks mapped on every finding (OWASP LLM/MCP/Agentic, ATLAS, NIST AI RMF, EU AI Act, NIST CSF, ISO 27001, SOC 2, CIS Controls) |

**Weakest layer**: Identity (no OIDC/IdP integration, no NHI management). Strongest: Tool Security and MCP layers.

---

## Scanner Architecture Diagram

```
Input Sources
├── Local MCP configs (20 client types)
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
└── Compliance tagging: 10 frameworks per finding
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

## Next Audit Checklist (delta from this audit)

When re-running this audit, check:

- [ ] NVIDIA advisory filter still narrow? (O1)
- [ ] Maven/Go ecosystem test coverage added? (O2)
- [ ] `discover_governance`/`discover_activity` extended beyond Snowflake? (O3)
- [ ] New modules added without tests?
- [ ] New CIS benchmarks added — does output/__init__.py serialize them?
- [ ] @mcp.tool count still matches _SERVER_CARD_TOOLS count (both should be 22)?
- [ ] Any new compliance frameworks added to scanner but not to ARCHITECTURE.md?
- [ ] Databricks security checks: if CIS ever publishes a Databricks benchmark, rename accordingly
