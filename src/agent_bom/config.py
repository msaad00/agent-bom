"""Centralized configuration — env-var-overridable tuning knobs.

All thresholds, weights, and scoring parameters that operators may need
to adjust for their environment.  Standards-defined constants (CVSS 3.x
formula coefficients, OWASP codes, ATLAS technique IDs) are NOT here —
they belong in their respective modules.

Environment variable convention: ``AGENT_BOM_<SECTION>_<NAME>``
"""

from __future__ import annotations

import os


def _float(env_key: str, default: float) -> float:
    """Read a float from *env_key*, falling back to *default*."""
    raw = os.environ.get(env_key)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _int(env_key: str, default: int) -> int:
    """Read an int from *env_key*, falling back to *default*."""
    raw = os.environ.get(env_key)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _str(env_key: str, default: str) -> str:
    """Read a string from *env_key*, falling back to *default*."""
    return os.environ.get(env_key, default)


# ── EPSS Thresholds ─────────────────────────────────────────────────────────
# EPSS (Exploit Prediction Scoring System) probability thresholds.
# Source: https://www.first.org/epss/
#
# 0.5  — roughly the top 5 % of all scored CVEs; strong signal of real-world
#         exploitation activity, comparable to CISA KEV inclusion criteria.
# 0.7  — top ~2 %; very high likelihood of exploitation within 30 days.
# 0.3  — top ~10 %; elevated risk when combined with HIGH severity.

EPSS_ACTIVE_EXPLOITATION_THRESHOLD = _float(
    "AGENT_BOM_EPSS_ACTIVE_THRESHOLD",
    0.5,
)
EPSS_CRITICAL_THRESHOLD = _float(
    "AGENT_BOM_EPSS_CRITICAL_THRESHOLD",
    0.7,
)
EPSS_HIGH_LIKELY_THRESHOLD = _float(
    "AGENT_BOM_EPSS_HIGH_THRESHOLD",
    0.3,
)


# ── Blast Radius Risk Scoring ───────────────────────────────────────────────
# Used by models.BlastRadius.calculate_risk_score().
#
# Design rationale:
#   Base severity starts at 80 % of max (CRITICAL = 8.0 / 10.0) to leave
#   headroom for reach amplifiers.  Each step down drops ~2 points so that a
#   MEDIUM finding can still reach HIGH territory when many agents or creds
#   are exposed.

RISK_BASE_CRITICAL = _float("AGENT_BOM_RISK_BASE_CRITICAL", 8.0)
RISK_BASE_HIGH = _float("AGENT_BOM_RISK_BASE_HIGH", 6.0)
RISK_BASE_MEDIUM = _float("AGENT_BOM_RISK_BASE_MEDIUM", 4.0)
RISK_BASE_LOW = _float("AGENT_BOM_RISK_BASE_LOW", 2.0)

# Reach amplifiers — each affected entity adds *weight*, capped at *cap*.
#   agent  0.5 × n (cap 2.0)  → 4+ agents = full amplification
#   cred   0.3 × n (cap 1.5)  → 5+ creds  = full amplification
#   tool   0.1 × n (cap 1.0)  → 10+ tools = full amplification
RISK_AGENT_WEIGHT = _float("AGENT_BOM_RISK_AGENT_WEIGHT", 0.5)
RISK_AGENT_CAP = _float("AGENT_BOM_RISK_AGENT_CAP", 2.0)
RISK_CRED_WEIGHT = _float("AGENT_BOM_RISK_CRED_WEIGHT", 0.3)
RISK_CRED_CAP = _float("AGENT_BOM_RISK_CRED_CAP", 1.5)
RISK_TOOL_WEIGHT = _float("AGENT_BOM_RISK_TOOL_WEIGHT", 0.1)
RISK_TOOL_CAP = _float("AGENT_BOM_RISK_TOOL_CAP", 1.0)

# Conditional boosts — applied when specific conditions are met.
#   AI boost (0.5): AI framework package with both creds AND tools exposed.
#   KEV boost (1.0): Vulnerability in CISA Known Exploited Vulnerabilities.
#   EPSS boost (0.5): EPSS score ≥ EPSS_CRITICAL_THRESHOLD.
RISK_AI_BOOST = _float("AGENT_BOM_RISK_AI_BOOST", 0.5)
RISK_KEV_BOOST = _float("AGENT_BOM_RISK_KEV_BOOST", 1.0)
RISK_EPSS_BOOST = _float("AGENT_BOM_RISK_EPSS_BOOST", 0.5)

# Scorecard boost — poorly-maintained packages amplify risk.
#   < 3.0 → +0.75  (abandoned / no CI / no SAST)
#   < 5.0 → +0.50  (minimal maintenance)
#   < 7.0 → +0.25  (below average)
#   ≥ 7.0 → +0.00  (well-maintained)
RISK_SCORECARD_TIER1_THRESHOLD = _float("AGENT_BOM_RISK_SCORECARD_T1", 3.0)
RISK_SCORECARD_TIER1_BOOST = _float("AGENT_BOM_RISK_SCORECARD_B1", 0.75)
RISK_SCORECARD_TIER2_THRESHOLD = _float("AGENT_BOM_RISK_SCORECARD_T2", 5.0)
RISK_SCORECARD_TIER2_BOOST = _float("AGENT_BOM_RISK_SCORECARD_B2", 0.5)
RISK_SCORECARD_TIER3_THRESHOLD = _float("AGENT_BOM_RISK_SCORECARD_T3", 7.0)
RISK_SCORECARD_TIER3_BOOST = _float("AGENT_BOM_RISK_SCORECARD_B3", 0.25)


# ── Server Risk Scoring ─────────────────────────────────────────────────────
# Used by risk_analyzer.score_server_risk().
#
# Base ceiling 7.0 normalises the capability-weighted sum so that a server
# with ALL capability types still only reaches 7.0 before amplifiers.

SERVER_RISK_BASE_CEILING = _float("AGENT_BOM_SERVER_RISK_CEILING", 7.0)

SERVER_RISK_TOOL_WEIGHT = _float("AGENT_BOM_SERVER_TOOL_WEIGHT", 0.15)
SERVER_RISK_TOOL_CAP = _float("AGENT_BOM_SERVER_TOOL_CAP", 1.5)
SERVER_RISK_CRED_WEIGHT = _float("AGENT_BOM_SERVER_CRED_WEIGHT", 0.5)
SERVER_RISK_CRED_CAP = _float("AGENT_BOM_SERVER_CRED_CAP", 2.0)
SERVER_RISK_COMBO_WEIGHT = _float("AGENT_BOM_SERVER_COMBO_WEIGHT", 0.3)
SERVER_RISK_COMBO_CAP = _float("AGENT_BOM_SERVER_COMBO_CAP", 1.5)

# Registry floor — when the bundled MCP registry says a server is "high" or
# "medium" risk, enforce a minimum score regardless of tool analysis.
SERVER_RISK_REGISTRY_HIGH_FLOOR = _float("AGENT_BOM_SERVER_REG_HIGH", 6.0)
SERVER_RISK_REGISTRY_MEDIUM_FLOOR = _float("AGENT_BOM_SERVER_REG_MEDIUM", 3.0)

# Risk level thresholds for server risk classification.
SERVER_RISK_CRITICAL_THRESHOLD = _float("AGENT_BOM_SERVER_CRITICAL", 9.0)
SERVER_RISK_HIGH_THRESHOLD = _float("AGENT_BOM_SERVER_HIGH", 7.0)
SERVER_RISK_MEDIUM_THRESHOLD = _float("AGENT_BOM_SERVER_MEDIUM", 4.0)


# ── HTTP Client ───────────────────────────────────────────────────────────
# Used by http_client.create_client() and request_with_retry().
#
# Defaults: 3 retries with 1s initial backoff (doubles each retry, capped
# at 30s).  30s per-request timeout covers most external APIs; NVD can be
# slow so operators may raise this.

HTTP_MAX_RETRIES = _int("AGENT_BOM_HTTP_MAX_RETRIES", 3)
HTTP_INITIAL_BACKOFF = _float("AGENT_BOM_HTTP_INITIAL_BACKOFF", 1.0)
HTTP_MAX_BACKOFF = _float("AGENT_BOM_HTTP_MAX_BACKOFF", 30.0)
HTTP_DEFAULT_TIMEOUT = _float("AGENT_BOM_HTTP_DEFAULT_TIMEOUT", 30.0)
CLOUD_DISCOVERY_TIMEOUT = _float("AGENT_BOM_CLOUD_DISCOVERY_TIMEOUT", 45.0)


# ── Scanner Batching ──────────────────────────────────────────────────────
# Used by scanners/__init__.py for OSV batch API concurrency.
#
# 10 concurrent requests with 500ms delay between batches keeps us well
# under OSV.dev's rate limit while still being fast for large inventories.

SCANNER_MAX_CONCURRENT = _int("AGENT_BOM_SCANNER_MAX_CONCURRENT", 10)
SCANNER_BATCH_DELAY = _float("AGENT_BOM_SCANNER_BATCH_DELAY", 0.5)
SCANNER_BATCH_SIZE = _int("AGENT_BOM_SCANNER_BATCH_SIZE", 1000)  # OSV API max is 1000


# ── Scan Cache ────────────────────────────────────────────────────────────────
# SQLite-backed OSV result cache (~/.agent-bom/scan_cache.db).
#
# 100,000 entries covers ~5-10 large enterprise scans before eviction kicks in.
# Oldest entries are removed first (LRU by insertion time) when the limit is hit.
# Set to 0 to disable the cap (unbounded growth — not recommended for servers).

SCAN_CACHE_MAX_ENTRIES = _int("AGENT_BOM_SCAN_CACHE_MAX_ENTRIES", 100_000)


# ── AI Enrichment ─────────────────────────────────────────────────────────
# Used by ai_enrich.py for LLM-powered risk narratives.
#
# Cache bounded at 1,000 entries (sha256 keyed) to prevent unbounded memory
# growth during large scans.  Ollama default URL assumes local Docker/native
# install.

AI_CACHE_MAX_ENTRIES = _int("AGENT_BOM_AI_CACHE_MAX", 1_000)
OLLAMA_BASE_URL = _str("AGENT_BOM_OLLAMA_URL", "http://localhost:11434")


# ── Enrichment Cache ──────────────────────────────────────────────────────
# Used by enrichment.py for persistent NVD + EPSS disk cache.
#
# 7-day TTL balances freshness vs. API rate limits.  10,000 entries covers
# most enterprise scans without unbounded disk/memory growth.

ENRICHMENT_TTL_SECONDS = _int("AGENT_BOM_ENRICHMENT_TTL", 604_800)
ENRICHMENT_MAX_CACHE_ENTRIES = _int("AGENT_BOM_ENRICHMENT_MAX_CACHE", 10_000)


# ── API Server Limits ─────────────────────────────────────────────────────
# Used by api/server.py for the REST API job queue.
#
# 10 concurrent scan jobs prevents resource exhaustion on shared hosts.
# 1-hour TTL auto-cleans completed jobs.  200 in-memory ceiling triggers
# LRU eviction for long-running API instances.

API_MAX_CONCURRENT_JOBS = _int("AGENT_BOM_API_MAX_JOBS", 10)
API_JOB_TTL_SECONDS = _int("AGENT_BOM_API_JOB_TTL", 3_600)
API_MAX_IN_MEMORY_JOBS = _int("AGENT_BOM_API_MAX_MEMORY_JOBS", 200)
API_MAX_ACTIVE_SCAN_JOBS_PER_TENANT = _int("AGENT_BOM_API_MAX_ACTIVE_SCAN_JOBS_PER_TENANT", API_MAX_CONCURRENT_JOBS)
API_MAX_RETAINED_JOBS_PER_TENANT = _int("AGENT_BOM_API_MAX_RETAINED_JOBS_PER_TENANT", 500)
API_MAX_FLEET_AGENTS_PER_TENANT = _int("AGENT_BOM_API_MAX_FLEET_AGENTS_PER_TENANT", 1_000)
API_MAX_SCHEDULES_PER_TENANT = _int("AGENT_BOM_API_MAX_SCHEDULES_PER_TENANT", 100)


# ── MCP Server Limits ────────────────────────────────────────────────────
# Used by mcp_server.py for file-size and response-size guards, tool execution
# governance, and lightweight in-process observability.
#
# 50 MB max file size prevents accidental ingestion of large binaries.
# 500,000 char response cap keeps MCP tool responses within typical
# LLM context windows. 8 concurrent tools keeps hosted MCP usage bounded
# without artificially constraining typical desktop usage. A 30s per-tool
# timeout prevents slow integrations from monopolizing the server forever.

MCP_MAX_FILE_SIZE = _int("AGENT_BOM_MCP_MAX_FILE_SIZE", 50 * 1024 * 1024)
MCP_MAX_RESPONSE_CHARS = _int("AGENT_BOM_MCP_MAX_RESPONSE", 500_000)
MCP_MAX_CONCURRENT_TOOLS = _int("AGENT_BOM_MCP_MAX_CONCURRENT_TOOLS", 8)
MCP_TOOL_TIMEOUT_SECONDS = _float("AGENT_BOM_MCP_TOOL_TIMEOUT_SECONDS", 30.0)
MCP_MAX_TOOL_METRICS = _int("AGENT_BOM_MCP_MAX_TOOL_METRICS", 128)
MCP_CALLER_RATE_LIMIT = _int("AGENT_BOM_MCP_CALLER_RATE_LIMIT", 120)
MCP_CALLER_WINDOW_SECONDS = _float("AGENT_BOM_MCP_CALLER_WINDOW_SECONDS", 60.0)
MCP_MAX_CALLER_STATES = _int("AGENT_BOM_MCP_MAX_CALLER_STATES", 256)
MCP_MAX_REQUEST_TRACES = _int("AGENT_BOM_MCP_MAX_REQUEST_TRACES", 256)
