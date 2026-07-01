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


def _bool(env_key: str, default: bool) -> bool:
    """Read a boolean from *env_key*, falling back to *default*."""
    raw = os.environ.get(env_key)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _str(env_key: str, default: str) -> str:
    """Read a string from *env_key*, falling back to *default*."""
    return os.environ.get(env_key, default)


# ── Extension Loading ─────────────────────────────────────────────────────
# Disabled by default so third-party provider/connector/parser entry points
# never execute unless an operator explicitly opts in.

ENABLE_EXTENSION_ENTRYPOINTS = _bool("AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS", False)


# ── OS-package reporting ──────────────────────────────────────────────────────
# When False (default), OS/distro advisories with no fix for the scanned release
# (no-dsa / won't-fix / end-of-life open) are suppressed so container reporting
# matches mainstream scanner conventions. Set AGENT_BOM_INCLUDE_UNFIXED=1 to
# surface them. The scanner re-reads this env var at scan time so it can be
# toggled per-invocation; see agent_bom.scanners.set_include_unfixed.

INCLUDE_UNFIXED_OS_ADVISORIES = _bool("AGENT_BOM_INCLUDE_UNFIXED", False)


# ── Image Scanning ────────────────────────────────────────────────────────────
# Optional Grype fallback for ``agent-bom image --tar`` when native OCI/archive
# extraction yields no packages. Off by default — enable only when bridging
# legacy tarballs that Grype handles better than the native parser.

IMAGE_GRYPE_FALLBACK = _bool("AGENT_BOM_IMAGE_GRYPE_FALLBACK", False)


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

# Graph-walk reachability adjustment — applied only when
# `agent_bom.graph.dependency_reach.compute_dependency_reach` has stamped
# the BlastRadius with a definitive answer (None leaves scoring unchanged).
#   reachable    → +0.5  (an agent's USES/DEPENDS_ON closure includes the package)
#   unreachable  → −0.5  (package is in inventory but no agent traversal reaches it)
# The boost is intentionally smaller than the AI/KEV boosts (0.5 each) so
# reachability sharpens triage order but does not eclipse a CISA KEV signal.
RISK_REACHABLE_BOOST = _float("AGENT_BOM_RISK_REACHABLE_BOOST", 0.5)
RISK_UNREACHABLE_PENALTY = _float("AGENT_BOM_RISK_UNREACHABLE_PENALTY", 0.5)


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
# Registry rate-limit circuit breaker: number of HTTP 429 responses from a
# single host within one scan before live lookups to that host are short-
# circuited to the cached/bundled fallback path for the rest of the run. Keeps
# a registry throttle (e.g. npm at peak) from turning into a multi-minute stall
# and a per-package warning storm. Reset per scan via reset_rate_limit_breaker.
HTTP_RATE_LIMIT_BREAKER_THRESHOLD = _int("AGENT_BOM_HTTP_RATE_LIMIT_BREAKER_THRESHOLD", 3)
CLOUD_DISCOVERY_TIMEOUT = _float("AGENT_BOM_CLOUD_DISCOVERY_TIMEOUT", 45.0)


# ── Scanner Batching ──────────────────────────────────────────────────────
# Used by scanners/__init__.py for OSV batch API concurrency.
#
# 10 concurrent requests with 500ms delay between batches keeps us well
# under OSV.dev's rate limit while still being fast for large inventories.

SCANNER_MAX_CONCURRENT = _int("AGENT_BOM_SCANNER_MAX_CONCURRENT", 10)
SCANNER_OSV_BATCH_CONCURRENCY = _int("AGENT_BOM_SCANNER_OSV_BATCH_CONCURRENCY", 3)
# Opt-in CPE candidate matching against the local NVD CPE cache. Off by default:
# CPE product names don't always equal package names, so these are review-grade
# (nvd_cpe_candidate) and only applied to components OSV/distro feeds miss.
ENABLE_CPE_MATCH = _bool("AGENT_BOM_ENABLE_CPE_MATCH", False)
SCANNER_BATCH_DELAY = _float("AGENT_BOM_SCANNER_BATCH_DELAY", 0.5)
SCANNER_BATCH_SIZE = _int("AGENT_BOM_SCANNER_BATCH_SIZE", 1000)  # OSV API max is 1000
# Cap unauthenticated GHSA advisory lookups so no-token scans fail fast
# with partial coverage instead of spending minutes on GitHub rate limits.
GHSA_UNAUTH_PACKAGE_BUDGET = _int("AGENT_BOM_GHSA_UNAUTH_PACKAGE_BUDGET", 25)


# ── Scan Cache ────────────────────────────────────────────────────────────────
# SQLite-backed OSV result cache (~/.agent-bom/scan_cache.db).
#
# 100,000 entries covers ~5-10 large enterprise scans before eviction kicks in.
# Oldest entries are removed first (LRU by insertion time) when the limit is hit.
# Set to 0 to disable the cap (unbounded growth — not recommended for servers).

SCAN_CACHE_MAX_ENTRIES = _int("AGENT_BOM_SCAN_CACHE_MAX_ENTRIES", 100_000)


# ── Local Analytics ─────────────────────────────────────────────────────────
# Optional path override for the local scan analytics SQL mirror. Empty string
# means use ~/.agent-bom/local-analytics.sqlite.

LOCAL_ANALYTICS_DB = _str("AGENT_BOM_LOCAL_ANALYTICS_DB", "")


# ── Graph Backend Selection ───────────────────────────────────────────────
# SQLite is the local default. Postgres remains selected by AGENT_BOM_POSTGRES_URL.
# Neptune is an explicit enterprise lane and must fail closed without endpoint
# configuration so deployments do not silently fall back to a different graph.

GRAPH_BACKEND = _str("AGENT_BOM_GRAPH_BACKEND", "")
NEPTUNE_ENDPOINT = _str("AGENT_BOM_NEPTUNE_ENDPOINT", "")
NEPTUNE_TRAVERSAL_SOURCE = _str("AGENT_BOM_NEPTUNE_TRAVERSAL_SOURCE", "g")


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
API_SCAN_WORKERS = _int("AGENT_BOM_API_SCAN_WORKERS", min(4, (os.cpu_count() or 2)))
API_SCAN_WORKER_RECYCLE_JOBS = _int("AGENT_BOM_API_SCAN_WORKER_RECYCLE_JOBS", 10)
# Distributed scan dispatch (multi-replica work-stealing). When enabled, scan
# jobs are enqueued to a shared Postgres dispatch queue and any control-plane
# replica claims them via FOR UPDATE SKIP LOCKED, so scan throughput scales with
# replicas instead of pinning each job to the node that received the request.
# Lease seconds bound how long a claimed job may run before another node may
# reclaim it (the owning node renews the lease each poll while the job runs).
API_SCAN_LEASE_SECONDS = _int("AGENT_BOM_API_SCAN_LEASE_SECONDS", 600)
API_SCAN_CLAIM_POLL_SECONDS = _int("AGENT_BOM_API_SCAN_CLAIM_POLL_SECONDS", 3)
# Cloud-connection scan scheduler (Phase B.2). The background loop re-scans
# cloud connections that carry an interval, so "connect once, keeps evaluating"
# is automatic. Disabled by default (AGENT_BOM_CONNECTIONS_SCHEDULER, read live)
# so it never runs in CLI/dev. The minimum per-connection interval guards
# against hammering a customer account; concurrency bounds how many brokered
# scans run at once; poll seconds is how often the loop re-checks for due work.
CONNECTIONS_SCHEDULER_POLL_SECONDS = _int("AGENT_BOM_CONNECTIONS_SCHEDULER_POLL_SECONDS", 60)
CONNECTIONS_SCHEDULER_MIN_INTERVAL_MINUTES = _int("AGENT_BOM_CONNECTIONS_SCHEDULER_MIN_INTERVAL_MINUTES", 15)
CONNECTIONS_SCHEDULER_MAX_CONCURRENCY = _int("AGENT_BOM_CONNECTIONS_SCHEDULER_MAX_CONCURRENCY", 4)
# Event-driven AWS posture ingestion (continuous posture). When an operator
# wires EventBridge→SQS (opt-in via AGENT_BOM_AWS_EVENT_QUEUE_URL, read live,
# default off), the bounded SQS consumer drains change events and re-evaluates
# only the affected resource's CIS rules — polling stays the fallback. These
# knobs bound a single consume pass so it always terminates: messages per
# receive, receive batches per pass, per-message visibility timeout, and the
# long-poll wait. Caps mirror the SQS API limits (10 messages, 20s wait).
AWS_EVENT_MAX_MESSAGES = _int("AGENT_BOM_AWS_EVENT_MAX_MESSAGES", 10)
AWS_EVENT_MAX_BATCHES = _int("AGENT_BOM_AWS_EVENT_MAX_BATCHES", 10)
AWS_EVENT_VISIBILITY_TIMEOUT = _int("AGENT_BOM_AWS_EVENT_VISIBILITY_TIMEOUT", 120)
AWS_EVENT_WAIT_SECONDS = _int("AGENT_BOM_AWS_EVENT_WAIT_SECONDS", 5)
# Event-driven Azure posture ingestion. When an operator wires Azure Monitor
# Activity Log / Event Grid → a Storage Queue (opt-in via AGENT_BOM_AZURE_EVENT_QUEUE,
# read live, default off), the bounded queue consumer drains change events and
# re-evaluates only the affected resource's Azure CIS rules. These knobs bound a
# single consume pass so it always terminates: messages per receive, receive
# batches per pass, and per-message visibility timeout.
AZURE_EVENT_MAX_MESSAGES = _int("AGENT_BOM_AZURE_EVENT_MAX_MESSAGES", 10)
AZURE_EVENT_MAX_BATCHES = _int("AGENT_BOM_AZURE_EVENT_MAX_BATCHES", 10)
AZURE_EVENT_VISIBILITY_TIMEOUT = _int("AGENT_BOM_AZURE_EVENT_VISIBILITY_TIMEOUT", 120)
# Event-driven GCP posture ingestion. When an operator wires Cloud Asset
# Inventory feed / audit logs → a Pub/Sub subscription (opt-in via
# AGENT_BOM_GCP_EVENT_SUBSCRIPTION, read live, default off), the bounded Pub/Sub
# consumer drains change events and re-evaluates only the affected resource's GCP
# CIS rules. These knobs bound a single pull pass so it always terminates.
GCP_EVENT_MAX_MESSAGES = _int("AGENT_BOM_GCP_EVENT_MAX_MESSAGES", 10)
GCP_EVENT_MAX_BATCHES = _int("AGENT_BOM_GCP_EVENT_MAX_BATCHES", 10)
API_JOB_TTL_SECONDS = _int("AGENT_BOM_API_JOB_TTL", 3_600)
API_MAX_IN_MEMORY_JOBS = _int("AGENT_BOM_API_MAX_MEMORY_JOBS", 200)
API_MAX_JOB_PROGRESS_EVENTS = _int("AGENT_BOM_API_MAX_JOB_PROGRESS_EVENTS", 500)
API_MAX_ACTIVE_SCAN_JOBS_PER_TENANT = _int("AGENT_BOM_API_MAX_ACTIVE_SCAN_JOBS_PER_TENANT", API_MAX_CONCURRENT_JOBS)
API_MAX_RETAINED_JOBS_PER_TENANT = _int("AGENT_BOM_API_MAX_RETAINED_JOBS_PER_TENANT", 500)
API_MAX_FLEET_AGENTS_PER_TENANT = _int("AGENT_BOM_API_MAX_FLEET_AGENTS_PER_TENANT", 1_000)
API_MAX_SCHEDULES_PER_TENANT = _int("AGENT_BOM_API_MAX_SCHEDULES_PER_TENANT", 100)
API_ALLOW_UNAUTHENTICATED = _bool("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", False)
# Slowloris throughput floor (audit-5 PR-C): minimum sustained body
# bytes/second once a request body crosses the warmup threshold inside
# MaxBodySizeMiddleware. 0 disables the floor entirely (escape hatch
# for legitimate slow clients in restricted networks).
API_BODY_MIN_BPS = _int("AGENT_BOM_BODY_MIN_BPS", 256)


# ── PostgreSQL Control Plane Tuning ──────────────────────────────────────
# Used by api/postgres_store.py and shared Postgres-backed control-plane
# services such as the distributed rate limiter.
#
# Defaults target multi-replica self-hosted control planes rather than a
# single local developer process.

POSTGRES_POOL_MIN_SIZE = _int("AGENT_BOM_POSTGRES_POOL_MIN_SIZE", 5)
POSTGRES_POOL_MAX_SIZE = _int("AGENT_BOM_POSTGRES_POOL_MAX_SIZE", 20)
POSTGRES_CONNECT_TIMEOUT_SECONDS = _int("AGENT_BOM_POSTGRES_CONNECT_TIMEOUT_SECONDS", 5)
POSTGRES_STATEMENT_TIMEOUT_MS = _int("AGENT_BOM_POSTGRES_STATEMENT_TIMEOUT_MS", 15_000)
POSTGRES_GRAPH_SEARCH_TIMEOUT_MS = _int("AGENT_BOM_POSTGRES_GRAPH_SEARCH_TIMEOUT_MS", 3_000)


# ── Rate-limit fingerprint key rotation policy ──────────────────────────
# Operators rotate AGENT_BOM_RATE_LIMIT_KEY periodically and record the
# rotation timestamp in AGENT_BOM_RATE_LIMIT_KEY_LAST_ROTATED (ISO-8601
# with timezone). The control plane warns when the configured key age
# approaches the rotation interval and surfaces the status via
# /v1/auth/policy so dashboards and runbooks can act on it.

RATE_LIMIT_KEY_ROTATION_DAYS = _int("AGENT_BOM_RATE_LIMIT_KEY_ROTATION_DAYS", 30)
RATE_LIMIT_KEY_MAX_AGE_DAYS = _int("AGENT_BOM_RATE_LIMIT_KEY_MAX_AGE_DAYS", 90)
RATE_LIMIT_KEY_LAST_ROTATED = (os.environ.get("AGENT_BOM_RATE_LIMIT_KEY_LAST_ROTATED") or "").strip()


# ── Runtime → graph incident feedback ────────────────────────────────────
# The feedback direction of the agentic moat: the runtime ProtectionEngine
# appends observed incidents (credential reach, lateral movement, kill-switch)
# to a durable JSONL sink at this path; the next scan's graph builder ingests
# them so the graph reflects OBSERVED behavior, not just static reachability.
# Default-off — empty means no sink and no projection (current behavior). The
# value is re-read dynamically by agent_bom.runtime.incident_feedback so it can
# be set per-process; this declaration is the canonical default.
RUNTIME_FEEDBACK_PATH = _str("AGENT_BOM_RUNTIME_FEEDBACK_PATH", "")


# ── Agent-to-Agent (A2A) auth posture ────────────────────────────────────
# Governance thresholds for the A2A auth posture evaluator
# (agent_bom.a2a_auth_posture). agent-bom does not broker A2A auth; it scans
# discovered agents + gateway/proxy policies + delegation chains and flags
# weak inter-agent authentication as findings.
#
# A2A_AUTH_MAX_DELEGATION_DEPTH: delegation chains deeper than this are flagged
#   as over-broad/unbounded transitive delegation.
# A2A_AUTH_MAX_BOUND_AGENTS: a policy that binds more than this many agents (and
#   is therefore close to wildcard) is flagged as over-broad delegation scope.
# A2A_AUTH_SHARED_TOKEN_MIN_AGENTS: an opaque token mapped to at least this many
#   distinct agents is treated as a shared/long-lived credential.
# A2A_AUTH_REQUIRE_SIGNED_TOKENS: when true, delegation crossing a trust
#   boundary without a verifiable (signed/JWKS) actor token is flagged.

A2A_AUTH_MAX_DELEGATION_DEPTH = _int("AGENT_BOM_A2A_AUTH_MAX_DELEGATION_DEPTH", 4)
A2A_AUTH_MAX_BOUND_AGENTS = _int("AGENT_BOM_A2A_AUTH_MAX_BOUND_AGENTS", 10)
A2A_AUTH_SHARED_TOKEN_MIN_AGENTS = _int("AGENT_BOM_A2A_AUTH_SHARED_TOKEN_MIN_AGENTS", 2)
A2A_AUTH_REQUIRE_SIGNED_TOKENS = _bool("AGENT_BOM_A2A_AUTH_REQUIRE_SIGNED_TOKENS", True)


# ── MCP / agent→MCP auth posture ──────────────────────────────────────────
# Governance thresholds for the MCP server auth posture evaluator
# (agent_bom.mcp_auth_posture). This is the complement of the A2A evaluator:
# A2A covers inter-AGENT auth, this covers MCP SERVER auth + the agent→MCP edge
# per the MCP authorization spec (OAuth 2.1 for remote MCP servers, 2025).
# agent-bom does not broker MCP auth; it scans discovered MCP servers, their
# transports/config, and proxy bound_agents policies and flags weak or missing
# authentication as findings. Reference-only — never emits secret values.
#
# MCP_AUTH_FLAG_LOCAL_STDIO: when true, also flag local stdio servers that ship
#   static credentials (lower risk than network transports; off by default so
#   the default run focuses on the high-risk network surface).
# MCP_AUTH_REQUIRE_TLS: when true, remote MCP reached over plaintext http://
#   (no TLS) is flagged as weak transport security.
# MCP_AUTH_REQUIRE_NETWORK_AUTH: when true, a network-reachable MCP server with
#   no auth required is flagged as an unauthenticated server.
# MCP_AUTH_STATIC_CRED_ALLOWLIST: comma-separated env-var substrings whose
#   presence is treated as acceptable static credentials (e.g. a documented
#   break-glass key), suppressing the over-broad-static-credential finding.

MCP_AUTH_FLAG_LOCAL_STDIO = _bool("AGENT_BOM_MCP_AUTH_FLAG_LOCAL_STDIO", False)
MCP_AUTH_REQUIRE_TLS = _bool("AGENT_BOM_MCP_AUTH_REQUIRE_TLS", True)
MCP_AUTH_REQUIRE_NETWORK_AUTH = _bool("AGENT_BOM_MCP_AUTH_REQUIRE_NETWORK_AUTH", True)
MCP_AUTH_STATIC_CRED_ALLOWLIST = [
    item.strip().lower() for item in _str("AGENT_BOM_MCP_AUTH_STATIC_CRED_ALLOWLIST", "").split(",") if item.strip()
]


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
# Process-wide ceiling across all MCP callers, enforced in addition to the
# per-caller window. Backstops a flood that spreads across many distinct (or
# unverified per-connection) caller identities. Defaults to a generous multiple
# of the per-caller budget so it only trips genuine aggregate abuse.
MCP_GLOBAL_RATE_LIMIT = _int("AGENT_BOM_MCP_GLOBAL_RATE_LIMIT", MCP_CALLER_RATE_LIMIT * 20)
MCP_GLOBAL_WINDOW_SECONDS = _float("AGENT_BOM_MCP_GLOBAL_WINDOW_SECONDS", MCP_CALLER_WINDOW_SECONDS)
MCP_MAX_REQUEST_TRACES = _int("AGENT_BOM_MCP_MAX_REQUEST_TRACES", 256)


# ── Shield async bridge limits ───────────────────────────────────────────
# The synchronous Shield SDK can be called from inside a running event loop.
# Use a small shared pool for that bridge instead of spawning a fresh unbounded
# executor per call.

SHIELD_ASYNC_BRIDGE_MAX_WORKERS = _int("AGENT_BOM_SHIELD_ASYNC_BRIDGE_MAX_WORKERS", 4)


# ── Public-repo clone-and-scan bounds ────────────────────────────────────
# Cloning untrusted public repositories by URL is bounded to keep the
# operation safe and predictable: shallow single-branch clones only, with a
# wall-clock timeout, a total on-disk size cap, and a file-count cap. The scan
# itself is static (no repo code is ever executed), so these bounds guard
# against resource exhaustion (huge repos / clone bombs), not code execution.

# Max wall-clock seconds for the `git clone` step before it is aborted.
REPO_SCAN_CLONE_TIMEOUT_SECONDS = _float("AGENT_BOM_REPO_SCAN_CLONE_TIMEOUT_SECONDS", 120.0)
# Max total on-disk size (bytes) of the cloned working tree. Default 1 GiB.
REPO_SCAN_MAX_SIZE_BYTES = _int("AGENT_BOM_REPO_SCAN_MAX_SIZE_BYTES", 1024 * 1024 * 1024)
# Max number of files in the cloned working tree.
REPO_SCAN_MAX_FILES = _int("AGENT_BOM_REPO_SCAN_MAX_FILES", 100_000)


# ── Cloud audit-trail behavioral ingestion (opt-in, read-only) ───────────
# agent-bom can read the security-relevant slice of each cloud's native audit
# trail (AWS CloudTrail / Azure Activity Log / GCP Cloud Audit Logs) to derive
# behavioral graph edges (who *did* reach what). It is NOT a log/observability
# platform: raw log lines are never stored — only aggregated edges. The reader
# is disabled unless explicitly opted in, and the lookback window + event count
# are bounded so a scan never pulls an unbounded log volume. It needs NO new IAM
# role: it reuses the SAME existing read-only connect role (AWS SecurityAudit,
# Azure Reader/Security Reader, GCP roles/viewer). On AWS cloudtrail:LookupEvents
# is already in the AWS-managed SecurityAudit policy, so enabling it adds zero new
# permission; on Azure/GCP the reads sit inside the existing Reader/viewer grants
# in standard setups.

# Master opt-in. When False (default), audit-trail ingestion is a clean no-op.
# Reuses the existing read-only connect role — no new IAM role, and (in standard
# setups) no new permission.
AUDIT_TRAIL_ENABLED = _bool("AGENT_BOM_AUDIT_TRAIL", False)
# Lookback window (hours) for audit events; the reader clamps to two weeks.
AUDIT_TRAIL_LOOKBACK_HOURS = _int("AGENT_BOM_AUDIT_TRAIL_LOOKBACK_HOURS", 24)
# Per-provider event cap; the reader clamps to a hard ceiling and warns when hit.
AUDIT_TRAIL_MAX_EVENTS = _int("AGENT_BOM_AUDIT_TRAIL_MAX_EVENTS", 2000)
