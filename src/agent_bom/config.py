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
