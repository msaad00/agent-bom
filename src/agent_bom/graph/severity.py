"""Unified severity system — single source of truth for the entire codebase.

All severity mappings (OCSF, syslog, rank, risk score, badge) are defined
here and imported everywhere else.  No module should define its own.
"""

from __future__ import annotations

from enum import IntEnum


class OCSFSeverity(IntEnum):
    """OCSF v1.1.0 severity_id values."""

    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


# ── String → OCSF ────────────────────────────────────────────────────────

SEVERITY_TO_OCSF: dict[str, int] = {
    "critical": OCSFSeverity.CRITICAL,
    "high": OCSFSeverity.HIGH,
    "medium": OCSFSeverity.MEDIUM,
    "low": OCSFSeverity.LOW,
    "info": OCSFSeverity.INFORMATIONAL,
    "informational": OCSFSeverity.INFORMATIONAL,
    "none": OCSFSeverity.UNKNOWN,
    "unknown": OCSFSeverity.UNKNOWN,
}

# ── OCSF → display name ──────────────────────────────────────────────────

OCSF_SEVERITY_NAMES: dict[int, str] = {
    OCSFSeverity.CRITICAL: "Critical",
    OCSFSeverity.HIGH: "High",
    OCSFSeverity.MEDIUM: "Medium",
    OCSFSeverity.LOW: "Low",
    OCSFSeverity.INFORMATIONAL: "Informational",
    OCSFSeverity.UNKNOWN: "Unknown",
}

# ── Rank (0-5, higher = worse) ───────────────────────────────────────────

SEVERITY_RANK: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "informational": 1,
    "none": 0,
    "unknown": 0,
}

# Policy/threshold comparisons keep UNKNOWN below NONE, matching FIRST/CVSS
# policy semantics. Display/risk ranking can still treat both as zero-impact.
SEVERITY_POLICY_ORDER: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "NONE": 0,
    "UNKNOWN": -1,
}

SEVERITY_THRESHOLD_LABELS: tuple[str, ...] = ("critical", "high", "medium", "low")
SEVERITY_BUCKETS_WORST_FIRST: tuple[str, ...] = ("critical", "high", "medium", "low", "info", "none")
SEVERITY_BUCKETS_ASPM: tuple[str, ...] = ("critical", "high", "medium", "low", "info", "unknown")

# ── Risk score contribution ──────────────────────────────────────────────

SEVERITY_RISK_SCORE: dict[str, float] = {
    "critical": 8.0,
    "high": 6.0,
    "medium": 4.0,
    "low": 2.0,
    "info": 0.5,
    "informational": 0.5,
    "none": 0.0,
    "unknown": 0.0,
}

# ── Badge (compact CLI display) ──────────────────────────────────────────

SEVERITY_BADGE: dict[str, str] = {
    "critical": "R2",
    "high": "R1",
    "medium": "M",
    "low": "L",
    "info": "I",
    "unknown": "?",
}

# ── OCSF → RFC 5424 syslog ──────────────────────────────────────────────

OCSF_TO_SYSLOG: dict[int, int] = {
    OCSFSeverity.CRITICAL: 2,
    OCSFSeverity.HIGH: 3,
    OCSFSeverity.MEDIUM: 4,
    OCSFSeverity.LOW: 5,
    OCSFSeverity.INFORMATIONAL: 6,
    OCSFSeverity.UNKNOWN: 6,
}

# ── Helpers ──────────────────────────────────────────────────────────────


def severity_rank(sev: str) -> int:
    """Return numeric rank for a severity string. Higher = worse."""
    return SEVERITY_RANK.get(sev.lower() if sev else "", 0)


def normalize_severity(sev: str | None) -> str:
    """Return the canonical lowercase severity label."""
    normalized = (sev or "").strip().lower()
    if normalized == "informational":
        return "info"
    return normalized if normalized in SEVERITY_RANK else "unknown"


def severity_policy_rank(sev: str | None) -> int:
    """Return policy comparison rank where UNKNOWN is below NONE."""
    return SEVERITY_POLICY_ORDER.get(normalize_severity(sev).upper(), SEVERITY_POLICY_ORDER["UNKNOWN"])


def severity_at_or_above(candidate: str | None, threshold: str | None) -> bool:
    """Return true when ``candidate`` meets or exceeds ``threshold``."""
    return severity_policy_rank(candidate) >= severity_policy_rank(threshold)


def severity_worst_first_rank(sev: str | None) -> int:
    """Ascending sort rank where more severe findings sort earlier."""
    return -severity_policy_rank(sev)


def severity_to_ocsf(sev: str) -> int:
    """Convert severity string to OCSF severity_id."""
    return SEVERITY_TO_OCSF.get(sev.lower() if sev else "", OCSFSeverity.UNKNOWN)


def ocsf_to_severity(severity_id: int) -> str:
    """Convert OCSF severity_id to lowercase severity string."""
    return OCSF_SEVERITY_NAMES.get(severity_id, "Unknown").lower()
