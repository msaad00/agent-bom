"""Unified severity system — single source of truth for the entire codebase.

All severity mappings (OCSF, syslog, rank, risk score, badge) are defined
here and imported everywhere else.  No module should define its own.
"""

from __future__ import annotations

from enum import Enum, IntEnum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"
    UNKNOWN = "unknown"  # No CVSS/severity data available — not the same as NONE (no vulnerability)


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
    "INFO": 1,
    "NONE": 0,
    "UNKNOWN": -1,
}

SEVERITY_THRESHOLD_LABELS: tuple[str, ...] = ("critical", "high", "medium", "low")
SEVERITY_BUCKETS_WORST_FIRST: tuple[str, ...] = ("critical", "high", "medium", "low", "info", "none")
SEVERITY_BUCKETS_ASPM: tuple[str, ...] = ("critical", "high", "medium", "low", "info", "unknown")

# ── Display histogram: the four rated bands plus one honest home for the rest ─
# ``unrated`` is where a finding goes when its severity is empty, ``unknown``,
# ``none``, ``info``, or a vendor label the histogram does not recognize. It
# exists so ``sum(histogram.values()) == total`` always holds: a severity the
# UI cannot name is reported, never dropped. Every surface that paints a
# severity strip (overview tiles, posture counts, the demo estate summary)
# derives its buckets here so two panes on one screen cannot disagree.
UNRATED_SEVERITY_BUCKET = "unrated"
SEVERITY_DISPLAY_BUCKETS: tuple[str, ...] = (*SEVERITY_THRESHOLD_LABELS, UNRATED_SEVERITY_BUCKET)

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


# Vendor labels that name a canonical band under another word: GHSA and Red
# Hat publish MODERATE, Red Hat publishes Important.
_SEVERITY_ALIASES: dict[str, str] = {
    "informational": "info",
    "moderate": "medium",
    "important": "high",
    "minor": "low",
    "negligible": "low",
    "unimportant": "low",
}


def severity_rank(sev: str) -> int:
    """Return numeric rank for a severity string. Higher = worse."""
    return SEVERITY_RANK[normalize_severity(sev)]


def normalize_severity(sev: str | None) -> str:
    """Return the canonical lowercase severity label."""
    normalized = (sev or "").strip().lower()
    normalized = _SEVERITY_ALIASES.get(normalized, normalized)
    return normalized if normalized in SEVERITY_RANK else "unknown"


def severity_display_bucket(sev: str | None) -> str:
    """Return the display histogram bucket for ``sev`` — a rated band or ``unrated``.

    The single choke point for severity histograms, so a finding is counted in
    one and only one bucket and no unrecognized severity is silently dropped.
    """
    key = normalize_severity(sev)
    return key if key in SEVERITY_THRESHOLD_LABELS else UNRATED_SEVERITY_BUCKET


def empty_severity_histogram() -> dict[str, int]:
    """Return a zeroed histogram carrying every display bucket, including ``unrated``."""
    return {key: 0 for key in SEVERITY_DISPLAY_BUCKETS}


def severity_band_rank(sev: str | None) -> int:
    """Worst-first position among the rated bands: critical=0 … low=3.

    Everything the display histogram calls ``unrated`` (info, none, unknown,
    empty, unrecognized) shares the rank after ``low``, so it sorts last and
    ties among itself.
    """
    bucket = severity_display_bucket(sev)
    if bucket == UNRATED_SEVERITY_BUCKET:
        return len(SEVERITY_THRESHOLD_LABELS)
    return SEVERITY_THRESHOLD_LABELS.index(bucket)


# ── Remediation priority (1 = fix first … 4 = advisory) ──────────────────
# Critical and high share the top slot; anything unrated defaults to the
# low-severity slot rather than being promoted or dropped.
SEVERITY_FIX_PRIORITY: dict[str, int] = {
    "critical": 1,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}
_DEFAULT_FIX_PRIORITY = 3


def severity_fix_priority(sev: str | None) -> int:
    """Return the remediation priority for ``sev`` (1 = fix first, 4 = advisory)."""
    return SEVERITY_FIX_PRIORITY.get(normalize_severity(sev), _DEFAULT_FIX_PRIORITY)


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
    return SEVERITY_TO_OCSF.get(normalize_severity(sev), OCSFSeverity.UNKNOWN)


def ocsf_to_severity(severity_id: int) -> str:
    """Convert OCSF severity_id to lowercase severity string."""
    return OCSF_SEVERITY_NAMES.get(severity_id, "Unknown").lower()


def severity_from_label(raw: Any) -> Severity:
    """Normalize vendor labels into the scanner's supported severity enum."""
    label = normalize_severity(str(raw) if raw is not None else None)
    return Severity(label) if label != "info" else Severity.UNKNOWN


def evaluated_control_status(sev_breakdown: dict[str, int]) -> str:
    """Classify mapped findings by severity; unrated evidence never implies pass."""
    if sev_breakdown.get("critical", 0) > 0 or sev_breakdown.get("high", 0) > 0:
        return "fail"
    if sev_breakdown.get("medium", 0) > 0 or sev_breakdown.get("low", 0) > 0:
        return "warning"
    return "not_evaluated"
