"""Scanner risk helpers.

Risk parsing and severity derivation live here so the main scanner module
does not own CVSS parsing, OSV severity interpretation, and related helpers.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional

from agent_bom.core.cvss import (
    cvss_to_severity as cvss_to_severity,
)
from agent_bom.core.cvss import (
    normalize_cvss_score as _normalize_cvss_score,
)
from agent_bom.core.cvss import parse_cvss4_vector as _parse_cvss4_vector  # noqa: F401 - compatibility export
from agent_bom.core.cvss import (
    parse_cvss_vector as parse_cvss_vector,
)
from agent_bom.core.severity import Severity, severity_from_label

_logger = logging.getLogger(__name__)

_OSV_MEDIUM_FALLBACK_PREFIXES = ("OSV-", "PYSEC-", "RUSTSEC-", "GO-", "MAL-", "GSD-")
_DISTRO_MEDIUM_FALLBACK_PREFIXES = ("DEBIAN-CVE-",)


def advisory_id_severity_fallback(advisory_id: str) -> tuple[Severity, Optional[str]]:
    """Return conservative triage severity for advisory-only IDs.

    Some advisory ecosystems publish IDs before CVSS/vendor severity arrives.
    These should not stay invisible as ``unknown`` findings in operator views,
    but only known advisory namespaces get this fallback. Arbitrary missing
    severity still remains ``UNKNOWN``.
    """
    normalized = advisory_id.upper()
    if normalized.startswith("GHSA-"):
        return Severity.MEDIUM, "ghsa_heuristic"
    if normalized.startswith(_OSV_MEDIUM_FALLBACK_PREFIXES):
        return Severity.MEDIUM, "osv_heuristic"
    if normalized.startswith(_DISTRO_MEDIUM_FALLBACK_PREFIXES):
        return Severity.MEDIUM, "distro_advisory_heuristic"
    return Severity.UNKNOWN, None


def _first_vendor_severity(*blocks: Any) -> tuple[Severity, Optional[str]]:
    for source, block in blocks:
        if not isinstance(block, dict):
            continue
        severity = severity_from_label(block.get("severity"))
        if severity != Severity.UNKNOWN:
            return severity, source
    return Severity.UNKNOWN, None


_CVSS_KEYS = ("cvss", "cvss_score", "cvss_v3", "severity_vectors")
# OSV ``severity[].type`` tiers, in basis precedence order. ``CVSS_V3_1`` is not
# an OSV schema type but appears in vendor feeds, so it joins the v3 tier.
_OSV_CVSS_TYPE_TIERS: tuple[tuple[str, ...], ...] = (("CVSS_V3", "CVSS_V3_1"), ("CVSS_V4",), ("CVSS_V2",))


@dataclass(frozen=True)
class OsvSeverityBasis:
    """The one severity basis an OSV advisory record yields, online or offline."""

    severity: Severity
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    severity_source: Optional[str]


def _vector_tier(vector: str) -> int:
    upper = vector.upper()
    if upper.startswith("CVSS:3"):
        return 0
    if upper.startswith("CVSS:4"):
        return 1
    return 2


def _as_vector(raw: Any) -> Optional[str]:
    return raw.strip() if isinstance(raw, str) and raw.strip().upper().startswith("CVSS:") else None


def _cvss_candidate(value: Any) -> tuple[Optional[float], Optional[str]]:
    """Return ``(score, vector)`` from a vendor CVSS field, applying the v3 → v4 tiering.

    Lists are ranked by vector version (v3.x first) instead of taking the
    maximum, which let a v4.0 score silently outrank the v3.1 basis.
    """
    if value is None:
        return None, None
    if isinstance(value, list):
        ranked = sorted(
            (item for item in value if item is not None),
            key=lambda item: _vector_tier(item) if isinstance(item, str) and _as_vector(item) else 3,
        )
        for item in ranked:
            score, vector = _cvss_candidate(item)
            if score is not None:
                return score, vector
        return None, None
    if isinstance(value, dict):
        for key in ("score", "baseScore", "base_score", "cvss", "vector", "vectorString"):
            score, vector = _cvss_candidate(value.get(key))
            if score is not None:
                if vector is None:
                    vector = _as_vector(value.get("vector")) or _as_vector(value.get("vectorString"))
                return score, vector
        return None, None
    score = _normalize_cvss_score(value)
    return (score, _as_vector(value)) if score is not None else (None, None)


def _osv_severity_array_cvss(vuln_data: dict) -> tuple[Optional[float], Optional[str]]:
    """Return the score and matching vector from an OSV ``severity`` array.

    Tiered by CVSS version — v3.x, then v4.0, then v2 — and first-listed within
    a tier. The vector is only ever the one that produced the returned score.
    """
    entries = [sev for sev in vuln_data.get("severity") or [] if isinstance(sev, dict)]
    for tier in _OSV_CVSS_TYPE_TIERS:
        for sev in entries:
            if sev.get("type") not in tier:
                continue
            raw = sev.get("score")
            score = _normalize_cvss_score(raw)
            if score is not None:
                return score, _as_vector(raw)
    return None, None


def osv_severity_basis(vuln_data: dict, *, advisory_id_fallback: bool = True) -> OsvSeverityBasis:
    """Derive severity from an OSV record with the single documented precedence.

    Used by the online OSV scan and the offline local-DB sync alike, so a CVE
    gets the same severity, score, vector, and source in both modes:

    1. CVSS base score from the OSV ``severity`` array: v3.x, then v4.0, then v2.
    2. Otherwise a CVSS score/vector in top-level ``database_specific``, then
       top-level ``severity_vectors``, then ``affected[]`` vendor blocks
       (lists ranked v3.x before v4.0).
    3. With a CVSS score, severity is the FIRST.org qualitative rating band of that score
       (``severity_source="cvss"``); the vector reports the scored version.
    4. Otherwise the advisory's own label: ``database_specific`` (``osv_database``),
       ``ecosystem_specific`` (``osv_ecosystem``), then ``affected[]`` blocks.
    5. Otherwise a conservative advisory-namespace fallback (e.g. GHSA → medium),
       which the offline DB applies at read time instead of persisting.
    """
    cvss_score, cvss_vector = _osv_severity_array_cvss(vuln_data)

    db_specific = vuln_data.get("database_specific")
    if cvss_score is None and isinstance(db_specific, dict):
        for key in _CVSS_KEYS:
            cvss_score, cvss_vector = _cvss_candidate(db_specific.get(key))
            if cvss_score is not None:
                break

    if cvss_score is None:
        cvss_score, cvss_vector = _cvss_candidate(vuln_data.get("severity_vectors"))

    if cvss_score is None:
        for affected in vuln_data.get("affected") or []:
            if not isinstance(affected, dict):
                continue
            for block_name in ("database_specific", "ecosystem_specific"):
                block = affected.get(block_name)
                if not isinstance(block, dict):
                    continue
                for key in _CVSS_KEYS:
                    cvss_score, cvss_vector = _cvss_candidate(block.get(key))
                    if cvss_score is not None:
                        break
                if cvss_score is not None:
                    break
            if cvss_score is not None:
                break

    if cvss_score is not None:
        return OsvSeverityBasis(cvss_to_severity(cvss_score), cvss_score, cvss_vector, "cvss")

    severity, severity_source = _first_vendor_severity(
        ("osv_database", db_specific),
        ("osv_ecosystem", vuln_data.get("ecosystem_specific")),
    )
    if severity == Severity.UNKNOWN:
        for affected in vuln_data.get("affected") or []:
            if not isinstance(affected, dict):
                continue
            severity, severity_source = _first_vendor_severity(
                ("osv_affected_database", affected.get("database_specific")),
                ("osv_affected_ecosystem", affected.get("ecosystem_specific")),
            )
            if severity != Severity.UNKNOWN:
                break

    if severity == Severity.UNKNOWN and advisory_id_fallback:
        severity, severity_source = advisory_id_severity_fallback(str(vuln_data.get("id", "")).upper())

    return OsvSeverityBasis(severity, None, None, severity_source)


def osv_cvss_vector(vuln_data: dict) -> Optional[str]:
    """CVSS vector behind the score :func:`parse_osv_severity` reports, if any."""
    return osv_severity_basis(vuln_data).cvss_vector


def parse_osv_severity(vuln_data: dict) -> tuple[Severity, Optional[float], Optional[str]]:
    """Extract severity, CVSS score, and severity source from OSV data."""
    basis = osv_severity_basis(vuln_data)
    return basis.severity, basis.cvss_score, basis.severity_source
