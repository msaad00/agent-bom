"""Scanner risk helpers.

Risk parsing and severity derivation live here so the main scanner module
does not own CVSS parsing, OSV severity interpretation, and related helpers.
"""

from __future__ import annotations

import logging
import math
from typing import Any, Optional

from cvss import CVSS4

from agent_bom.models import Severity

_logger = logging.getLogger(__name__)

_OSV_MEDIUM_FALLBACK_PREFIXES = ("OSV-", "PYSEC-", "RUSTSEC-", "GO-", "MAL-", "GSD-")
_DISTRO_MEDIUM_FALLBACK_PREFIXES = ("DEBIAN-CVE-",)
_SEVERITY_LABELS = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "IMPORTANT": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "MINOR": Severity.LOW,
    "NEGLIGIBLE": Severity.LOW,
    "UNIMPORTANT": Severity.LOW,
    "NONE": Severity.NONE,
}


def severity_from_label(raw: Any) -> Severity:
    """Normalize scanner/vendor severity labels without inflating unknown data."""
    if raw is None:
        return Severity.UNKNOWN
    normalized = str(raw).strip().replace("-", "_").replace(" ", "_").upper()
    return _SEVERITY_LABELS.get(normalized, Severity.UNKNOWN)


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


def cvss_to_severity(score: Optional[float]) -> Severity:
    if score is None:
        return Severity.UNKNOWN
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.NONE


# CVSS 3.1 Base Score metric weights.
# Reference: FIRST CVSS v3.1 Specification, Section 7.4 — Metric Values
# https://www.first.org/cvss/v3.1/specification-document#7-4-Metric-Values
_CVSS3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_CVSS3_AC = {"L": 0.77, "H": 0.44}
_CVSS3_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_CVSS3_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_CVSS3_UI = {"N": 0.85, "R": 0.62}
_CVSS3_CIA = {"N": 0.00, "L": 0.22, "H": 0.56}


def _parse_cvss4_vector(vector: str) -> Optional[float]:
    """Score CVSS 4.0 with its macrovector algorithm, not v3-style weights."""
    try:
        return float(CVSS4(vector).scores()[0])
    except Exception as exc:  # noqa: BLE001
        _logger.debug("CVSS 4.0 vector parse failed for %r: %s", vector, exc)
        return None


def parse_cvss_vector(vector: str) -> Optional[float]:
    """Compute CVSS base score from a vector string (v3.x and v4.0)."""
    try:
        if vector.startswith("CVSS:4"):
            return _parse_cvss4_vector(vector)
        if not vector.startswith("CVSS:3"):
            return None

        parts = vector.split("/")[1:]
        metrics = dict(p.split(":") for p in parts)

        av = _CVSS3_AV.get(metrics.get("AV", ""), None)
        ac = _CVSS3_AC.get(metrics.get("AC", ""), None)
        scope = metrics.get("S", "U")
        pr_map = _CVSS3_PR_C if scope == "C" else _CVSS3_PR_U
        pr = pr_map.get(metrics.get("PR", ""), None)
        ui = _CVSS3_UI.get(metrics.get("UI", ""), None)
        c = _CVSS3_CIA.get(metrics.get("C", ""), None)
        i = _CVSS3_CIA.get(metrics.get("I", ""), None)
        a = _CVSS3_CIA.get(metrics.get("A", ""), None)

        if any(value is None for value in (av, ac, pr, ui, c, i, a)):
            return None

        av, ac, pr, ui = float(av), float(ac), float(pr), float(ui)  # type: ignore[arg-type]
        c, i, a = float(c), float(i), float(a)  # type: ignore[arg-type]

        isc_base = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
        if scope == "C":
            isc = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)
        else:
            isc = 6.42 * isc_base

        if isc <= 0:
            return 0.0

        exploitability = 8.22 * av * ac * pr * ui
        raw = min(1.08 * (isc + exploitability), 10.0) if scope == "C" else min(isc + exploitability, 10.0)
        return math.ceil(raw * 10) / 10.0
    except Exception as exc:  # noqa: BLE001
        _logger.debug("CVSS vector parse failed for %r: %s", vector, exc)
        return None


def _normalize_cvss_score(value: Any) -> Optional[float]:
    """Extract a 0-10 CVSS score from common OSV/vendor record shapes."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        score = float(value)
        return score if 0.0 <= score <= 10.0 else None
    if isinstance(value, str):
        try:
            score = float(value)
            return score if 0.0 <= score <= 10.0 else None
        except ValueError:
            computed = parse_cvss_vector(value)
            return computed if computed is not None and 0.0 <= computed <= 10.0 else None
    if isinstance(value, dict):
        for key in ("score", "baseScore", "base_score", "cvss", "vector", "vectorString"):
            nested_score = _normalize_cvss_score(value.get(key))
            if nested_score is not None:
                return nested_score
    if isinstance(value, list):
        scores = [_normalize_cvss_score(item) for item in value]
        valid_scores = [score for score in scores if score is not None]
        if valid_scores:
            return max(valid_scores)
    return None


def _first_vendor_severity(*blocks: Any) -> tuple[Severity, Optional[str]]:
    for source, block in blocks:
        if not isinstance(block, dict):
            continue
        severity = severity_from_label(block.get("severity"))
        if severity != Severity.UNKNOWN:
            return severity, source
    return Severity.UNKNOWN, None


def _osv_severity_array_cvss(vuln_data: dict) -> tuple[Optional[float], Optional[str]]:
    """Return the score and matching vector from an OSV ``severity`` array.

    The last parseable CVSS v3/v4 entry wins (OSV lists v4 after v3), and the
    vector is only ever the one that produced the returned score.
    """
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    for sev in vuln_data.get("severity", []):
        if sev.get("type") in ("CVSS_V3", "CVSS_V3_1", "CVSS_V4"):
            raw = sev.get("score")
            score = _normalize_cvss_score(raw)
            if score is not None:
                cvss_score = score
                cvss_vector = raw.strip() if isinstance(raw, str) and raw.strip().upper().startswith("CVSS:") else None
    return cvss_score, cvss_vector


def osv_cvss_vector(vuln_data: dict) -> Optional[str]:
    """CVSS vector behind the score :func:`parse_osv_severity` reports, if any."""
    return _osv_severity_array_cvss(vuln_data)[1]


def parse_osv_severity(vuln_data: dict) -> tuple[Severity, Optional[float], Optional[str]]:
    """Extract severity, CVSS score, and severity source from OSV data."""
    severity = Severity.UNKNOWN
    severity_source: Optional[str] = None

    cvss_score, _vector = _osv_severity_array_cvss(vuln_data)

    db_specific = vuln_data.get("database_specific", {})
    severity, severity_source = _first_vendor_severity(("osv_database", db_specific))

    if cvss_score is None and isinstance(db_specific, dict):
        for key in ("cvss", "cvss_score", "cvss_v3", "severity_vectors"):
            score = _normalize_cvss_score(db_specific.get(key))
            if score is not None:
                cvss_score = score
                break

    if cvss_score is None:
        score = _normalize_cvss_score(vuln_data.get("severity_vectors"))
        if score is not None:
            cvss_score = score

    if cvss_score is None:
        for affected in vuln_data.get("affected", []):
            if not isinstance(affected, dict):
                continue
            for block_name in ("database_specific", "ecosystem_specific"):
                block = affected.get(block_name)
                if not isinstance(block, dict):
                    continue
                for key in ("cvss", "cvss_score", "cvss_v3", "severity_vectors"):
                    score = _normalize_cvss_score(block.get(key))
                    if score is not None:
                        cvss_score = score
                        break
                if cvss_score is not None:
                    break
            if cvss_score is not None:
                break

    if cvss_score is not None:
        severity = cvss_to_severity(cvss_score)
        severity_source = "cvss"

    if severity == Severity.UNKNOWN:
        eco_specific = vuln_data.get("ecosystem_specific", {})
        severity, severity_source = _first_vendor_severity(("osv_ecosystem", eco_specific))

    if severity == Severity.UNKNOWN:
        for affected in vuln_data.get("affected", []):
            if not isinstance(affected, dict):
                continue
            severity, severity_source = _first_vendor_severity(
                ("osv_affected_database", affected.get("database_specific")),
                ("osv_affected_ecosystem", affected.get("ecosystem_specific")),
            )
            if severity != Severity.UNKNOWN:
                break

    if severity == Severity.UNKNOWN:
        advisory_id = str(vuln_data.get("id", "")).upper()
        fallback, source = advisory_id_severity_fallback(advisory_id)
        if fallback != Severity.UNKNOWN:
            severity = fallback
            severity_source = source

    return severity, cvss_score, severity_source
