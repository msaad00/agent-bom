"""Scanner risk helpers.

Risk parsing and severity derivation live here so the main scanner module
does not own CVSS parsing, OSV severity interpretation, and related helpers.
"""

from __future__ import annotations

import logging
import math
from typing import Optional, cast

from agent_bom.models import Severity

_logger = logging.getLogger(__name__)


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
    """Extract an approximate base score from a CVSS 4.0 vector string."""
    try:
        parts = vector.split("/")[1:]
        metrics = dict(p.split(":") for p in parts)

        av = {"N": 1.0, "A": 0.75, "L": 0.55, "P": 0.20}.get(metrics.get("AV", ""), None)
        ac = {"L": 1.0, "H": 0.55}.get(metrics.get("AC", ""), None)
        attack_requirements = {"N": 1.0, "P": 0.60}.get(metrics.get("AT", ""), None)
        pr = {"N": 1.0, "L": 0.65, "H": 0.30}.get(metrics.get("PR", ""), None)
        ui = {"N": 1.0, "P": 0.70, "A": 0.55}.get(metrics.get("UI", ""), None)

        vc = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics.get("VC", ""), None)
        vi = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics.get("VI", ""), None)
        va = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics.get("VA", ""), None)

        required = (av, ac, attack_requirements, pr, ui, vc, vi, va)
        if any(value is None for value in required):
            return None

        av = float(cast(float, av))
        ac = float(cast(float, ac))
        attack_requirements = float(cast(float, attack_requirements))
        pr = float(cast(float, pr))
        ui = float(cast(float, ui))
        vc = float(cast(float, vc))
        vi = float(cast(float, vi))
        va = float(cast(float, va))

        sc = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics.get("SC", "N"), 0.0)
        si = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics.get("SI", "N"), 0.0)
        sa = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics.get("SA", "N"), 0.0)

        isc = 1.0 - (1.0 - vc) * (1.0 - vi) * (1.0 - va)
        isc_sub = 1.0 - (1.0 - sc) * (1.0 - si) * (1.0 - sa)
        impact = max(isc, isc + 0.25 * isc_sub)

        if impact <= 0:
            return 0.0

        exploitability = av * ac * attack_requirements * pr * ui
        raw = min(10.0, 1.1 * (6.42 * impact + 8.22 * exploitability * 0.6))
        return math.ceil(raw * 10) / 10.0
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


def parse_osv_severity(vuln_data: dict) -> tuple[Severity, Optional[float], Optional[str]]:
    """Extract severity, CVSS score, and severity source from OSV data."""
    cvss_score = None
    severity = Severity.UNKNOWN
    severity_source: Optional[str] = None

    for sev in vuln_data.get("severity", []):
        if sev.get("type") in ("CVSS_V3", "CVSS_V3_1", "CVSS_V4"):
            score_str = sev.get("score", "")
            try:
                parsed = float(score_str)
                if 0.0 <= parsed <= 10.0:
                    cvss_score = parsed
            except ValueError:
                computed = parse_cvss_vector(score_str)
                if computed is not None and 0.0 <= computed <= 10.0:
                    cvss_score = computed

    db_specific = vuln_data.get("database_specific", {})
    if "severity" in db_specific:
        sev_str = db_specific["severity"].upper()
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MODERATE": Severity.MEDIUM,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }
        resolved = severity_map.get(sev_str, Severity.UNKNOWN)
        if resolved != Severity.UNKNOWN:
            severity = resolved
            severity_source = "osv_database"

    if cvss_score is not None:
        severity = cvss_to_severity(cvss_score)
        severity_source = "cvss"

    if severity == Severity.UNKNOWN:
        eco_specific = vuln_data.get("ecosystem_specific", {})
        if isinstance(eco_specific, dict) and "severity" in eco_specific:
            sev_str = str(eco_specific["severity"]).upper()
            severity_map = {
                "CRITICAL": Severity.CRITICAL,
                "HIGH": Severity.HIGH,
                "MODERATE": Severity.MEDIUM,
                "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW,
            }
            resolved = severity_map.get(sev_str, severity)
            if resolved != Severity.UNKNOWN:
                severity = resolved
                severity_source = "osv_ecosystem"

    if severity == Severity.UNKNOWN and str(vuln_data.get("id", "")).startswith("GHSA-"):
        severity = Severity.MEDIUM
        severity_source = "ghsa_heuristic"

    return severity, cvss_score, severity_source
