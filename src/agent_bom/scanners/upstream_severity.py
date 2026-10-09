"""Give distro fix advisories the severity and intel of the CVEs they fix.

OSV publishes distro fix advisories (Debian DLA/DSA, Ubuntu USN, AlmaLinux
ALSA, Red Hat RHSA, ...) without a severity of their own; the record only links
the upstream CVEs it fixes. Left ``unknown``, such a finding trips the
fail-closed policy gate even when every upstream CVE is scored.

For each unknown-severity advisory with upstream CVEs, the severity becomes the
maximum of those CVEs (CVSS score first, then the advisory label), read from
records the scan already holds and then from the local vulnerability DB. EPSS
and KEV attach through the same upstream CVEs from the local DB. No network
request is made. An advisory whose upstream CVEs are all unscored stays
``unknown`` and keeps failing closed.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from agent_bom.advisory_ids import upstream_advisory_ids
from agent_bom.core.severity import severity_rank
from agent_bom.db import schema as db_schema
from agent_bom.exploitability import parse_cvss_vector_signals
from agent_bom.models import Package, Severity, Vulnerability
from agent_bom.scanners.advisory_merge import advisory_keys
from agent_bom.scanners.enrichment_apply import apply_epss_entry, apply_kev_entry
from agent_bom.scanners.risk import cvss_to_severity, parse_cvss_vector, severity_from_label
from agent_bom.vuln_compliance import tag_vulnerability

_logger = logging.getLogger(__name__)
_SQLITE_CHUNK = 400


@dataclass(frozen=True)
class _Score:
    cve_id: str
    severity: Severity
    cvss_score: float | None
    cvss_vector: str | None

    def rank(self) -> tuple[float, int]:
        """Higher CVSS score first, then the worse advisory label."""
        return (self.cvss_score if self.cvss_score is not None else -1.0, severity_rank(self.severity.value))


def _score(cve_id: str, label: object, cvss_score: float | None, cvss_vector: str | None) -> _Score | None:
    if cvss_score is None and isinstance(cvss_vector, str) and cvss_vector:
        cvss_score = parse_cvss_vector(cvss_vector)
    severity = cvss_to_severity(cvss_score) if cvss_score is not None else severity_from_label(label if isinstance(label, str) else None)
    if severity in (Severity.UNKNOWN, Severity.NONE):
        return None
    return _Score(cve_id, severity, cvss_score, cvss_vector or None)


def _upstream_cves(vuln: Vulnerability) -> list[str]:
    return [item for item in upstream_advisory_ids(vuln.upstream_ids) if item.upper().startswith("CVE-")]


def _scan_index(packages: Iterable[Package]) -> dict[str, _Score]:
    index: dict[str, _Score] = {}
    for pkg in packages:
        for vuln in pkg.vulnerabilities:
            for key in advisory_keys(vuln):
                if not key.upper().startswith("CVE-"):
                    continue
                score = _score(key, vuln.severity.value, vuln.cvss_score, vuln.cvss_vector)
                if score is not None and (key not in index or score.rank() > index[key].rank()):
                    index[key] = score
    return index


@dataclass
class _LocalIntel:
    scores: dict[str, _Score]
    epss: dict[str, dict]
    kev: dict[str, dict]


def _read_local_intel(db_path: Path, cve_ids: list[str]) -> _LocalIntel:
    intel = _LocalIntel({}, {}, {})
    if not cve_ids or not db_path.is_file():
        return intel
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        _logger.debug("Local vulnerability DB unavailable for upstream severity: %s", exc)
        return intel
    try:
        for offset in range(0, len(cve_ids), _SQLITE_CHUNK):
            chunk = cve_ids[offset : offset + _SQLITE_CHUNK]
            marks = ",".join("?" for _ in chunk)
            for cve_id, label, cvss_score, cvss_vector in conn.execute(
                f"SELECT id, severity, cvss_score, cvss_vector FROM vulns WHERE id IN ({marks})",  # nosec B608 -- generated placeholders only; values are bound.
                chunk,
            ):
                score = _score(cve_id, label, cvss_score, cvss_vector)
                if score is not None:
                    intel.scores[cve_id] = score
            for cve_id, probability, percentile in conn.execute(
                f"SELECT cve_id, probability, percentile FROM epss_scores WHERE cve_id IN ({marks})",  # nosec B608 -- generated placeholders only; values are bound.
                chunk,
            ):
                intel.epss[cve_id] = {"score": probability, "percentile": percentile}
            for cve_id, date_added, due_date in conn.execute(
                f"SELECT cve_id, date_added, due_date FROM kev_entries WHERE cve_id IN ({marks})",  # nosec B608 -- generated placeholders only; values are bound.
                chunk,
            ):
                intel.kev[cve_id] = {"date_added": date_added, "due_date": due_date}
    except sqlite3.Error as exc:
        _logger.debug("Local vulnerability DB read failed for upstream severity: %s", exc)
    finally:
        conn.close()
    return intel


def _apply_score(vuln: Vulnerability, pkg: Package, best: _Score) -> None:
    vuln.severity = best.severity
    vuln.cvss_score = best.cvss_score
    vuln.cvss_vector = best.cvss_vector
    vuln.severity_source = f"upstream_cve:{best.cve_id}"
    signals = parse_cvss_vector_signals(best.cvss_vector)
    vuln.attack_vector = signals.attack_vector
    vuln.attack_complexity = signals.attack_complexity
    vuln.privileges_required = signals.privileges_required
    vuln.user_interaction = signals.user_interaction
    vuln.network_exploitable = bool(signals.network_exploitable)
    vuln.compliance_tags = tag_vulnerability(vuln, pkg)


def resolve_upstream_advisory_severity(packages: list[Package], *, db_path: Path | None = None) -> int:
    """Resolve unknown advisory severities from upstream CVEs; return how many changed."""
    targets = [(pkg, vuln) for pkg in packages for vuln in pkg.vulnerabilities if _upstream_cves(vuln)]
    if not targets:
        return 0
    index = _scan_index(packages)
    wanted = sorted({cve for _, vuln in targets for cve in _upstream_cves(vuln)})
    local = _read_local_intel(db_path or db_schema.DB_PATH, wanted)
    resolved = 0
    for pkg, vuln in targets:
        cves = _upstream_cves(vuln)
        if vuln.epss_score is None:
            apply_epss_entry(vuln, cves, local.epss)
        if not vuln.is_kev:
            apply_kev_entry(vuln, cves, local.kev)
        if vuln.severity != Severity.UNKNOWN:
            continue
        # Sorted first so equal ranks resolve to the lowest CVE id on every run.
        candidates = [score for cve in sorted(cves) if (score := index.get(cve) or local.scores.get(cve)) is not None]
        if candidates:
            _apply_score(vuln, pkg, max(candidates, key=_Score.rank))
            resolved += 1
    return resolved
