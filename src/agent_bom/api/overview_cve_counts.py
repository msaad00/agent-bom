"""CVE occurrence counts shared by current scan and pushed-evidence folds."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from agent_bom.advisory_ids import all_cve_identifiers, derive_cve_from_advisory_id
from agent_bom.core.severity import empty_severity_histogram, severity_display_bucket
from agent_bom.finding_scope import finding_class_for_row


def empty_cve_counts() -> dict[str, int]:
    return {**empty_severity_histogram(), "kev": 0}


def add_cve_finding(counts: dict[str, int], row: Mapping[str, Any]) -> None:
    """Fold an already current, open occurrence only when it carries a CVE.

    An alias identifies the same advisory occurrence, not another finding.
    Explicit code/configuration findings do not become CVEs merely by naming one.
    Lifecycle, tenant, time-window and occurrence deduplication belong to the
    current-evidence readers that feed this fold.
    """
    if finding_class_for_row(row) != "vulnerability":
        return
    finding_type = str(row.get("finding_type") or "").upper()
    if finding_type and finding_type not in {"CVE", "VULNERABILITY"}:
        return
    advisory_id = str(row.get("cve_id") or row.get("vulnerability_id") or "")
    aliases = row.get("aliases")
    identifiers = all_cve_identifiers(advisory_id, aliases if isinstance(aliases, list) else [])
    if not any(derive_cve_from_advisory_id(value) for value in identifiers):
        return
    counts[severity_display_bucket(str(row.get("severity") or ""))] += 1
    counts["kev"] += int(bool(row.get("is_kev") or row.get("cisa_kev")))


def compose_cve_domain(
    scan: Mapping[str, int],
    hub: Mapping[str, int],
    *,
    scan_complete: bool,
    hub_status: str,
    packages: int,
    graph_href: Callable[[dict[str, int]], str],
) -> dict[str, Any]:
    """Expose occurrence counts and lower-bound metadata without inventing zeroes."""
    severity = {band: scan.get(band, 0) + hub.get(band, 0) for band in empty_severity_histogram()}
    metric = sum(severity.values())
    exact = scan_complete and hub_status == "complete"
    evidence_status = hub_status if hub_status != "complete" else ("complete" if exact else "partial")
    status = "critical" if severity["critical"] else ("warn" if severity["high"] else "ok")
    if not metric:
        status = "idle" if exact else "unknown"
    return {
        "label": "Vuln / SCA",
        "href": "/findings?issue=vulnerability",
        "graph_href": graph_href(severity),
        "metric": metric,
        "metric_label": "open CVE findings",
        "count_exact": exact,
        "evidence_status": evidence_status,
        "status": status,
        "detail": {
            "critical": severity["critical"],
            "high": severity["high"],
            "kev": scan.get("kev", 0) + hub.get("kev", 0),
            "packages": packages,
            "severity": severity,
        },
    }
