"""CSV output for spreadsheet/SIEM ingestion and executive reporting.

One row per vulnerability finding with all enrichment data.
UTF-8 BOM included for Excel compatibility.
"""

from __future__ import annotations

import csv
import io

from agent_bom.compliance_utils import framework_qualified_finding_tags
from agent_bom.models import AIBOMReport, BlastRadius
from agent_bom.output.finding_views import cve_findings, evidence, package_ecosystem, package_name, package_version, severity_value

_COLUMNS = [
    "cve_id",
    "package",
    "version",
    "ecosystem",
    "severity",
    "cvss_score",
    "epss_score",
    "is_kev",
    "published_at",
    "modified_at",
    "fixed_version",
    "cwe_ids",
    "affected_agents",
    "affected_servers",
    "exposed_credentials",
    "summary",
    "severity_source",
    "epss_percentile",
    "kev_date_added",
    "kev_due_date",
    "compliance_tags",
]


def to_csv(report: AIBOMReport, blast_radii: list[BlastRadius] | None = None) -> str:
    """Convert an AIBOMReport to CSV string with UTF-8 BOM."""
    findings = cve_findings(report, blast_radii)

    buf = io.StringIO()
    # UTF-8 BOM for Excel auto-detection
    buf.write("\ufeff")

    writer = csv.DictWriter(buf, fieldnames=_COLUMNS, quoting=csv.QUOTE_MINIMAL)
    writer.writeheader()

    for finding in findings:
        writer.writerow(
            {
                "cve_id": finding.cve_id or finding.id,
                "package": package_name(finding),
                "version": package_version(finding),
                "ecosystem": package_ecosystem(finding),
                "severity": severity_value(finding),
                "cvss_score": finding.cvss_score if finding.cvss_score is not None else "",
                "epss_score": f"{finding.epss_score:.4f}" if finding.epss_score is not None else "",
                "is_kev": "yes" if finding.is_kev else "no",
                "published_at": evidence(finding, "published_at", ""),
                "modified_at": evidence(finding, "modified_at", ""),
                "fixed_version": finding.fixed_version or "",
                "cwe_ids": ";".join(finding.cwe_ids) if finding.cwe_ids else "",
                "affected_agents": ";".join(finding.affected_agents),
                "affected_servers": ";".join(finding.affected_servers),
                "exposed_credentials": str(len(finding.exposed_credentials)),
                "summary": finding.description or "",
                "severity_source": evidence(finding, "severity_source", ""),
                "epss_percentile": _format_optional_float(evidence(finding, "epss_percentile", None)),
                "kev_date_added": evidence(finding, "kev_date_added", ""),
                "kev_due_date": evidence(finding, "kev_due_date", ""),
                "compliance_tags": _compliance_tags_cell(finding),
            }
        )

    return buf.getvalue()


def _format_optional_float(value: object) -> str:
    if value is None or value == "":
        return ""
    if not isinstance(value, (int, float, str)):
        return str(value)
    try:
        return f"{float(value):.4f}"
    except (TypeError, ValueError):
        return str(value)


def _compliance_tags_cell(finding: object) -> str:
    """Return framework-qualified tags for one spreadsheet cell."""
    return ";".join(framework_qualified_finding_tags(finding))


def export_csv(report: AIBOMReport, output_path: str, blast_radii: list[BlastRadius] | None = None) -> None:
    """Write CSV report to file."""
    from pathlib import Path

    Path(output_path).write_text(to_csv(report, blast_radii), encoding="utf-8")
