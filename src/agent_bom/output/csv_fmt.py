"""CSV output for spreadsheet/SIEM ingestion and executive reporting.

One row per vulnerability finding with all enrichment data.
UTF-8 BOM included for Excel compatibility.
"""

from __future__ import annotations

import csv
import io

from agent_bom.models import AIBOMReport, BlastRadius

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
]


def to_csv(report: AIBOMReport, blast_radii: list[BlastRadius] | None = None) -> str:
    """Convert an AIBOMReport to CSV string with UTF-8 BOM."""
    brs = blast_radii or report.blast_radii

    buf = io.StringIO()
    # UTF-8 BOM for Excel auto-detection
    buf.write("\ufeff")

    writer = csv.DictWriter(buf, fieldnames=_COLUMNS, quoting=csv.QUOTE_MINIMAL)
    writer.writeheader()

    for br in brs:
        v = br.vulnerability
        writer.writerow(
            {
                "cve_id": v.id,
                "package": br.package.name,
                "version": br.package.version or "",
                "ecosystem": br.package.ecosystem or "",
                "severity": v.severity.value,
                "cvss_score": v.cvss_score if v.cvss_score is not None else "",
                "epss_score": f"{v.epss_score:.4f}" if v.epss_score is not None else "",
                "is_kev": "yes" if v.is_kev else "no",
                "published_at": v.published_at or "",
                "modified_at": v.modified_at or "",
                "fixed_version": v.fixed_version or "",
                "cwe_ids": ";".join(v.cwe_ids) if v.cwe_ids else "",
                "affected_agents": ";".join(a.name for a in br.affected_agents),
                "affected_servers": ";".join(s.name for s in br.affected_servers),
                "exposed_credentials": str(len(br.exposed_credentials)),
                "summary": v.summary or "",
            }
        )

    return buf.getvalue()


def export_csv(report: AIBOMReport, output_path: str, blast_radii: list[BlastRadius] | None = None) -> None:
    """Write CSV report to file."""
    from pathlib import Path

    Path(output_path).write_text(to_csv(report, blast_radii), encoding="utf-8")
