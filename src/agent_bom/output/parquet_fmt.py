"""Parquet output for data-lake / columnar analytics interop (#3499).

Requires the optional ``lake`` extra (``pyarrow``). Rows mirror the CSV
finding export with reachability columns for SIEM and lake pipelines.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agent_bom.compliance_utils import compliance_tags_export_cell
from agent_bom.models import AIBOMReport, BlastRadius
from agent_bom.output.finding_views import (
    cve_findings,
    evidence,
    package_ecosystem,
    package_name,
    package_version,
    severity_value,
)

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
    "symbol_reachability",
    "reachable_affected_symbols",
    "graph_reachable",
    "graph_min_hop_distance",
]


def _require_pyarrow():
    try:
        import pyarrow as pa  # noqa: PLC0415
        import pyarrow.parquet as pq  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - exercised via test monkeypatch
        raise RuntimeError(
            "Parquet export requires pyarrow. Install with: pip install 'agent-bom[lake]'"
        ) from exc
    return pa, pq


def _row_dict(finding) -> dict[str, Any]:
    return {
        "cve_id": finding.cve_id or finding.id,
        "package": package_name(finding),
        "version": package_version(finding),
        "ecosystem": package_ecosystem(finding),
        "severity": severity_value(finding),
        "cvss_score": finding.cvss_score if finding.cvss_score is not None else None,
        "epss_score": float(finding.epss_score) if finding.epss_score is not None else None,
        "is_kev": bool(finding.is_kev),
        "published_at": evidence(finding, "published_at", "") or None,
        "modified_at": evidence(finding, "modified_at", "") or None,
        "fixed_version": finding.fixed_version or None,
        "cwe_ids": ";".join(finding.cwe_ids) if finding.cwe_ids else None,
        "affected_agents": ";".join(finding.affected_agents),
        "affected_servers": ";".join(finding.affected_servers),
        "exposed_credentials": len(finding.exposed_credentials),
        "summary": finding.description or None,
        "severity_source": evidence(finding, "severity_source", "") or None,
        "epss_percentile": evidence(finding, "epss_percentile", None),
        "kev_date_added": evidence(finding, "kev_date_added", "") or None,
        "kev_due_date": evidence(finding, "kev_due_date", "") or None,
        "compliance_tags": compliance_tags_export_cell(finding) or None,
        "symbol_reachability": evidence(finding, "symbol_reachability", "") or None,
        "reachable_affected_symbols": ";".join(evidence(finding, "reachable_affected_symbols", []) or [])
        or None,
        "graph_reachable": evidence(finding, "graph_reachable", None),
        "graph_min_hop_distance": evidence(finding, "graph_min_hop_distance", None),
    }


def to_parquet_bytes(report: AIBOMReport, blast_radii: list[BlastRadius] | None = None) -> bytes:
    """Serialize CVE findings to an in-memory Parquet file."""
    pa, pq = _require_pyarrow()
    rows = [_row_dict(finding) for finding in cve_findings(report, blast_radii)]
    table = pa.Table.from_pylist(rows, schema=_schema(pa))
    sink = pa.BufferOutputStream()
    pq.write_table(table, sink, compression="snappy")
    return sink.getvalue().to_pybytes()


def export_parquet(
    report: AIBOMReport,
    output_path: str,
    blast_radii: list[BlastRadius] | None = None,
) -> None:
    """Write CVE findings as a Parquet file."""
    Path(output_path).write_bytes(to_parquet_bytes(report, blast_radii))


def _schema(pa):
    return pa.schema(
        [
            ("cve_id", pa.string()),
            ("package", pa.string()),
            ("version", pa.string()),
            ("ecosystem", pa.string()),
            ("severity", pa.string()),
            ("cvss_score", pa.float64()),
            ("epss_score", pa.float64()),
            ("is_kev", pa.bool_()),
            ("published_at", pa.string()),
            ("modified_at", pa.string()),
            ("fixed_version", pa.string()),
            ("cwe_ids", pa.string()),
            ("affected_agents", pa.string()),
            ("affected_servers", pa.string()),
            ("exposed_credentials", pa.int64()),
            ("summary", pa.string()),
            ("severity_source", pa.string()),
            ("epss_percentile", pa.float64()),
            ("kev_date_added", pa.string()),
            ("kev_due_date", pa.string()),
            ("compliance_tags", pa.string()),
            ("symbol_reachability", pa.string()),
            ("reachable_affected_symbols", pa.string()),
            ("graph_reachable", pa.bool_()),
            ("graph_min_hop_distance", pa.int64()),
        ],
    )


__all__ = ["export_parquet", "to_parquet_bytes"]
