"""Render a scan report in a caller-requested output format.

One dispatch shared by every surface that lets a caller choose the shape of a
scan result. ``POST /v1/scan`` published a ``format`` enum that nothing read, so
a request for SARIF completed as ``done``, echoed ``format: sarif`` back, and
returned plain AI-BOM JSON. This module is what makes that field mean something,
and it delegates to the existing converters rather than growing a second
implementation of any format.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agent_bom.models import AIBOMReport, BlastRadius

# The formats a scan job can be asked for. Kept as the single list the API enum,
# the renderer, and the contract tests all read, so a value cannot be published
# without a renderer behind it.
SCAN_DOCUMENT_FORMATS: tuple[str, ...] = ("json", "cyclonedx", "sarif", "spdx", "html", "text")


def to_text(report: "AIBOMReport", blast_radii: list["BlastRadius"] | None = None) -> str:
    """Tab-separated plain text for piping to grep/awk."""
    lines = [
        f"agent-bom {report.tool_version}",
        f"agents={report.total_agents} servers={report.total_servers} "
        f"packages={report.total_packages} vulnerabilities={report.total_vulnerabilities}",
        "",
    ]

    for agent in report.agents:
        for server in agent.mcp_servers:
            for pkg in server.packages:
                lines.append(f"{agent.name}\t{server.name}\t{pkg.ecosystem}\t{pkg.name}\t{pkg.version}")

    if blast_radii:
        lines.append("")
        lines.append("VULN_ID\tSEVERITY\tPACKAGE\tFIX\tAGENTS\tCREDENTIALS")
        for br in blast_radii:
            vuln = br.vulnerability
            lines.append(
                f"{vuln.id}\t{vuln.severity.value}\t{br.package.name}@{br.package.version}\t"
                f"{vuln.fixed_version or '-'}\t{len(br.affected_agents)}\t{len(br.exposed_credentials)}"
            )

    return "\n".join(lines) + "\n"


def render_scan_document(
    report: "AIBOMReport",
    output_format: str,
    *,
    blast_radii: list["BlastRadius"] | None = None,
    offline_html: bool = True,
) -> dict[str, Any] | str:
    """Render ``report`` as ``output_format``.

    ``offline_html`` defaults to True so a rendered HTML document is
    self-contained: a stored artifact must never pull scripts from a third-party
    CDN when it is later opened.

    Raises:
        ValueError: the format is not one of :data:`SCAN_DOCUMENT_FORMATS`.
    """
    fmt = (output_format or "json").strip().lower()
    if fmt not in SCAN_DOCUMENT_FORMATS:
        raise ValueError(f"Unsupported scan output format: {output_format!r}. Valid: {', '.join(SCAN_DOCUMENT_FORMATS)}")

    radii = list(blast_radii if blast_radii is not None else (report.blast_radii or []))

    if fmt == "json":
        from agent_bom.output.json_fmt import to_json

        return to_json(report)
    if fmt == "cyclonedx":
        from agent_bom.output.cyclonedx_fmt import to_cyclonedx

        return to_cyclonedx(report)
    if fmt == "sarif":
        from agent_bom.output.sarif import to_sarif

        return to_sarif(report, blast_radii=radii or None)
    if fmt == "spdx":
        from agent_bom.output.spdx_fmt import to_spdx

        return to_spdx(report)
    if fmt == "html":
        from agent_bom.output.html import to_html

        return to_html(report, radii, offline_assets=offline_html)
    return to_text(report, radii)
