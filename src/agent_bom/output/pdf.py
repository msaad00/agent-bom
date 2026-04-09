"""Self-contained PDF report export.

The release branch previously used WeasyPrint to render HTML into PDF, but
that pulled in a dependency chain that violates this repo's license policy.
This module keeps PDF export available without external rendering packages by
writing a compact text-first PDF directly.
"""

from __future__ import annotations

from io import BytesIO
from pathlib import Path
from textwrap import wrap
from typing import Iterable

from agent_bom.models import AIBOMReport, BlastRadius

_PAGE_WIDTH = 612
_PAGE_HEIGHT = 792
_LEFT_MARGIN = 48
_TOP_START = 760
_BOTTOM_MARGIN = 52
_LINE_HEIGHT = 14
_WRAP_WIDTH = 92


def _sanitize_text(value: object) -> str:
    text = str(value)
    replacements = {
        "\u2014": "-",
        "\u2013": "-",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2022": "*",
        "\u2192": "->",
        "\u00a0": " ",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text.encode("latin-1", "replace").decode("latin-1")


def _escape_pdf_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _append_wrapped(lines: list[str], value: object = "", *, indent: str = "") -> None:
    text = _sanitize_text(value).strip()
    if not text:
        lines.append("")
        return
    wrapped = wrap(
        text,
        width=max(20, _WRAP_WIDTH - len(indent)),
        break_long_words=False,
        break_on_hyphens=False,
    )
    if not wrapped:
        lines.append(indent.rstrip())
        return
    lines.append(f"{indent}{wrapped[0]}")
    follow_indent = " " * len(indent)
    for chunk in wrapped[1:]:
        lines.append(f"{follow_indent}{chunk}")


def _build_report_lines(report: AIBOMReport, blast_radii: Iterable[BlastRadius]) -> list[str]:
    lines: list[str] = []
    lines.append("Agent-BOM Scan Report")
    lines.append("=" * 76)
    lines.append(f"Generated: {_sanitize_text(report.generated_at.isoformat())}")
    lines.append(f"Version: {_sanitize_text(report.tool_version or 'unknown')}")
    lines.append(f"Scan ID: {_sanitize_text(report.scan_id or 'n/a')}")
    lines.append("")
    lines.append("Summary")
    lines.append("-" * 76)
    lines.append(f"Agents: {report.total_agents}")
    lines.append(f"Servers: {report.total_servers}")
    lines.append(f"Packages: {report.total_packages}")
    lines.append(f"Vulnerabilities: {report.total_vulnerabilities}")
    lines.append(f"Critical findings: {len(report.critical_vulns)}")
    if report.scan_sources:
        _append_wrapped(lines, f"Sources: {', '.join(report.scan_sources)}")
    if report.executive_summary:
        lines.append("")
        lines.append("Executive Summary")
        lines.append("-" * 76)
        _append_wrapped(lines, report.executive_summary)

    sorted_radii = sorted(blast_radii, key=lambda item: item.risk_score, reverse=True)
    if sorted_radii:
        lines.append("")
        lines.append("Top Blast Radius Findings")
        lines.append("-" * 76)
        for index, br in enumerate(sorted_radii[:15], start=1):
            vuln = br.vulnerability
            header = (
                f"{index}. {vuln.id} | {br.package.name}@{br.package.version} | {vuln.severity.value.upper()} | risk {br.risk_score:.1f}"
            )
            _append_wrapped(lines, header)
            details: list[str] = []
            if br.affected_agents:
                details.append(f"agents={len(br.affected_agents)}")
            if br.exposed_credentials:
                details.append(f"creds={', '.join(br.exposed_credentials[:4])}")
            if br.exposed_tools:
                details.append(f"tools={len(br.exposed_tools)}")
            if vuln.fixed_version:
                details.append(f"fix={vuln.fixed_version}")
            if details:
                _append_wrapped(lines, "; ".join(details), indent="   ")
            summary = vuln.summary or br.attack_vector_summary or br.ai_summary
            if summary:
                _append_wrapped(lines, summary, indent="   ")

    if report.ai_threat_chains:
        lines.append("")
        lines.append("Threat Chains")
        lines.append("-" * 76)
        for chain in report.ai_threat_chains[:5]:
            _append_wrapped(lines, chain, indent="* ")

    return lines


def _split_pages(lines: list[str]) -> list[list[str]]:
    usable_height = _TOP_START - _BOTTOM_MARGIN
    page_capacity = max(12, usable_height // _LINE_HEIGHT)
    return [lines[i : i + page_capacity] for i in range(0, len(lines), page_capacity)] or [["Agent-BOM Scan Report"]]


def _page_stream(lines: list[str]) -> bytes:
    commands = ["BT", "/F1 10 Tf", f"{_LINE_HEIGHT} TL", f"{_LEFT_MARGIN} {_TOP_START} Td"]
    for index, line in enumerate(lines):
        if index:
            commands.append("T*")
        commands.append(f"({_escape_pdf_text(line)}) Tj")
    commands.append("ET")
    return "\n".join(commands).encode("latin-1")


def _build_pdf(lines: list[str]) -> bytes:
    pages = _split_pages(lines)
    object_ids: list[int] = []
    objects: list[bytes] = []

    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")

    page_ids = [4 + (index * 2) for index in range(len(pages))]
    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects.append(f"<< /Type /Pages /Count {len(pages)} /Kids [{kids}] >>".encode("latin-1"))
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    for index, lines_for_page in enumerate(pages):
        page_id = page_ids[index]
        content_id = page_id + 1
        page_obj = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {_PAGE_WIDTH} {_PAGE_HEIGHT}] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>"
        ).encode("latin-1")
        stream = _page_stream(lines_for_page)
        content_obj = b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream"
        objects.append(page_obj)
        objects.append(content_obj)
        object_ids.extend([page_id, content_id])

    buffer = BytesIO()
    buffer.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for object_number, object_bytes in enumerate(objects, start=1):
        offsets.append(buffer.tell())
        buffer.write(f"{object_number} 0 obj\n".encode("ascii"))
        buffer.write(object_bytes)
        buffer.write(b"\nendobj\n")

    xref_start = buffer.tell()
    buffer.write(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    buffer.write(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        buffer.write(f"{offset:010d} 00000 n \n".encode("ascii"))
    buffer.write(f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF\n".encode("ascii"))
    return buffer.getvalue()


def to_pdf(report: AIBOMReport, blast_radii: list | None = None) -> bytes:
    """Render the report to PDF bytes without external renderers."""
    lines = _build_report_lines(report, blast_radii or [])
    return _build_pdf(lines)


def export_pdf(report: AIBOMReport, output_path: str, blast_radii: list | None = None) -> None:
    """Write the rendered PDF report to disk."""
    Path(output_path).write_bytes(to_pdf(report, blast_radii))
