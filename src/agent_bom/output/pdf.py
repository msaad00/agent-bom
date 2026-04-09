"""PDF report export built from the HTML renderer."""

from __future__ import annotations

import importlib
from pathlib import Path

from agent_bom.models import AIBOMReport
from agent_bom.output.html import to_html


def _load_weasyprint_html():
    """Load the optional WeasyPrint HTML renderer."""
    try:
        module = importlib.import_module("weasyprint")
    except ImportError as exc:
        raise RuntimeError("PDF export requires the optional WeasyPrint dependency. Install with: pip install 'agent-bom[pdf]'") from exc

    html_cls = getattr(module, "HTML", None)
    if html_cls is None:
        raise RuntimeError("PDF export dependency is incomplete: weasyprint.HTML is unavailable")
    return html_cls


def to_pdf(report: AIBOMReport, blast_radii: list | None = None) -> bytes:
    """Render the existing HTML report to PDF bytes."""
    html_cls = _load_weasyprint_html()
    html = to_html(report, blast_radii or [])
    return html_cls(string=html, base_url=str(Path.cwd())).write_pdf()


def export_pdf(report: AIBOMReport, output_path: str, blast_radii: list | None = None) -> None:
    """Write the rendered PDF report to disk."""
    html_cls = _load_weasyprint_html()
    html = to_html(report, blast_radii or [])
    html_cls(string=html, base_url=str(Path(output_path).resolve().parent)).write_pdf(target=output_path)
