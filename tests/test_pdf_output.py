"""Tests for built-in PDF report export."""

from __future__ import annotations

from datetime import datetime, timezone

from agent_bom.models import AIBOMReport


def _report() -> AIBOMReport:
    return AIBOMReport(generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc), tool_version="0.76.0")


def test_to_pdf_renders_pdf_bytes():
    from agent_bom.output.pdf import to_pdf

    data = to_pdf(_report(), [])

    assert data.startswith(b"%PDF")
    assert b"/Type /Catalog" in data
    assert b"Agent-BOM Scan Report" in data


def test_export_pdf_writes_file(tmp_path):
    from agent_bom.output.pdf import export_pdf

    out = tmp_path / "report.pdf"
    export_pdf(_report(), str(out), [])

    assert out.read_bytes().startswith(b"%PDF")
    assert b"Agent-BOM Scan Report" in out.read_bytes()
