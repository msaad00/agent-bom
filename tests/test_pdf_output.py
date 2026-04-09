"""Tests for optional PDF report export."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from agent_bom.models import AIBOMReport


def _report() -> AIBOMReport:
    return AIBOMReport(generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc), tool_version="0.75.15")


def test_to_pdf_uses_weasyprint_renderer():
    from agent_bom.output.pdf import to_pdf

    class _FakeHTML:
        def __init__(self, string: str, base_url: str | None = None):
            self.string = string
            self.base_url = base_url

        def write_pdf(self, target=None):
            assert target is None
            return b"%PDF-1.7\nbody\n"

    with patch.dict(sys.modules, {"weasyprint": SimpleNamespace(HTML=_FakeHTML)}):
        data = to_pdf(_report(), [])

    assert data.startswith(b"%PDF")


def test_export_pdf_writes_file(tmp_path):
    from agent_bom.output.pdf import export_pdf

    class _FakeHTML:
        def __init__(self, string: str, base_url: str | None = None):
            self.string = string
            self.base_url = base_url

        def write_pdf(self, target=None):
            assert target is not None
            from pathlib import Path

            Path(target).write_bytes(b"%PDF-1.7\nfile\n")
            return None

    out = tmp_path / "report.pdf"
    with patch.dict(sys.modules, {"weasyprint": SimpleNamespace(HTML=_FakeHTML)}):
        export_pdf(_report(), str(out), [])

    assert out.read_bytes().startswith(b"%PDF")


def test_pdf_export_requires_optional_dependency():
    from agent_bom.output.pdf import to_pdf

    with patch("agent_bom.output.pdf.importlib.import_module", side_effect=ImportError("missing")):
        with pytest.raises(RuntimeError, match="agent-bom\\[pdf\\]"):
            to_pdf(_report(), [])
