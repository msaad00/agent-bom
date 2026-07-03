"""Smoke tests for README architecture SVG generator."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from scripts.generate_doc_architecture_svgs import _audit_github_safe, _audit_layout, architecture, how_it_works, persona_value

IMAGES = Path(__file__).resolve().parents[1] / "docs" / "images"


def test_how_it_works_includes_pipeline_steps() -> None:
    svg = how_it_works("dark")
    for step in ("Discover", "Extract", "Scan", "Enrich", "Analyze", "Report"):
        assert step in svg
    assert "PIPELINE" not in svg


def test_architecture_includes_core_surfaces() -> None:
    svg = architecture("light")
    assert "Unified Finding" in svg
    assert "UnifiedGraph" in svg
    assert "70 tools" in svg
    assert "283 ops" in svg
    assert "Agents &amp; MCP" in svg


def test_persona_value_renders_buyer_lanes() -> None:
    svg = persona_value("dark")
    assert "AppSec / GRC" in svg
    assert "findings queue" in svg
    assert "283 API ops" in svg
    assert "Self-hosted control plane" in svg


def test_blast_radius_text_is_clipped_in_cards() -> None:
    from scripts.generate_blast_radius_svgs import blast_radius

    svg = blast_radius("light")
    assert "clipPath" in svg
    assert 'clip-path="url(#br-light-pkg)"' in svg
    assert "ANTHROPIC_KEY" in svg
    assert "run_shell" in svg
    assert _audit_layout(svg) == []
    assert _audit_github_safe(svg) == []


def test_generated_svgs_have_no_rect_overflow() -> None:
    for name in (
        "how-it-works-dark.svg",
        "architecture-dark.svg",
        "persona-value-dark.svg",
        "blast-radius-dark.svg",
    ):
        text = (IMAGES / name).read_text(encoding="utf-8")
        assert _audit_layout(text) == [], name


def test_generated_files_exist_and_are_valid_svg() -> None:
    for name in (
        "how-it-works-dark.svg",
        "how-it-works-light.svg",
        "architecture-dark.svg",
        "architecture-light.svg",
        "persona-value-dark.svg",
        "persona-value-light.svg",
        "blast-radius-dark.svg",
        "blast-radius-light.svg",
    ):
        path = IMAGES / name
        assert path.exists(), name
        text = path.read_text(encoding="utf-8")
        assert text.lstrip().startswith("<?xml") or text.startswith("<svg")
        assert text.rstrip().endswith("</svg>")
        assert re.search(r'viewBox="0 0 \d+ \d+"', text)
        assert re.search(r'width="\d+" height="\d+"', text)
        ET.parse(path)


def test_generated_svgs_are_github_safe() -> None:
    for name in (
        "how-it-works-dark.svg",
        "architecture-dark.svg",
        "persona-value-dark.svg",
        "blast-radius-dark.svg",
    ):
        text = (IMAGES / name).read_text(encoding="utf-8")
        assert _audit_github_safe(text) == [], name
