"""Smoke tests for README architecture SVG generator."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from scripts.generate_doc_architecture_svgs import (
    MCP_TOOL_COUNT,
    PERSONA_LANES,
    REST_OPERATION_COUNT,
    _audit_github_safe,
    _audit_layout,
    _audit_persona_copy,
    architecture,
    how_it_works,
    persona_value,
)

ROOT = Path(__file__).resolve().parents[1]
IMAGES = ROOT / "docs" / "images"


def _readme_persona_rows() -> list[list[str]]:
    """Return the ``## Who it is for`` table body rows as trimmed cell lists."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    section = readme.split("## Who it is for", 1)[1].split("\n## ", 1)[0]
    rows = [
        [cell.strip() for cell in line.strip().strip("|").split("|")]
        for line in section.splitlines()
        if line.strip().startswith("|")
    ]
    # Drop the header row and the |---|---|---| separator.
    return rows[2:]


def test_how_it_works_includes_pipeline_steps() -> None:
    svg = how_it_works("dark")
    for step in ("Discover", "Extract", "Scan", "Enrich", "Analyze", "Report"):
        assert step in svg
    assert "Connect -&gt; Scan -&gt; Graph -&gt; Serve" in svg
    assert "Scan -&gt; Sync -&gt; Enforce" not in svg
    assert "Build -&gt; Serve -&gt; Orchestrate" not in svg
    assert "PIPELINE" not in svg
    # Connect is a first-class beat (read-only onboarding), not a footnote.
    assert "CONNECT" in svg
    assert "GRAPH" in svg
    assert "SERVE" in svg
    assert "Finding" in svg
    assert "CDX" in svg
    assert "Gateway" in svg
    assert "FINDINGS" not in svg
    assert "DELIVER" not in svg
    assert "ENFORCE" not in svg
    assert "one pane of glass" in svg
    # Official cloud icon marks (dashboard assets) + readable labels on light chips.
    assert 'fill="#FF9900"' in svg or 'fill="#f90"' in svg
    assert 'fill="#035bda"' in svg or 'fill="#0078D4"' in svg
    assert 'fill="#29B5E8"' in svg or 'fill="#29b5e8"' in svg
    assert re.search(r"<text[^>]*>\s*AWS\s*</text>", svg)
    assert re.search(r"<text[^>]*>\s*Snowflake\s*</text>", svg)


def test_architecture_includes_core_surfaces() -> None:
    svg = architecture("light")
    assert "Unified Finding" in svg
    assert "UnifiedGraph" in svg
    assert f"{MCP_TOOL_COUNT} tools" in svg
    assert f"{REST_OPERATION_COUNT} ops" in svg
    assert "Agents &amp; MCP" in svg


def test_persona_value_renders_buyer_lanes() -> None:
    svg = persona_value("dark")
    assert "AppSec" in svg
    assert "GRC / audit" in svg
    assert "AppSec / GRC" not in svg
    assert f"{REST_OPERATION_COUNT} API ops" in svg
    assert "Self-hosted control plane" in svg
    assert "Accurate SCA" in svg
    assert "Audit-ready exports" in svg
    assert _audit_layout(svg) == []


def test_persona_lanes_are_the_single_source_for_image_and_table() -> None:
    """The band, the README table under it, and the alt text name the same five."""
    titles = [lane.title for lane in PERSONA_LANES]
    assert len(titles) == 5

    assert [row[0] for row in _readme_persona_rows()] == titles

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    alt = re.search(r'alt="(agent-bom personas[^"]*)"', readme)
    assert alt is not None, "persona image is missing its alt text"
    for title in titles:
        assert title in alt.group(1), f"{title} missing from persona alt text"

    for theme in ("light", "dark"):
        svg = persona_value(theme)
        for title in titles:
            assert title in svg, f"{title} missing from the {theme} persona band"


def test_persona_table_rows_all_carry_a_runnable_command() -> None:
    """Every persona row gives a literal first command, not a noun phrase."""
    for row in _readme_persona_rows():
        start_here = row[1]
        assert "`agent-bom " in start_here or "`pip install " in start_here, row


def test_persona_card_copy_fits_inside_its_card() -> None:
    assert _audit_persona_copy() == []


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
