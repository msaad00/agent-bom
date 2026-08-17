"""Smoke tests for README architecture SVG generator."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from scripts.generate_doc_architecture_svgs import (
    MCP_TOOL_COUNT,
    REST_OPERATION_COUNT,
    _audit_github_safe,
    _audit_layout,
    _audit_persona_copy,
    architecture,
    how_it_works,
    persona_value,
    workflow,
)

ROOT = Path(__file__).resolve().parents[1]
IMAGES = ROOT / "docs" / "images"


def _readme_persona_rows() -> list[list[str]]:
    """Return the ``## Who it is for`` table body rows as trimmed cell lists."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    section = readme.split("## Who it is for", 1)[1].split("\n## ", 1)[0]
    table_lines: list[str] = []
    in_table = False
    for line in section.splitlines():
        if line.strip().startswith("|"):
            in_table = True
            table_lines.append(line)
        elif in_table:
            break
    rows = [[cell.strip() for cell in line.strip().strip("|").split("|")] for line in table_lines]
    # Drop the header row and the |---|---|---| separator.
    return rows[2:]


def test_how_it_works_includes_pipeline_steps() -> None:
    svg = how_it_works("dark")
    for lane in ("SCAN", "CENTRALIZE", "ENFORCE"):
        assert lane in svg
    assert "Finding + UnifiedGraph" in svg
    assert "agent-bom scan ." in svg
    assert "agent-bom serve" in svg
    assert "agent-bom gateway serve --help" in svg
    assert "ContextGraph" not in svg


def test_workflow_maps_sources_to_verified_outcomes() -> None:
    svg = workflow("dark")
    for label in (
        "SOURCES",
        "COLLECT + SCAN",
        "NORMALIZE",
        "CORRELATE + PRIORITIZE",
        "OWN + REMEDIATE",
        "VERIFY + ACT",
    ):
        assert label in svg
    for source in (
        "Repository + CI",
        "Workstation + endpoint",
        "Images + Kubernetes",
        "Cloud + data platforms",
        "MCP + runtime",
    ):
        assert source in svg
    for outcome in ("SARIF", "CycloneDX", "SPDX", "Control plane", "Runtime policy"):
        assert outcome in svg
    assert "Finding + UnifiedGraph" in svg
    assert "PATH  ›  IMPACT  ›  OWNER  ›  FIX  ›  VERIFY" in svg
    assert "Unavailable remains unavailable" in svg
    assert "Raw source + credentials stay local" in svg
    assert _audit_layout(svg) == []
    assert _audit_github_safe(svg) == []


def test_architecture_includes_core_surfaces() -> None:
    svg = architecture("light")
    assert "Unified Finding" in svg
    assert "UnifiedGraph" in svg
    assert f"{MCP_TOOL_COUNT} tools" in svg
    assert f"{REST_OPERATION_COUNT} operations" in svg
    assert "Agents + MCP + models" in svg
    assert "Cloud + data" in svg
    assert "Fleet + scheduler" in svg


def test_persona_value_renders_buyer_lanes() -> None:
    svg = persona_value("dark")
    for title in ("AI engineer", "Security engineer", "GRC / audit", "Leadership / CISO"):
        assert title in svg
    # The old lane titles must not linger anywhere in the artwork.
    for retired in ("AppSec", "Developers", "Platform / SRE", "AI / MCP owners"):
        assert retired not in svg, retired
    assert f"{REST_OPERATION_COUNT} API ops" in svg
    assert "Agent-native surface" in svg
    assert "Triage by reachability" in svg
    assert "Audit-ready exports" in svg
    assert "SCAN + CI · CENTRALIZE EVIDENCE · ENFORCE AT RUNTIME — one Finding + UnifiedGraph" in svg
    assert "LOCAL SCAN · CONTROL PLANE · RUNTIME" not in svg
    assert _audit_layout(svg) == []


def test_readme_places_persona_artwork_before_the_compact_role_table() -> None:
    """Public onboarding stays accessible while retaining visual workflow proof."""
    titles = [row[0] for row in _readme_persona_rows()]
    # The table and the artwork must name the SAME audiences. They had drifted
    # to seven rows against five illustrated lanes, so the picture and the text
    # described different products. Pinned as equality, not membership, so a new
    # row cannot be added to one without the other.
    assert titles == [
        "AI engineer",
        "Security engineer",
        "GRC / audit",
        "Leadership / CISO",
    ]

    from scripts.generate_doc_architecture_svgs import PERSONA_LANES

    assert [lane.title for lane in PERSONA_LANES] == titles

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    who_it_is_for = readme.index("## Who it is for")
    persona_artwork = readme.index("persona-value-dark.svg", who_it_is_for)
    role_table = readme.index("| Role | Start here | Primary outcome |", who_it_is_for)
    assert who_it_is_for < persona_artwork < role_table
    assert "persona-value-light.svg" in readme[who_it_is_for:role_table]
    assert "<summary><b>Audience workflow map</b></summary>" not in readme


def test_readme_surfaces_the_end_to_end_workflow_before_architecture_detail() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    workflow_heading = readme.index("## Scan, correlate, and act")
    workflow_art = readme.index("workflow-dark.svg", workflow_heading)
    architecture_detail = readme.index("<summary><b>Control-plane architecture</b></summary>")
    assert workflow_heading < workflow_art < architecture_detail
    assert "workflow-light.svg" in readme[workflow_heading:architecture_detail]
    assert "raw source and credentials stay local" in readme[workflow_heading:architecture_detail].lower()
    assert "### From source to verified action" not in readme


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
        "workflow-dark.svg",
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
        "workflow-dark.svg",
        "workflow-light.svg",
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
        "workflow-dark.svg",
    ):
        text = (IMAGES / name).read_text(encoding="utf-8")
        assert _audit_github_safe(text) == [], name


def test_all_generated_svg_bytes_match_their_generators() -> None:
    from scripts.generate_blast_radius_svgs import blast_radius

    expected = {
        "how-it-works-dark.svg": how_it_works("dark"),
        "how-it-works-light.svg": how_it_works("light"),
        "architecture-dark.svg": architecture("dark"),
        "architecture-light.svg": architecture("light"),
        "persona-value-dark.svg": persona_value("dark"),
        "persona-value-light.svg": persona_value("light"),
        "blast-radius-dark.svg": blast_radius("dark"),
        "blast-radius-light.svg": blast_radius("light"),
        "workflow-dark.svg": workflow("dark"),
        "workflow-light.svg": workflow("light"),
    }
    for name, svg in expected.items():
        assert (IMAGES / name).read_text(encoding="utf-8") == svg + "\n", name


def test_readme_flow_diagrams_keep_a_ten_pixel_rendered_text_floor() -> None:
    from scripts.generate_blast_radius_svgs import blast_radius

    for name, (svg, readme_scale) in {
        "how-it-works": (how_it_works("light"), 1100 / 1120),
        "workflow": (workflow("light"), 1100 / 1120),
        "architecture": (architecture("light"), 1000 / 1120),
        "blast-radius": (blast_radius("light"), 900 / 960),
    }.items():
        sizes = [float(value) for value in re.findall(r'font-size="([0-9.]+)"', svg)]
        assert sizes and min(sizes) * readme_scale >= 10, (name, min(sizes) * readme_scale)


def test_dense_diagrams_hold_their_improved_rendered_text_floor() -> None:
    """The floor these two can hold without clipping — which is lower than before.

    An earlier pass scaled type up to reach 7.92px and 7.05px rendered. That was
    measured against a fit audit that only bounded text against the *canvas*, so
    it never saw labels running past the card borders they sit in. They did:
    "15 ecosystems · EPSS/KEV · distro-aware", "Self-hosted control plane" and
    "381 API ops · 77 MCP tools · SARIF" all clipped in the README.

    With a box-aware audit the honest ceiling was lower — until the persona band
    was relaid out. Five cards on a 1280px row gave each 211px, leaving nothing
    to scale into; three per row gives ~402px, and the type now renders larger
    than the clipped version did *and* fits: 7.77px against the 7.05px that was
    overflowing.

    Architecture now uses the same layered reflow as the workflow diagram, so
    it is covered by the ten-pixel README floor above. The persona band remains
    intentionally denser because it is paired with an accessible HTML table.
    """
    for name, (svg, readme_scale, floor) in {
        "persona-value": (persona_value("light"), 900 / 1280, 7.5),
    }.items():
        sizes = [float(value) for value in re.findall(r'font-size="([0-9.]+)"', svg)]
        rendered = min(sizes) * readme_scale
        assert rendered >= floor, (name, rendered, floor)


def test_dense_diagram_text_stays_inside_the_canvas() -> None:
    """Scaling type for legibility needs a check that looks at type *and* boxes.

    `_audit_layout` bounds `<rect>` elements only, so it reported no issues at
    every font scale tried. The first version of this audit then bounded text
    against the canvas only, which passed while labels ran past the cards they
    sit in — the clipping visible in the README. It now attributes each run to
    its tightest containing rect.
    """
    from scripts.generate_doc_architecture_svgs import _audit_text_fit

    for name, svg in {
        "architecture": architecture("light"),
        "persona-value": persona_value("light"),
        "how-it-works": how_it_works("light"),
        "workflow": workflow("light"),
    }.items():
        assert _audit_text_fit(svg) == [], name
