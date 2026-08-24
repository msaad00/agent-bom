"""Smoke tests for README architecture SVG generator."""

from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from scripts.generate_doc_architecture_svgs import (
    ICONS,
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


def test_workflow_uses_semantic_scan_and_action_icons() -> None:
    """The visual vocabulary should describe actions, not decorate them."""
    svg = workflow("dark")
    collect = svg.split("COLLECT + SCAN", 1)[0].rsplit('<rect x="84"', 1)[-1]
    assert ICONS["search"] in collect
    assert ICONS["bug"] not in collect
    assert ICONS["graph"] in svg
    assert ICONS["tool"] in svg
    assert ICONS["shield"] in svg


def test_workflow_and_architecture_use_provenance_pinned_vendor_vectors() -> None:
    workflow_svg = workflow("dark")
    architecture_svg = architecture("light")
    for vendor in ("AWS", "Azure", "Google Cloud", "Kubernetes", "Snowflake", "Databricks", "ClickHouse"):
        assert f'data-vendor="{vendor}"' in workflow_svg, vendor
    for vendor in ("Kubernetes", "Snowflake"):
        assert f'data-vendor="{vendor}"' in architecture_svg, vendor

    provenance = json.loads((IMAGES / "vendor" / "provenance.json").read_text(encoding="utf-8"))
    by_path = {entry["path"]: entry for entry in provenance["assets"]}
    for filename in (
        "amazonwebservices.svg",
        "microsoftazure.svg",
        "googlecloud.svg",
        "kubernetes.svg",
        "snowflake.svg",
        "databricks.svg",
        "clickhouse.svg",
    ):
        path = f"docs/images/vendor/simple-icons/{filename}"
        assert path in by_path
        record = by_path[path]
        assert record["license"] == "CC0-1.0"
        assert record["source_repo"] == "https://github.com/msaad00/cloud-ai-security-skills"
        assert record["source_commit"] == "2c8496410e28d8c3a3149fec139a1f178bb501f6"
        assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == record["sha256"]


def test_architecture_includes_core_surfaces() -> None:
    svg = architecture("light")
    assert "Unified Finding" in svg
    assert "UnifiedGraph" in svg
    assert f"{MCP_TOOL_COUNT} tools" in svg
    assert f"{REST_OPERATION_COUNT} operations" in svg
    assert "Agents + MCP + models" in svg
    assert "Cloud + data" in svg
    assert "Fleet + scheduler" in svg
    assert "SCAN + CORRELATION RUNTIME" in svg
    assert "runs where you deploy it" in svg
    assert "Workstation + CI" in svg
    assert "Docker + Kubernetes" in svg
    assert "Customer control plane" in svg
    assert "VPC · EKS · Helm" in svg
    assert "LOCAL PROCESSING ENGINE" not in svg
    assert "local processing engine" not in svg
    assert 'data-vendor="AWS"' in svg
    assert 'data-vendor="Kubernetes"' in svg


def test_architecture_does_not_present_snowflake_as_a_hosting_target() -> None:
    svg = architecture("dark")
    execution = svg.split("EXECUTION LOCATIONS", 1)[1].split("Scan", 1)[0]
    assert "Snowflake" not in execution
    assert "Customer control plane" in execution
    assert "Snowflake" in svg


def test_persona_value_renders_buyer_lanes() -> None:
    svg = persona_value("dark")
    for title in (
        "AppSec / product security",
        "AI / ML engineer",
        "Cloud security",
        "Platform / DevOps",
        "GRC / audit",
        "Leadership / CISO",
    ):
        assert title in svg
    for retired in ("Developers", "Platform / SRE", "AI / MCP owners"):
        assert retired not in svg, retired
    assert f"{REST_OPERATION_COUNT} API ops" in svg
    assert "Gate CI with reachable risk" in svg
    assert "Agent-native inventory" in svg
    assert "Read-only connected posture" in svg
    assert "Self-hosted evidence plane" in svg
    assert "Audit-ready exports" in svg
    for command in (
        "agent-bom scan .",
        "agent-bom serve",
        "agent-bom report compliance-narrative",
    ):
        assert command in svg
    for artifact in (
        "SARIF · SBOM · paths",
        "AI BOM · graph · runtime",
        "Posture · identity · graph",
        "Owners · SLA · verification",
        "Mappings · signed evidence",
        "Posture · coverage · trends",
    ):
        assert artifact in svg
    assert "SCAN + CI · CENTRALIZE EVIDENCE · ENFORCE AT RUNTIME — one Finding + UnifiedGraph" in svg
    assert "LOCAL SCAN · CONTROL PLANE · RUNTIME" not in svg
    assert _audit_layout(svg) == []


def test_readme_persona_table_covers_each_operating_lane() -> None:
    """Public onboarding routes each audience to its actual first action."""
    titles = [row[0] for row in _readme_persona_rows()]
    assert titles == [
        "AppSec / product security",
        "AI / ML engineer",
        "Cloud security",
        "Platform / DevOps",
        "GRC / audit",
        "Leadership / CISO",
    ]

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    who_it_is_for = readme.index("## Who it is for")
    role_table = readme.index("| Role | Start here | Primary outcome |", who_it_is_for)
    assert who_it_is_for < role_table
    assert "persona-value-dark.svg" not in readme


def test_readme_links_end_to_end_workflow_before_persona_detail() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    workflow_heading = readme.index("## Discover → Scan → Correlate → Act")
    workflow_link = readme.index("[Evidence workflow](docs/HOW_IT_WORKS.md)", workflow_heading)
    persona_heading = readme.index("## Who it is for")
    assert workflow_heading < workflow_link < persona_heading
    assert "[Control-plane architecture](docs/ARCHITECTURE.md)" in readme[workflow_heading:persona_heading]
    assert (
        "raw source and credentials stay inside the customer-controlled execution boundary"
        in readme[workflow_heading:persona_heading].lower()
    )
    assert "### From source to verified action" not in readme


def test_readme_moves_dense_workflow_and_architecture_art_to_full_size_docs() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for diagram in ("workflow-dark.svg", "architecture-dark.svg", "persona-value-dark.svg"):
        assert diagram not in readme
    assert "[Evidence workflow](docs/HOW_IT_WORKS.md)" in readme
    assert "[Control-plane architecture](docs/ARCHITECTURE.md)" in readme


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
    was relaid out. Two cards per row provide enough room for a literal command,
    outcome, and proof artifact while keeping the type readable at README width.

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
