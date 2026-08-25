"""Public storefront and release-note contracts."""

from __future__ import annotations

import struct
from pathlib import Path

from scripts.render_release_highlights import render_highlights
from scripts.render_social_preview_svg import render as render_social_preview

ROOT = Path(__file__).resolve().parents[1]


def test_social_preview_is_portable_and_evidence_focused() -> None:
    preview = ROOT / "docs" / "images" / "social-preview.png"
    source = ROOT / "docs" / "images" / "social-preview.svg"
    template = ROOT / "docs" / "images" / "social-preview.source.svg"

    png_header = preview.read_bytes()[:24]
    assert png_header[:8] == b"\x89PNG\r\n\x1a\n"
    assert struct.unpack(">II", png_header[16:24]) == (1280, 420)

    svg = source.read_text(encoding="utf-8")
    template_svg = template.read_text(encoding="utf-8")
    for claim in (
        "Discover. Scan.",
        "Correlate. Act.",
        "Security evidence across repositories, supply chains, AI + MCP, cloud, identity, and data.",
        "repos + SCA",
        "images + IaC",
        "AI + MCP + models",
        "cloud + identity + data",
        "AI CLIENTS + MODELS",
        "CLOUD + IDENTITY + DATA",
        "discover → scan → correlate → act",
    ):
        assert claim in svg
    for integration in (
        "Claude",
        "OpenAI / Codex",
        "Cursor",
        "GitHub Copilot",
        "VS Code",
        "Windsurf",
        "Cortex Code",
        "AWS",
        "Azure",
        "GCP",
        "Kubernetes",
        "Snowflake",
        "Databricks",
        "ClickHouse",
    ):
        assert integration in svg

    assert ">CVE</text>" not in svg
    assert ">package</text>" not in svg
    assert 'width="244" height="64"' not in svg
    assert svg.count('width="64" height="64" rx="16"') == 12

    assert "file:///" not in svg
    assert "/Users/" not in svg
    assert "<image" not in svg
    assert "tint-" not in svg
    assert "Codex CLI" not in svg
    assert "OpenAI · GPT" not in svg
    assert svg.count("<symbol ") == 12
    assert svg.count('href="#embedded-') == 13
    assert render_social_preview(template) == svg
    for relative_asset in (
        "brand/mark-dark.svg",
        "vendor/claude-icon-rounded.svg",
        "vendor/openai-blossom-white.svg",
        "vendor/simple-icons/cursor.svg",
        "vendor/simple-icons/githubcopilot.svg",
        "vendor/simple-icons/amazonwebservices.svg",
        "vendor/simple-icons/microsoftazure.svg",
        "vendor/simple-icons/googlecloud.svg",
        "vendor/simple-icons/kubernetes.svg",
        "vendor/simple-icons/snowflake.svg",
        "vendor/simple-icons/databricks.svg",
    ):
        assert relative_asset in template_svg
        assert (source.parent / relative_asset).is_file()


def test_readme_shows_the_end_to_end_product_journey_and_links_the_gallery() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    journey = readme.split("### Product journey", 1)[1].split("## Quick start", 1)[0]
    stages = ["Discover inventory", "Scan", "Reachable graph", "Ranked path", "Act and verify"]
    images = ["fleet-state-live.png", "jobs-pipeline-live.png", "lineage-graph-live.png", "security-graph-live.png", "remediation-live.png"]
    assert all(stage in journey for stage in stages)
    assert all(image in journey for image in images)
    assert [journey.index(stage) for stage in stages] == sorted(journey.index(stage) for stage in stages)
    assert [journey.index(image) for image in images] == sorted(journey.index(image) for image in images)
    assert 'width="900"' in readme
    assert "[Continue to runtime enforcement in the full product gallery](docs/GALLERY.md)" in readme
    for diagram in ("workflow-dark.svg", "architecture-dark.svg", "persona-value-dark.svg"):
        assert diagram not in readme


def test_readme_leads_with_discover_scan_correlate_act_brand_header() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    header = readme.split("<!-- mcp-name:", 1)[0]

    assert "docs/images/social-preview.svg" in header
    assert "Discover. Scan. Correlate. Act." in header
    assert "logo-dark.svg" not in header
    assert header.index("social-preview.svg") < header.index("img.shields.io")


def test_readme_frontdoor_is_short_and_integration_roles_are_explicit() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    frontdoor = readme.split("## Discover → Scan → Correlate → Act", 1)[1].split("## Who it is for", 1)[0]
    content_lines = [line for line in frontdoor.splitlines() if line.strip()]
    normalized = " ".join(frontdoor.split())

    assert len(content_lines) <= 12
    assert "agent or tool entrypoint → MCP server → package → finding" in frontdoor
    for capability in ("repositories", "SCA", "secrets", "IaC", "AI agents", "models", "cloud", "identity"):
        assert capability in frontdoor
    assert "scheduled or connected scans" in frontdoor
    assert "incomplete evidence stays explicit" in normalized
    assert "[Integration capability matrix](docs/INTEGRATIONS.md)" in frontdoor

    header_note = readme.split('<p align="center">', 2)[2].split("</p>", 1)[0]
    assert "Supported backends vary by capability" in header_note
    assert "Capability matrix" in header_note

    matrix = (ROOT / "docs" / "INTEGRATIONS.md").read_text(encoding="utf-8")
    for role in ("Client discovery", "Read-only cloud connection", "Scan and deploy", "Identity", "Data platform", "Analytics backend"):
        assert role in matrix
    assert "agent-bom scan --databricks --databricks-security" in matrix
    assert "agent-bom cloud databricks" not in matrix


def test_gallery_retains_full_size_product_screens() -> None:
    gallery = (ROOT / "docs" / "GALLERY.md").read_text(encoding="utf-8")

    for image in (
        "dashboard-live.png",
        "dependency-map-live.png",
        "security-graph-live.png",
        "remediation-live.png",
        "lineage-graph-live.png",
        "mesh-live.png",
    ):
        assert image in gallery
    assert 'width="900"' in gallery


def test_persona_routes_start_with_their_actual_work() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    personas = readme.split("## Who it is for", 1)[1].split("\n## ", 1)[0]

    assert "| AppSec / product security | `agent-bom scan . -f sarif -o findings.sarif`" in personas
    assert "| AI / ML engineer | `agent-bom scan .`" in personas
    assert "| Cloud security | `agent-bom connect aws --emit --out agent-bom-aws-readonly.json`" in personas
    assert "| Platform / DevOps | `pip install 'agent-bom[ui]' && agent-bom serve`" in personas
    assert "owner and sla" in personas.lower()


def test_cloud_connect_leads_with_wheel_safe_emit_before_optional_terraform() -> None:
    guide = (ROOT / "docs" / "CLOUD_CONNECT.md").read_text(encoding="utf-8")
    command = "agent-bom connect aws --emit --out agent-bom-aws-readonly.json"

    assert command in guide
    assert guide.index(command) < guide.index("deploy/terraform/connect-*")
    assert "Repository Terraform (optional)" in guide


def test_readme_header_omits_volatile_metric_strip() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    header = readme.split("## Discover → Scan → Correlate → Act", 1)[0]

    assert "package ecosystems" not in header
    assert "compliance surfaces" not in header
    assert "MCP tools · no account required" not in header


def test_readme_offline_bootstrap_leads_with_truthful_ecosystem_scope() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    offline = readme.split("Need a disconnected scan?", 1)[1].split("**A non-zero exit", 1)[0]

    assert "agent-bom db update --osv-ecosystem PyPI" in offline
    assert "covers only" in offline.lower()
    assert "selected ecosystem" in offline.lower()
    assert offline.index("--osv-ecosystem PyPI") < offline.index("--source osv")


def test_docs_home_leads_with_product_value_and_attack_path_proof() -> None:
    home = (ROOT / "site-docs" / "index.md").read_text(encoding="utf-8")

    assert home.index("**Open security scanner") < home.index('!!! info "Canonical docs tree"')
    assert home.index("security-graph-live.png") < home.index('!!! info "Canonical docs tree"')


def test_release_highlights_prepend_three_changelog_bullets() -> None:
    changelog = """# Changelog

## [1.2.3] - 2026-08-20

Release context.

### Added

- First human-written outcome.
- Second human-written outcome with
  a wrapped continuation.

### Fixed

- Third human-written outcome.
- Fourth detail stays out of the highlights.

## [1.2.2] - 2026-08-19
"""

    assert (
        render_highlights(changelog, "v1.2.3")
        == """## Highlights

- First human-written outcome.
- Second human-written outcome with a wrapped continuation.
- Third human-written outcome.
"""
    )


def test_release_workflow_prepends_curated_highlights_to_generated_notes() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    assert "scripts/render_release_highlights.py" in workflow
    assert '--generate-notes --notes "$HIGHLIGHTS"' in workflow
