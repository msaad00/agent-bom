"""Public storefront and release-note contracts."""

from __future__ import annotations

from pathlib import Path

from scripts.render_release_highlights import render_highlights

ROOT = Path(__file__).resolve().parents[1]


def test_readme_keeps_one_readable_product_proof_and_links_the_gallery() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert readme.count("-live.png") == 1
    assert 'width="430"' not in readme
    assert 'width="900"' in readme
    assert "[View the full product gallery](docs/GALLERY.md)" in readme
    for diagram in ("workflow-dark.svg", "architecture-dark.svg", "persona-value-dark.svg"):
        assert diagram not in readme


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

    assert "| Security engineer | `agent-bom scan . -f sarif -o findings.sarif`" in personas
    assert "| Platform / DevOps | `pip install 'agent-bom[ui]' && agent-bom serve`" in personas
    assert "owner and sla" in personas.lower()


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
