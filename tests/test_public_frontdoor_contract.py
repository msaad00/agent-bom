"""Public storefront and release-note contracts."""

from __future__ import annotations

import struct
from pathlib import Path

from scripts.render_release_highlights import render_highlights
from scripts.render_social_preview_svg import render as render_social_preview

ROOT = Path(__file__).resolve().parents[1]
DURABLE_LOCAL_CONTROL_PLANE = "agent-bom serve --persist ~/.agent-bom/control-plane.db"


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
    assert svg.count('width="64" height="64" rx="16"') == 13

    assert "file:///" not in svg
    assert "/Users/" not in svg
    assert "<image" not in svg
    assert "tint-" not in svg
    assert "Codex CLI" not in svg
    assert "OpenAI · GPT" not in svg
    for brand_color in ("#EA4335", "#4285F4", "#34A853", "#FBBC05"):
        assert brand_color in svg
    assert 'href="vendor/openai-blossom-white.svg" x="-15" y="-15" width="94" height="94"' in template_svg
    assert 'href="vendor/simple-icons/clickhouse.svg"' in template_svg
    assert 'href="vendor/google-cloud-mark.svg"' in template_svg
    assert 'href="vendor/simple-icons/googlecloud.svg"' not in template_svg
    assert "Also supports VS Code · Okta · ClickHouse" not in template_svg
    assert svg.count("<symbol ") == 13
    assert svg.count('href="#embedded-') == 14
    assert render_social_preview(template) == svg
    for relative_asset in (
        "brand/mark-dark.svg",
        "vendor/claude-icon-rounded.svg",
        "vendor/openai-blossom-white.svg",
        "vendor/simple-icons/cursor.svg",
        "vendor/simple-icons/githubcopilot.svg",
        "vendor/simple-icons/amazonwebservices.svg",
        "vendor/simple-icons/microsoftazure.svg",
        "vendor/google-cloud-mark.svg",
        "vendor/simple-icons/kubernetes.svg",
        "vendor/simple-icons/snowflake.svg",
        "vendor/simple-icons/databricks.svg",
        "vendor/simple-icons/clickhouse.svg",
    ):
        assert relative_asset in template_svg
        assert (source.parent / relative_asset).is_file()


def test_readme_shows_the_end_to_end_product_journey_and_links_the_gallery() -> None:
    import re

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    journey = readme.split("## Product tour", 1)[1].split("## Self-host", 1)[0]
    images = re.findall(r'<img src="docs/images/([^"]+)"', journey)
    assert images == ["dashboard-live.png", "correlation-graph-live.png", "remediation-live.png"]
    assert journey.count('width="920"') == 3
    for image in images:
        assert (ROOT / "docs/images" / image).is_file()
    for marker in ("source receipts", "owners", "re-scan", "verify", "labeled sample data", "modeled infrastructure", "CVE-2023-4863"):
        assert marker in journey
    assert "[Discover and scan](docs/GALLERY.md)" in journey
    assert "A blocked call does not establish" in journey
    assert "DEMO-VULN" not in journey


def test_readme_leads_with_discover_scan_correlate_act_brand_header() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    header = readme.split("<!-- mcp-name:", 1)[0]

    assert "docs/images/social-preview.svg" in header
    assert "Discover. Scan. Correlate. Act." in header
    assert "logo-dark.svg" not in header
    assert header.index("social-preview.svg") < header.index("img.shields.io")


def test_readme_frontdoor_is_short_and_integration_roles_are_explicit() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    integrations = readme.split("### Work with your existing tools", 1)[1].split("## Quick start", 1)[0]
    for capability in ("CLI or GitHub Action", "REST API", "MCP", "SARIF", "CycloneDX", "SPDX", "fleet sync", "runtime evidence"):
        assert capability in integrations
    assert "[Integration capability matrix](docs/INTEGRATIONS.md)" in integrations
    matrix = (ROOT / "docs/INTEGRATIONS.md").read_text(encoding="utf-8")
    for role in ("Client discovery", "Read-only cloud connection", "Scan and deploy", "Identity", "Data platform", "Analytics backend"):
        assert role in matrix
    assert "agent-bom scan --databricks --databricks-security" in matrix
    assert "agent-bom cloud databricks" not in matrix


def test_scenarios_separate_reproducible_proof_from_synthetic_layout_fixtures() -> None:
    gallery = (ROOT / "docs" / "GALLERY.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert gallery.count("<img ") == 1
    assert "correlation-path-live.png" in gallery
    assert "correlation-path-live.png" not in readme
    assert "correlation-receipts-live.png" not in gallery
    assert 'width="900"' in gallery
    assert "scripts/replay_package_remediation.py" in gallery
    assert "CVE-2023-4863" in gallery
    assert "DEMO-VULN" not in gallery
    assert "not a current upgrade recommendation" in gallery
    for synthetic in ("mesh-live.png", "security-graph-live.png", "lineage-graph-live.png"):
        assert synthetic not in gallery


def test_docker_ui_first_run_has_a_result_and_preserves_local_auth_boundary() -> None:
    guide = (ROOT / "DOCKER_HUB_UI_README.md").read_text(encoding="utf-8")
    assert "docker compose -f docker-compose.pilot.yml up -d" in guide
    assert "**New Scan**" in guide
    assert "**Connections**" in guide
    assert "inventory and findings" in guide
    assert "loopback" in guide
    assert "configured authentication" in guide
    assert "AGENT_BOM_API_URL" in guide
    assert "NEXT_PUBLIC_API_URL" in guide


def test_persona_routes_start_with_their_actual_work() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    personas = readme.split("## Built for the teams", 1)[1].split("## Product tour", 1)[0]
    for marker in (
        "Developers & AI engineers",
        "AppSec & cloud security",
        "Platform & DevOps",
        "GRC & audit",
        "Security & engineering leaders",
        "AI assistants & automation",
    ):
        assert marker in personas
    assert "Open **Compliance**" in personas
    assert "Open **Overview**" in personas
    assert "docs/GALLERY.md#scan-a-repository-before-shipping" in personas
    assert "docs/MCP_WORKFLOWS.md" in personas
    assert "caller’s permissions" in personas


def test_public_first_run_surfaces_share_one_primary_command() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    pypi = (ROOT / "PYPI_README.md").read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "FIRST_RUN.md").read_text(encoding="utf-8")

    assert "pip install agent-bom\nagent-bom scan ." in readme
    assert "pip install agent-bom\nagent-bom scan ." in pypi
    assert "pip install agent-bom\nagent-bom scan ." in guide
    assert "agent-bom scan -p ." not in guide


def test_primary_local_control_plane_first_runs_use_one_durable_sqlite_path() -> None:
    for filename, heading in (
        ("PYPI_README.md", "## Recommended starting points"),
        ("docs/START_HERE.md", "## Platform / SRE"),
        ("docs/FIRST_RUN.md", "## 3. Open the Dashboard"),
    ):
        text = (ROOT / filename).read_text(encoding="utf-8")
        section = text.split(heading, 1)[1].split("\n## ", 1)[0]
        assert DURABLE_LOCAL_CONTROL_PLANE in section
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    self_host = readme.split("## Self-host", 1)[1].split("## Quick start", 1)[0]
    assert "docker compose up -d" in self_host
    assert "retains state in a Docker volume" in self_host
    assert "docs/DEPLOY_QUICKSTART.md" in self_host


def test_readme_primary_local_operator_first_runs_grant_scan_role_explicitly() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    self_host = readme.split("## Self-host", 1)[1].split("## Quick start", 1)[0]
    assert "docker compose up -d" in self_host
    assert "loopback" in self_host
    assert "authenticated deployment" in self_host
    assert "site-docs/deployment/authenticated-hosted-instance.md" in self_host
    entrypoint = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    assert "deploy/docker-compose.pilot.yml" in entrypoint
    compose = (ROOT / "deploy/docker-compose.pilot.yml").read_text(encoding="utf-8")
    assert "AGENT_BOM_NO_AUTH_ROLE" in compose
    assert "analyst" in compose
    assert "127.0.0.1" in compose


def test_readme_connection_first_run_requires_an_explicit_scan_after_verification() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    self_host = readme.split("## Self-host", 1)[1].split("## Quick start", 1)[0]
    assert "read-only connection, verify access, then start a scan" in self_host
    assert "Connections default to auto-scan on creation" not in readme


def test_cloud_connect_leads_with_wheel_safe_emit_before_optional_terraform() -> None:
    guide = (ROOT / "docs" / "CLOUD_CONNECT.md").read_text(encoding="utf-8")
    command = "agent-bom connect aws --emit --out agent-bom-aws-readonly.json"

    assert command in guide
    assert guide.index(command) < guide.index("deploy/terraform/connect-*")
    assert "Repository Terraform (optional)" in guide


def test_readme_header_omits_volatile_metric_strip() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    header = readme.split("## From evidence source to verified action", 1)[0]

    assert "package ecosystems" not in header
    assert "compliance surfaces" not in header
    assert "MCP tools · no account required" not in header


def test_readme_offline_bootstrap_leads_with_truthful_ecosystem_scope() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    offline = readme.split("<summary>Developer gates and offline scans</summary>", 1)[1].split("</details>", 1)[0]
    assert "agent-bom db update --osv-ecosystem PyPI" in offline
    assert "covers only the selected ecosystem" in offline
    assert offline.index("--osv-ecosystem PyPI") < offline.index("--source osv")
    assert "security gate or incomplete assessment" in offline


def test_docs_home_leads_with_product_value_and_attack_path_proof() -> None:
    home = (ROOT / "site-docs" / "index.md").read_text(encoding="utf-8")

    assert home.index("**Open security scanner") < home.index('!!! info "Canonical docs tree"')
    assert home.index("correlation-path-live.png") < home.index('!!! info "Canonical docs tree"')


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
