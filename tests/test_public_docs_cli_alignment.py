"""Public docs and bundled skills should teach commands that actually work."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from agent_bom.cli import main

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_CLI_DOCS = [
    ROOT / "integrations" / "cortex-code" / "SKILL.md",
    ROOT / "integrations" / "openclaw" / "analyze" / "SKILL.md",
    ROOT / "integrations" / "openclaw" / "compliance" / "SKILL.md",
    ROOT / "integrations" / "openclaw" / "scan-infra" / "SKILL.md",
    ROOT / "site-docs" / "features" / "sbom.md",
    ROOT / "site-docs" / "features" / "scanning.md",
    ROOT / "site-docs" / "features" / "policy.md",
    ROOT / "site-docs" / "features" / "compliance.md",
    ROOT / "site-docs" / "features" / "blast-radius.md",
    ROOT / "site-docs" / "getting-started" / "install.md",
    ROOT / "site-docs" / "reference" / "exit-codes.md",
    ROOT / "site-docs" / "architecture" / "agentic-skills-architecture.md",
]


def test_public_docs_do_not_teach_removed_cli_surfaces() -> None:
    combined = "\n".join(path.read_text(encoding="utf-8") for path in PUBLIC_CLI_DOCS)

    removed_or_misleading = [
        "agent-bom generate-sbom",
        "agent-bom cloud snowflake",
        "agent-bom cis-benchmark",
        "agent-bom scan --sbom cyclonedx",
        "agent-bom scan --sbom spdx",
        "agent-bom scan --sbom-input",
    ]
    for command in removed_or_misleading:
        assert command not in combined


def test_readme_promotes_repository_scan_before_the_failing_demo() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    quick_start = readme.split("## Quick start", 1)[1].split("## Self-host", 1)[0]

    repository_scan = quick_start.index("agent-bom scan .")
    demo_warning = quick_start.index("security gate (exit `1`)")
    demo_scan = quick_start.index("agent-bom scan --demo --offline")

    assert repository_scan < demo_scan < demo_warning
    assert demo_warning < quick_start.index("docs/images/demo-latest.gif")


def test_readme_first_run_explains_blast_radius_and_mcp_evidence() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    tour = readme.split("## Product tour", 1)[1].split("## Self-host", 1)[0]
    normalized = " ".join(tour.lower().split())
    for marker in ("finding", "source receipts", "graph", "reachable data asset", "owners", "fix", "re-scan", "verify"):
        assert marker in normalized


def test_primary_docker_scan_persists_vulnerability_state() -> None:
    docker_hub = (ROOT / "DOCKER_HUB_README.md").read_text(encoding="utf-8")

    assert docker_hub.count("-v agentbom-state:/home/abom/.agent-bom") >= 3
    assert "reuses vulnerability and scan state" in docker_hub


def test_connect_sources_do_not_teach_removed_cli_surfaces() -> None:
    # The `connect <provider>` guidance prints a scan command; it must point at a
    # real surface, not a removed/misleading one (e.g. `agent-bom cloud snowflake`,
    # which the cloud group does not register — Snowflake uses `scan --snowflake`).
    from agent_bom.cli._entry_points import _CONNECT_SOURCES

    removed_or_misleading = [
        "agent-bom generate-sbom",
        "agent-bom cloud snowflake",
        "agent-bom cis-benchmark",
    ]
    for source in _CONNECT_SOURCES.values():
        for bad in removed_or_misleading:
            assert bad not in source.scan_command, f"{source.name} teaches removed surface: {source.scan_command}"


def test_documented_primary_commands_are_real_cli_surfaces() -> None:
    runner = CliRunner()
    commands = [
        ["agents", "--help"],
        ["image", "--help"],
        ["sbom", "--help"],
        ["cloud", "aws", "--help"],
        ["graph", "--help"],
        ["validate", "--help"],
        ["db", "status", "--help"],
        ["skills", "scan", "--help"],
        ["findings", "push", "--help"],
        ["fleet", "sync", "--help"],
    ]

    for command in commands:
        result = runner.invoke(main, command)
        assert result.exit_code == 0, f"agent-bom {' '.join(command)} failed:\n{result.output}"


def test_cli_reference_lists_all_visible_root_commands() -> None:
    cli_reference = (ROOT / "site-docs" / "reference" / "cli.md").read_text(encoding="utf-8")
    visible_commands = sorted(name for name, command in main.commands.items() if not getattr(command, "hidden", False))

    missing = [name for name in visible_commands if f"| `{name}` |" not in cli_reference]

    assert missing == []


def test_public_docs_do_not_overclaim_smithery_catalog_liveness() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    smithery_doc = (ROOT / "site-docs/integrations/smithery.md").read_text(encoding="utf-8")
    assert "agent-bom is published in the [Smithery]" not in smithery_doc
    assert "Also on [Glama]" not in readme
    assert "[Smithery setup and manifest](site-docs/integrations/smithery.md)" in readme


def test_release_prep_does_not_call_unpublished_version_current() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    docker_hub = (ROOT / "DOCKER_HUB_README.md").read_text(encoding="utf-8")
    assert "0.98.1` | Current stable" not in docker_hub
    assert "[published release checkout](https://github.com/msaad00/agent-bom/releases)" in readme
    assert "verify registry availability before pinning" in docker_hub


def test_readme_distinguishes_graph_relationship_provenance() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    normalized = " ".join(readme.lower().split())
    assert "Graph views use observed nodes and relationships" not in readme
    for claim in (
        "source receipts",
        "labeled sample data",
        "modeled infrastructure",
        "a blocked call does not establish that the underlying package was fixed",
    ):
        assert claim in normalized
    assert "[Evidence workflow](docs/HOW_IT_WORKS.md)" in readme
    workflow = " ".join((ROOT / "docs/HOW_IT_WORKS.md").read_text().lower().split())
    for boundary in (
        "they do not merge permission-bearing runtime occurrences",
        "observed, inferred, or modeled",
        "a drawn connection alone is not exploit proof",
        "labels, similar names, and mutable image tags never create a cross-source join",
    ):
        assert boundary in workflow
    assert "observed graph evidence" not in readme


def test_release_verification_blocks_on_stale_registry_surfaces() -> None:
    verification = (ROOT / "docs" / "RELEASE_VERIFICATION.md").read_text(encoding="utf-8")

    assert "Registry surface freshness" in verification
    assert "Glama" in verification
    assert "do not mark the release complete" in verification.lower()
    assert "Browser behavioral lock-in" in verification
    assert "this matrix does not claim one browser test per control" in verification


def test_readme_storefront_is_concise_ordered_and_actionable() -> None:
    import re

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    markers = ["## Built for the teams", "## Product tour", "## Self-host in your environment", "## Quick start", "## Trust and evidence"]
    positions = [readme.index(marker) for marker in markers]
    assert positions == sorted(positions)
    hero = readme[: positions[0]]
    assert hero.count("img.shields.io/") == 8
    assert hero.count("Open security scanner and self-hosted control plane") == 1
    for anchor in ("#product-tour", "#self-host-in-your-environment", "#quick-start"):
        assert f'href="{anchor}"' in hero
    assert "Scan your software and AI infrastructure" not in hero
    for noise in ("package ecosystems", "compliance surfaces", "MCP tools · no account required", "demo.agent-bom.com"):
        assert noise not in hero
    quick_start = readme.split("## Quick start", 1)[1].split("\n## ", 1)[0]
    block = re.search(r"```bash\n(.*?)\n```", quick_start, re.S)
    assert block and block.group(1).splitlines() == ["pip install agent-bom", "agent-bom scan ."]
    assert "agent-bom mcp server" in quick_start
    demo = readme.index("docs/images/demo-latest.gif")
    assert readme[:demo].count("<details>") == readme[:demo].count("</details>")
    assert len(readme.splitlines()) <= 210
    images = re.findall(r'<img src="docs/images/([^"]+-live.png)"', readme)
    assert images == ["dashboard-live.png", "correlation-graph-live.png", "dependency-map-live.png", "remediation-live.png"]
    assert "correlation-path-live.png" not in readme
    assert "docs/GALLERY.md" in readme
    for diagram in ("workflow-dark.svg", "architecture-dark.svg", "persona-value-dark.svg", "blast-radius-dark.svg"):
        assert diagram not in readme
    assert "AppSec / GRC" not in readme


def test_readme_grc_persona_row_links_a_runnable_compliance_workflow() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    row = next(line for line in readme.splitlines() if line.startswith("| **GRC & audit**"))
    assert "Open **Compliance**" in row
    assert "docs/GALLERY.md#scan-a-repository-before-shipping" in row
    scenario = (ROOT / "docs/GALLERY.md").read_text().split("## Scan a repository before shipping", 1)[1].split("\n## ", 1)[0]
    assert "agent-bom scan . -f json -o scan.json" in scenario
    assert "agent-bom report compliance-narrative scan.json" in scenario
    result = CliRunner().invoke(main, ["report", "compliance-narrative", "--help"])
    assert result.exit_code == 0 and "SCAN_FILE" in result.output


def test_permissions_doc_keeps_network_boundary_scoped() -> None:
    permissions = (ROOT / "docs" / "PERMISSIONS.md").read_text(encoding="utf-8")

    assert "External API Calls (exhaustive list)" not in permissions
    assert "exhaustive list of all outbound URLs" not in permissions
    assert "Zero network calls unless scanning for vulnerabilities" not in permissions
    assert "No hidden telemetry, analytics, or tracking." in permissions
    assert "Explicit Push, Export, and Integration Destinations" in permissions


def test_mcp_server_instructions_do_not_overclaim_read_only_surface() -> None:
    factory = (ROOT / "src" / "agent_bom" / "mcp_server_factory.py").read_text(encoding="utf-8")

    assert "Read-only, agentless, no credentials required." not in factory
    assert "Scanner and posture tools are read-only" in factory
    assert "write actions require an authenticated operator token" in factory
    assert "operator_role is audit metadata" in factory


def test_no_shipped_docstring_carries_an_issue_reference() -> None:
    """Issue references belong in commit messages, not in shipped source.

    `agent-bom graph --help` printed "Closes #292." to every user, because the
    tracker reference lived in the command's docstring and Click renders
    docstrings as help text. The same pattern sat in module docstrings that ship
    inside the wheel.
    """
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    pattern = re.compile(r"\b(?:Closes|Fixes|Resolves|Refs?)\s+#\d+", re.IGNORECASE)

    offenders: list[str] = []
    for path in sorted((root / "src" / "agent_bom").rglob("*.py")):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if pattern.search(line):
                offenders.append(f"{path.relative_to(root)}:{lineno}: {line.strip()}")
    assert not offenders, "tracker references in shipped source:\n" + "\n".join(offenders)


def test_public_docs_make_no_unverifiable_adoption_claim() -> None:
    """No shipped doc may assert an install/download/user count.

    CONTRIBUTING.md opened with "agent-bom has 7,000+ monthly installs" — a
    number nothing in this repo can derive or check, sitting in the first line a
    prospective contributor reads. Registry download stats move constantly and
    are not reproducible from a checkout, so the honest options are to cite the
    live source or to make no claim; a hardcoded figure is neither, and an
    unverifiable adoption number in a security tool is a trust problem rather
    than a marketing one.
    """
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    surfaces = [
        root / "README.md",
        root / "PYPI_README.md",
        root / "DOCKER_HUB_README.md",
        root / "CONTRIBUTING.md",
        *sorted((root / "docs").rglob("*.md")),
        *sorted((root / "site-docs").rglob("*.md")),
    ]
    pattern = re.compile(r"\b\d[\d,]*\+?\s*(?:monthly\s+)?(?:installs|downloads|active users|stars)\b", re.IGNORECASE)

    offenders: list[str] = []
    for path in surfaces:
        if not path.exists():
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if pattern.search(line):
                offenders.append(f"{path.relative_to(root)}:{lineno}: {line.strip()}")
    assert not offenders, "unverifiable adoption claim(s) in shipped docs:\n" + "\n".join(offenders)
