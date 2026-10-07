"""Lockfile edges and manifest roots remain distinct from flat inventory."""

import json

from agent_bom.parsers.compiled_parsers import parse_cargo_packages, parse_go_packages
from agent_bom.parsers.node_parsers import parse_pnpm_lock, parse_yarn_lock


def assert_chain(packages):
    by_name = {p.name: p for p in packages}
    assert by_name["parent"].is_direct is True
    assert by_name["child"].is_direct is False
    assert by_name["child"].parent_package == "parent"
    assert by_name["child"].dependency_depth == 1
    assert by_name["child"].reachability_evidence == "lockfile"
    assert by_name["child"].version_source == "lockfile"


def test_yarn_classic_retains_manifest_roots_and_lock_edges(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"parent": "^1.0.0"}}))
    (tmp_path / "yarn.lock").write_text(
        'parent@^1.0.0:\n  version "1.0.0"\n  dependencies:\n    child "^2.0.0"\n\nchild@^2.0.0:\n  version "2.0.0"\n'
    )
    assert_chain(parse_yarn_lock(tmp_path))


def test_pnpm_retains_importer_roots_and_snapshot_edges(tmp_path):
    (tmp_path / "pnpm-lock.yaml").write_text(
        'lockfileVersion: "9.0"\n'
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      parent:\n"
        "        specifier: ^1\n"
        "        version: 1.0.0\n"
        "packages:\n"
        "  parent@1.0.0: {}\n"
        "  child@2.0.0: {}\n"
        "snapshots:\n"
        "  parent@1.0.0:\n"
        "    dependencies:\n"
        "      child: 2.0.0\n"
        "  child@2.0.0: {}\n"
    )
    assert_chain(parse_pnpm_lock(tmp_path))


def test_cargo_lock_excludes_proven_root_crate_and_retains_edges(tmp_path):
    (tmp_path / "Cargo.toml").write_text('[package]\nname = "root"\nversion = "1.0.0"\n[dependencies]\nparent = "1"\n')
    (tmp_path / "Cargo.lock").write_text(
        "version = 3\n"
        "[[package]]\n"
        'name = "root"\n'
        'version = "1.0.0"\n'
        'dependencies = ["parent"]\n'
        "[[package]]\n"
        'name = "parent"\n'
        'version = "1.0.0"\n'
        'source = "registry+https://example.com"\n'
        'dependencies = ["child"]\n'
        "[[package]]\n"
        'name = "child"\n'
        'version = "2.0.0"\n'
        'source = "registry+https://example.com"\n'
    )
    packages = parse_cargo_packages(tmp_path)
    assert "root" not in {p.name for p in packages}
    assert_chain(packages)
    assert all(p.version_evidence[0]["source_file"].endswith("Cargo.lock") for p in packages)


def test_go_source_location_is_recorded_for_sarif(tmp_path):
    (tmp_path / "go.mod").write_text("module sample\nrequire github.com/example/parent v1.0.0\n")
    package = parse_go_packages(tmp_path, verify_checksums=False)[0]
    assert package.version_evidence[0]["source_file"].endswith("go.mod")
    assert package.version_source == "manifest"


def test_uv_lock_records_resolved_version_source(tmp_path):
    from agent_bom.parsers.uv_lock import parse_uv_lock

    (tmp_path / "pyproject.toml").write_text('[project]\nname="sample"\nversion="1.0.0"\ndependencies=["parent"]\n')
    (tmp_path / "uv.lock").write_text('version=1\n[[package]]\nname="parent"\nversion="1.0.0"\n')
    package = parse_uv_lock(tmp_path)[0]
    assert package.version_source == "lockfile"


def test_unrooted_go_checksums_have_unknown_directness_and_source(tmp_path):
    (tmp_path / "go.sum").write_text("github.com/example/pkg v1.0.0 h1:fakechecksum\n")
    package = parse_go_packages(tmp_path, verify_checksums=False)[0]
    assert package.is_direct is None
    assert package.version_source == "lockfile"
    assert package.version_evidence[0]["source_file"].endswith("go.sum")


def test_swift_lock_has_source_metadata_and_unknown_directness(tmp_path):
    from agent_bom.parsers.swift_parsers import parse_package_resolved

    (tmp_path / "Package.resolved").write_text(
        json.dumps(
            {
                "version": 2,
                "pins": [{"identity": "package", "location": "https://github.com/example/package.git", "state": {"version": "1.0.0"}}],
            }
        )
    )
    package = parse_package_resolved(tmp_path)[0]
    assert package.is_direct is None
    assert package.version_source == "lockfile"
    assert package.version_evidence[0]["source_file"].endswith("Package.resolved")


def test_go_sarif_uses_recorded_manifest_location(tmp_path):
    from agent_bom.models import Agent, AgentType, AIBOMReport, BlastRadius, MCPServer, Severity, Vulnerability
    from agent_bom.output.sarif import to_sarif

    (tmp_path / "go.mod").write_text("module sample\nrequire github.com/example/parent v1.0.0\n")
    package = parse_go_packages(tmp_path, verify_checksums=False)[0]
    server = MCPServer(name="repository", command="", packages=[package])
    agent = Agent(name="repository", agent_type=AgentType.CUSTOM, config_path=str(tmp_path), mcp_servers=[server])
    radius = BlastRadius(
        package=package,
        vulnerability=Vulnerability(id="CVE-2026-9999", summary="fixture", severity=Severity.HIGH),
        affected_agents=[agent],
        affected_servers=[server],
        exposed_credentials=[],
        exposed_tools=[],
    )
    document = to_sarif(AIBOMReport(agents=[agent], blast_radii=[radius]))
    location = document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "go.mod"


def test_malformed_manifest_roots_preserve_yarn_inventory_as_unknown(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": null}')
    (tmp_path / "yarn.lock").write_text('parent@^1.0.0:\n  version "1.0.0"\n')
    packages = parse_yarn_lock(tmp_path)
    assert len(packages) == 1
    assert packages[0].is_direct is None


def test_malformed_pnpm_importers_preserve_inventory_as_unknown(tmp_path):
    (tmp_path / "pnpm-lock.yaml").write_text('lockfileVersion: "9.0"\nimporters: null\npackages:\n  parent@1.0.0: {}\n')
    packages = parse_pnpm_lock(tmp_path)
    assert len(packages) == 1
    assert packages[0].is_direct is None
