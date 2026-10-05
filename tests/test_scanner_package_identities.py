"""Bounded lockfile/graph regressions: installed aliases are not package identities."""

import json

import pytest

from agent_bom.models import Agent, AgentType, AIBOMReport, BlastRadius, MCPServer, Package, Severity, Vulnerability
from agent_bom.parsers.node_parsers import parse_bun_packages, parse_npm_packages, parse_yarn_lock
from agent_bom.parsers.ruby_parsers import parse_gemfile_lock


@pytest.mark.parametrize("canonical", ["lodash", "@scope/library"])
def test_npm_lock_alias_uses_registry_identity(tmp_path, canonical):
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"old-library": f"npm:{canonical}@4.17.4"}},
                    "node_modules/old-library": {"name": canonical, "version": "4.17.4"},
                },
            }
        )
    )
    (pkg,) = parse_npm_packages(tmp_path)
    assert (pkg.name, pkg.version, pkg.is_direct) == (canonical, "4.17.4", True)
    assert "old-library" not in pkg.purl


def test_npm_manifest_alias_uses_target_and_exact_version(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"old": "npm:lodash@4.17.4"}}))
    (pkg,) = parse_npm_packages(tmp_path)
    assert (pkg.name, pkg.version) == ("lodash", "4.17.4")


@pytest.mark.parametrize("berry", [False, True])
def test_yarn_alias_uses_target_identity(tmp_path, berry):
    content = '"old@npm:lodash@4.17.4":\n  version "4.17.4"\n'
    if berry:
        content = '__metadata:\n  version: 8\n\n"old@npm:lodash@4.17.4":\n  version: 4.17.4\n  resolution: "lodash@npm:4.17.4"\n'
    (tmp_path / "yarn.lock").write_text(content)
    (pkg,) = parse_yarn_lock(tmp_path)
    assert (pkg.name, pkg.version) == ("lodash", "4.17.4")


def test_bun_jsonc_resolved_versions_aliases_and_transitives(tmp_path):
    # Bun text lock shape: https://bun.sh/blog/bun-lock-text-lockfile
    (tmp_path / "bun.lock").write_text("""{
      // Declared ranges must not replace resolved versions.
      "lockfileVersion": 1,
      "workspaces": {"": {"dependencies": {"old": "npm:lodash@^4.17.0", "parent":"^1.0.0",},},},
      "packages": {
        "old": ["lodash@4.17.4", "", {}, "sha512-YQ=="],
        "parent": ["parent@1.0.2", "", {"dependencies":{"child":"^2.0.0"}}, ""],
        "child": ["child@2.3.4", "", {}, ""],
      },
    }""")
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"old": "npm:lodash@^4.17.0"}}))
    packages = parse_bun_packages(tmp_path)
    by_name = {p.name: p for p in packages}
    assert {(p.name, p.version) for p in packages} == {("lodash", "4.17.4"), ("parent", "1.0.2"), ("child", "2.3.4")}
    assert by_name["lodash"].is_direct
    assert not by_name["child"].is_direct
    assert by_name["child"].parent_package == "parent"
    assert parse_npm_packages(tmp_path) == []  # no duplicate alias@unknown


def test_ruby_platform_suffix_is_provenance_not_advisory_version(tmp_path):
    (tmp_path / "Gemfile.lock").write_text("""GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.19.0-x86_64-linux-gnu)
    nokogiri (1.19.0-arm64-darwin)
    other (2.0.0.pre.1)

PLATFORMS
  arm64-darwin
  x86_64-linux-gnu

DEPENDENCIES
  nokogiri
""")
    packages = parse_gemfile_lock(tmp_path)
    assert [(p.name, p.version) for p in packages] == [("nokogiri", "1.19.0"), ("other", "2.0.0.pre.1")]
    assert len(packages[0].version_evidence) == 2


@pytest.mark.parametrize("attack", [False, True])
def test_graph_keeps_package_versions_and_advisories_separate(attack):
    from agent_bom.output.graph import build_attack_flow_elements, build_graph_elements

    old = Package(name="debug", version="2.6.8", ecosystem="npm")
    new = Package(name="debug", version="2.6.9", ecosystem="npm")
    old.vulnerabilities = [Vulnerability(id="CVE-OLD", severity=Severity.HIGH, summary="old only")]
    new.vulnerabilities = [Vulnerability(id="CVE-NEW", severity=Severity.LOW, summary="new only")]
    server = MCPServer(name="server", packages=[old, new])
    agent = Agent(name="agent", agent_type=AgentType.CUSTOM, config_path="", mcp_servers=[server])
    radii = [
        BlastRadius(
            vulnerability=p.vulnerabilities[0],
            package=p,
            affected_servers=[server],
            affected_agents=[agent],
            exposed_credentials=[],
            exposed_tools=[],
        )
        for p in [old, new]
    ]
    elements = (build_attack_flow_elements if attack else build_graph_elements)(AIBOMReport(agents=[agent], blast_radii=radii))
    nodes = [e["data"] for e in elements if e["data"].get("type") == "pkg_vuln"]
    assert len(nodes) == 2
    for node in nodes:
        if attack:
            sources = {
                e["data"]["source"] for e in elements if e["data"].get("target") == node["id"] and e["data"].get("type") == "exploits"
            }
            assert sources == ({"cve:CVE-OLD"} if node["version"] == "2.6.8" else {"cve:CVE-NEW"})
            continue
        targets = {e["data"]["target"] for e in elements if e["data"].get("source") == node["id"] and e["data"].get("type") == "affects"}
        assert targets == ({"cve:CVE-OLD"} if node["version"] == "2.6.8" else {"cve:CVE-NEW"})


def test_bun_workspace_reads_only_its_resolved_closure(tmp_path):
    root = {
        "lockfileVersion": 1,
        "workspaces": {"app": {"dependencies": {"a": "^1"}}, "other": {"dependencies": {"b": "^2"}}},
        "packages": {
            "a": ["a@1.2.3", "", {"dependencies": {"shared": "^3"}}, ""],
            "b": ["b@2.0.0", "", {}, ""],
            "shared": ["shared@3.1.0", "", {}, ""],
        },
    }
    (tmp_path / "bun.lock").write_text(json.dumps(root))
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(json.dumps({"dependencies": {"a": "^1"}}))
    assert {p.name for p in parse_bun_packages(app)} == {"a", "shared"}
    assert parse_npm_packages(app) == []


@pytest.mark.parametrize("content", ['{"lockfileVersion":1,"packages":', 'lockfileVersion: 0\ndependencies:\n  "a": "1.0.0"'])
def test_bun_malformed_or_invented_format_discloses_incomplete_coverage(tmp_path, content):
    from agent_bom.scanners.state import consume_coverage_warnings

    consume_coverage_warnings()
    (tmp_path / "bun.lock").write_text(content)
    assert parse_bun_packages(tmp_path) == []
    assert any(row["reason"] == "manifest_parse_error" for row in consume_coverage_warnings())


def test_bun_mixed_valid_and_unresolved_entries_preserves_resolved_packages(tmp_path):
    from agent_bom.scanners.state import consume_coverage_warnings

    consume_coverage_warnings()
    (tmp_path / "bun.lock").write_text(
        json.dumps(
            {
                "lockfileVersion": 1,
                "workspaces": {"": {}},
                "packages": {"a": ["a@1.0.0", "", {}, ""], "broken": ["git+https://example.invalid/repo", "", {}, ""]},
            }
        )
    )
    assert [(p.name, p.version) for p in parse_bun_packages(tmp_path)] == [("a", "1.0.0")]
    assert consume_coverage_warnings()


def test_npm_v1_alias_resolves_version_instead_of_protocol_token(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 1, "dependencies": {"old": {"version": "npm:lodash@4.17.4"}}})
    )
    (pkg,) = parse_npm_packages(tmp_path)
    assert (pkg.name, pkg.version) == ("lodash", "4.17.4")


@pytest.mark.parametrize(
    "workspace,metadata", [(None, {}), ({"dependencies": None}, {}), ({"dependencies": {"a": "1"}}, {"dependencies": None})]
)
def test_bun_malformed_relationships_preserve_resolved_inventory(tmp_path, workspace, metadata):
    from agent_bom.scanners.state import consume_coverage_warnings

    consume_coverage_warnings()
    (tmp_path / "bun.lock").write_text(
        json.dumps({"lockfileVersion": 1, "workspaces": {"": workspace}, "packages": {"a": ["a@1.0.0", "", metadata, ""]}})
    )
    assert [(p.name, p.version) for p in parse_bun_packages(tmp_path)] == [("a", "1.0.0")]
    assert consume_coverage_warnings()


def test_bun_alias_dedup_keeps_direct_path(tmp_path):
    (tmp_path / "bun.lock").write_text(
        json.dumps(
            {
                "lockfileVersion": 1,
                "workspaces": {"": {"dependencies": {"parent": "1", "alias": "npm:a@1"}}},
                "packages": {
                    "parent": ["parent@1.0.0", "", {"dependencies": {"a": "1"}}, ""],
                    "a": ["a@1.0.0", "", {}, ""],
                    "alias": ["a@1.0.0", "", {}, ""],
                },
            }
        )
    )
    pkg = next(p for p in parse_bun_packages(tmp_path) if p.name == "a")
    assert pkg.is_direct and pkg.dependency_depth == 0 and pkg.parent_package is None
    assert len(pkg.version_evidence) == 2


def test_bun_jsonc_preserves_strings_and_rejects_duplicate_keys():
    from agent_bom.parsers.node_lockfiles import _jsonc

    assert _jsonc('{"url":"https://example.test/,}",/* comment */"x":[1,],}') == {"url": "https://example.test/,}", "x": [1]}
    with pytest.raises(ValueError, match="Duplicate"):
        _jsonc('{"packages": {}, "packages": {}}')


@pytest.mark.asyncio
async def test_ruby_artifact_filename_is_incomplete_without_platform_metadata(monkeypatch):
    import agent_bom.scanners as scanners

    called = []
    monkeypatch.setattr(scanners, "_scan_packages_local_db", lambda packages: (called.extend(packages) or 0, set()))
    package = Package(name="nokogiri", version="1.19.0-x86_64-linux-gnu", ecosystem="rubygems")
    scanners.reset_scan_warnings()
    try:
        await scanners.scan_packages([package], options=scanners.ScanOptions(offline=True))
    except scanners.IncompleteScanError:
        pass
    assert called == []  # invalid Gem::Version cannot broaden every local advisory range
    assert scanners.consume_scan_warnings()


def test_cli_invalid_ruby_version_cannot_be_clean():
    from click.testing import CliRunner

    from agent_bom.cli import main

    result = CliRunner().invoke(main, ["check", "nokogiri@1.19.0-x86_64-linux-gnu", "-e", "rubygems", "--offline", "-f", "json"])
    assert result.exit_code == 2, result.output
    assert json.loads(result.output)["verdict"] == "incomplete"


@pytest.mark.asyncio
async def test_mcp_invalid_ruby_version_cannot_be_clean():
    from agent_bom.mcp_tools.scanning import check_impl

    result = json.loads(
        await check_impl(
            package="nokogiri@1.19.0-x86_64-linux-gnu",
            ecosystem="rubygems",
            offline=True,
            _validate_ecosystem=lambda value: value,
            _truncate_response=lambda value: value,
        )
    )
    assert result["status"] == "incomplete"
    assert result["canonical_verdict"] == "incomplete"
