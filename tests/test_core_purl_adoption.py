"""Every producer of a ``Package.purl`` / SBOM / VEX product purl builds it through the core kernel.

Hand-built ``f"pkg:{eco}/{name}@{ver}"`` strings are wrong for maven
(group:artifact must become a namespace), scoped npm (``@scope`` must be a
percent-encoded namespace), PyPI (names are lowercased and ``_`` → ``-``) and Go
(the purl type is ``golang``, not ``go``). Each case below asserts the emitted
purl equals ``synthesize_purl`` and parses as a spec-valid purl.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from packageurl import PackageURL

from agent_bom.core.packages import package_purl, synthesize_purl
from agent_bom.models import AIBOMReport, BlastRadius, Package, Severity, Vulnerability

GO_MODULE = "github.com/Azure/azure-sdk-for-go"

# (name, version, ecosystem, expected canonical purl)
CASES = [
    ("org.apache.commons:commons-text", "1.10.0", "maven", "pkg:maven/org.apache.commons/commons-text@1.10.0"),
    ("@scope/name", "1.0.0", "npm", "pkg:npm/%40scope/name@1.0.0"),
    ("PyYAML", "6.0.1", "pypi", "pkg:pypi/pyyaml@6.0.1"),
    ("Foo_Bar", "2.0", "pypi", "pkg:pypi/foo-bar@2.0"),
    (GO_MODULE, "v1.2.3", "go", f"pkg:golang/{GO_MODULE}@v1.2.3"),
]
IDS = ["maven", "scoped-npm", "pypi-caps", "pypi-underscore", "golang"]


def _assert_canonical(purl: str | None, name: str, version: str, ecosystem: str, expected: str) -> None:
    assert purl == expected
    assert purl == synthesize_purl(name, version, ecosystem)
    parsed = PackageURL.from_string(purl)
    assert parsed.to_string() == purl
    assert parsed.version == version


@pytest.mark.parametrize(("name", "version", "ecosystem", "expected"), CASES, ids=IDS)
def test_package_purl_prefers_synthesized_purl(name, version, ecosystem, expected):
    _assert_canonical(package_purl(name, version, ecosystem), name, version, ecosystem, expected)


def test_package_purl_fallback_is_spec_encoded_for_os_and_unlisted_types():
    # No distro namespace is known, so the best-effort purl carries none — but
    # the components are still percent-encoded instead of pasted raw.
    assert package_purl("libc6", "2.36-9+deb12u4", "deb") == "pkg:deb/libc6@2.36-9%2Bdeb12u4"
    assert package_purl("Phoenix", "1.7.0", "hex") == "pkg:hex/phoenix@1.7.0"
    assert package_purl("left-pad", "unknown", "npm") == "pkg:npm/left-pad@unknown"
    assert package_purl("left-pad", "", "npm") == "pkg:npm/left-pad"
    assert package_purl("", "1.0", "npm") is None
    assert package_purl("x", "1.0", "") is None


@pytest.mark.parametrize(("name", "version", "ecosystem", "expected"), CASES, ids=IDS)
def test_registry_version_fallback_emits_canonical_purl(name, version, ecosystem, expected):
    from agent_bom.resolver import _apply_registry_version_fallback

    pkg = Package(name=name, version="latest", ecosystem=ecosystem)
    pkg.registry_version = version
    assert _apply_registry_version_fallback(pkg) is True
    _assert_canonical(pkg.purl, name, version, ecosystem, expected)


@pytest.mark.asyncio
async def test_resolver_latest_lookup_emits_canonical_scoped_npm_purl():
    from agent_bom import resolver

    pkg = Package(name="@scope/name", version="latest", ecosystem="npm")
    with patch.object(resolver, "resolve_npm_metadata", AsyncMock(return_value=("1.0.0", "MIT"))):
        assert await resolver.resolve_package_version(pkg, AsyncMock()) is True
    _assert_canonical(pkg.purl, "@scope/name", "1.0.0", "npm", "pkg:npm/%40scope/name@1.0.0")


@pytest.mark.asyncio
async def test_resolver_latest_lookup_emits_canonical_maven_purl():
    from agent_bom import resolver

    pkg = Package(name="org.apache.commons:commons-text", version="latest", ecosystem="maven")
    with patch("agent_bom.version_utils.resolve_maven_metadata", AsyncMock(return_value=("1.10.0", None))):
        assert await resolver.resolve_package_version(pkg, AsyncMock()) is True
    _assert_canonical(pkg.purl, pkg.name, "1.10.0", "maven", "pkg:maven/org.apache.commons/commons-text@1.10.0")


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "version", "ecosystem", "expected"), CASES, ids=IDS)
async def test_deps_dev_transitive_packages_emit_canonical_purl(name, version, ecosystem, expected):
    from agent_bom import deps_dev

    parent = Package(name="root", version="1.0.0", ecosystem="npm")
    system = deps_dev.ECOSYSTEM_MAP[ecosystem]
    deps = [{"name": name, "version": version, "system": system, "relation": "DIRECT"}]
    with patch.object(deps_dev, "get_dependencies", AsyncMock(return_value=deps)):
        resolved = await deps_dev._resolve_one_package(parent, AsyncMock(), max_depth=3, seen=set())
    assert len(resolved) == 1
    _assert_canonical(resolved[0].purl, name, version, deps_dev._system_to_ecosystem(system), expected)


@pytest.mark.asyncio
async def test_deps_dev_package_reaches_cyclonedx_with_canonical_purl():
    """The Package.purl a producer sets is what CycloneDX publishes verbatim."""
    from agent_bom import deps_dev
    from agent_bom.models import Agent, AgentType, MCPServer
    from agent_bom.output.cyclonedx_fmt import to_cyclonedx

    parent = Package(name="root", version="1.0.0", ecosystem="maven")
    deps = [{"name": "org.apache.commons:commons-text", "version": "1.10.0", "system": "maven", "relation": "DIRECT"}]
    with patch.object(deps_dev, "get_dependencies", AsyncMock(return_value=deps)):
        (pkg,) = await deps_dev._resolve_one_package(parent, AsyncMock(), max_depth=3, seen=set())
    server = MCPServer(name="srv", command="java", packages=[pkg])
    agent = Agent(name="a", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp/x", mcp_servers=[server])
    doc = to_cyclonedx(AIBOMReport(agents=[agent]))
    purls = {c.get("purl") for c in doc.get("components", []) if c.get("type") == "library"}
    assert "pkg:maven/org.apache.commons/commons-text@1.10.0" in purls


def _tar_with_node_package(tmp_path: Path, name: str, version: str) -> Path:
    tar_path = tmp_path / "rootfs.tar"
    payload = json.dumps({"name": name, "version": version}).encode()
    with tarfile.open(tar_path, "w") as tf:
        info = tarfile.TarInfo(f"usr/lib/node_modules/{name}/package.json")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    return tar_path


def test_image_tar_node_package_emits_canonical_scoped_npm_purl(tmp_path):
    from agent_bom.image import _packages_from_tar

    packages = _packages_from_tar(_tar_with_node_package(tmp_path, "@scope/name", "1.0.0"))
    npm = [p for p in packages if p.ecosystem == "npm"]
    assert len(npm) == 1
    _assert_canonical(npm[0].purl, "@scope/name", "1.0.0", "npm", "pkg:npm/%40scope/name@1.0.0")


@pytest.mark.parametrize(("name", "version", "ecosystem", "expected"), CASES, ids=IDS)
def test_vex_product_for_purl_less_package_is_canonical(name, version, ecosystem, expected):
    from agent_bom.vex import generate_vex

    pkg = Package(name=name, version=version, ecosystem=ecosystem, purl=None)
    vuln = Vulnerability(id="CVE-2024-0001", summary="x", severity=Severity.HIGH)
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
    )
    doc = generate_vex(AIBOMReport(blast_radii=[br]))
    assert doc.statements[0].products == [expected]


@pytest.mark.parametrize(("name", "version", "ecosystem", "expected"), CASES, ids=IDS)
def test_snyk_lookup_purl_is_canonical(name, version, ecosystem, expected):
    from agent_bom.snyk import _purl_for_package

    _assert_canonical(_purl_for_package(Package(name=name, version=version, ecosystem=ecosystem)), name, version, ecosystem, expected)


def test_snyk_lookup_purl_versionless_and_unsupported():
    from agent_bom.snyk import _purl_for_package

    assert _purl_for_package(Package(name="@scope/name", version="latest", ecosystem="npm")) == "pkg:npm/%40scope/name"
    assert _purl_for_package(Package(name="PyYAML", version="unknown", ecosystem="PyPI")) == "pkg:pypi/pyyaml"
    assert _purl_for_package(Package(name="libc6", version="2.36", ecosystem="deb")) is None


@pytest.mark.parametrize(("name", "version", "ecosystem", "expected"), CASES, ids=IDS)
def test_registry_purl_is_canonical(name, version, ecosystem, expected):
    from agent_bom.parsers import _registry_purl

    _assert_canonical(_registry_purl(ecosystem, name, version), name, version, ecosystem, expected)


def test_hex_lockfile_purl_is_spec_normalized(tmp_path):
    from agent_bom.parsers.beam_parsers import parse_hex_packages

    (tmp_path / "mix.lock").write_text('%{\n  "phoenix": {:hex, :Phoenix, "1.7.0", "abc", [:mix], [], "hexpm", "def"},\n}\n')
    packages = parse_hex_packages(tmp_path)
    assert [p.purl for p in packages] == ["pkg:hex/phoenix@1.7.0"]


def test_conda_lock_pip_entry_purl_is_canonical(tmp_path):
    from agent_bom.parsers.compiled_parsers import parse_conda_packages

    (tmp_path / "conda-lock.yml").write_text(
        "version: 1\npackage:\n"
        "  - name: PyYAML\n    version: 6.0.1\n    manager: pip\n"
        "  - name: numpy\n    version: 1.26.4\n    manager: conda\n"
    )
    purls = {p.name: p.purl for p in parse_conda_packages(tmp_path)}
    assert purls["PyYAML"] == "pkg:pypi/pyyaml@6.0.1"
    assert purls["numpy"] == "pkg:conda/numpy@1.26.4"


@pytest.mark.asyncio
async def test_scan_packages_local_install_resolution_emits_canonical_purls(tmp_path, monkeypatch):
    from agent_bom.resolvers import runtime_resolver
    from agent_bom.scanners.package_scan import IncompleteScanError, default_scan_options, scan_packages

    monkeypatch.setattr(runtime_resolver, "resolve_npm_versions", lambda _path: {"@scope/name": "1.0.0"})
    monkeypatch.setattr(runtime_resolver, "resolve_go_versions", lambda _path: {GO_MODULE: "v1.2.3"})
    npm_pkg = Package(name="@scope/name", version="latest", ecosystem="npm")
    go_pkg = Package(name=GO_MODULE, version="latest", ecosystem="go")
    options = default_scan_options(offline=True, prefer_local_db=False, project_dir=str(tmp_path))
    # Local install resolution runs before advisory lookup; with no local DB the
    # offline scan then stops, which is irrelevant to the purls set here.
    with pytest.raises(IncompleteScanError):
        await scan_packages([npm_pkg, go_pkg], options=options)
    assert (npm_pkg.version, npm_pkg.version_source) == ("1.0.0", "installed")
    assert (go_pkg.version, go_pkg.version_source) == ("v1.2.3", "installed")
    _assert_canonical(npm_pkg.purl, "@scope/name", "1.0.0", "npm", "pkg:npm/%40scope/name@1.0.0")
    _assert_canonical(go_pkg.purl, GO_MODULE, "v1.2.3", "go", f"pkg:golang/{GO_MODULE}@v1.2.3")
