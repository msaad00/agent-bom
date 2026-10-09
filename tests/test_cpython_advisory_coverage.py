"""Runtime advisory lookups must establish identity and preserve unknowns."""

import hashlib
import io
import json
import tarfile

import httpx
import pytest

from agent_bom import http_client
from agent_bom.models import Agent, AgentType, MCPServer, Package
from agent_bom.oci_parser import LayerMetadata, _extract_packages_from_layer
from agent_bom.scanners import ScanOptions, scan_agents, scan_packages
from agent_bom.scanners.state import peek_coverage_warnings, reset_scan_warnings

REPO = "https://github.com/python/cpython"
ADVISORY = {
    "id": "PSF-2026-40",
    "aliases": ["CVE-2026-87910"],
    "summary": "Tarfile filter rejection ignored",
    "affected": [
        {"ranges": [{"type": "GIT", "repo": REPO, "events": [{"introduced": "0"}, {"fixed": "a" * 40}]}], "versions": ["v3.14.8"]}
    ],
}


@pytest.fixture(autouse=True)
def warning_boundary():
    reset_scan_warnings()
    yield
    reset_scan_warnings()


def runtime():
    return Package(
        name="cpython",
        version="3.14.8",
        ecosystem="generic",
        version_source="installed_package",
        version_evidence=[{"type": "installed_metadata", "source_file": "usr/local/include/python3.14/patchlevel.h"}],
    )


def transport(monkeypatch, response, header='#define PY_VERSION "3.14.8"\n'):
    requests = []

    def handle(request):
        requests.append(request)
        if request.url.host == "raw.githubusercontent.com":
            return httpx.Response(200, text=header)
        return httpx.Response(200, json=response)

    monkeypatch.setattr(http_client, "create_client", lambda **kw: httpx.AsyncClient(transport=httpx.MockTransport(handle)))

    # Keep transport validation/retry tests in their owning suite; this is an
    # offline protocol fixture with no DNS dependency.
    async def request(client, method, url, **kw):
        return await client.request(method, url, **kw)

    monkeypatch.setattr(http_client, "request_with_retry", request)
    return requests


@pytest.mark.asyncio
async def test_runtime_scan_uses_verified_upstream_git_tag_not_pypi(monkeypatch):
    requests = transport(monkeypatch, {"vulns": [ADVISORY]})
    package = runtime()
    assert await scan_packages([package]) == 1
    assert package.vulnerabilities[0].id == "CVE-2026-87910"
    assert package.vulnerabilities[0].fixed_version is None
    assert not peek_coverage_warnings()
    assert json.loads(requests[1].content) == {"package": {"name": REPO, "ecosystem": "GIT"}, "version": "v3.14.8"}


@pytest.mark.asyncio
async def test_empty_lookup_requires_verified_release_identity(monkeypatch):
    transport(monkeypatch, {}, header='#define PY_VERSION "3.14.7"\n')
    assert await scan_packages([runtime()]) == 0
    assert peek_coverage_warnings()[0]["reason"] == "runtime_advisory_coverage_unknown"


@pytest.mark.asyncio
async def test_offline_runtime_stays_unknown_without_network(monkeypatch):
    requests = transport(monkeypatch, {})
    assert await scan_packages([runtime()], options=ScanOptions(offline=True)) == 0
    assert not requests
    assert peek_coverage_warnings()[0]["reason"] == "runtime_advisory_coverage_unknown"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [{"vulns": None}, {"vulns": [{}]}, {"vulns": [dict(ADVISORY, affected=[])]}, {"next_page_token": "same"}, {"error": "failure"}],
)
async def test_incomplete_or_unscoped_answers_are_not_clean(monkeypatch, response):
    transport(monkeypatch, response)
    assert await scan_packages([runtime()]) == 0
    assert peek_coverage_warnings()[0]["reason"] == "runtime_advisory_coverage_unknown"


@pytest.mark.asyncio
async def test_verified_release_with_no_returned_advisories_records_lookup_scope(monkeypatch):
    transport(monkeypatch, {})
    package = runtime()
    assert await scan_packages([package]) == 0
    assert not peek_coverage_warnings()
    assert package.version_evidence[-1]["assessment"] == "upstream_release_lookup_complete"


@pytest.mark.asyncio
async def test_imported_hash_claim_cannot_hide_a_runtime_finding(monkeypatch):
    from agent_bom.scanners.cpython_advisory import _TARFILE_FIX

    transport(monkeypatch, {"vulns": [ADVISORY]})
    package = runtime()
    package.version_evidence.append(
        {"type": "runtime_source_sha256", "source_file": "usr/local/lib/python3.14/tarfile.py", "sha256": _TARFILE_FIX}
    )
    assert await scan_packages([package]) == 1


def image_runtime(layers):
    packages, index = [], {}
    for number, files in enumerate(layers):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as archive:
            for name, body in files.items():
                member = tarfile.TarInfo(name)
                if body is None:
                    member.type = tarfile.SYMTYPE
                    member.linkname = "elsewhere.py"
                    archive.addfile(member)
                else:
                    data = body.encode()
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
        buf.seek(0)
        with tarfile.open(fileobj=buf) as archive:
            _extract_packages_from_layer(
                archive, index, packages, set(), LayerMetadata(layer_index=number, layer_id=f"sha256:{number}", layer_path="layer"), [], []
            )
    return packages[0]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "replacement", [None, "modified", "symlink", "whiteout", "opaque", "new_header", "parent_symlink", "directory_whiteout"]
)
async def test_only_effective_measured_source_establishes_backport(monkeypatch, replacement):
    from agent_bom.scanners import cpython_advisory

    fixed = "verified source fixture"
    monkeypatch.setattr(cpython_advisory, "_TARFILE_FIX", hashlib.sha256(fixed.encode()).hexdigest())
    transport(monkeypatch, {"vulns": [ADVISORY]})
    header = "usr/local/include/python3.14/patchlevel.h"
    module = "usr/local/lib/python3.14/tarfile.py"
    layers = [{header: '#define PY_VERSION "3.14.8"\n', module: fixed}]
    if replacement == "modified":
        layers.append({module: "other source"})
    if replacement == "symlink":
        layers.append({module: None})
    if replacement == "whiteout":
        layers.append({"usr/local/lib/python3.14/.wh.tarfile.py": ""})
    if replacement == "opaque":
        layers.append({"usr/local/lib/python3.14/.wh..wh..opq": ""})
    if replacement == "parent_symlink":
        layers.append({"usr/local/lib/python3.14": None})
    if replacement == "directory_whiteout":
        layers.append({"usr/local/lib/.wh.python3.14": ""})
    if replacement == "new_header":
        layers.append({header: '#define PY_VERSION "3.14.8"\n'})
    package = image_runtime(layers)
    assert await scan_packages([package]) == (0 if replacement is None else 1)
    receipts = [item for item in package.version_evidence if item["type"] == "runtime_advisory_fix"]
    assert bool(receipts) is (replacement is None)
    if receipts:
        from agent_bom.asset_provenance import package_version_provenance

        published = package_version_provenance(package)["evidence"]
        receipt = next(item for item in published if item["type"] == "runtime_advisory_fix")
        assert receipt["advisory_id"] == "CVE-2026-87910"
        assert receipt["status"] == "fixed_source_observed"
        assert receipt["upstream_fix"].startswith(REPO + "/commit/")
        lookup = next(item for item in published if item["type"] == "runtime_advisory_lookup")
        assert lookup["tag"] == "v3.14.8"
        assert lookup["advisory_count"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("fixed_first", [True, False])
async def test_backport_does_not_hide_same_version_in_another_image(monkeypatch, fixed_first):
    from agent_bom.scanners import cpython_advisory

    fixed = "verified source fixture"
    monkeypatch.setattr(cpython_advisory, "_TARFILE_FIX", hashlib.sha256(fixed.encode()).hexdigest())
    transport(monkeypatch, {"vulns": [ADVISORY]})
    patched = image_runtime(
        [
            {
                "usr/local/include/python3.14/patchlevel.h": '#define PY_VERSION "3.14.8"\n',
                "usr/local/lib/python3.14/tarfile.py": fixed,
            }
        ]
    )
    unpatched = runtime()
    packages = [patched, unpatched] if fixed_first else [unpatched, patched]
    servers = [MCPServer(name=f"image-{index}", packages=[package]) for index, package in enumerate(packages)]
    agent = Agent(name="images", agent_type=AgentType.CUSTOM, config_path="", mcp_servers=servers)
    findings = await scan_agents([agent], show_scan_banner=False)
    assert not patched.vulnerabilities
    assert [v.id for v in unpatched.vulnerabilities] == ["CVE-2026-87910"]
    assert len(findings) == 1
    assert findings[0].affected_servers == [servers[packages.index(unpatched)]]


@pytest.mark.asyncio
async def test_upstream_timeout_is_unknown_and_does_not_leak_error(monkeypatch):
    transport(monkeypatch, {})

    async def timeout(*args, **kwargs):
        raise httpx.ReadTimeout("private-token-must-not-leak")

    monkeypatch.setattr(http_client, "request_with_retry", timeout)
    assert await scan_packages([runtime()]) == 0
    warnings = peek_coverage_warnings()
    assert warnings[0]["reason"] == "runtime_advisory_coverage_unknown"
    assert "private-token" not in json.dumps(warnings)


@pytest.mark.asyncio
async def test_identical_runtime_instances_each_retain_current_lookup_receipts(monkeypatch):
    transport(monkeypatch, {})
    packages = [runtime(), runtime()]
    packages[1].version_evidence.append({"type": "runtime_advisory_fix", "advisory_id": "stale"})
    servers = [MCPServer(name=f"image-{index}", packages=[package]) for index, package in enumerate(packages)]
    agent = Agent(name="images", agent_type=AgentType.CUSTOM, config_path="", mcp_servers=servers)
    await scan_agents([agent], show_scan_banner=False)
    for package in packages:
        assert any(item.get("assessment") == "upstream_release_lookup_complete" for item in package.version_evidence)
        assert not any(item.get("advisory_id") == "stale" for item in package.version_evidence)


def _advisory_with_release_events(events):
    advisory = json.loads(json.dumps(ADVISORY))
    advisory["affected"][0]["ranges"][0]["database_specific"] = {"extracted_events": events, "source": ["AFFECTED_FIELD"]}
    return advisory


@pytest.mark.asyncio
async def test_runtime_fix_comes_from_the_release_window_containing_the_install(monkeypatch):
    # OSV's GIT range carries only commit SHAs; the release-numbered windows
    # live in ``database_specific.extracted_events`` (CVE-2025-8194 shape).
    events = [
        {"introduced": "0"},
        {"fixed": "3.9.24"},
        {"introduced": "3.13.0"},
        {"fixed": "3.13.6"},
        {"introduced": "3.14.0a1"},
        {"fixed": "3.14.9"},
    ]
    transport(monkeypatch, {"vulns": [_advisory_with_release_events(events)]})
    package = runtime()

    assert await scan_packages([package]) == 1

    assert package.vulnerabilities[0].fixed_version == "3.14.9"


@pytest.mark.asyncio
async def test_runtime_fix_stays_unknown_when_no_release_window_contains_the_install(monkeypatch):
    events = [{"introduced": "0"}, {"fixed": "3.9.24"}, {"introduced": "3.13.0"}, {"fixed": "3.13.6"}]
    transport(monkeypatch, {"vulns": [_advisory_with_release_events(events)]})
    package = runtime()

    assert await scan_packages([package]) == 1

    assert package.vulnerabilities[0].fixed_version is None
