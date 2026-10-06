"""Only complete OSV lookup evidence may survive as a cached verdict."""

import asyncio
import io
import json
import time
from contextlib import asynccontextmanager

import httpx
import pytest
from rich.console import Console

from agent_bom.models import Package
from agent_bom.scan_cache import ScanCache
from agent_bom.scanners import osv, state


@pytest.fixture
def cache(tmp_path):
    instance = ScanCache(tmp_path / "cache.db")
    yield instance
    instance._conn.close()


async def query(cache, packages, payloads, monkeypatch, *, ecosystems=None, available=True):
    state.reset_scan_warnings()
    monkeypatch.setattr(osv, "enrichment_source_available", lambda _: available)
    calls = []

    @asynccontextmanager
    async def client(**kwargs):
        yield None

    async def request(*args, **kwargs):
        calls.append(kwargs["json"])
        payload = payloads.pop(0)
        return None if payload is None else httpx.Response(200, json=payload)

    async def enrich(results):
        return results

    result = await osv.query_osv_batch_impl(
        packages,
        console=Console(file=io.StringIO()),
        get_scan_cache=lambda: cache,
        get_api_semaphore=lambda: asyncio.Semaphore(1),
        bump_scan_perf=lambda *args: None,
        enrich_results_if_needed_fn=enrich,
        record_scan_warning=state.record_scan_warning,
        osv_ecosystems_for_package=ecosystems or (lambda _: ["PyPI"]),
        non_osv_ecosystems=frozenset(),
        create_client_fn=client,
        request_with_retry_fn=request,
    )
    return result, calls


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [None, {}, {"results": []}, {"results": [None]}, {"results": [{"vulns": None}]}, {"results": [{"vulns": [{}]}]}, {"results": [{}, {}]}],
)
async def test_failed_or_malformed_lookup_is_not_cached_and_retries(cache, monkeypatch, payload):
    package = Package(name="requests", version="2.19.0", ecosystem="pypi")
    await query(cache, [package], [payload], monkeypatch)
    assert cache.get("pypi", "requests", "2.19.0") is None
    assert any(w.get("kind") == "remote_lookup_error" for w in state.peek_coverage_warnings())
    result, calls = await query(cache, [package], [{"results": [{"vulns": [{"id": "GHSA-recovered"}]}]}], monkeypatch)
    assert len(calls) == 1
    assert result["pypi:requests@2.19.0"] == [{"id": "GHSA-recovered"}]


@pytest.mark.asyncio
async def test_successful_clean_lookup_is_cached(cache, monkeypatch):
    package = Package(name="safe", version="1.0", ecosystem="pypi")
    await query(cache, [package], [{"results": [{}]}], monkeypatch)
    assert cache.get("pypi", "safe", "1.0") == []
    result, calls = await query(cache, [package], [], monkeypatch)
    assert result == {} and calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "ecosystem,name,query_name,osv_ecosystem",
    [
        ("go", "github.com/Azure/azure-sdk-for-go", "github.com/Azure/azure-sdk-for-go", "Go"),
        ("nuget", "System.Text.Encodings.Web", "System.Text.Encodings.Web", "NuGet"),
        ("pypi", "Django_REST_Framework", "django-rest-framework", "PyPI"),
    ],
)
async def test_query_spelling_preserves_ecosystem_case_without_changing_identity(
    cache, monkeypatch, ecosystem, name, query_name, osv_ecosystem
):
    from agent_bom.core.packages import normalize_package_name

    package = Package(name=name, version="1.0.0", ecosystem=ecosystem)
    vulnerability = {"id": "GHSA-known"}
    result, calls = await query(
        cache, [package], [{"results": [{"vulns": [vulnerability]}]}], monkeypatch, ecosystems=lambda _: [osv_ecosystem]
    )
    assert calls[0]["queries"][0]["package"] == {"name": query_name, "ecosystem": osv_ecosystem}
    normalized = normalize_package_name(name, ecosystem)
    assert result == {f"{ecosystem}:{normalized}@1.0.0": [vulnerability]}
    assert cache.get(ecosystem, normalized, "1.0.0") == [vulnerability]
    assert osv.package_lookup_names(package) == [normalized]
    cached_result, cached_calls = await query(cache, [package], [], monkeypatch, ecosystems=lambda _: [osv_ecosystem])
    assert cached_calls == []
    assert cached_result == result


@pytest.mark.asyncio
async def test_open_circuit_keeps_uncached_packages_incomplete(cache, monkeypatch):
    package = Package(name="requests", version="2.19.0", ecosystem="pypi")
    result, calls = await query(cache, [package], [], monkeypatch, available=False)
    assert result == {} and calls == []
    assert cache.get("pypi", "requests", "2.19.0") is None
    assert any(w.get("kind") == "remote_lookup_error" for w in state.peek_coverage_warnings())


@pytest.mark.asyncio
async def test_paginated_result_keeps_findings_but_is_not_cached(cache, monkeypatch):
    package = Package(name="requests", version="2.19.0", ecosystem="pypi")
    payload = {"results": [{"vulns": [{"id": "GHSA-known"}], "next_page_token": "more"}]}
    result, _ = await query(cache, [package], [payload], monkeypatch)
    assert result["pypi:requests@2.19.0"] == [{"id": "GHSA-known"}]
    assert cache.get("pypi", "requests", "2.19.0") is None
    assert state.peek_coverage_warnings()


@pytest.mark.asyncio
async def test_mixed_batches_cache_only_complete_packages(cache, monkeypatch):
    monkeypatch.setattr(osv, "_BATCH_SIZE", 1)
    packages = [Package(name="same", version=v, ecosystem="pypi") for v in ("1.0", "2.0")]
    await query(cache, packages, [{"results": [{}]}, None], monkeypatch)
    assert cache.get("pypi", "same", "1.0") == []
    assert cache.get("pypi", "same", "2.0") is None


@pytest.mark.asyncio
@pytest.mark.parametrize("aliases", [False, True])
async def test_every_alias_and_ecosystem_must_complete(cache, monkeypatch, aliases):
    monkeypatch.setattr(osv, "_BATCH_SIZE", 1)
    package = Package(name="binary", version="1.0", ecosystem="pypi")
    if aliases:
        monkeypatch.setattr(osv, "package_lookup_names", lambda _: ["binary", "source"])
    ecosystems = (lambda _: ["PyPI"]) if aliases else (lambda _: ["PyPI", "Other"])
    result, _ = await query(cache, [package], [{"results": [{"vulns": [{"id": "GHSA-known"}]}]}, None], monkeypatch, ecosystems=ecosystems)
    assert result["pypi:binary@1.0"] == [{"id": "GHSA-known"}]
    assert cache.get("pypi" if aliases else "pypi|PyPI|Other", "binary", "1.0") is None


@pytest.mark.asyncio
async def test_truncated_batch_preserves_known_findings_without_caching(cache, monkeypatch):
    packages = [Package(name=name, version="1.0", ecosystem="pypi") for name in ("one", "two")]
    result, _ = await query(cache, packages, [{"results": [{"vulns": [{"id": "GHSA-known"}]}]}], monkeypatch)
    assert result["pypi:one@1.0"] == [{"id": "GHSA-known"}]
    assert cache.size == 0
    assert state.peek_coverage_warnings()


def test_legacy_entries_are_retained_but_never_used_as_current_evidence(cache):
    for name, vulns in (("clean", []), ("partial", [{"id": "GHSA-known"}])):
        cache._conn.execute("INSERT INTO osv_cache VALUES (?, ?, ?)", (f"pypi:{name}@1.0", json.dumps(vulns), time.time()))
    cache._conn.commit()
    assert cache.get("pypi", "clean", "1.0") is None
    assert cache.get("pypi", "partial", "1.0") is None
    assert cache._conn.execute("SELECT COUNT(*) FROM osv_cache").fetchone()[0] == 2
    cache.put("pypi", "clean", "1.0", [])
    assert cache.get("pypi", "clean", "1.0") == []
    assert cache._conn.execute("SELECT COUNT(*) FROM osv_cache").fetchone()[0] == 3


def test_lookup_warning_never_prints_clean_cli_verdict():
    from types import SimpleNamespace

    from agent_bom.cli.agents.scan_pipeline.matching import _print_scan_verdict
    from agent_bom.cli.agents.scan_pipeline.state import ScanState

    output = io.StringIO()
    scan = ScanState(con=Console(file=output), scan_warnings=["1 package lookup error(s)"])
    _print_scan_verdict(SimpleNamespace(offline=False), scan, 0)
    assert "No known vulnerabilities found" not in output.getvalue()
    assert "lookup warnings" in output.getvalue()
