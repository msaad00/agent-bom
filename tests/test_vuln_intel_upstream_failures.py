"""Vulnerability-intel clients turn every upstream failure into a typed, visible gap.

Covers OSV (batch query + advisory details), NVD, EPSS and CISA KEV against
HTTP 429, 5xx, exhausted retries (timeout / connection: ``request_with_retry``
returns ``None``), DNS/egress refusal (``SecurityError``) and malformed JSON.
A failure may degrade coverage; it must never read as an empty, clean answer.
"""

from __future__ import annotations

import asyncio
import io
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from rich.console import Console

from agent_bom import enrichment
from agent_bom.core.errors import (
    UpstreamError,
    UpstreamInvalidResponseError,
    UpstreamRateLimitedError,
    UpstreamUnavailableError,
)
from agent_bom.models import Package, Severity, Vulnerability
from agent_bom.scanners import osv
from agent_bom.scanners import state as scanner_state
from agent_bom.security import SecurityError


@pytest.fixture(autouse=True)
def _clean_scanner_state():
    scanner_state.reset_scan_warnings()
    yield
    scanner_state.reset_scan_warnings()


def _response(status: int, payload: Any = None, headers: dict[str, str] | None = None) -> httpx.Response:
    request = httpx.Request("GET", "https://example.invalid/")
    if payload is None:
        return httpx.Response(status, headers=headers, request=request)
    return httpx.Response(status, json=payload, headers=headers, request=request)


def _fake_request(outcome: Any):
    async def _request(*_args: Any, **_kwargs: Any) -> httpx.Response | None:
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    return _request


FAILURES = [
    pytest.param(_response(429, headers={"Retry-After": "0"}), UpstreamRateLimitedError, id="429"),
    pytest.param(_response(503), UpstreamUnavailableError, id="5xx"),
    pytest.param(None, UpstreamUnavailableError, id="timeout-exhausted"),
    pytest.param(SecurityError("Cannot resolve hostname: api.example"), UpstreamUnavailableError, id="dns"),
]


# ── OSV batch query ───────────────────────────────────────────────────────


@asynccontextmanager
async def _null_client(**_kwargs: Any):
    yield AsyncMock()


async def _identity(results: dict) -> dict:
    return results


def _query_osv(outcome: Any) -> tuple[dict, list[str]]:
    warnings: list[str] = []

    async def _run() -> dict:
        return await osv.query_osv_batch_impl(
            [Package(name="jinja2", version="3.1.2", ecosystem="pypi")],
            console=Console(file=io.StringIO()),
            get_scan_cache=lambda: None,
            get_api_semaphore=lambda: asyncio.Semaphore(4),
            bump_scan_perf=lambda _key, _delta: None,
            enrich_results_if_needed_fn=_identity,
            record_scan_warning=warnings.append,
            osv_ecosystems_for_package=lambda _pkg: ["PyPI"],
            non_osv_ecosystems=frozenset(),
            create_client_fn=_null_client,
            request_with_retry_fn=_fake_request(outcome),
        )

    return asyncio.run(_run()), warnings


@pytest.mark.parametrize(
    ("outcome", "kind"),
    [
        *FAILURES,
        pytest.param(_response(200, {"results": ["not-an-object"]}), UpstreamInvalidResponseError, id="malformed-shape"),
        pytest.param(_response(200, ["not", "an", "object"]), UpstreamInvalidResponseError, id="malformed-root"),
    ],
)
def test_osv_batch_failure_is_a_typed_coverage_gap_not_a_crash_or_clean(outcome, kind):
    results, warnings = _query_osv(outcome)

    assert results == {}
    assert warnings == ["1 package lookup error(s)"]
    [coverage] = scanner_state.peek_coverage_warnings()
    assert coverage["kind"] == "remote_lookup_error"
    assert coverage["release"] == "remote:osv"
    assert coverage["package_count"] == 1
    assert coverage["reasons"] == [kind.kind]


def test_osv_batch_success_is_unchanged():
    results, warnings = _query_osv(_response(200, {"results": [{"vulns": [{"id": "GHSA-x", "modified": "2024"}]}]}))
    assert results == {"pypi:jinja2@3.1.2": [{"id": "GHSA-x", "modified": "2024"}]}
    assert warnings == []
    assert scanner_state.peek_coverage_warnings() == []


# ── OSV advisory details ──────────────────────────────────────────────────


def _enrich_details(outcome: Any) -> tuple[dict, list[str]]:
    warnings: list[str] = []
    results = {"pypi:jinja2@3.1.2": [{"id": "GHSA-x", "modified": "2024"}]}

    async def _run() -> dict:
        return await osv.enrich_results_if_needed(
            results,
            console=Console(file=io.StringIO()),
            record_scan_warning=warnings.append,
            create_client_fn=_null_client,
            request_with_retry_fn=_fake_request(outcome),
        )

    return asyncio.run(_run()), warnings


@pytest.mark.parametrize(
    ("outcome", "kind"),
    [*FAILURES, pytest.param(_response(200, ["not-an-advisory"]), UpstreamInvalidResponseError, id="malformed")],
)
def test_osv_detail_failures_are_recorded_instead_of_silently_dropped(outcome, kind):
    results, warnings = _enrich_details(outcome)

    assert results["pypi:jinja2@3.1.2"] == [{"id": "GHSA-x", "modified": "2024"}]
    assert warnings == [f"OSV advisory details incomplete: 1 of 1 advisory record(s) not retrieved ({kind.kind})"]


def test_osv_detail_404_is_a_withdrawn_advisory_not_a_gap():
    _results, warnings = _enrich_details(_response(404))
    assert warnings == []


def test_osv_detail_success_is_unchanged():
    results, warnings = _enrich_details(_response(200, {"id": "GHSA-x", "summary": "s", "affected": []}))
    assert results["pypi:jinja2@3.1.2"] == [{"id": "GHSA-x", "modified": "2024", "summary": "s", "affected": []}]
    assert warnings == []


# ── NVD / EPSS / KEV fetchers ─────────────────────────────────────────────


@pytest.fixture
def _cold_enrichment_caches(tmp_path):
    with (
        patch.object(enrichment, "_load_enrichment_cache"),
        patch.object(enrichment, "_save_enrichment_cache"),
        patch.object(enrichment, "_nvd_file_cache", {}),
        patch.object(enrichment, "_epss_file_cache", {}),
        patch.object(enrichment, "_kev_cache", None),
        patch.object(enrichment, "_kev_cache_time", None),
        patch.object(enrichment, "_KEV_CACHE_FILE", tmp_path / "kev.json"),
        patch.object(enrichment, "_cached_epss_scores", return_value={}),
        patch.object(enrichment, "_cached_kev_catalog", return_value={}),
    ):
        yield


NVD_FAILURES = [
    *FAILURES,
    pytest.param(_response(403), UpstreamRateLimitedError, id="nvd-403-throttle"),
    pytest.param(_response(200, {"vulnerabilities": ["not-an-object"]}), UpstreamInvalidResponseError, id="malformed"),
]


@pytest.mark.usefixtures("_cold_enrichment_caches")
@pytest.mark.parametrize(("outcome", "kind"), NVD_FAILURES)
def test_nvd_failures_are_typed(outcome, kind):
    errors: list[UpstreamError] = []
    with patch.object(enrichment, "request_with_retry", _fake_request(outcome)):
        result = asyncio.run(enrichment.fetch_nvd_data("CVE-2024-0001", AsyncMock(), errors=errors))
    assert result is None
    assert [type(error) for error in errors] == [kind]
    assert errors[0].source == "nvd"


@pytest.mark.usefixtures("_cold_enrichment_caches")
def test_nvd_not_found_is_an_answer_not_an_error():
    errors: list[UpstreamError] = []
    with patch.object(enrichment, "request_with_retry", _fake_request(_response(404))):
        assert asyncio.run(enrichment.fetch_nvd_data("CVE-2024-0001", AsyncMock(), errors=errors)) is None
    assert errors == []


@pytest.mark.usefixtures("_cold_enrichment_caches")
@pytest.mark.parametrize(
    ("outcome", "kind"),
    [*FAILURES, pytest.param(_response(200, {"data": ["not-an-object"]}), UpstreamInvalidResponseError, id="malformed")],
)
def test_epss_failures_are_typed(outcome, kind):
    errors: list[UpstreamError] = []
    with patch.object(enrichment, "request_with_retry", _fake_request(outcome)):
        result = asyncio.run(enrichment.fetch_epss_scores(["CVE-2024-0001"], AsyncMock(), errors=errors))
    assert result == {}
    assert [type(error) for error in errors] == [kind]
    assert errors[0].source == "epss"


@pytest.mark.usefixtures("_cold_enrichment_caches")
@pytest.mark.parametrize(
    ("outcome", "kind"),
    [
        *FAILURES,
        pytest.param(_response(200, ["not-an-object"]), UpstreamInvalidResponseError, id="malformed-root"),
        pytest.param(_response(200, {"vulnerabilities": ["x"]}), UpstreamInvalidResponseError, id="malformed-entry"),
    ],
)
def test_kev_failures_are_typed(outcome, kind):
    errors: list[UpstreamError] = []
    with patch.object(enrichment, "request_with_retry", _fake_request(outcome)):
        result = asyncio.run(enrichment.fetch_cisa_kev_catalog(AsyncMock(), errors=errors))
    assert result == {}
    assert [type(error) for error in errors] == [kind]
    assert errors[0].source == "cisa_kev"


@pytest.mark.usefixtures("_cold_enrichment_caches")
def test_fetchers_success_paths_are_unchanged():
    kev_payload = {"vulnerabilities": [{"cveID": "CVE-2024-0001", "dateAdded": "2024-01-01"}]}
    errors: list[UpstreamError] = []
    with patch.object(enrichment, "request_with_retry", _fake_request(_response(200, kev_payload))):
        kev = asyncio.run(enrichment.fetch_cisa_kev_catalog(AsyncMock(), errors=errors))
    assert kev["CVE-2024-0001"]["date_added"] == "2024-01-01"
    epss_payload = {"data": [{"cve": "CVE-2024-0001", "epss": "0.5", "percentile": "0.9", "date": "2024-01-01"}]}
    with patch.object(enrichment, "request_with_retry", _fake_request(_response(200, epss_payload))):
        epss = asyncio.run(enrichment.fetch_epss_scores(["CVE-2024-0001"], AsyncMock(), errors=errors))
    assert epss == {"CVE-2024-0001": {"score": 0.5, "percentile": 0.9, "date": "2024-01-01"}}
    nvd_payload = {"vulnerabilities": [{"cve": {"id": "CVE-2024-0001"}}]}
    with patch.object(enrichment, "request_with_retry", _fake_request(_response(200, nvd_payload))):
        nvd = asyncio.run(enrichment.fetch_nvd_data("CVE-2024-0001", AsyncMock(), errors=errors))
    assert nvd == {"id": "CVE-2024-0001"}
    assert errors == []


# ── enrich_vulnerabilities end to end ─────────────────────────────────────


def _enrich_all(outcome: Any) -> tuple[Vulnerability, str]:
    vuln = Vulnerability(id="CVE-2024-0001", summary="s", severity=Severity.HIGH)
    buffer = io.StringIO()
    with (
        patch.object(enrichment, "request_with_retry", _fake_request(outcome)),
        patch.object(enrichment, "console", Console(file=buffer, width=200)),
    ):
        asyncio.run(enrichment.enrich_vulnerabilities([vuln], enable_nvd=True, enable_epss=True, enable_kev=True))
    return vuln, buffer.getvalue()


@pytest.mark.usefixtures("_cold_enrichment_caches")
@pytest.mark.parametrize(("outcome", "kind"), FAILURES)
def test_enrichment_outage_is_a_scan_warning_and_never_a_green_kev_verdict(outcome, kind):
    vuln, output = _enrich_all(outcome)

    assert vuln.is_kev is False
    assert "no actively exploited CVEs" not in output
    assert "KEV data unavailable" in output
    warnings = scanner_state.consume_scan_warnings()
    assert f"CISA KEV incomplete: 1 of 1 catalog(s) not retrieved ({kind.kind})" in warnings
    assert f"EPSS incomplete: 1 of 1 CVE(s) not retrieved ({kind.kind})" in warnings
    assert f"NVD incomplete: 1 of 1 CVE(s) not retrieved ({kind.kind})" in warnings


@pytest.mark.usefixtures("_cold_enrichment_caches")
def test_enrichment_success_records_no_warning():
    def _route(*_args: Any, **kwargs: Any) -> httpx.Response:
        url = _args[2]
        if url == enrichment.CISA_KEV_URL:
            return _response(200, {"vulnerabilities": []})
        if url == enrichment.EPSS_API_URL:
            return _response(200, {"data": []})
        return _response(200, {"vulnerabilities": [{"cve": {"id": "CVE-2024-0001"}}]})

    async def _request(*args: Any, **kwargs: Any) -> httpx.Response:
        return _route(*args, **kwargs)

    vuln = Vulnerability(id="CVE-2024-0001", summary="s", severity=Severity.HIGH)
    buffer = io.StringIO()
    with patch.object(enrichment, "request_with_retry", _request), patch.object(enrichment, "console", Console(file=buffer, width=200)):
        asyncio.run(enrichment.enrich_vulnerabilities([vuln]))
    assert "no actively exploited CVEs" in buffer.getvalue()
    assert scanner_state.consume_scan_warnings() == []
