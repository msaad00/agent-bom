from __future__ import annotations

import asyncio

import pytest
from rich.console import Console

from agent_bom.enrichment_posture import (
    describe_enrichment_posture,
    enrichment_source_available,
    record_enrichment_source,
    reset_enrichment_posture_for_tests,
)
from agent_bom.models import Package
from agent_bom.scanners.osv import query_osv_batch_impl


def setup_function() -> None:
    reset_enrichment_posture_for_tests()


def test_enrichment_source_circuit_opens_after_consecutive_failures(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_ENRICHMENT_OSV_CIRCUIT_FAILURES", "2")
    monkeypatch.setenv("AGENT_BOM_ENRICHMENT_OSV_CIRCUIT_OPEN_SECONDS", "60")

    record_enrichment_source("osv", "failure", error="timeout")
    assert enrichment_source_available("osv") is True

    record_enrichment_source("osv", "failure", error="timeout")
    assert enrichment_source_available("osv") is False

    posture = describe_enrichment_posture()
    osv = next(source for source in posture["sources"] if source["source"] == "osv")
    assert posture["status"] == "circuit_open"
    assert osv["status"] == "circuit_open"
    assert osv["consecutive_failure_count"] == 2
    assert osv["circuit_open_until"]


def test_success_resets_circuit_state(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_ENRICHMENT_OSV_CIRCUIT_FAILURES", "1")

    record_enrichment_source("osv", "failure", error="HTTP 500")
    assert enrichment_source_available("osv") is False

    record_enrichment_source("osv", "success")
    assert enrichment_source_available("osv") is True

    osv = next(source for source in describe_enrichment_posture()["sources"] if source["source"] == "osv")
    assert osv["status"] == "ok"
    assert osv["consecutive_failure_count"] == 0
    assert osv["circuit_open_until"] is None


@pytest.mark.asyncio
async def test_osv_query_skips_remote_when_circuit_open(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_ENRICHMENT_OSV_CIRCUIT_FAILURES", "1")
    record_enrichment_source("osv", "failure", error="timeout")
    called = False
    warnings: list[str] = []

    async def request_with_retry(*args, **kwargs):  # noqa: ARG001
        nonlocal called
        called = True
        return None

    result = await query_osv_batch_impl(
        [Package(name="requests", version="2.31.0", ecosystem="pypi")],
        console=Console(file=None, force_terminal=False, quiet=True),
        get_scan_cache=lambda: None,
        get_api_semaphore=lambda: asyncio.Semaphore(1),
        bump_scan_perf=lambda _name, _count: None,
        enrich_results_if_needed_fn=lambda results: asyncio.sleep(0, result=results),
        record_scan_warning=warnings.append,
        osv_ecosystems_for_package=lambda _pkg: ["PyPI"],
        non_osv_ecosystems=frozenset(),
        request_with_retry_fn=request_with_retry,
    )

    assert result == {}
    assert called is False
    assert warnings == ["OSV enrichment circuit open"]
