from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from agent_bom.backpressure import (
    BackpressureController,
    BackpressureRejectedError,
    adaptive_backpressure,
    describe_backpressure_posture,
    reset_backpressure_for_tests,
)
from agent_bom.enrichment import enrich_vulnerabilities
from agent_bom.models import Severity, Vulnerability
from agent_bom.scanners.state import consume_scan_warnings, reset_scan_warnings


@pytest.fixture(autouse=True)
def _reset_backpressure(monkeypatch):
    reset_backpressure_for_tests()
    reset_scan_warnings()
    monkeypatch.delenv("AGENT_BOM_BACKPRESSURE_ENABLED", raising=False)
    monkeypatch.delenv("AGENT_BOM_BACKPRESSURE_GRAPH_CONCURRENCY", raising=False)
    monkeypatch.delenv("AGENT_BOM_BACKPRESSURE_GRAPH_P99_MS", raising=False)
    monkeypatch.delenv("AGENT_BOM_BACKPRESSURE_GRAPH_COOLDOWN_SECONDS", raising=False)
    monkeypatch.delenv("AGENT_BOM_BACKPRESSURE_GRAPH_MIN_SAMPLES", raising=False)
    monkeypatch.delenv("AGENT_BOM_BACKPRESSURE_ENRICHMENT_CONCURRENCY", raising=False)
    monkeypatch.delenv("AGENT_BOM_BACKPRESSURE_ENRICHMENT_P99_MS", raising=False)
    monkeypatch.delenv("AGENT_BOM_BACKPRESSURE_ENRICHMENT_COOLDOWN_SECONDS", raising=False)
    monkeypatch.delenv("AGENT_BOM_BACKPRESSURE_ENRICHMENT_MIN_SAMPLES", raising=False)
    yield
    reset_backpressure_for_tests()
    reset_scan_warnings()


def test_retry_after_seconds_adds_bounded_jitter(monkeypatch) -> None:
    controller = BackpressureController(
        path="graph",
        max_concurrency=1,
        p99_threshold_ms=1,
        cooldown_seconds=30,
        min_samples=1,
    )
    controller.open_until_monotonic = 110.0
    monkeypatch.setattr("agent_bom.backpressure.random.uniform", lambda low, high: high)

    # base = 10s, jitter_factor = 1.35 (mocked to high) → ceil(13.5) = 14.
    assert controller.retry_after_seconds(now=100.0) == 14


def test_retry_after_seconds_produces_distinct_values_at_base_one_second() -> None:
    # Regression: the original additive jitter (`int(base + uniform(0, base*0.3) + 0.999)`)
    # collapsed to a single value (2) for the most common case where base ≈ 1s
    # because the controller clamps base to max(1.0, ...). Multiplicative jitter
    # over [0.85, 1.35] must yield at least two distinct ceil values per call set.
    controller = BackpressureController(
        path="graph",
        max_concurrency=1,
        p99_threshold_ms=1,
        cooldown_seconds=1,
        min_samples=1,
    )
    controller.open_until_monotonic = 100.0
    samples = {controller.retry_after_seconds(now=99.5) for _ in range(64)}

    assert len(samples) >= 2, f"jitter collapsed to single value: {samples}"
    assert min(samples) >= 1
    assert max(samples) <= 3


@pytest.mark.asyncio
async def test_backpressure_records_normal_path_posture() -> None:
    async with adaptive_backpressure("graph"):
        await asyncio.sleep(0)

    posture = describe_backpressure_posture()
    graph = next(path for path in posture["paths"] if path["path"] == "graph")

    assert posture["status"] == "ready"
    assert graph["state"] == "closed"
    assert graph["completed"] == 1
    assert graph["rejected"] == 0


@pytest.mark.asyncio
async def test_backpressure_rejects_when_concurrency_is_saturated(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_BACKPRESSURE_GRAPH_CONCURRENCY", "1")

    async with adaptive_backpressure("graph"):
        with pytest.raises(BackpressureRejectedError) as exc:
            async with adaptive_backpressure("graph"):
                pass

    assert exc.value.reason == "concurrency_limit"
    posture = describe_backpressure_posture()
    graph = next(path for path in posture["paths"] if path["path"] == "graph")
    assert graph["rejected"] == 1


@pytest.mark.asyncio
async def test_backpressure_opens_after_p99_threshold_and_recovers(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_BACKPRESSURE_GRAPH_P99_MS", "1")
    monkeypatch.setenv("AGENT_BOM_BACKPRESSURE_GRAPH_MIN_SAMPLES", "1")
    monkeypatch.setenv("AGENT_BOM_BACKPRESSURE_GRAPH_COOLDOWN_SECONDS", "1")

    async with adaptive_backpressure("graph"):
        await asyncio.sleep(0.01)

    with pytest.raises(BackpressureRejectedError) as exc:
        async with adaptive_backpressure("graph"):
            pass

    assert exc.value.reason == "p99_latency_threshold"
    assert describe_backpressure_posture()["status"] == "active"

    await asyncio.sleep(1.05)
    async with adaptive_backpressure("graph"):
        pass

    posture = describe_backpressure_posture()
    graph = next(path for path in posture["paths"] if path["path"] == "graph")
    assert graph["state"] == "closed"


@pytest.mark.asyncio
async def test_enrichment_backpressure_sheds_with_scan_warning(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_BACKPRESSURE_ENRICHMENT_P99_MS", "1")
    monkeypatch.setenv("AGENT_BOM_BACKPRESSURE_ENRICHMENT_MIN_SAMPLES", "1")
    monkeypatch.setenv("AGENT_BOM_BACKPRESSURE_ENRICHMENT_COOLDOWN_SECONDS", "30")

    vuln = Vulnerability(id="CVE-2026-0001", summary="test", severity=Severity.HIGH)
    calls = 0

    async def _slow_epss(cve_ids, client):  # noqa: ARG001
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.01)
        return {}

    with (
        patch("agent_bom.enrichment.fetch_epss_scores", side_effect=_slow_epss),
        patch("agent_bom.enrichment.fetch_cisa_kev_catalog", return_value={}),
        patch("agent_bom.enrichment._save_enrichment_cache"),
    ):
        first = await enrich_vulnerabilities([vuln], enable_nvd=False, enable_epss=True, enable_kev=False)
        second = await enrich_vulnerabilities([vuln], enable_nvd=False, enable_epss=True, enable_kev=False)

    assert first == 0
    assert second == 0
    assert calls == 1
    assert "external enrichment skipped by adaptive backpressure" in consume_scan_warnings()

    posture = describe_backpressure_posture()
    enrichment = next(path for path in posture["paths"] if path["path"] == "enrichment")
    assert enrichment["state"] == "open"
    assert enrichment["reason"] == "p99_latency_threshold"
