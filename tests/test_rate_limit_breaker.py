"""Tests for the registry rate-limit circuit breaker.

Simulates sustained HTTP 429s from a registry and asserts that:
  * the breaker trips after the configured threshold,
  * subsequent lookups short-circuit to the cached/bundled fallback path
    without issuing further HTTP requests,
  * no per-package "exhausted retries" warning storm is emitted, and
  * the resolver renders a single honest summary line.
"""

from __future__ import annotations

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock

import pytest

import agent_bom.http_client as http_client
from agent_bom.http_client import (
    RATE_LIMIT_BREAKER_THRESHOLD,
    registry_breaker_tripped,
    request_with_retry,
    reset_rate_limit_breaker,
    sync_request_with_retry,
)

NPM = "https://registry.npmjs.org"


@pytest.fixture(autouse=True)
def _reset_breaker_and_validation(monkeypatch):
    monkeypatch.setattr("agent_bom.security.validate_url", lambda _url: None)
    reset_rate_limit_breaker()
    yield
    reset_rate_limit_breaker()


def _mk_429() -> MagicMock:
    resp = MagicMock()
    resp.status_code = 429
    resp.headers = {}
    return resp


def _mk_200() -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.headers = {}
    return resp


class TestBreakerTrips:
    @pytest.mark.asyncio
    async def test_trips_after_threshold_then_short_circuits(self, monkeypatch):
        monkeypatch.setattr(asyncio, "sleep", AsyncMock())
        client = AsyncMock()
        client.request.return_value = _mk_429()

        # A single call with sustained 429s must trip within threshold attempts
        # and return immediately (no full backoff ladder).
        result = await request_with_retry(client, "GET", f"{NPM}/left-pad/latest", max_retries=10)
        assert result is not None and result.status_code == 429
        assert client.request.await_count == RATE_LIMIT_BREAKER_THRESHOLD
        assert registry_breaker_tripped(NPM)

        # Subsequent lookups to the same host short-circuit with no HTTP call.
        client.request.reset_mock()
        result2 = await request_with_retry(client, "GET", f"{NPM}/react/latest", max_retries=10)
        assert result2 is None
        assert client.request.await_count == 0

    @pytest.mark.asyncio
    async def test_no_exhausted_warning_storm(self, monkeypatch, caplog):
        monkeypatch.setattr(asyncio, "sleep", AsyncMock())
        client = AsyncMock()
        client.request.return_value = _mk_429()
        with caplog.at_level(logging.WARNING, logger="agent_bom.http_client"):
            for name in ("a", "b", "c", "d", "e", "f"):
                await request_with_retry(client, "GET", f"{NPM}/{name}/latest", max_retries=10)
        warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert not any("exhausted" in r.getMessage() for r in warnings)

    @pytest.mark.asyncio
    async def test_other_host_unaffected(self, monkeypatch):
        monkeypatch.setattr(asyncio, "sleep", AsyncMock())
        client = AsyncMock()
        client.request.return_value = _mk_429()
        await request_with_retry(client, "GET", f"{NPM}/x/latest", max_retries=10)
        assert registry_breaker_tripped(NPM)
        assert not registry_breaker_tripped("https://pypi.org")

        # PyPI still gets a normal (non-short-circuited) attempt.
        client.request.reset_mock()
        client.request.return_value = _mk_200()
        result = await request_with_retry(client, "GET", "https://pypi.org/pypi/requests/json")
        assert result.status_code == 200
        assert client.request.await_count == 1

    def test_success_resets_counter(self):
        host = "registry.npmjs.org"
        # Below-threshold 429s, then a success — counter must reset so the host
        # is not tripped by unrelated later blips.
        for _ in range(RATE_LIMIT_BREAKER_THRESHOLD - 1):
            assert http_client._record_rate_limit(host) is False
        http_client._record_non_rate_limited(host)
        # One more 429 should not trip because the counter was cleared.
        for _ in range(RATE_LIMIT_BREAKER_THRESHOLD - 1):
            assert http_client._record_rate_limit(host) is False
        assert not registry_breaker_tripped(host)

    def test_sync_breaker_short_circuits(self, monkeypatch):
        monkeypatch.setattr("agent_bom.http_client.time.sleep", lambda _s: None)
        client = MagicMock()
        client.request.return_value = _mk_429()
        result = sync_request_with_retry(client, "GET", f"{NPM}/lodash/latest", max_retries=10)
        assert result is not None and result.status_code == 429
        assert client.request.call_count == RATE_LIMIT_BREAKER_THRESHOLD
        assert registry_breaker_tripped(NPM)

        client.request.reset_mock()
        result2 = sync_request_with_retry(client, "GET", f"{NPM}/express/latest", max_retries=10)
        assert result2 is None
        assert client.request.call_count == 0


class TestResolverUnderSustained429:
    @pytest.mark.asyncio
    async def test_resolver_short_circuits_and_single_summary(self, monkeypatch):
        from agent_bom import resolver
        from agent_bom.models import Package

        resolver.reset_performance_stats()  # also resets the breaker
        monkeypatch.setattr("agent_bom.http_client.asyncio.sleep", AsyncMock())

        calls = {"n": 0}

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def request(self, *args, **kwargs):
                calls["n"] += 1
                return _mk_429()

        monkeypatch.setattr("agent_bom.resolver.create_client", lambda **kw: FakeClient())

        recorder = MagicMock()
        monkeypatch.setattr("agent_bom.resolver.console", recorder)

        packages = [Package(name=f"pkg-{i}", version="latest", ecosystem="npm") for i in range(30)]
        await resolver.resolve_all_versions(packages, global_timeout=10.0)

        # Breaker tripped, and live HTTP calls are bounded to a handful rather
        # than one (or more) per package.
        assert registry_breaker_tripped(resolver.NPM_REGISTRY)
        assert calls["n"] <= RATE_LIMIT_BREAKER_THRESHOLD + 2

        printed = [str(c.args[0]) for c in recorder.print.call_args_list if c.args]
        rate_limit_lines = [line for line in printed if "rate-limited" in line]
        assert len(rate_limit_lines) == 1
        assert "circuit breaker" in rate_limit_lines[0]
