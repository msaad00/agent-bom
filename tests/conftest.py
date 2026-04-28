"""Global test fixtures for shared module state reset."""

from __future__ import annotations

import pytest


def _reset_resolver_state() -> None:
    try:
        import agent_bom.resolver as resolver

        resolver._NPM_LATEST_CACHE.clear()
        if hasattr(resolver, "_NPM_LATEST_INFLIGHT"):
            resolver._NPM_LATEST_INFLIGHT.clear()
        resolver._PYPI_INFO_CACHE.clear()
        if hasattr(resolver, "_PYPI_INFO_INFLIGHT"):
            resolver._PYPI_INFO_INFLIGHT.clear()
        resolver._NPM_RATE_LIMIT_UNTIL = 0.0
        resolver._NPM_RATE_LIMIT_HITS = 0
        resolver.reset_performance_stats()
    except Exception:
        pass


def _reset_registry_state() -> None:
    try:
        from agent_bom.mcp_server_helpers import reset_registry_cache_for_tests

        reset_registry_cache_for_tests()
    except Exception:
        pass

    try:
        import agent_bom.parsers as parsers

        parsers._registry_cache = None
    except Exception:
        pass


def _reset_api_runtime_state() -> None:
    try:
        from agent_bom.api import server as api_server
        from agent_bom.api.stores import set_scim_store

        set_scim_store(None)
        api_server.configure_api(api_key=None)
    except Exception:
        pass


@pytest.fixture(autouse=True)
def reset_global_test_state():
    """Reset process-global caches so test order does not affect outcomes."""
    _reset_resolver_state()
    _reset_registry_state()
    _reset_api_runtime_state()
    yield
    _reset_resolver_state()
    _reset_registry_state()
    _reset_api_runtime_state()
