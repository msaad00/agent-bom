"""Global test fixtures for shared module state reset."""

from __future__ import annotations

import os
import tempfile

import pytest

os.environ.setdefault("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", "1")

# Force a wide, deterministic console width. Under pytest-xdist there is no TTY,
# so Rich defaults to 80 cols and wraps long output (e.g. file paths) across
# lines — breaking substring assertions on CLI output. Pin it so tests render
# identically whether run serially or in parallel workers.
os.environ.setdefault("COLUMNS", "200")

# Isolate persistent runtime state (e.g. the protection-engine kill-switch
# file, default ~/.agent-bom/killswitch.json) into a throwaway per-process
# directory. Without this, a test that trips the kill-switch persists a blocked
# CRITICAL state to the real home dir, and a later ProtectionEngine.start() on
# the same xdist worker restores it — leaking "critical" into unrelated shield
# tests. Each worker process gets its own dir, so workers never collide.
os.environ.setdefault(
    "AGENT_BOM_STATE_DIR",
    tempfile.mkdtemp(prefix="agent-bom-test-state-"),
)


def _reset_runtime_state() -> None:
    # Remove the kill-switch state file between tests so a blocked/CRITICAL
    # state from one test never restores into the next on the same worker.
    try:
        from pathlib import Path

        state_dir = Path(os.environ["AGENT_BOM_STATE_DIR"])
        (state_dir / "killswitch.json").unlink(missing_ok=True)
        (state_dir / "killswitch.tmp").unlink(missing_ok=True)
    except Exception:
        pass


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

    # Cloud provider entry-point registry is process-global. A test that
    # registers a fake entry-point provider (and toggles entrypoints_enabled)
    # would otherwise leak warnings + provider rows into the next test on the
    # same xdist worker, breaking the discovery-provider contract assertions.
    try:
        import agent_bom.cloud as cloud_registry

        cloud_registry._reset_provider_registry_for_tests()
    except Exception:
        pass


def _reset_identity_cache_state() -> None:
    # JWKS responses are cached in a process-global dict keyed by URI with a
    # 1-hour TTL. test_fetch_jwks_cached pre-populates it; without a reset a
    # later test fetching the same URI gets the stale cached doc instead of its
    # own mocked httpx response. Clear it so JWKS tests are order-independent.
    try:
        import agent_bom.agent_identity as agent_identity

        with agent_identity._jwks_lock:
            agent_identity._jwks_cache.clear()
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

    # The API key store and the "env keys already seeded" flag are
    # process-global. A test that seeds API keys (or configures auth) would
    # otherwise leave them set, so a later test on the same xdist worker that
    # expects unauthenticated access gets a 401. Reset to a fresh in-memory
    # store and re-arm the env seeding so each test starts from a clean slate.
    try:
        from agent_bom.api import server as api_server
        from agent_bom.api.auth import KeyStore, set_key_store

        set_key_store(KeyStore())
        api_server._env_api_keys_seeded = False
        api_server._api_key = None
    except Exception:
        pass

    # FastAPI dependency overrides are stored on the app object and persist
    # across tests; a leaked override changes auth/behaviour for unrelated
    # tests sharing the worker.
    try:
        from agent_bom.api.server import app

        app.dependency_overrides.clear()
    except Exception:
        pass

    # The in-memory scan-job hot cache (_jobs) is process-global. list_jobs()
    # consults it directly even when the store is mocked, so a job left behind
    # by an earlier test (e.g. one that called store.put) leaks into a later
    # test on the same xdist worker — changing whether list_jobs hydrates from
    # the store and corrupting tenant-isolation assertions. Clear it so each
    # test starts with an empty hot cache.
    try:
        from agent_bom.api import stores as api_stores

        with api_stores._jobs_lock:
            api_stores._jobs.clear()
            api_stores._job_locks.clear()
    except Exception:
        pass


@pytest.fixture(autouse=True)
def reset_global_test_state():
    """Reset process-global caches so test order does not affect outcomes."""
    _reset_resolver_state()
    _reset_registry_state()
    _reset_identity_cache_state()
    _reset_api_runtime_state()
    _reset_runtime_state()
    yield
    _reset_resolver_state()
    _reset_registry_state()
    _reset_identity_cache_state()
    _reset_api_runtime_state()
    _reset_runtime_state()
