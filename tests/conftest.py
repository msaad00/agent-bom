"""Global test fixtures for shared module state reset."""

from __future__ import annotations

import os
import tempfile

import pytest

os.environ.setdefault("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", "1")
os.environ.setdefault("AGENT_BOM_NO_AUTH_ROLE", "admin")

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

# The control-plane lifecycle stores (agent identity, JIT grants, runtime
# session/event) are durable-by-default in production: without config they now
# persist to a SQLite file under AGENT_BOM_STATE_DIR instead of memory. In the
# test suite that shared on-disk file would leak rows between tests that rely on
# the implicit default on the same xdist worker. Opt into the explicit ephemeral
# (in-memory) tier for the suite so those tests stay isolated; the durable
# default and the SQLite/Postgres tiers are exercised directly by the stores'
# own tests, which construct the backends explicitly. Production never sets this.
os.environ.setdefault("AGENT_BOM_EPHEMERAL_STORE", "1")


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
        api_server._runtime_api_key_seeded = False
        api_server._api_key = None
        api_server.set_dev_api_key(None)
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


def _reset_durable_store_singletons() -> None:
    # The agent-identity, JIT-grant, and runtime session/event stores are now
    # durable by default (SQLite under AGENT_BOM_STATE_DIR — the isolated temp
    # dir set above — instead of in-memory). Their selectors memoize a
    # process-global singleton on first use, so a store created (and the rows
    # written) by one test would otherwise persist into the next test on the
    # same xdist worker via the singleton AND the on-disk file. Reset the
    # singletons to None so each test reselects a fresh store, and the per-test
    # AGENT_BOM_DB-free default reads/writes only the isolated state dir.
    try:
        from agent_bom.api.agent_identity_store import set_agent_identity_store

        set_agent_identity_store(None)
    except Exception:
        pass
    try:
        from agent_bom.api.runtime_event_store import set_runtime_event_store

        set_runtime_event_store(None)
    except Exception:
        pass
    try:
        from agent_bom.api.cost_store import set_cost_store

        set_cost_store(None)
    except Exception:
        pass


# Auth-influencing env vars. ``configure_api`` re-derives whether the API key
# middleware is installed from these on every call (server.py auth_configured),
# so any one of them left set makes an otherwise-open endpoint return 401. A
# test that sets one directly (tests/auth_helpers.py, or a setup_module block)
# and then errors before its own cleanup runs would leak it to the next test on
# the same xdist worker — the root of the intermittent ``assert 401 == 200``
# flake. We snapshot these before each test and restore them after; see below.
_AUTH_ENV_VARS = (
    "AGENT_BOM_API_KEY",
    "AGENT_BOM_API_KEYS",
    "AGENT_BOM_TRUST_PROXY_AUTH",
    "AGENT_BOM_TRUST_PROXY_AUTH_SECRET",
    "AGENT_BOM_TRUST_PROXY_AUTH_ISSUER",
    "AGENT_BOM_OIDC_ISSUER",
    "AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON",
    "AGENT_BOM_SCIM_BEARER_TOKEN",
    "AGENT_BOM_SCIM_BEARER_TOKENS_JSON",
)

_STORAGE_ENV_VARS = (
    "AGENT_BOM_POSTGRES_URL",
    "AGENT_BOM_POSTGRES_DSN",
)

# Env vars that server/CLI runtime code sets as a side effect during a test body
# (e.g. binding the MCP server remotely, enabling permissive CORS). They are NOT
# auth/storage config, but if a test that triggers this code path skips its own
# cleanup the value leaks into later tests on the same worker and makes outcomes
# depend on collection order — e.g. AGENT_BOM_MCP_REMOTE_BIND leaking into
# repo_scan, which then demands an explicit host allowlist. Snapshot + revert.
_SERVER_RUNTIME_ENV_VARS = (
    "AGENT_BOM_MCP_REMOTE_BIND",
    "AGENT_BOM_CORS_ALL",
    "AGENT_BOM_ANALYTICS_BACKEND",
    "AGENT_BOM_CLICKHOUSE_URL",
    "AGENT_BOM_CLICKHOUSE_BUFFERED",
    "AGENT_BOM_CLICKHOUSE_FLUSH_INTERVAL",
    "AGENT_BOM_CLICKHOUSE_MAX_BATCH",
    "AGENT_BOM_PROFILE",
)


@pytest.fixture(autouse=True)
def reset_global_test_state():
    """Reset process-global caches so test order does not affect outcomes."""
    _reset_resolver_state()
    _reset_registry_state()
    _reset_identity_cache_state()
    _reset_api_runtime_state()
    _reset_durable_store_singletons()
    _reset_runtime_state()

    # Snapshot auth env AFTER module-scoped setup has run (setup_module fires
    # before this function-scoped fixture), so module-level auth env is captured
    # and preserved across the module's tests. Anything a *test body* sets is not
    # in the snapshot and is reverted on teardown below — so a test that enables
    # auth and skips its own cleanup (e.g. on an assertion error) cannot leak a
    # 401-inducing env var into the next test on the same worker.
    auth_env_snapshot = {var: os.environ.get(var) for var in _AUTH_ENV_VARS}
    storage_env_snapshot = {var: os.environ.get(var) for var in _STORAGE_ENV_VARS}
    server_env_snapshot = {var: os.environ.get(var) for var in _SERVER_RUNTIME_ENV_VARS}

    yield

    for var, value in {
        **auth_env_snapshot,
        **storage_env_snapshot,
        **server_env_snapshot,
    }.items():
        if value is None:
            os.environ.pop(var, None)
        else:
            os.environ[var] = value

    _reset_resolver_state()
    _reset_registry_state()
    _reset_identity_cache_state()
    _reset_api_runtime_state()
    _reset_durable_store_singletons()
    _reset_runtime_state()
