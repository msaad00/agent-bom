"""Global test fixtures for shared module state reset."""

from __future__ import annotations

import importlib
import inspect
import logging
import os
import sys
import tempfile
from typing import Any

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


def _sync_test_auth_config_from_env() -> None:
    """Re-read auth posture flags from env after per-test env mutations."""
    try:
        import agent_bom.config as config

        config.DEMO_ESTATE = (os.environ.get("AGENT_BOM_DEMO_ESTATE") or "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        role = (os.environ.get("AGENT_BOM_NO_AUTH_ROLE") or "admin").strip()
        config.NO_AUTH_ROLE = role
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

    _sync_test_auth_config_from_env()

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


def _reset_proxy_route_state() -> None:
    # The proxy status/alerts route keeps process-global in-memory buffers:
    # a bounded _proxy_alerts deque, its _proxy_alerts_total counter, the latest
    # _proxy_metrics / _proxy_metrics_by_tenant snapshots, and a 24h audit-event
    # dedupe table (_audit_dedupe, guarded by _audit_dedupe_lock, up to 50k
    # entries). _load_proxy_alerts only falls back to the AGENT_BOM_LOG file when
    # _proxy_alerts is EMPTY, so an alert left in the deque by an earlier test
    # makes /v1/proxy/status ignore the log and report the wrong count (e.g.
    # test_proxy_status_from_log asserting total_alerts==1 gets 0). The dedupe
    # table is just as order-sensitive: a (tenant, event_id) key emitted by one
    # test suppresses the same event in a later test asserting emission, so a
    # test that ingests then one that re-ingests the same id can flake. Clear all
    # of them so each test starts clean. The dedupe table uses the route's own
    # lock-safe reset helper.
    try:
        from agent_bom.api.routes import proxy as proxy_routes

        proxy_routes._proxy_alerts.clear()
        proxy_routes._proxy_alerts_total = 0
        proxy_routes._proxy_metrics = None
        proxy_routes._proxy_metrics_by_tenant.clear()
        proxy_routes._reset_audit_dedupe_for_tests()
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
    "AGENT_BOM_NO_AUTH_ROLE",
    "AGENT_BOM_DEMO_ESTATE",
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


# ── Global store-singleton snapshot/restore (order-flake root cause) ─────────
# The API exposes ~35 ``set_*_store`` accessors across these modules, each of
# which mutates a process-global singleton holder. A test that swaps a backend
# via ``set_*`` and skips restoring it (e.g. on an assertion error) leaks that
# singleton into later tests on the same xdist worker — the order-dependent
# flake class behind the leaked durable job store (#3663) and NO_AUTH_ROLE
# poisoning (#3660). Rather than hand-maintain a per-store reset list (which
# goes stale as stores are added), we snapshot EVERY singleton holder in these
# modules before each test and restore it verbatim afterward, so a leaked
# ``set_*`` can never cross a test boundary. New stores added to any of these
# modules are covered automatically.
_STORE_SINGLETON_MODULES = (
    "agent_bom.api.stores",
    "agent_bom.api.auth",
    "agent_bom.api.audit_log",
    "agent_bom.api.proxy_replay_store",
    "agent_bom.api.agent_identity_store",
    "agent_bom.api.connection_store",
    "agent_bom.api.drift_incident_store",
    "agent_bom.api.cost_store",
    "agent_bom.api.webhook_store",
    "agent_bom.api.dataset_version_store",
    "agent_bom.api.evaluation_store",
    "agent_bom.api.report_job_store",
    "agent_bom.api.access_review",
    "agent_bom.api.hitl_approval_store",
    "agent_bom.api.runtime_event_store",
    "agent_bom.api.compliance_hub_store",
)

# Swappable process-globals in the modules above whose identifier does not end
# in ``_store`` (case-insensitively) and so is not caught by the suffix rule.
_STORE_SINGLETON_EXTRA_NAMES = frozenset(
    {
        "_last_scan_report",  # stores.py — baseline comparison snapshot
        "_audit_log",  # audit_log.py — audit sink singleton
        "_CAPTURE_REPLAY_ENABLED",  # proxy_replay_store.py — capture toggle
    }
)

# Auth-posture constants that live-config code (server.py auth wiring) reads
# directly. ``_sync_test_auth_config_from_env`` re-derives most from env, but a
# test that assigns the module attribute directly would still leak; snapshot and
# restore them verbatim as a backstop.
_CONFIG_AUTH_CONSTANTS = ("NO_AUTH_ROLE", "DEMO_ESTATE", "API_ALLOW_UNAUTHENTICATED")


def _is_store_singleton_name(name: str) -> bool:
    return name.lower().endswith("_store") or name in _STORE_SINGLETON_EXTRA_NAMES


def _snapshot_store_singletons() -> list[tuple[Any, str, Any]]:
    """Capture every process-global store singleton so it can be restored.

    Returns (module, attr_name, value) triples. The ``set_*``/``_get_*``
    accessors themselves also end in ``_store``; functions and classes are
    skipped so only state holders (None or a store instance) are captured.
    Modules are imported eagerly so the very first test to touch a store still
    has a pristine baseline to restore to (an unimported module has no state to
    leak, but importing here closes the first-mutation gap).
    """
    snapshot: list[tuple[Any, str, Any]] = []
    for mod_path in _STORE_SINGLETON_MODULES:
        mod = sys.modules.get(mod_path)
        if mod is None:
            try:
                mod = importlib.import_module(mod_path)
            except Exception:
                continue
        try:
            members = list(vars(mod).items())
        except Exception:
            continue
        for name, value in members:
            if not _is_store_singleton_name(name):
                continue
            if inspect.isroutine(value) or inspect.isclass(value):
                continue
            snapshot.append((mod, name, value))
    return snapshot


def _restore_store_singletons(snapshot: list[tuple[Any, str, Any]]) -> None:
    for mod, name, value in snapshot:
        try:
            setattr(mod, name, value)
        except Exception:
            pass


def _snapshot_output_console() -> Any:
    """Capture the shared Rich console the CLI renders through.

    ``console_render._console()`` resolves ``agent_bom.output.console`` at call
    time. Many tests swap this barrel attribute for a StringIO-backed capture
    console and restore it in a ``finally`` — but a test that skips its restore
    (assertion error before cleanup, or no cleanup at all) leaks the capture
    console into later CLI tests, whose output then lands in the stale console
    instead of Click's captured stdout — surfacing as empty ``result.output``
    (e.g. test_diff_quiet_prints_compact_summary asserting on missing text).
    Snapshot the barrel console and restore it verbatim after each test.
    """
    try:
        import agent_bom.output as output_mod

        return getattr(output_mod, "console", None)
    except Exception:
        return None


def _restore_output_console(console_obj: Any) -> None:
    if console_obj is None:
        return
    try:
        import agent_bom.output as output_mod

        output_mod.console = console_obj
    except Exception:
        pass


def _snapshot_config_auth() -> dict[str, Any]:
    try:
        import agent_bom.config as config
    except Exception:
        return {}
    return {name: getattr(config, name) for name in _CONFIG_AUTH_CONSTANTS if hasattr(config, name)}


def _restore_config_auth(snapshot: dict[str, Any]) -> None:
    try:
        import agent_bom.config as config
    except Exception:
        return
    for name, value in snapshot.items():
        try:
            setattr(config, name, value)
        except Exception:
            pass


@pytest.fixture(autouse=True)
def reset_global_test_state():
    """Reset process-global caches so test order does not affect outcomes."""
    _reset_resolver_state()
    _reset_registry_state()
    _reset_identity_cache_state()
    _reset_api_runtime_state()
    _reset_durable_store_singletons()
    _reset_proxy_route_state()
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

    # Snapshot the pluggable store singletons and auth-config constants AFTER the
    # resets above have established a clean baseline. Any set_*_store a test body
    # performs (and skips restoring) is reverted on teardown, killing the
    # order-dependent flake class at the root.
    store_singleton_snapshot = _snapshot_store_singletons()
    config_auth_snapshot = _snapshot_config_auth()
    output_console_snapshot = _snapshot_output_console()

    # Snapshot root-logger handlers + level. Several CLI/gateway paths call
    # ``configure_logging``/``logging.basicConfig`` which ``addHandler`` to root
    # without removing existing ones, so handlers ACCUMULATE across a worker's
    # tests. A leaked handler (e.g. one writing to stdout) then contaminates a
    # later test that parses a command's stdout as JSON — an xdist-order flake.
    # Restore the exact handler set + level on teardown so no test can leak one.
    root_logger = logging.getLogger()
    logging_handlers_snapshot = root_logger.handlers[:]
    logging_level_snapshot = root_logger.level

    yield

    root_logger.handlers[:] = logging_handlers_snapshot
    root_logger.setLevel(logging_level_snapshot)
    _restore_store_singletons(store_singleton_snapshot)
    _restore_config_auth(config_auth_snapshot)
    _restore_output_console(output_console_snapshot)

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
    _reset_proxy_route_state()
    _reset_runtime_state()
