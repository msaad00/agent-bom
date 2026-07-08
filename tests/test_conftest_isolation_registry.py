"""Guards that keep the conftest test-isolation registries from silently rotting.

The autouse ``reset_global_test_state`` fixture in ``tests/conftest.py`` snapshots
and restores process-global state by name: a tuple of store-singleton module
paths, a tuple of auth-config constant names, and the proxy-route buffer globals.
Those name lists are the whole isolation mechanism — if a module is renamed or a
constant moves, the fixture's defensive ``try/except`` swallows the failure and
the suite quietly regains an order-dependent flake surface.

These tests turn that silent rot into a hard, loud failure: every registered
module must import and actually contribute a snapshot-eligible singleton, every
registered config constant must exist, and every proxy-route global the reset
touches must be present. Do NOT relax an assertion to make it pass — update the
registry (or the code it points at) instead.
"""

from __future__ import annotations

import importlib
import os
import sys

# conftest.py holds the isolation registries under test. It is loaded by pytest
# as a plugin, not necessarily importable by name, so put its directory on the
# path and import it explicitly.
sys.path.insert(0, os.path.dirname(__file__))
import conftest  # noqa: E402


def test_store_singleton_modules_all_import_and_contribute() -> None:
    """Every module in the store-singleton registry imports and has a holder."""
    assert conftest._STORE_SINGLETON_MODULES, "registry must not be empty"
    for mod_path in conftest._STORE_SINGLETON_MODULES:
        # importlib raises ModuleNotFoundError here if the path is stale — the
        # fixture would otherwise swallow it, hiding the rot this test exists to
        # catch.
        mod = importlib.import_module(mod_path)
        holders = [
            name
            for name, value in vars(mod).items()
            if conftest._is_store_singleton_name(name) and not callable(value)
        ]
        assert holders, (
            f"{mod_path} is listed in _STORE_SINGLETON_MODULES but exposes no "
            f"snapshot-eligible singleton (a non-callable global whose name ends "
            f"in '_store', or one of {sorted(conftest._STORE_SINGLETON_EXTRA_NAMES)}). "
            f"Remove the module from the registry or fix the introspection rule."
        )


def test_snapshot_captures_every_registered_module() -> None:
    """The live snapshot covers every registered module (no import swallowed)."""
    captured = {mod.__name__ for mod, _name, _value in conftest._snapshot_store_singletons()}
    missing = set(conftest._STORE_SINGLETON_MODULES) - captured
    assert not missing, f"snapshot silently skipped registered modules: {sorted(missing)}"


def test_config_auth_constants_all_exist() -> None:
    """Every auth-config constant the fixture restores exists on config."""
    import agent_bom.config as config

    assert conftest._CONFIG_AUTH_CONSTANTS, "registry must not be empty"
    missing = [name for name in conftest._CONFIG_AUTH_CONSTANTS if not hasattr(config, name)]
    assert not missing, (
        f"_CONFIG_AUTH_CONSTANTS names not found on agent_bom.config: {missing}. "
        f"The fixture's hasattr guard would silently skip these — restoring nothing. "
        f"Remove the dead names or point them at where the state actually lives."
    )
    # And the live snapshot must actually capture each one.
    snap = conftest._snapshot_config_auth()
    assert set(conftest._CONFIG_AUTH_CONSTANTS) <= set(snap), (
        f"snapshot missed config constants: {set(conftest._CONFIG_AUTH_CONSTANTS) - set(snap)}"
    )


def test_proxy_route_reset_targets_exist() -> None:
    """The proxy-route reset only helps if the globals it clears still exist."""
    from agent_bom.api.routes import proxy as proxy_routes

    for attr in (
        "_proxy_alerts",
        "_proxy_alerts_total",
        "_proxy_metrics",
        "_proxy_metrics_by_tenant",
        "_audit_dedupe",
        "_audit_dedupe_lock",
        "_reset_audit_dedupe_for_tests",
    ):
        assert hasattr(proxy_routes, attr), (
            f"agent_bom.api.routes.proxy.{attr} is gone but _reset_proxy_route_state "
            f"still targets it — the reset is silently a no-op. Update the reset."
        )


def test_reset_clears_leaked_audit_dedupe() -> None:
    """A leaked dedupe key must not survive into the next test (order flake #1)."""
    from agent_bom.api.routes import proxy as proxy_routes

    # Simulate a prior test that claimed an audit event id.
    assert proxy_routes._claim_audit_event("default", "evt-isolation-guard") is True
    # First claim registered the key; a re-claim now returns False (deduped).
    assert proxy_routes._claim_audit_event("default", "evt-isolation-guard") is False
    # The autouse reset runs on teardown; prove the reset primitive clears it so
    # the next test re-claiming the same id sees it as new again.
    conftest._reset_proxy_route_state()
    assert proxy_routes._claim_audit_event("default", "evt-isolation-guard") is True
