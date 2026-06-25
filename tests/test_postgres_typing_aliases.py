"""Runtime-safety guard for the Postgres store typing aliases.

The Postgres store modules annotate their ``pool`` parameters with the
``ConnectionPool`` alias exported from :mod:`agent_bom.api.postgres_common`.
``psycopg``/``psycopg_pool`` are optional dependencies that ship no type stubs,
so the alias is imported under ``TYPE_CHECKING`` for mypy and falls back to a
plain ``object`` at runtime. This test pins that contract: the alias must stay
importable (and the stores must keep importing) even when psycopg is not
installed, so a deployment without the ``[postgres]`` extra never fails at
import time. If someone moves the alias under ``TYPE_CHECKING`` only, the
runtime imports below break and this test catches it.
"""

from __future__ import annotations

import importlib

import agent_bom.api.postgres_common as postgres_common

# Stores that import the ConnectionPool alias and annotate __init__ with it.
_STORE_MODULES = [
    "agent_bom.api.postgres_access_review",
    "agent_bom.api.postgres_agent_identity",
    "agent_bom.api.postgres_audit",
    "agent_bom.api.postgres_compliance_hub",
    "agent_bom.api.postgres_cost",
    "agent_bom.api.postgres_runtime_event",
    "agent_bom.api.postgres_scim",
    "agent_bom.api.postgres_tenant_quota",
]


def test_common_exposes_runtime_safe_aliases() -> None:
    # Importable at runtime (not TYPE_CHECKING-only) so no-psycopg installs work.
    assert postgres_common.Connection is not None
    assert postgres_common.ConnectionPool is not None


def test_store_modules_import_the_alias() -> None:
    for name in _STORE_MODULES:
        module = importlib.import_module(name)
        assert module.ConnectionPool is postgres_common.ConnectionPool


def test_pool_argument_defaults_to_none() -> None:
    # The annotated ``pool: ConnectionPool | None = None`` keeps its default,
    # so constructing a store still lazily resolves the shared pool.
    from agent_bom.api.postgres_tenant_quota import PostgresTenantQuotaStore

    assert PostgresTenantQuotaStore.__init__.__defaults__ == (None,)
