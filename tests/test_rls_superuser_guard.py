"""Startup guard: refuse to serve when the DB role can bypass tenant RLS (#3665).

Postgres superusers and BYPASSRLS roles ignore ``FORCE ROW LEVEL SECURITY``,
which silently voids every ``*_tenant_isolation`` policy created by
``_ensure_tenant_rls``. These tests exercise the fail-closed guard wired into
``_get_pool`` and the ``AGENT_BOM_ALLOW_SUPERUSER_DB`` escape hatch.
"""

import logging

import pytest

from agent_bom.api import postgres_common
from agent_bom.api.postgres_common import RlsRolePrivilegeError


class _RoleCursor:
    def __init__(self, row):
        self._row = row

    def fetchone(self):
        return self._row


class _RoleConnection:
    def __init__(self, row):
        self._row = row

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        assert "pg_roles" in sql and "rolsuper" in sql and "rolbypassrls" in sql
        return _RoleCursor(self._row)


class _RolePool:
    """Minimal pool whose connection reports fixed pg_roles attributes."""

    def __init__(self, row):
        self._row = row

    def connection(self):
        return _RoleConnection(self._row)


@pytest.fixture(autouse=True)
def _reset_guard():
    postgres_common.reset_pool()
    yield
    postgres_common.reset_pool()


def test_guard_raises_when_role_is_superuser(monkeypatch):
    """A SUPERUSER role must abort startup because FORCE RLS is a no-op for it."""
    monkeypatch.setattr(postgres_common, "ALLOW_SUPERUSER_DB", False, raising=False)
    pool = _RolePool((True, False, "agent_bom"))

    with pytest.raises(RlsRolePrivilegeError) as excinfo:
        postgres_common._guard_rls_capable_role(pool)

    message = str(excinfo.value)
    assert "agent_bom" in message
    assert "SUPERUSER" in message
    assert "AGENT_BOM_ALLOW_SUPERUSER_DB" in message


def test_guard_raises_when_role_has_bypassrls(monkeypatch):
    """A BYPASSRLS (non-superuser) role must also abort startup."""
    monkeypatch.setattr(postgres_common, "ALLOW_SUPERUSER_DB", False, raising=False)
    pool = _RolePool((False, True, "sneaky_role"))

    with pytest.raises(RlsRolePrivilegeError) as excinfo:
        postgres_common._guard_rls_capable_role(pool)

    assert "BYPASSRLS" in str(excinfo.value)


def test_escape_hatch_downgrades_to_warning(monkeypatch, caplog):
    """AGENT_BOM_ALLOW_SUPERUSER_DB downgrades the hard error to a warning."""
    monkeypatch.setattr(postgres_common, "ALLOW_SUPERUSER_DB", True, raising=False)
    pool = _RolePool((True, False, "agent_bom"))

    with caplog.at_level(logging.WARNING, logger=postgres_common.logger.name):
        postgres_common._guard_rls_capable_role(pool)  # must not raise

    assert any("AGENT_BOM_ALLOW_SUPERUSER_DB" in rec.message for rec in caplog.records)
    assert any("not enforced" in rec.message.lower() for rec in caplog.records)


def test_guard_passes_for_nonprivileged_role(monkeypatch):
    """A NOSUPERUSER NOBYPASSRLS role is the supported config and must pass."""
    monkeypatch.setattr(postgres_common, "ALLOW_SUPERUSER_DB", False, raising=False)
    pool = _RolePool((False, False, "agent_bom_app"))

    postgres_common._guard_rls_capable_role(pool)  # must not raise


def test_guard_runs_once_per_pool(monkeypatch):
    """The role is inspected once; a later escape-hatch flip is not re-evaluated."""
    monkeypatch.setattr(postgres_common, "ALLOW_SUPERUSER_DB", True, raising=False)
    pool = _RolePool((True, False, "agent_bom"))
    postgres_common._guard_rls_capable_role(pool)  # warns, marks checked

    # Even if the operator "tightens" the flag afterwards, the cached check
    # short-circuits — the guard is a startup gate, not a per-query one.
    monkeypatch.setattr(postgres_common, "ALLOW_SUPERUSER_DB", False, raising=False)
    postgres_common._guard_rls_capable_role(pool)  # must not raise


def test_guard_is_best_effort_when_probe_fails(monkeypatch):
    """A connection/probe error must not mask the primary failure path."""
    monkeypatch.setattr(postgres_common, "ALLOW_SUPERUSER_DB", False, raising=False)

    class _BrokenPool:
        def connection(self):
            raise RuntimeError("connection refused")

    # Swallows the probe error and returns without raising.
    postgres_common._guard_rls_capable_role(_BrokenPool())
