"""Startup guard: refuse to serve when the DB role can bypass tenant RLS (#3665).

Postgres superusers and BYPASSRLS roles ignore ``FORCE ROW LEVEL SECURITY``,
which silently voids every ``*_tenant_isolation`` policy created by
``_ensure_tenant_rls``. These tests exercise the fail-closed guard wired into
``_get_pool`` and the ``AGENT_BOM_ALLOW_SUPERUSER_DB`` escape hatch.
"""

import logging
from concurrent.futures import ThreadPoolExecutor

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


def test_guard_rechecks_when_override_is_revoked(monkeypatch):
    monkeypatch.setattr(postgres_common, "ALLOW_SUPERUSER_DB", True)
    pool = _RolePool((True, False, "agent_bom"))
    postgres_common._guard_rls_capable_role(pool)
    monkeypatch.setattr(postgres_common, "ALLOW_SUPERUSER_DB", False)
    with pytest.raises(RlsRolePrivilegeError):
        postgres_common._guard_rls_capable_role(pool)


@pytest.mark.parametrize("row", [(True, False, "super"), (False, True, "bypass")])
def test_rejected_role_stays_rejected_on_retry(monkeypatch, row):
    monkeypatch.setattr(postgres_common, "ALLOW_SUPERUSER_DB", False)
    monkeypatch.setattr(postgres_common, "_pool", _RolePool(row))
    for _ in range(3):
        with pytest.raises(RlsRolePrivilegeError):
            postgres_common._get_pool()


def test_guard_caches_each_pool_independently(monkeypatch):
    monkeypatch.setattr(postgres_common, "ALLOW_SUPERUSER_DB", False)
    postgres_common._guard_rls_capable_role(_RolePool((False, False, "safe")))
    with pytest.raises(RlsRolePrivilegeError):
        postgres_common._guard_rls_capable_role(_RolePool((False, True, "unsafe")))


@pytest.mark.parametrize("row", [None, (), (False,), (None, False, "unknown")])
def test_missing_or_malformed_role_fails_closed(monkeypatch, row):
    monkeypatch.setattr(postgres_common, "ALLOW_SUPERUSER_DB", True)
    pool = _RolePool(row)
    for _ in range(2):
        with pytest.raises(RlsRolePrivilegeError, match="inspect"):
            postgres_common._guard_rls_capable_role(pool)


def test_probe_failure_rejects_then_recovers(monkeypatch):
    monkeypatch.setattr(postgres_common, "ALLOW_SUPERUSER_DB", False)

    class RecoveringPool(_RolePool):
        broken = True

        def connection(self):
            if self.broken:
                raise RuntimeError("secret-connection-string")
            return super().connection()

    pool = RecoveringPool((False, False, "safe"))
    for _ in range(2):
        with pytest.raises(RlsRolePrivilegeError, match="inspect") as error:
            postgres_common._guard_rls_capable_role(pool)
        assert "secret-connection-string" not in str(error.value)
    pool.broken = False
    postgres_common._guard_rls_capable_role(pool)


def test_concurrent_first_access_validates_once_and_reset_rechecks(monkeypatch):
    monkeypatch.setattr(postgres_common, "ALLOW_SUPERUSER_DB", False)

    class CountingPool(_RolePool):
        calls = 0

        def connection(self):
            self.calls += 1
            return super().connection()

    pool = CountingPool((False, False, "safe"))
    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(postgres_common._guard_rls_capable_role, [pool] * 16))
    assert pool.calls == 1
    postgres_common.reset_pool()
    postgres_common._guard_rls_capable_role(pool)
    assert pool.calls == 2


def test_fence_pool_does_not_inherit_application_validation(monkeypatch):
    monkeypatch.setattr(postgres_common, "ALLOW_SUPERUSER_DB", False)
    monkeypatch.setattr(postgres_common, "_pool", _RolePool((False, False, "safe")))
    monkeypatch.setattr(postgres_common, "_idempotency_fence_pool", _RolePool((True, False, "unsafe")))
    postgres_common._get_pool()
    for _ in range(2):
        with pytest.raises(RlsRolePrivilegeError):
            postgres_common._get_idempotency_fence_pool()
