"""Fail-closed contracts for the dedicated Postgres maintenance pool."""

from __future__ import annotations

import sys
import types

import pytest

from agent_bom.api import postgres_common


class _Cursor:
    def __init__(self, row):
        self._row = row

    def fetchone(self):
        return self._row


class _Connection:
    def __init__(
        self,
        role: str,
        *,
        maintenance_member: bool = False,
        can_login: bool = True,
        superuser: bool = False,
        bypass_rls: bool = False,
    ):
        self.role = role
        self.maintenance_member = maintenance_member
        self.can_login = can_login
        self.superuser = superuser
        self.bypass_rls = bypass_rls
        self.settings: dict[str, str] = {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        if "rolsuper" in sql and "rolbypassrls" in sql and "pg_has_role" not in sql:
            return _Cursor((self.superuser, self.bypass_rls, self.role))
        if "pg_has_role" in sql:
            return _Cursor(
                (self.role, self.can_login, self.superuser, self.bypass_rls, self.maintenance_member)
            )
        if "set_config" in sql and params:
            if "app.tenant_id" in sql:
                self.settings["app.tenant_id"] = params[0]
            elif "app.bypass_rls" in sql:
                self.settings["app.bypass_rls"] = params[0]
            return _Cursor(None)
        return _Cursor(None)


class _Pool:
    def __init__(self, connection: _Connection):
        self._connection = connection
        self.closed = False

    def connection(self):
        return self._connection

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def _reset_pools():
    postgres_common.reset_pool()
    yield
    postgres_common.reset_pool()


def _configure_urls(monkeypatch, tmp_path, *, app_user="agent_bom_app", maintenance_user="agent_bom_maintenance"):
    password_file = tmp_path / "maintenance-password"
    password_file.write_text("maintenance-secret\n", encoding="utf-8")
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", f"postgresql://{app_user}@db:5432/agent_bom")
    monkeypatch.setenv(
        "AGENT_BOM_POSTGRES_MAINTENANCE_URL",
        f"postgresql://{maintenance_user}@db:5432/agent_bom",
    )
    monkeypatch.setenv("AGENT_BOM_POSTGRES_MAINTENANCE_PASSWORD_FILE", str(password_file))
    monkeypatch.delenv("AGENT_BOM_POSTGRES_PASSWORD_FILE", raising=False)
    monkeypatch.delenv("AGENT_BOM_POSTGRES_AUTH_MODE", raising=False)


def _install_pool_factory(
    monkeypatch,
    *,
    app_member=False,
    app_super=False,
    app_bypass=False,
    maintenance_member=True,
    maintenance_can_login=True,
):
    captured: list[dict[str, object]] = []

    def factory(conninfo=None, **kwargs):
        role = "agent_bom_maintenance" if "agent_bom_maintenance" in conninfo else "agent_bom_app"
        connection = _Connection(
            role,
            maintenance_member=maintenance_member if role == "agent_bom_maintenance" else app_member,
            can_login=maintenance_can_login if role == "agent_bom_maintenance" else True,
            superuser=app_super if role == "agent_bom_app" else False,
            bypass_rls=app_bypass if role == "agent_bom_app" else False,
        )
        pool = _Pool(connection)
        captured.append({"conninfo": conninfo, "kwargs": kwargs, "pool": pool, "connection": connection})
        return pool

    monkeypatch.setitem(sys.modules, "psycopg_pool", types.SimpleNamespace(ConnectionPool=factory))
    return captured


def test_maintenance_url_is_required_without_app_fallback(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://agent_bom_app@app-db/agent_bom")
    monkeypatch.delenv("AGENT_BOM_POSTGRES_MAINTENANCE_URL", raising=False)

    with pytest.raises(ValueError, match="AGENT_BOM_POSTGRES_MAINTENANCE_URL"):
        postgres_common.resolve_postgres_maintenance_url()


def test_maintenance_password_file_stays_out_of_conninfo(monkeypatch, tmp_path):
    _configure_urls(monkeypatch, tmp_path)

    assert postgres_common.resolve_postgres_maintenance_url() == (
        "postgresql://agent_bom_maintenance@db:5432/agent_bom"
    )
    assert postgres_common.resolve_postgres_maintenance_secret() == "maintenance-secret"
    assert "maintenance-secret" not in postgres_common.resolve_postgres_maintenance_url()


def test_maintenance_pool_rejects_same_login_as_app(monkeypatch, tmp_path):
    _configure_urls(monkeypatch, tmp_path, maintenance_user="agent_bom_app")

    with pytest.raises(postgres_common.MaintenanceRoleConfigurationError, match="distinct"):
        postgres_common._get_maintenance_pool()


@pytest.mark.parametrize(
    ("app_member", "maintenance_member", "maintenance_can_login", "message"),
    [
        (True, True, True, "application role"),
        (False, False, True, "member"),
        (False, True, False, "LOGIN"),
    ],
)
def test_maintenance_pool_validates_role_separation(
    monkeypatch,
    tmp_path,
    app_member,
    maintenance_member,
    maintenance_can_login,
    message,
):
    _configure_urls(monkeypatch, tmp_path)
    _install_pool_factory(
        monkeypatch,
        app_member=app_member,
        maintenance_member=maintenance_member,
        maintenance_can_login=maintenance_can_login,
    )

    with pytest.raises(postgres_common.MaintenanceRoleConfigurationError, match=message):
        postgres_common._get_maintenance_pool()


def test_maintenance_pool_is_distinct_bounded_and_password_is_separate(monkeypatch, tmp_path):
    _configure_urls(monkeypatch, tmp_path)
    captured = _install_pool_factory(monkeypatch)

    app_pool = postgres_common._get_pool()
    maintenance_pool = postgres_common._get_maintenance_pool()

    assert maintenance_pool is not app_pool
    assert len(captured) == 2
    maintenance_config = next(item for item in captured if "agent_bom_maintenance" in item["conninfo"])
    assert maintenance_config["kwargs"]["min_size"] == 1
    assert 1 <= maintenance_config["kwargs"]["max_size"] <= 4
    assert maintenance_config["kwargs"]["kwargs"]["password"] == "maintenance-secret"


def test_combined_preflight_rejects_superuser_app_without_explicit_acknowledgement(
    monkeypatch,
    tmp_path,
):
    _configure_urls(monkeypatch, tmp_path)
    monkeypatch.setattr(postgres_common, "ALLOW_SUPERUSER_DB", False)
    _install_pool_factory(monkeypatch, app_super=True)

    with pytest.raises(postgres_common.RlsRolePrivilegeError, match="NOSUPERUSER"):
        postgres_common.preflight_rls_capable_role()


def test_combined_preflight_preserves_explicit_single_tenant_superuser_acknowledgement(
    monkeypatch,
    tmp_path,
    caplog,
):
    _configure_urls(monkeypatch, tmp_path)
    monkeypatch.setattr(postgres_common, "ALLOW_SUPERUSER_DB", True)
    _install_pool_factory(monkeypatch, app_super=True)

    postgres_common.preflight_rls_capable_role()

    assert postgres_common._pool is not postgres_common._maintenance_pool
    assert any("disposable single-tenant/dev" in record.message for record in caplog.records)


def test_bypass_context_requires_explicit_maintenance_connection(monkeypatch):
    app_connection = _Connection("agent_bom_app")
    app_pool = _Pool(app_connection)

    with postgres_common.bypass_tenant_rls(audit=False):
        with pytest.raises(postgres_common.MaintenanceRoleConfigurationError, match="maintenance"):
            with postgres_common._tenant_connection(app_pool):
                pass

    assert app_connection.settings == {}


def test_maintenance_connection_applies_scoped_bypass_to_maintenance_pool(monkeypatch):
    maintenance_connection = _Connection("agent_bom_maintenance", maintenance_member=True)
    maintenance_pool = _Pool(maintenance_connection)
    monkeypatch.setattr(postgres_common, "_get_maintenance_pool", lambda: maintenance_pool)

    with postgres_common.bypass_tenant_rls(audit=False):
        with postgres_common._maintenance_connection() as conn:
            assert conn is maintenance_connection
            assert maintenance_connection.settings["app.bypass_rls"] == "1"

    assert not postgres_common.is_tenant_rls_bypassed()


def test_reset_pool_closes_app_and_maintenance_pools(monkeypatch):
    app_pool = _Pool(_Connection("agent_bom_app"))
    maintenance_pool = _Pool(_Connection("agent_bom_maintenance", maintenance_member=True))
    monkeypatch.setattr(postgres_common, "_pool", app_pool)
    monkeypatch.setattr(postgres_common, "_maintenance_pool", maintenance_pool, raising=False)

    postgres_common.reset_pool()

    assert app_pool.closed is True
    assert maintenance_pool.closed is True
    assert postgres_common._pool is None
    assert postgres_common._maintenance_pool is None


def test_runtime_rls_helper_requires_marker_membership_and_scoped_flag():
    statements: list[str] = []

    class _RecordingConnection:
        def execute(self, sql, params=None):
            statements.append(sql)

    postgres_common._ensure_rls_helpers(_RecordingConnection())

    bypass_function = next(sql for sql in statements if "FUNCTION public.abom_rls_bypass" in sql)
    assert "current_setting('app.bypass_rls', true)" in bypass_function
    assert "pg_has_role(session_user, 'agent_bom_rls_maintenance', 'MEMBER')" in bypass_function


def test_bounded_maintenance_poll_skips_stack_warning_and_signed_audit(monkeypatch):
    monkeypatch.setattr(postgres_common.inspect, "stack", lambda **_kwargs: pytest.fail("stack inspected"))
    monkeypatch.setattr(postgres_common.logger, "warning", lambda *_args, **_kwargs: pytest.fail("warning emitted"))
    monkeypatch.setattr(
        postgres_common,
        "_audit_rls_bypass_activation",
        lambda **_kwargs: pytest.fail("signed audit emitted"),
    )

    with postgres_common.bypass_tenant_rls(audit=False, warn=False):
        assert postgres_common.is_tenant_rls_bypassed()
