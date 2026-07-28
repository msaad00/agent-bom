"""Startup preflight for the Postgres RLS-bypass role (epic #4274 item 5).

Tenant isolation on Postgres is enforced entirely by ``FORCE ROW LEVEL
SECURITY``. A ``SUPERUSER`` / ``BYPASSRLS`` role ignores those policies, so the
control plane must refuse such a role. ``_guard_rls_capable_role`` already does
this, but only lazily on the first pool use — i.e. the first request. These
tests cover the CLI bind-path preflight that surfaces the same failure at boot,
before uvicorn accepts traffic, mirroring the existing non-loopback auth gate.
"""

from __future__ import annotations

import click
import pytest

from agent_bom.api.postgres_common import MaintenanceRoleConfigurationError, RlsRolePrivilegeError
from agent_bom.cli._server import _enforce_database_role_posture


def test_preflight_noop_without_postgres_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    """No Postgres configured => the DB-role gate never touches a pool."""
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.delenv("SNOWFLAKE_ACCOUNT", raising=False)

    called = False

    def _boom() -> None:
        nonlocal called
        called = True
        raise AssertionError("preflight must not run without Postgres configured")

    monkeypatch.setattr("agent_bom.api.postgres_common.preflight_rls_capable_role", _boom)
    _enforce_database_role_posture("serve")
    assert called is False


def test_preflight_noop_when_snowflake_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    """Snowflake takes precedence over Postgres; the PG role gate is inert."""
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgres://agent_bom_app@localhost/x")
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acme")

    monkeypatch.setattr(
        "agent_bom.api.postgres_common.preflight_rls_capable_role",
        lambda: (_ for _ in ()).throw(AssertionError("must not run for Snowflake backend")),
    )
    _enforce_database_role_posture("serve")


def test_preflight_raises_click_exception_on_rls_bypass_role(monkeypatch: pytest.MonkeyPatch) -> None:
    """A SUPERUSER/BYPASSRLS role aborts the bind with an actionable CLI error."""
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgres://postgres@localhost/x")
    monkeypatch.delenv("SNOWFLAKE_ACCOUNT", raising=False)

    def _raise() -> None:
        raise RlsRolePrivilegeError("Postgres role 'postgres' has SUPERUSER, which bypasses FORCE ROW LEVEL SECURITY")

    monkeypatch.setattr("agent_bom.api.postgres_common.preflight_rls_capable_role", _raise)
    with pytest.raises(click.ClickException, match="FORCE ROW LEVEL SECURITY"):
        _enforce_database_role_posture("serve")


def test_preflight_passes_for_non_superuser_role(monkeypatch: pytest.MonkeyPatch) -> None:
    """A NOSUPERUSER NOBYPASSRLS role returns cleanly — bind proceeds."""
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgres://agent_bom_app@localhost/x")
    monkeypatch.delenv("SNOWFLAKE_ACCOUNT", raising=False)

    ran = False

    def _ok() -> None:
        nonlocal ran
        ran = True

    monkeypatch.setattr("agent_bom.api.postgres_common.preflight_rls_capable_role", _ok)
    _enforce_database_role_posture("serve")
    assert ran is True


@pytest.mark.parametrize(
    "error",
    [
        ValueError("AGENT_BOM_POSTGRES_MAINTENANCE_URL is required"),
        MaintenanceRoleConfigurationError("maintenance role must be distinct"),
    ],
)
def test_preflight_rejects_invalid_maintenance_configuration(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
) -> None:
    """Missing or unsafe maintenance credentials abort before the server binds."""
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgres://agent_bom_app@localhost/x")
    monkeypatch.delenv("SNOWFLAKE_ACCOUNT", raising=False)

    def _raise() -> None:
        raise error

    monkeypatch.setattr("agent_bom.api.postgres_common.preflight_rls_capable_role", _raise)
    with pytest.raises(click.ClickException, match="(?i)maintenance"):
        _enforce_database_role_posture("serve")


@pytest.mark.parametrize(
    "error",
    [
        OSError("connection refused"),
        RuntimeError("password authentication failed for user agent_bom_maintenance"),
    ],
)
def test_preflight_probe_or_credential_failure_blocks_bind_without_leaking_driver_text(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
) -> None:
    """An unvalidated maintenance boundary must never accept requests."""
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgres://agent_bom_app@localhost/x")
    monkeypatch.delenv("SNOWFLAKE_ACCOUNT", raising=False)

    def _probe_error() -> None:
        raise error

    monkeypatch.setattr("agent_bom.api.postgres_common.preflight_rls_capable_role", _probe_error)
    with pytest.raises(click.ClickException, match="Postgres role preflight failed") as denied:
        _enforce_database_role_posture("serve")
    assert str(error) not in str(denied.value)
