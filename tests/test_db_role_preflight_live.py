"""Live-Postgres tier for the RLS-bypass role preflight (epic #4274 item 5).

Two opt-in env vars gate this:
- ``AGENT_BOM_POSTGRES_URL`` — the app-role URL. The role behind it MUST be
  ``NOSUPERUSER NOBYPASSRLS`` (this is the CI assertion the epic asks for).
- ``AGENT_BOM_POSTGRES_ADMIN_URL`` — a role that can ``CREATE ROLE`` / ``DROP
  ROLE`` (never used by the app). Used to spin up a throwaway ``BYPASSRLS`` role
  and prove the runtime ``pg_roles`` guard rejects it — the name blocklist alone
  does not cover a superuser role with a non-obvious name.
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import click
import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("AGENT_BOM_POSTGRES_URL"),
    reason="AGENT_BOM_POSTGRES_URL is required for the live DB-role preflight tests",
)


def _reset_pool() -> None:
    from agent_bom.api import postgres_common

    pool = postgres_common._pool
    if pool is not None:
        pool.close()
    postgres_common.reset_pool()


def test_configured_app_role_is_non_superuser_and_passes_preflight() -> None:
    """The deployed app role must not be able to bypass RLS — preflight is clean."""
    from agent_bom.api import postgres_common

    _reset_pool()
    try:
        postgres_common.preflight_rls_capable_role()  # must not raise
    finally:
        _reset_pool()


def test_cli_gate_passes_for_configured_app_role() -> None:
    """The CLI bind-path gate is a no-op boot success for the safe app role."""
    from agent_bom.cli._server import _enforce_database_role_posture

    _reset_pool()
    try:
        _enforce_database_role_posture("serve")  # must not raise
    finally:
        _reset_pool()


@pytest.mark.skipif(
    not os.environ.get("AGENT_BOM_POSTGRES_ADMIN_URL"),
    reason="AGENT_BOM_POSTGRES_ADMIN_URL (CREATE ROLE) required to prove the BYPASSRLS rejection",
)
def test_bypassrls_role_is_rejected_by_runtime_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """A BYPASSRLS role with a non-blocklisted name is caught by the pg_roles
    guard (not just the URL name blocklist) and aborts the bind."""
    import psycopg

    from agent_bom.api import postgres_common

    admin_url = os.environ["AGENT_BOM_POSTGRES_ADMIN_URL"]
    role = f"abom_bypass_{uuid4().hex[:10]}"
    password = "preflightprobe"  # literal (DDL cannot be parameterized); no quotes to escape

    with psycopg.connect(admin_url, autocommit=True) as conn:
        conn.execute(f"CREATE ROLE \"{role}\" LOGIN PASSWORD '{password}' BYPASSRLS")
    try:
        parts = urlsplit(os.environ["AGENT_BOM_POSTGRES_URL"])
        netloc = f"{role}:{password}@{parts.hostname}"
        if parts.port:
            netloc += f":{parts.port}"
        bypass_url = urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))

        monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", bypass_url)
        _reset_pool()

        with pytest.raises(postgres_common.RlsRolePrivilegeError, match="BYPASSRLS"):
            postgres_common.preflight_rls_capable_role()

        _reset_pool()
        from agent_bom.cli._server import _enforce_database_role_posture

        with pytest.raises(click.ClickException, match="BYPASSRLS"):
            _enforce_database_role_posture("serve")
    finally:
        _reset_pool()
        with psycopg.connect(admin_url, autocommit=True) as conn:
            conn.execute(f'DROP ROLE IF EXISTS "{role}"')
