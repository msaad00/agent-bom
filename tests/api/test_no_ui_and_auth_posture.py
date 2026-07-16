"""Regression tests for `--no-ui` root gating and the startup auth-posture log.

Covers two operator-facing correctness bugs:

* ``--no-ui`` (``AGENT_BOM_NO_UI``) must actually stop ``GET /`` from serving the
  bundled dashboard. The SPA mount already honoured the gate, but the explicit
  ``/`` route did not, so the root kept returning the dashboard index HTML.
* The control-plane "no authentication configured" CRITICAL must reflect the
  *final* auth posture, not a transient import-time state. ``configure_api``
  runs at import (``configure_api_from_env``) with only environment auth in
  scope, so emitting from there produced a misleading CRITICAL whenever the key
  arrived via a CLI ``--api-key`` flag before the CLI reconfigured.
"""

import logging
from pathlib import Path

from starlette.testclient import TestClient

from agent_bom.api import server
from agent_bom.api.middleware import configure_auth_runtime
from agent_bom.api.server import (
    _DashboardFile,
    _log_control_plane_auth_posture,
    app,
    configure_api,
    configure_api_from_env,
)

_SERVER_LOGGER = "agent_bom.api.server"
_NO_AUTH_MSG = "No control-plane authentication configured"
_UNAUTH_OPT_IN_MSG = "enables unauthenticated API access"


def _fake_bundled_index(tmp_path: Path, monkeypatch) -> None:
    """Pretend a dashboard bundle exists so the root-serving path is exercised.

    The packaged ``ui_dist`` is a build artifact absent from a fresh checkout, so
    without this the root would redirect regardless of the flag and the test
    would not exercise the gate.
    """
    index = tmp_path / "index.html"
    index.write_text("<!DOCTYPE html><html><body>DASHBOARD</body></html>", encoding="utf-8")
    fake = _DashboardFile(path=index, relative_path="index.html")
    monkeypatch.setattr(server, "_dashboard_index_file", lambda: fake)


# ── Claim D: `--no-ui` disables the dashboard at `/` ─────────────────────────


def test_no_ui_root_redirects_to_docs(tmp_path, monkeypatch):
    _fake_bundled_index(tmp_path, monkeypatch)
    monkeypatch.setenv("AGENT_BOM_NO_UI", "1")

    client = TestClient(app)
    resp = client.get("/", follow_redirects=False)

    assert resp.status_code in (302, 307)
    assert resp.headers["location"] == "/docs"
    assert "DASHBOARD" not in resp.text


def test_ui_enabled_root_serves_dashboard(tmp_path, monkeypatch):
    # Control: with the gate off, the same bundle IS served at the root, proving
    # the redirect above is caused by `--no-ui` and not the missing bundle.
    _fake_bundled_index(tmp_path, monkeypatch)
    monkeypatch.delenv("AGENT_BOM_NO_UI", raising=False)

    client = TestClient(app)
    resp = client.get("/", follow_redirects=False)

    assert resp.status_code == 200
    assert "DASHBOARD" in resp.text


def test_no_ui_keeps_api_surfaces(tmp_path, monkeypatch):
    _fake_bundled_index(tmp_path, monkeypatch)
    monkeypatch.setenv("AGENT_BOM_NO_UI", "1")

    client = TestClient(app)
    assert client.get("/health").status_code == 200
    assert client.get("/openapi.json").status_code == 200


# ── Claim E: startup auth-posture log reflects final state, not import-time ──


def test_configure_api_does_not_emit_transient_auth_log(monkeypatch, caplog):
    # A CLI `--api-key` flag is not in the environment, so the import-time
    # configure_api_from_env sees no auth. It must NOT log the CRITICAL there —
    # logging is deferred to serving start (lifespan).
    for var in ("AGENT_BOM_API_KEY", "AGENT_BOM_API_KEYS", "AGENT_BOM_OIDC_ISSUER"):
        monkeypatch.delenv(var, raising=False)

    with caplog.at_level(logging.DEBUG, logger=_SERVER_LOGGER):
        configure_api_from_env()

    messages = [rec.getMessage() for rec in caplog.records]
    assert not any(_NO_AUTH_MSG in m for m in messages), messages
    assert not any(_UNAUTH_OPT_IN_MSG in m for m in messages), messages


def test_configure_api_with_key_does_not_emit_auth_log(caplog):
    with caplog.at_level(logging.DEBUG, logger=_SERVER_LOGGER):
        configure_api(api_key="secret-key", allow_unauthenticated=False)

    messages = [rec.getMessage() for rec in caplog.records]
    assert not any(_NO_AUTH_MSG in m for m in messages), messages


def test_auth_posture_helper_silent_when_key_configured(caplog):
    configure_auth_runtime(
        api_key_configured=True,
        oidc_enabled=False,
        trusted_proxy_enabled=False,
        unauthenticated_allowed=False,
    )
    with caplog.at_level(logging.DEBUG, logger=_SERVER_LOGGER):
        _log_control_plane_auth_posture()

    assert not any(_NO_AUTH_MSG in r.getMessage() for r in caplog.records)
    assert not any(_UNAUTH_OPT_IN_MSG in r.getMessage() for r in caplog.records)


def test_auth_posture_helper_critical_when_nothing_configured(caplog):
    configure_auth_runtime(
        api_key_configured=False,
        oidc_enabled=False,
        trusted_proxy_enabled=False,
        unauthenticated_allowed=False,
    )
    with caplog.at_level(logging.DEBUG, logger=_SERVER_LOGGER):
        _log_control_plane_auth_posture()

    criticals = [r for r in caplog.records if r.levelno == logging.CRITICAL and _NO_AUTH_MSG in r.getMessage()]
    assert criticals, [r.getMessage() for r in caplog.records]


def test_auth_posture_helper_warns_when_unauthenticated_opt_in(caplog):
    configure_auth_runtime(
        api_key_configured=False,
        oidc_enabled=False,
        trusted_proxy_enabled=False,
        unauthenticated_allowed=True,
    )
    with caplog.at_level(logging.DEBUG, logger=_SERVER_LOGGER):
        _log_control_plane_auth_posture()

    assert any(r.levelno == logging.WARNING and _UNAUTH_OPT_IN_MSG in r.getMessage() for r in caplog.records)
    assert not any(_NO_AUTH_MSG in r.getMessage() for r in caplog.records)
