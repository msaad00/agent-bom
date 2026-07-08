"""Regression: env parse helpers must not silently flip security defaults (#3677)."""

from __future__ import annotations

import importlib

import pytest


def _reload_config(monkeypatch: pytest.MonkeyPatch) -> None:
    import agent_bom.config as config_mod

    importlib.reload(config_mod)


def test_bool_typo_on_true_default_keeps_default(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    monkeypatch.setenv("AGENT_BOM_MCP_AUTH_REQUIRE_TLS", "Ture")
    _reload_config(monkeypatch)
    from agent_bom.config import MCP_AUTH_REQUIRE_TLS

    assert MCP_AUTH_REQUIRE_TLS is True
    assert "unparseable boolean env AGENT_BOM_MCP_AUTH_REQUIRE_TLS" in caplog.text


def test_bool_explicit_false_overrides_true_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_MCP_AUTH_REQUIRE_TLS", "false")
    _reload_config(monkeypatch)
    from agent_bom.config import MCP_AUTH_REQUIRE_TLS

    assert MCP_AUTH_REQUIRE_TLS is False


def test_int_typo_falls_back_to_default(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    monkeypatch.setenv("AGENT_BOM_HTTP_MAX_RETRIES", "not-a-number")
    _reload_config(monkeypatch)
    from agent_bom.config import HTTP_MAX_RETRIES

    assert HTTP_MAX_RETRIES == 3
    assert "unparseable int env AGENT_BOM_HTTP_MAX_RETRIES" in caplog.text


def test_float_typo_falls_back_to_default(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    monkeypatch.setenv("AGENT_BOM_HTTP_INITIAL_BACKOFF", "NaN-ish")
    _reload_config(monkeypatch)
    from agent_bom.config import HTTP_INITIAL_BACKOFF

    assert HTTP_INITIAL_BACKOFF == 1.0
    assert "unparseable float env AGENT_BOM_HTTP_INITIAL_BACKOFF" in caplog.text
