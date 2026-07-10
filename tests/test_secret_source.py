"""Tests for api.secret_source — env-or-file secret resolution."""

from __future__ import annotations

import pytest

from agent_bom.api.secret_source import resolve_secret, secret_is_configured


def test_resolve_secret_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_API_KEY_FILE", raising=False)
    monkeypatch.setenv("AGENT_BOM_API_KEY", "  env-secret  ")
    assert resolve_secret("AGENT_BOM_API_KEY") == "env-secret"


def test_resolve_secret_file_wins_over_env(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    secret_file = tmp_path / "api_key"
    secret_file.write_text("file-secret\n", encoding="utf-8")
    monkeypatch.setenv("AGENT_BOM_API_KEY_FILE", str(secret_file))
    monkeypatch.setenv("AGENT_BOM_API_KEY", "env-secret")
    assert resolve_secret("AGENT_BOM_API_KEY") == "file-secret"


def test_resolve_secret_missing_file_raises(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    missing = tmp_path / "missing"
    monkeypatch.setenv("AGENT_BOM_API_KEY_FILE", str(missing))
    monkeypatch.setenv("AGENT_BOM_API_KEY", "env-secret")
    with pytest.raises(ValueError, match="not found"):
        resolve_secret("AGENT_BOM_API_KEY")


def test_resolve_secret_empty_file_raises(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    empty = tmp_path / "empty"
    empty.write_text("\n", encoding="utf-8")
    monkeypatch.setenv("AGENT_BOM_AUDIT_HMAC_KEY_FILE", str(empty))
    with pytest.raises(ValueError, match="empty"):
        resolve_secret("AGENT_BOM_AUDIT_HMAC_KEY")


def test_resolve_secret_required_missing_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_CONNECTIONS_KEY", raising=False)
    monkeypatch.delenv("AGENT_BOM_CONNECTIONS_KEY_FILE", raising=False)
    with pytest.raises(ValueError, match="required"):
        resolve_secret("AGENT_BOM_CONNECTIONS_KEY", required=True)


def test_resolve_secret_optional_missing_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_RATE_LIMIT_KEY", raising=False)
    monkeypatch.delenv("AGENT_BOM_RATE_LIMIT_KEY_FILE", raising=False)
    assert resolve_secret("AGENT_BOM_RATE_LIMIT_KEY") == ""


def test_secret_is_configured_env_and_file(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_SCIM_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("AGENT_BOM_SCIM_BEARER_TOKEN_FILE", raising=False)
    assert secret_is_configured("AGENT_BOM_SCIM_BEARER_TOKEN") is False

    monkeypatch.setenv("AGENT_BOM_SCIM_BEARER_TOKEN", "tok")
    assert secret_is_configured("AGENT_BOM_SCIM_BEARER_TOKEN") is True

    secret_file = tmp_path / "scim"
    secret_file.write_text("file-tok", encoding="utf-8")
    monkeypatch.setenv("AGENT_BOM_SCIM_BEARER_TOKEN_FILE", str(secret_file))
    monkeypatch.delenv("AGENT_BOM_SCIM_BEARER_TOKEN", raising=False)
    assert secret_is_configured("AGENT_BOM_SCIM_BEARER_TOKEN") is True

    monkeypatch.setenv("AGENT_BOM_SCIM_BEARER_TOKEN_FILE", str(tmp_path / "gone"))
    assert secret_is_configured("AGENT_BOM_SCIM_BEARER_TOKEN") is False
