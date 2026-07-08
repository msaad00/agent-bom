"""Regression: legacy env aliases resolve through canonical AGENT_BOM_* keys (#3677)."""

from __future__ import annotations

import importlib

import pytest


def _reload_config(monkeypatch: pytest.MonkeyPatch) -> None:
    import agent_bom.config as config_mod

    importlib.reload(config_mod)


def test_resolved_deployment_env_prefers_canonical_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_DEPLOYMENT_ENV", "Production")
    monkeypatch.setenv("AGENT_BOM_ENV", "staging")
    monkeypatch.setenv("ENVIRONMENT", "dev")
    _reload_config(monkeypatch)
    from agent_bom.config import resolved_deployment_env

    assert resolved_deployment_env() == "production"


def test_resolved_deployment_env_falls_back_to_legacy_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_DEPLOYMENT_ENV", raising=False)
    monkeypatch.setenv("AGENT_BOM_ENV", "Staging")
    _reload_config(monkeypatch)
    from agent_bom.config import resolved_deployment_env

    assert resolved_deployment_env() == "staging"


def test_resolved_cors_origins_prefers_canonical_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_CORS_ORIGINS", "https://app.example.com")
    monkeypatch.setenv("CORS_ORIGINS", "https://legacy.example.com")
    _reload_config(monkeypatch)
    from agent_bom.config import resolved_cors_origins_raw

    assert resolved_cors_origins_raw() == "https://app.example.com"


def test_resolved_cors_origins_falls_back_to_legacy_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_CORS_ORIGINS", raising=False)
    monkeypatch.setenv("CORS_ORIGINS", "https://legacy.example.com")
    _reload_config(monkeypatch)
    from agent_bom.config import resolved_cors_origins_raw

    assert resolved_cors_origins_raw() == "https://legacy.example.com"


def test_resolved_servicenow_instance_prefers_canonical_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_SERVICENOW_INSTANCE", "https://canonical.example.com")
    monkeypatch.setenv("SERVICENOW_INSTANCE", "https://legacy.example.com")
    _reload_config(monkeypatch)
    from agent_bom.config import resolved_servicenow_instance_url

    assert resolved_servicenow_instance_url() == "https://canonical.example.com"


def test_resolved_vault_addr_prefers_canonical_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_VAULT_ADDR", "https://vault-canonical.example.com")
    monkeypatch.setenv("VAULT_ADDR", "https://vault-legacy.example.com")
    _reload_config(monkeypatch)
    from agent_bom.config import resolved_vault_addr

    assert resolved_vault_addr() == "https://vault-canonical.example.com"
