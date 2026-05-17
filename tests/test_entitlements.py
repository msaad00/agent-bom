"""Tests for local metadata-only entitlement hooks."""

from __future__ import annotations

import json
from pathlib import Path

from starlette.testclient import TestClient

from agent_bom.api.audit_log import InMemoryAuditLog, set_audit_log
from agent_bom.api.server import app
from agent_bom.entitlements import load_entitlement_state
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


def setup_function() -> None:
    set_audit_log(InMemoryAuditLog())


def _admin_client() -> TestClient:
    client = TestClient(app)
    client.headers.update(proxy_headers(role="admin", tenant="tenant-alpha"))
    return client


def test_missing_entitlement_metadata_is_fail_safe(monkeypatch) -> None:
    monkeypatch.delenv("AGENT_BOM_ENTITLEMENT_FILE", raising=False)

    state = load_entitlement_state()

    assert state.status == "missing"
    assert state.enabled_features == ()
    assert state.current_oss_paths_gated is False
    assert state.check("support.sla").enabled is False
    assert state.check("support.sla").metadata_only is True


def test_invalid_entitlement_metadata_disables_metadata_features_only(monkeypatch, tmp_path: Path) -> None:
    entitlement = tmp_path / "entitlement.json"
    entitlement.write_text("{not-json", encoding="utf-8")
    monkeypatch.setenv("AGENT_BOM_ENTITLEMENT_FILE", str(entitlement))

    state = load_entitlement_state()

    assert state.status == "invalid"
    assert state.enabled_features == ()
    assert state.current_oss_paths_gated is False
    assert "not valid JSON" in state.errors[0]


def test_valid_entitlement_metadata_exposes_support_and_feature_checks(monkeypatch, tmp_path: Path) -> None:
    entitlement = tmp_path / "entitlement.json"
    entitlement.write_text(
        json.dumps(
            {
                "lane": "self-hosted-enterprise",
                "features": ["support.sla", "retention.extended", "support.sla"],
                "support": {"tier": "enterprise", "sla": "business-hours"},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("AGENT_BOM_ENTITLEMENT_FILE", str(entitlement))

    state = load_entitlement_state()

    assert state.status == "valid"
    assert state.lane == "self-hosted-enterprise"
    assert state.enabled_features == ("retention.extended", "support.sla")
    assert state.support_tier == "enterprise"
    assert state.sla == "business-hours"
    assert state.check("support_sla").enabled is False
    assert state.check("support.sla").enabled is True


def test_entitlement_admin_api_and_health_summary(monkeypatch, tmp_path: Path) -> None:
    entitlement = tmp_path / "entitlement.json"
    entitlement.write_text(
        json.dumps(
            {
                "lane": "self-hosted-enterprise",
                "features": ["support.sla"],
                "support": {"tier": "enterprise", "sla": "24x7"},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("AGENT_BOM_ENTITLEMENT_FILE", str(entitlement))
    client = _admin_client()

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["entitlements"] == {
        "status": "valid",
        "lane": "self-hosted-enterprise",
        "support_tier": "enterprise",
        "enabled_feature_count": 1,
        "metadata_only": True,
        "current_oss_paths_gated": False,
    }

    listing = client.get("/v1/entitlements")
    assert listing.status_code == 200, listing.text
    body = listing.json()
    assert body["metadata_only"] is True
    assert body["current_oss_paths_gated"] is False
    assert body["enabled_features"] == ["support.sla"]

    check = client.get("/v1/entitlements/check/support.sla")
    assert check.status_code == 200, check.text
    assert check.json()["check"]["enabled"] is True


def test_entitlement_routes_require_admin_role(monkeypatch) -> None:
    monkeypatch.delenv("AGENT_BOM_ENTITLEMENT_FILE", raising=False)
    client = TestClient(app)
    client.headers.update(proxy_headers(role="analyst", tenant="tenant-alpha"))

    response = client.get("/v1/entitlements")

    assert response.status_code == 403
