"""Tests for operator-facing policy + readiness surfaces.

Covers:
- /v1/auth/policy exposing API key + rate-limit key status
- /readyz flipping to 503 during graceful shutdown
- Rate-limit key rotation status computation for each documented state
"""

from __future__ import annotations

import importlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from starlette.testclient import TestClient

from agent_bom.api import audit_log as audit_log_module
from agent_bom.api import compliance_signing as compliance_signing_module
from agent_bom.api import server as _server_mod
from agent_bom.api import stores as _stores
from agent_bom.api.middleware import APIKeyMiddleware, get_rate_limit_key_status, get_rate_limit_runtime_status
from agent_bom.api.server import app
from agent_bom.api.stores import set_tenant_quota_store
from agent_bom.api.tenant_quota_store import InMemoryTenantQuotaStore

# ─── Rate-limit key status ────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _restore_runtime_modules():
    yield
    _reload_config()
    importlib.reload(audit_log_module)
    importlib.reload(compliance_signing_module)
    compliance_signing_module.reset_signer_cache_for_tests()


def _clear_rate_limit_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_RATE_LIMIT_KEY", raising=False)
    monkeypatch.delenv("AGENT_BOM_AUDIT_HMAC_KEY", raising=False)
    monkeypatch.delenv("AGENT_BOM_RATE_LIMIT_KEY_LAST_ROTATED", raising=False)


def _reload_config() -> None:
    import importlib

    import agent_bom.config as _cfg

    importlib.reload(_cfg)


def test_status_ephemeral_when_no_key(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_rate_limit_env(monkeypatch)
    _reload_config()
    status = get_rate_limit_key_status()
    assert status["status"] == "ephemeral"
    assert status["last_rotated"] is None
    assert status["age_days"] is None


def test_status_unknown_age_when_key_without_rotation_timestamp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_rate_limit_env(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_RATE_LIMIT_KEY", "secret-key")
    _reload_config()
    status = get_rate_limit_key_status()
    assert status["status"] == "unknown_age"
    assert status["fallback_source"] is None


def test_status_fallback_source_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_rate_limit_env(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_AUDIT_HMAC_KEY", "audit-fallback-key")
    _reload_config()
    status = get_rate_limit_key_status()
    assert status["fallback_source"] == "AGENT_BOM_AUDIT_HMAC_KEY"
    assert status["status"] == "unknown_age"


def test_status_ok_within_rotation_interval(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_rate_limit_env(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_RATE_LIMIT_KEY", "secret-key")
    rotated = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    monkeypatch.setenv("AGENT_BOM_RATE_LIMIT_KEY_LAST_ROTATED", rotated)
    _reload_config()
    status = get_rate_limit_key_status()
    assert status["status"] == "ok"
    assert status["age_days"] == 5


def test_status_rotation_due_past_interval(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_rate_limit_env(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_RATE_LIMIT_KEY", "secret-key")
    monkeypatch.setenv("AGENT_BOM_RATE_LIMIT_KEY_ROTATION_DAYS", "30")
    rotated = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
    monkeypatch.setenv("AGENT_BOM_RATE_LIMIT_KEY_LAST_ROTATED", rotated)
    _reload_config()
    status = get_rate_limit_key_status()
    assert status["status"] == "rotation_due"
    assert status["age_days"] == 45


def test_status_max_age_exceeded(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_rate_limit_env(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_RATE_LIMIT_KEY", "secret-key")
    monkeypatch.setenv("AGENT_BOM_RATE_LIMIT_KEY_MAX_AGE_DAYS", "90")
    rotated = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat()
    monkeypatch.setenv("AGENT_BOM_RATE_LIMIT_KEY_LAST_ROTATED", rotated)
    _reload_config()
    status = get_rate_limit_key_status()
    assert status["status"] == "max_age_exceeded"
    assert status["age_days"] == 120


def test_status_invalid_timestamp_reports_unknown_age(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_rate_limit_env(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_RATE_LIMIT_KEY", "secret-key")
    monkeypatch.setenv("AGENT_BOM_RATE_LIMIT_KEY_LAST_ROTATED", "not-a-date")
    _reload_config()
    status = get_rate_limit_key_status()
    assert status["status"] == "unknown_age"


# ─── /v1/auth/policy surface ──────────────────────────────────────────────────


def test_auth_policy_surface_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_rate_limit_env(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_RATE_LIMIT_KEY", "secret-key")
    _reload_config()
    importlib.reload(audit_log_module)
    compliance_signing_module.reset_signer_cache_for_tests()

    client = TestClient(app)
    resp = client.get("/v1/auth/policy")
    assert resp.status_code == 200
    body = resp.json()
    assert body["api_key"]["rotation_policy"] == "enforced"
    assert body["api_key"]["rotation_endpoint"] == "/v1/auth/keys/{key_id}/rotate"
    assert "default_ttl_seconds" in body["api_key"]
    assert "max_ttl_seconds" in body["api_key"]
    assert "default_overlap_seconds" in body["api_key"]
    assert "max_overlap_seconds" in body["api_key"]
    assert body["rate_limit_key"]["status"] in {"ok", "ephemeral", "unknown_age", "rotation_due", "max_age_exceeded"}
    assert body["ui"]["recommended_mode"] in {"no_auth", "reverse_proxy_oidc", "oidc_bearer", "session_api_key"}
    assert body["ui"]["session_storage_fallback"] == "session_api_key"
    assert body["rate_limit_runtime"]["backend"] in {"inmemory_single_process", "postgres_shared"}
    assert "shared_across_replicas" in body["rate_limit_runtime"]
    assert "configured_api_replicas" in body["rate_limit_runtime"]
    assert "fail_closed" in body["rate_limit_runtime"]
    assert body["secret_integrity"]["audit_hmac"]["status"] in {"configured", "ephemeral"}
    assert body["secret_integrity"]["compliance_signing"]["algorithm"] in {"HMAC-SHA256", "Ed25519"}
    assert body["tenant_quotas"]["active_scan_jobs"] >= 1
    assert body["tenant_quotas"]["retained_scan_jobs"] >= 1
    assert body["tenant_quotas"]["fleet_agents"] >= 1
    assert body["tenant_quotas"]["schedules"] >= 1
    assert body["tenant_quota_runtime"]["source"] == "global_default"
    assert body["tenant_quota_runtime"]["per_tenant_overrides"] is True
    assert body["tenant_quota_runtime"]["active_override"] is False
    assert body["tenant_quota_runtime"]["override_endpoint"] == "/v1/auth/quota"
    assert body["tenant_quota_runtime"]["usage"]["active_scan_jobs"]["current"] >= 0
    assert body["tenant_quota_runtime"]["usage"]["active_scan_jobs"]["limit"] >= 1
    assert body["tenant_quota_runtime"]["usage"]["active_scan_jobs"]["source"] == "global_default"
    assert body["tenant_quota_runtime"]["usage"]["active_scan_jobs"]["override_limit"] is None
    assert body["identity_provisioning"]["scim"]["status"] == "not_implemented"
    assert body["identity_provisioning"]["scim"]["supported"] is False
    assert "service_keys" in body["identity_provisioning"]["session_revocation"]


def test_auth_policy_reports_secret_integrity_posture(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_rate_limit_env(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_AUDIT_HMAC_KEY", "audit-secret")
    private_key = Ed25519PrivateKey.generate()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    monkeypatch.setenv("AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM", pem)
    _reload_config()
    importlib.reload(audit_log_module)
    importlib.reload(compliance_signing_module)
    compliance_signing_module.reset_signer_cache_for_tests()

    client = TestClient(app)
    body = client.get("/v1/auth/policy").json()

    assert body["secret_integrity"]["audit_hmac"] == {
        "status": "configured",
        "configured": True,
        "required": False,
        "source": "AGENT_BOM_AUDIT_HMAC_KEY",
        "persists_across_restart": True,
        "rotation_tracking_supported": False,
        "message": (
            "Audit log tamper detection uses a configured shared secret. "
            "Signatures remain verifiable across restarts as long as the same key stays in place."
        ),
    }
    assert body["secret_integrity"]["compliance_signing"]["algorithm"] == "Ed25519"
    assert body["secret_integrity"]["compliance_signing"]["mode"] == "asymmetric_public_key"
    assert body["secret_integrity"]["compliance_signing"]["public_key_endpoint"] == "/v1/compliance/verification-key"


def test_auth_quota_update_persists_tenant_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    _reload_config()
    _server_mod.configure_api(api_key=None)
    original_store = _stores._tenant_quota_store
    try:
        quota_store = InMemoryTenantQuotaStore()
        set_tenant_quota_store(quota_store)

        client = TestClient(app)
        headers = {
            "X-Agent-Bom-Role": "admin",
            "X-Agent-Bom-Tenant-ID": "tenant-alpha",
        }
        resp = client.put(
            "/v1/auth/quota",
            headers=headers,
            json={"active_scan_jobs": 7, "schedules": 3},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["source"] == "tenant_override"
        assert body["active_override"] is True
        assert body["overrides"] == {"active_scan_jobs": 7, "schedules": 3}
        assert body["usage"]["active_scan_jobs"]["limit"] == 7
        assert body["usage"]["active_scan_jobs"]["source"] == "tenant_override"
        assert body["usage"]["active_scan_jobs"]["override_limit"] == 7
        assert body["usage"]["retained_scan_jobs"]["source"] == "global_default"

        policy = client.get("/v1/auth/policy", headers=headers).json()
        assert policy["tenant_quota_runtime"]["usage"]["active_scan_jobs"]["limit"] == 7
        assert policy["tenant_quota_runtime"]["usage"]["schedules"]["limit"] == 3
    finally:
        _stores._tenant_quota_store = original_store


def test_rate_limit_runtime_reports_shared_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://example/test")
    monkeypatch.setenv("AGENT_BOM_REQUIRE_SHARED_RATE_LIMIT", "1")
    status = get_rate_limit_runtime_status()
    assert status == {
        "backend": "postgres_shared",
        "postgres_configured": True,
        "configured_api_replicas": 1,
        "shared_required": True,
        "shared_across_replicas": True,
        "fail_closed": True,
        "message": "Rate limiting uses Postgres-backed shared state across replicas.",
    }


def test_rate_limit_runtime_reports_single_replica_process_local_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_CONTROL_PLANE_REPLICAS", "1")
    status = get_rate_limit_runtime_status()
    assert status == {
        "backend": "inmemory_single_process",
        "postgres_configured": False,
        "configured_api_replicas": 1,
        "shared_required": False,
        "shared_across_replicas": False,
        "fail_closed": False,
        "message": (
            "Rate limiting is process-local only because the API is configured for a single replica. "
            "Multi-replica deployments must configure AGENT_BOM_POSTGRES_URL."
        ),
    }


def test_auth_policy_requires_admin_role_in_api_middleware() -> None:
    middleware = APIKeyMiddleware(app, api_key="static-secret")
    assert middleware._required_role("GET", "/v1/auth/policy") == "admin"
    assert middleware._required_role("PUT", "/v1/auth/quota") == "admin"
    assert middleware._required_role("DELETE", "/v1/auth/quota") == "admin"
    assert middleware._required_role("GET", "/v1/auth/debug") == "viewer"


def test_auth_debug_reports_runtime_auth_modes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    _reload_config()
    _server_mod.configure_api(api_key=None)

    client = TestClient(app)
    resp = client.get(
        "/v1/auth/debug",
        headers={
            "X-Agent-Bom-Role": "viewer",
            "X-Agent-Bom-Tenant-ID": "tenant-alpha",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["authenticated"] is True
    assert body["auth_required"] is True
    assert "trusted_proxy" in body["configured_modes"]
    assert body["recommended_ui_mode"] == "reverse_proxy_oidc"


# ─── /readyz drain behavior ──────────────────────────────────────────────────


def test_readyz_green_by_default() -> None:
    _server_mod._shutting_down = False
    client = TestClient(app)
    resp = client.get("/readyz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ready"}


def test_readyz_red_during_shutdown() -> None:
    _server_mod._shutting_down = True
    try:
        client = TestClient(app)
        resp = client.get("/readyz")
        assert resp.status_code == 503
        assert resp.json() == {"status": "draining"}
    finally:
        _server_mod._shutting_down = False
