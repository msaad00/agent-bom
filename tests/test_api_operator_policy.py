"""Tests for operator-facing policy + readiness surfaces.

Covers:
- /v1/auth/policy exposing API key + rate-limit key status
- /readyz flipping to 503 during graceful shutdown
- Rate-limit key rotation status computation for each documented state
"""

from __future__ import annotations

import importlib
import sqlite3
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
from agent_bom.api.storage_schema import (
    CONTROL_PLANE_SCHEMA_TABLE,
    CONTROL_PLANE_SCHEMA_VERSION,
    describe_control_plane_storage_schema,
    ensure_sqlite_schema_version,
)
from agent_bom.api.stores import set_tenant_quota_store
from agent_bom.api.tenant_quota_store import InMemoryTenantQuotaStore
from tests.auth_helpers import PROXY_SECRET, proxy_headers

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
    monkeypatch.delenv("AGENT_BOM_AUDIT_HMAC_LAST_ROTATED", raising=False)
    monkeypatch.delenv("AGENT_BOM_AUDIT_HMAC_ROTATION_DAYS", raising=False)
    monkeypatch.delenv("AGENT_BOM_AUDIT_HMAC_MAX_AGE_DAYS", raising=False)
    monkeypatch.delenv("AGENT_BOM_COMPLIANCE_SIGNING_LAST_ROTATED", raising=False)
    monkeypatch.delenv("AGENT_BOM_COMPLIANCE_SIGNING_ROTATION_DAYS", raising=False)
    monkeypatch.delenv("AGENT_BOM_COMPLIANCE_SIGNING_MAX_AGE_DAYS", raising=False)
    monkeypatch.delenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", raising=False)
    monkeypatch.delenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY_LAST_ROTATED", raising=False)
    monkeypatch.delenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY_ROTATION_DAYS", raising=False)
    monkeypatch.delenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY_MAX_AGE_DAYS", raising=False)
    monkeypatch.delenv("AGENT_BOM_SCIM_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("AGENT_BOM_SCIM_BEARER_TOKEN_ID", raising=False)
    monkeypatch.delenv("AGENT_BOM_SCIM_BEARER_TOKEN_LAST_ROTATED", raising=False)
    monkeypatch.delenv("AGENT_BOM_SCIM_BEARER_TOKEN_ROTATION_DAYS", raising=False)
    monkeypatch.delenv("AGENT_BOM_SCIM_BEARER_TOKEN_MAX_AGE_DAYS", raising=False)
    monkeypatch.delenv("AGENT_BOM_REQUIRE_SCIM", raising=False)
    monkeypatch.delenv("AGENT_BOM_SECRET_PROVIDER", raising=False)
    monkeypatch.delenv("AGENT_BOM_EXTERNAL_SECRETS_ENABLED", raising=False)


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
    assert body["ui"]["browser_session"] == "signed_http_only_cookie"
    assert body["ui"]["session_storage_fallback"] == "disabled"
    assert body["audit_hmac"]["rotation_tracking_supported"] is True
    assert body["rate_limit_runtime"]["backend"] in {"inmemory_single_process", "postgres_shared"}
    assert "shared_across_replicas" in body["rate_limit_runtime"]
    assert "configured_api_replicas" in body["rate_limit_runtime"]
    assert "fail_closed" in body["rate_limit_runtime"]
    assert body["secret_integrity"]["audit_hmac"]["status"] in {"configured", "ephemeral"}
    assert body["secret_integrity"]["audit_hmac"]["rotation_tracking_supported"] is True
    assert body["secret_integrity"]["audit_hmac"]["rotation_status"] in {
        "ok",
        "unknown_age",
        "ephemeral",
        "rotation_due",
        "max_age_exceeded",
    }
    assert body["secret_integrity"]["compliance_signing"]["algorithm"] in {"HMAC-SHA256", "Ed25519"}
    assert body["secret_integrity"]["compliance_signing"]["rotation_tracking_supported"] is True
    assert body["secret_integrity"]["compliance_signing"]["rotation_status"] in {
        "ok",
        "unknown_age",
        "ephemeral",
        "rotation_due",
        "max_age_exceeded",
    }
    assert body["secret_lifecycle"]["status"] in {"ok", "attention_required", "blocked"}
    assert body["secret_lifecycle"]["secrets"]["browser_session_signing"]["status"] in {"configured", "ephemeral"}
    assert body["secret_lifecycle"]["secrets"]["scim_bearer"]["status"] in {"configured", "not_configured", "missing_required"}
    assert body["secret_lifecycle"]["external_secret_provider"]["status"] in {"configured", "not_declared"}
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
    assert body["tenant_quota_runtime"]["usage"]["active_scan_jobs"]["status"] in {"ok", "near_limit", "at_limit", "unlimited"}
    assert body["tenant_quota_runtime"]["usage"]["active_scan_jobs"]["utilization_pct"] is not None
    assert "recommended_action" in body["tenant_quota_runtime"]["usage"]["active_scan_jobs"]
    assert body["storage_schema"]["schema_version"] == CONTROL_PLANE_SCHEMA_VERSION
    assert body["storage_schema"]["schema_table"] == CONTROL_PLANE_SCHEMA_TABLE
    assert body["storage_schema"]["component_count"] >= 10
    assert {"scan_jobs", "audit_log", "graph", "identity_scim", "analytics"} <= {
        component["component"] for component in body["storage_schema"]["components"]
    }
    assert body["identity_provisioning"]["oidc"]["mode"] == "disabled"
    assert body["identity_provisioning"]["saml"]["configured"] is False
    assert body["identity_provisioning"]["scim"]["status"] == "disabled"
    assert body["identity_provisioning"]["scim"]["supported"] is True
    assert body["identity_provisioning"]["scim"]["base_path"] == "/scim/v2"
    assert body["identity_provisioning"]["scim"]["token_configured"] is False
    assert {entry["idp"] for entry in body["identity_provisioning"]["scim"]["verified_idp_templates"]} == {
        "okta",
        "microsoft_entra_id",
        "google_cloud_identity",
    }
    assert "service_keys" in body["identity_provisioning"]["session_revocation"]


def test_auth_policy_redacts_oidc_config_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_rate_limit_env(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON", '{"tenant-secret":')

    client = TestClient(app)
    resp = client.get("/v1/auth/policy")

    assert resp.status_code == 200
    oidc = resp.json()["identity_provisioning"]["oidc"]
    assert oidc["mode"] == "invalid"
    assert oidc["message"] == "OIDC configuration is invalid. Check control-plane logs and OIDC environment settings."
    assert "tenant-secret" not in oidc["message"]
    assert "AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON" not in oidc["message"]


def test_auth_policy_reports_secret_integrity_posture(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_rate_limit_env(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_AUDIT_HMAC_KEY", "audit-secret")
    audit_rotated = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    compliance_rotated = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
    monkeypatch.setenv("AGENT_BOM_AUDIT_HMAC_LAST_ROTATED", audit_rotated)
    monkeypatch.setenv("AGENT_BOM_AUDIT_HMAC_ROTATION_DAYS", "30")
    monkeypatch.setenv("AGENT_BOM_AUDIT_HMAC_MAX_AGE_DAYS", "90")
    monkeypatch.setenv("AGENT_BOM_COMPLIANCE_SIGNING_LAST_ROTATED", compliance_rotated)
    monkeypatch.setenv("AGENT_BOM_COMPLIANCE_SIGNING_ROTATION_DAYS", "30")
    monkeypatch.setenv("AGENT_BOM_COMPLIANCE_SIGNING_MAX_AGE_DAYS", "180")
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

    audit_hmac = body["secret_integrity"]["audit_hmac"]
    assert audit_hmac["status"] == "configured"
    assert audit_hmac["configured"] is True
    assert audit_hmac["required"] is False
    assert audit_hmac["source"] == "AGENT_BOM_AUDIT_HMAC_KEY"
    assert audit_hmac["persists_across_restart"] is True
    assert audit_hmac["rotation_tracking_supported"] is True
    assert audit_hmac["rotation_status"] == "ok"
    assert audit_hmac["rotation_method"] == "env_swap_and_restart"
    assert audit_hmac["rotation_days"] == 30
    assert audit_hmac["max_age_days"] == 90
    assert audit_hmac["last_rotated"] == audit_rotated
    assert audit_hmac["age_days"] == 10

    signing = body["secret_integrity"]["compliance_signing"]
    assert signing["algorithm"] == "Ed25519"
    assert signing["mode"] == "asymmetric_public_key"
    assert signing["public_key_endpoint"] == "/v1/compliance/verification-key"
    assert signing["rotation_tracking_supported"] is True
    assert signing["rotation_status"] == "rotation_due"
    assert signing["rotation_method"] == "env_swap_and_restart"
    assert signing["rotation_days"] == 30
    assert signing["max_age_days"] == 180
    assert signing["last_rotated"] == compliance_rotated
    assert signing["age_days"] == 40


def test_auth_policy_reports_secret_lifecycle_posture(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_rate_limit_env(monkeypatch)
    browser_rotated = (datetime.now(timezone.utc) - timedelta(days=12)).isoformat()
    scim_rotated = (datetime.now(timezone.utc) - timedelta(days=95)).isoformat()
    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", "browser-secret")
    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY_LAST_ROTATED", browser_rotated)
    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY_ROTATION_DAYS", "30")
    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY_MAX_AGE_DAYS", "90")
    monkeypatch.setenv("AGENT_BOM_SCIM_BEARER_TOKEN", "scim-secret")
    monkeypatch.setenv("AGENT_BOM_SCIM_BEARER_TOKEN_ID", "scim-2026-04")
    monkeypatch.setenv("AGENT_BOM_SCIM_BEARER_TOKEN_LAST_ROTATED", scim_rotated)
    monkeypatch.setenv("AGENT_BOM_SCIM_BEARER_TOKEN_ROTATION_DAYS", "30")
    monkeypatch.setenv("AGENT_BOM_SCIM_BEARER_TOKEN_MAX_AGE_DAYS", "90")
    monkeypatch.setenv("AGENT_BOM_SECRET_PROVIDER", "aws_secrets_manager")
    monkeypatch.setenv("AGENT_BOM_EXTERNAL_SECRETS_ENABLED", "1")

    client = TestClient(app)
    body = client.get("/v1/auth/policy").json()
    lifecycle = body["secret_lifecycle"]

    assert lifecycle["status"] == "blocked"
    assert lifecycle["external_secret_provider"]["status"] == "configured"
    assert lifecycle["external_secret_provider"]["provider"] == "aws_secrets_manager"
    assert lifecycle["secrets"]["browser_session_signing"]["status"] == "configured"
    assert lifecycle["secrets"]["browser_session_signing"]["rotation_status"] == "ok"
    assert lifecycle["secrets"]["browser_session_signing"]["age_days"] == 12
    assert lifecycle["secrets"]["scim_bearer"]["status"] == "configured"
    assert lifecycle["secrets"]["scim_bearer"]["key_id"] == "scim-2026-04"
    assert lifecycle["secrets"]["scim_bearer"]["rotation_status"] == "max_age_exceeded"
    assert "scim_bearer" in lifecycle["blockers"]

    endpoint = client.get("/v1/auth/secrets/lifecycle").json()
    assert endpoint["secrets"]["scim_bearer"]["rotation_status"] == "max_age_exceeded"


def test_auth_secret_rotation_plan_is_non_secret_and_actionable(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_rate_limit_env(monkeypatch)
    scim_rotated = (datetime.now(timezone.utc) - timedelta(days=95)).isoformat()
    monkeypatch.setenv("AGENT_BOM_SCIM_BEARER_TOKEN", "super-secret-token")
    monkeypatch.setenv("AGENT_BOM_SCIM_BEARER_TOKEN_ID", "scim-2026-04")
    monkeypatch.setenv("AGENT_BOM_SCIM_BEARER_TOKEN_LAST_ROTATED", scim_rotated)
    monkeypatch.setenv("AGENT_BOM_SCIM_BEARER_TOKEN_ROTATION_DAYS", "30")
    monkeypatch.setenv("AGENT_BOM_SCIM_BEARER_TOKEN_MAX_AGE_DAYS", "90")
    monkeypatch.setenv("AGENT_BOM_SECRET_PROVIDER", "aws_secrets_manager")
    monkeypatch.setenv("AGENT_BOM_EXTERNAL_SECRETS_ENABLED", "1")

    client = TestClient(app)
    resp = client.get("/v1/auth/secrets/rotation-plan")
    assert resp.status_code == 200
    plan = resp.json()

    assert plan["status"] == "action_required"
    assert plan["secret_values_included"] is False
    assert plan["provider"] == "aws_secrets_manager"
    assert plan["action_count"] >= 1
    assert "super-secret-token" not in str(plan)
    scim_action = next(action for action in plan["actions"] if action["name"] == "scim_bearer")
    assert scim_action["status"] == "max_age_exceeded"
    assert scim_action["source_env"] == "AGENT_BOM_SCIM_BEARER_TOKEN"
    assert scim_action["last_rotated_env"] == "AGENT_BOM_SCIM_BEARER_TOKEN_LAST_ROTATED"
    assert scim_action["provider_rotation"]["tool"] == "aws-secrets-manager"
    assert "aws secretsmanager put-secret-value" in scim_action["provider_rotation"]["command"]
    assert scim_action["rollout"]["required"] is True
    assert "kubectl rollout restart deployment/agent-bom-api -n agent-bom" in scim_action["rollout"]["commands"]
    assert scim_action["record_timestamp"]["value_format"].startswith("ISO-8601")


def test_auth_quota_update_persists_tenant_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY_SECRET)
    _reload_config()
    _server_mod.configure_api(api_key=None)
    original_store = _stores._tenant_quota_store
    try:
        quota_store = InMemoryTenantQuotaStore()
        set_tenant_quota_store(quota_store)

        client = TestClient(app)
        headers = proxy_headers(role="admin", tenant="tenant-alpha")
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


def test_auth_policy_reports_identity_provider_posture(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_OIDC_ISSUER", "https://login.example.com")
    monkeypatch.setenv("AGENT_BOM_OIDC_AUDIENCE", "agent-bom")
    monkeypatch.setenv("AGENT_BOM_OIDC_REQUIRE_ROLE_CLAIM", "1")
    monkeypatch.setenv("AGENT_BOM_SAML_IDP_ENTITY_ID", "https://idp.example.com/metadata")
    monkeypatch.setenv("AGENT_BOM_SAML_IDP_SSO_URL", "https://idp.example.com/sso")
    monkeypatch.setenv("AGENT_BOM_SAML_IDP_X509_CERT", "-----BEGIN CERTIFICATE-----test-----END CERTIFICATE-----")
    monkeypatch.setenv("AGENT_BOM_SAML_SP_ENTITY_ID", "https://agent-bom.example.com/saml/metadata")
    monkeypatch.setenv("AGENT_BOM_SAML_SP_ACS_URL", "https://agent-bom.example.com/v1/auth/saml/login")
    monkeypatch.setenv("AGENT_BOM_SAML_SESSION_TTL_SECONDS", "1800")

    client = TestClient(app)
    body = client.get("/v1/auth/policy").json()

    assert body["identity_provisioning"]["oidc"]["configured"] is True
    assert body["identity_provisioning"]["oidc"]["mode"] == "single_issuer"
    assert body["identity_provisioning"]["oidc"]["issuer_hosts"] == ["login.example.com"]
    assert body["identity_provisioning"]["oidc"]["provider_count"] == 1
    assert body["identity_provisioning"]["oidc"]["require_role_claim"] is True
    assert body["identity_provisioning"]["oidc"]["require_tenant_claim"] is True
    assert body["identity_provisioning"]["saml"]["configured"] is True
    assert body["identity_provisioning"]["saml"]["metadata_endpoint"] == "/v1/auth/saml/metadata"
    assert body["identity_provisioning"]["saml"]["acs_path"] == "/v1/auth/saml/login"
    assert body["identity_provisioning"]["saml"]["idp_host"] == "idp.example.com"
    assert body["identity_provisioning"]["saml"]["session_ttl_seconds"] == 1800


def test_auth_policy_reports_scim_configuration_posture(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_SCIM_BEARER_TOKEN", "super-secret")
    monkeypatch.setenv("AGENT_BOM_SCIM_BASE_PATH", "/scim/v2")
    monkeypatch.setenv("AGENT_BOM_SCIM_ROLE_ATTRIBUTE", "roles")
    monkeypatch.setenv("AGENT_BOM_SCIM_TENANT_ATTRIBUTE", "organization_id")
    monkeypatch.setenv("AGENT_BOM_SCIM_EXTERNAL_ID_ATTRIBUTE", "employeeNumber")
    monkeypatch.setenv("AGENT_BOM_SCIM_REQUIRE_GROUPS", "1")

    client = TestClient(app)
    body = client.get("/v1/auth/policy").json()

    assert body["identity_provisioning"]["scim"]["configured"] is True
    assert body["identity_provisioning"]["scim"]["status"] == "configured"
    assert body["identity_provisioning"]["scim"]["base_path"] == "/scim/v2"
    assert body["identity_provisioning"]["scim"]["token_configured"] is True
    assert body["identity_provisioning"]["scim"]["tenant_id"] == "default"
    assert body["identity_provisioning"]["scim"]["storage_backend"] == "memory"
    assert body["identity_provisioning"]["scim"]["configured_api_replicas"] == 1
    assert body["identity_provisioning"]["scim"]["shared_store_required"] is False
    assert body["identity_provisioning"]["scim"]["multi_node_ready"] is False
    assert body["identity_provisioning"]["scim"]["lifecycle_endpoints"]["users"] == "/scim/v2/Users"
    assert body["identity_provisioning"]["scim"]["lifecycle_endpoints"]["groups"] == "/scim/v2/Groups"
    assert body["identity_provisioning"]["scim"]["role_attribute"] == "roles"
    assert body["identity_provisioning"]["scim"]["tenant_attribute"] == "organization_id"
    assert body["identity_provisioning"]["scim"]["external_id_attribute"] == "employeeNumber"
    assert body["identity_provisioning"]["scim"]["groups_required"] is True


def test_auth_policy_flags_clustered_scim_without_postgres(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_SCIM_BEARER_TOKEN", "super-secret")
    monkeypatch.setenv("AGENT_BOM_CONTROL_PLANE_REPLICAS", "3")

    client = TestClient(app)
    body = client.get("/v1/auth/policy").json()

    scim = body["identity_provisioning"]["scim"]
    assert scim["configured"] is True
    assert scim["status"] == "misconfigured"
    assert scim["configured_api_replicas"] == 3
    assert scim["shared_store_required"] is True
    assert scim["multi_node_ready"] is False


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
    assert middleware._required_role("GET", "/v1/auth/secrets/lifecycle") == "admin"
    assert middleware._required_role("GET", "/v1/auth/secrets/rotation-plan") == "admin"
    assert middleware._required_scope("GET", "/v1/auth/secrets/lifecycle") == "auth.secrets:read"
    assert middleware._required_scope("GET", "/v1/auth/secrets/rotation-plan") == "auth.secrets:read"
    assert middleware._required_role("GET", "/v1/auth/scim/config") == "admin"
    assert middleware._required_role("POST", "/scim/v2/Users") == "admin"
    assert middleware._required_scope("POST", "/scim/v2/Users") == "auth.scim:write"
    assert middleware._required_scope("GET", "/scim/v2/Groups") == "auth.scim:read"
    assert middleware._required_role("PUT", "/v1/auth/quota") == "admin"
    assert middleware._required_role("DELETE", "/v1/auth/quota") == "admin"
    assert middleware._required_role("GET", "/v1/tenant/tenant-a/data") == "admin"
    assert middleware._required_role("DELETE", "/v1/tenant/tenant-a/data") == "admin"
    assert middleware._required_scope("GET", "/v1/tenant/tenant-a/data") == "privacy.data:read"
    assert middleware._required_scope("DELETE", "/v1/tenant/tenant-a/data") == "privacy.data:delete"
    assert middleware._required_role("GET", "/v1/auth/debug") == "viewer"


def test_storage_schema_manifest_has_unique_components() -> None:
    manifest = describe_control_plane_storage_schema()
    components = manifest["components"]
    names = [component["component"] for component in components]
    assert len(names) == len(set(names))
    assert manifest["schema_table"] == "control_plane_schema_versions"
    assert all(component["version"] == CONTROL_PLANE_SCHEMA_VERSION for component in components)


def test_sqlite_schema_version_helper_is_idempotent() -> None:
    conn = sqlite3.connect(":memory:")
    ensure_sqlite_schema_version(conn, "scan_jobs")
    ensure_sqlite_schema_version(conn, "scan_jobs")
    rows = conn.execute(f"SELECT component, version FROM {CONTROL_PLANE_SCHEMA_TABLE}").fetchall()
    assert rows == [("scan_jobs", CONTROL_PLANE_SCHEMA_VERSION)]


def test_metrics_requires_authenticated_access(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY_SECRET)
    client = TestClient(app)
    unauthenticated = client.get("/metrics")
    assert unauthenticated.status_code == 401

    authenticated = client.get(
        "/metrics",
        headers=proxy_headers(role="viewer", tenant="tenant-alpha"),
    )
    assert authenticated.status_code == 200
    assert "agent_bom_" in authenticated.text


def test_auth_debug_reports_runtime_auth_modes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY_SECRET)
    _reload_config()
    _server_mod.configure_api(api_key=None)

    client = TestClient(app)
    resp = client.get(
        "/v1/auth/debug",
        headers=proxy_headers(role="viewer", tenant="tenant-alpha"),
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
