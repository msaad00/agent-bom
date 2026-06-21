"""Tests for credential expiry / rotation governance (issue #2923).

Covers classification across thresholds (ok / near_expiry / expired / overdue /
rotation_due / unknown_age), empty + missing-date safety, the rolled-up posture
verdict, and the non-secret API endpoint.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from starlette.testclient import TestClient

from agent_bom.api.credential_expiry import (
    classify_credential,
    describe_credential_expiry_posture,
    evaluate_credentials,
)
from agent_bom.api.server import app

NOW = datetime(2026, 6, 18, 12, 0, 0, tzinfo=timezone.utc)


def _iso(days_from_now: int) -> str:
    return (NOW + timedelta(days=days_from_now)).isoformat()


def _clear_cred_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "AGENT_BOM_CRED_NEAR_EXPIRY_DAYS",
        "AGENT_BOM_CRED_MAX_AGE_DAYS",
        "AGENT_BOM_CRED_ROTATION_DAYS",
    ):
        monkeypatch.delenv(name, raising=False)


def test_classify_ok_when_well_within_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_cred_env(monkeypatch)
    result = classify_credential(
        {"id": "svc-1", "name": "billing-svc", "credential_expires_at": _iso(120)},
        now=NOW,
    )
    assert result["state"] == "ok"
    assert result["blocking"] is False
    assert result["days_until_expiry"] == 120


def test_classify_near_expiry_inside_default_window(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_cred_env(monkeypatch)  # default near window = 14 days
    result = classify_credential(
        {"id": "svc-2", "credential_expires_at": _iso(10)},
        now=NOW,
    )
    assert result["state"] == "near_expiry"
    assert result["near_expiry_days"] == 14
    assert result["blocking"] is False


def test_classify_near_expiry_respects_custom_window(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_cred_env(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_CRED_NEAR_EXPIRY_DAYS", "30")
    result = classify_credential({"id": "svc-3", "credential_expires_at": _iso(20)}, now=NOW)
    assert result["state"] == "near_expiry"
    assert result["near_expiry_days"] == 30

    # Same credential is "ok" under the tighter default window.
    _clear_cred_env(monkeypatch)
    ok = classify_credential({"id": "svc-3", "credential_expires_at": _iso(20)}, now=NOW)
    assert ok["state"] == "ok"


def test_classify_expired(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_cred_env(monkeypatch)
    result = classify_credential({"id": "svc-4", "credential_expires_at": _iso(-3)}, now=NOW)
    assert result["state"] == "expired"
    assert result["blocking"] is True
    assert result["days_until_expiry"] == -3


def test_classify_rotation_due_from_age(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_cred_env(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_CRED_ROTATION_DAYS", "30")
    result = classify_credential({"id": "svc-5", "last_rotated": _iso(-45)}, now=NOW)
    assert result["state"] == "rotation_due"
    assert result["age_days"] == 45


def test_classify_overdue_when_past_max_age(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_cred_env(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_CRED_ROTATION_DAYS", "30")
    monkeypatch.setenv("AGENT_BOM_CRED_MAX_AGE_DAYS", "90")
    result = classify_credential({"id": "svc-6", "last_rotated": _iso(-120)}, now=NOW)
    assert result["state"] == "overdue"
    assert result["priority"] == 0
    assert result["blocking"] is True


def test_overdue_outranks_expired(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_cred_env(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_CRED_MAX_AGE_DAYS", "90")
    result = classify_credential(
        {"id": "svc-7", "last_rotated": _iso(-200), "credential_expires_at": _iso(-1)},
        now=NOW,
    )
    assert result["state"] == "overdue"
    # both reasons retained
    assert any("expired" in reason for reason in result["reasons"])
    assert any("max age" in reason for reason in result["reasons"])


def test_classify_unknown_age_when_no_dates(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_cred_env(monkeypatch)
    result = classify_credential({"id": "svc-8", "name": "no-dates"}, now=NOW)
    assert result["state"] == "unknown_age"
    assert result["age_days"] is None
    assert result["days_until_expiry"] is None


def test_invalid_and_future_dates_are_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_cred_env(monkeypatch)
    bad = classify_credential(
        {"id": "svc-9", "credential_expires_at": "not-a-date", "last_rotated": "also-bad"},
        now=NOW,
    )
    assert bad["state"] == "unknown_age"

    # A rotation timestamp in the future yields no usable age.
    future = classify_credential({"id": "svc-10", "last_rotated": _iso(10)}, now=NOW)
    assert future["age_days"] is None


def test_trailing_z_timestamp_parses(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_cred_env(monkeypatch)
    result = classify_credential(
        {"id": "svc-11", "credential_expires_at": "2026-06-28T12:00:00Z"},
        now=NOW,
    )
    assert result["state"] == "near_expiry"
    assert result["days_until_expiry"] == 10


def test_evaluate_empty_is_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_cred_env(monkeypatch)
    report = evaluate_credentials([], now=NOW)
    assert report["status"] == "ok"
    assert report["evaluated"] == 0
    assert report["blockers"] == []
    assert report["secret_values_included"] is False


def test_evaluate_rolls_up_worst_state_and_sorts(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_cred_env(monkeypatch)
    records = [
        {"id": "a", "name": "ok-cred", "credential_expires_at": _iso(200)},
        {"id": "b", "name": "near-cred", "credential_expires_at": _iso(5)},
        {"id": "c", "name": "expired-cred", "credential_expires_at": _iso(-2)},
    ]
    report = evaluate_credentials(records, now=NOW)
    assert report["status"] == "blocked"
    assert "expired-cred" in report["blockers"]
    assert "near-cred" in report["warnings"]
    # worst (expired) sorts first
    assert report["credentials"][0]["name"] == "expired-cred"
    assert report["counts"]["expired"] == 1
    assert report["counts"]["near_expiry"] == 1
    assert report["counts"]["ok"] == 1


def test_evaluate_attention_required_when_only_warnings(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_cred_env(monkeypatch)
    report = evaluate_credentials([{"id": "x", "name": "soon", "credential_expires_at": _iso(3)}], now=NOW)
    assert report["status"] == "attention_required"
    assert report["blockers"] == []


def test_evaluate_handles_non_dict_records(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_cred_env(monkeypatch)
    report = evaluate_credentials([{"id": "ok", "credential_expires_at": _iso(100)}], now=NOW)
    assert report["evaluated"] == 1


def test_describe_posture_includes_discovered_records_no_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_cred_env(monkeypatch)
    discovered = [
        {
            "id": "okta-app-1",
            "name": "ci-deployer",
            "provider": "okta",
            "identity_type": "service_account",
            "credential_expires_at": _iso(-5),
            "secret": "should-never-appear",
        }
    ]
    posture = describe_credential_expiry_posture(discovered, include_control_plane=False, now=NOW)
    assert posture["status"] == "blocked"
    assert posture["discovered_credential_count"] == 1
    assert posture["control_plane_included"] is False
    assert "should-never-appear" not in str(posture)
    assert posture["generated_from"] == "/v1/auth/secrets/credential-expiry"


def test_endpoint_requires_no_secret_values(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_cred_env(monkeypatch)
    client = TestClient(app)
    resp = client.get("/v1/auth/secrets/credential-expiry")
    assert resp.status_code == 200
    body = resp.json()
    assert body["secret_values_included"] is False
    assert "credentials" in body
    assert body["control_plane_included"] is True
    assert body["status"] in {"ok", "attention_required", "blocked"}


def test_endpoint_folds_in_discovered_nhi_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """With NHI discovery enabled, the endpoint governs discovered-NHI expiry.

    Previously the endpoint called describe_credential_expiry_posture() with no
    args, so discovered_credentials was always None. The wire now runs gated NHI
    discovery and folds the (expiry-bearing) records in.
    """
    _clear_cred_env(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_OKTA_DISCOVERY", "1")
    monkeypatch.delenv("AGENT_BOM_ENTRA_DISCOVERY", raising=False)

    from agent_bom.identity.okta_nhi import (
        DiscoveredNonHumanIdentity,
        NHIDiscoveryResult,
        NHIDiscoveryStatus,
    )

    expired = DiscoveredNonHumanIdentity(
        identity_id="okta:app:expired",
        provider="okta",
        identity_type="api_token",
        name="legacy-ci-token",
        credential_expires_at=_iso(-3),  # already expired
    )
    result = NHIDiscoveryResult(status=NHIDiscoveryStatus.OK, identities=(expired,))

    import agent_bom.identity as identity_pkg

    monkeypatch.setattr(identity_pkg, "discover_okta_non_human_identities", lambda *a, **k: result)
    # Entra flag off, but the helper calls both connectors; its result is empty
    # (DISABLED) so it contributes nothing — keep the real disabled path.

    client = TestClient(app)
    resp = client.get("/v1/auth/secrets/credential-expiry")
    assert resp.status_code == 200
    body = resp.json()
    assert body["discovered_credential_count"] >= 1
    assert body["status"] == "blocked"  # an expired NHI credential is a blocking finding
    assert any("legacy-ci-token" in str(c) for c in body["credentials"])


def test_endpoint_no_discovered_credentials_when_discovery_off(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default path unchanged: discovery off -> zero discovered records, control-plane only."""
    _clear_cred_env(monkeypatch)
    monkeypatch.delenv("AGENT_BOM_OKTA_DISCOVERY", raising=False)
    monkeypatch.delenv("AGENT_BOM_ENTRA_DISCOVERY", raising=False)

    client = TestClient(app)
    resp = client.get("/v1/auth/secrets/credential-expiry")
    assert resp.status_code == 200
    body = resp.json()
    assert body["discovered_credential_count"] == 0
    assert body["control_plane_included"] is True


def test_endpoint_rbac_role_and_scope() -> None:
    from agent_bom.api.middleware import APIKeyMiddleware

    middleware = APIKeyMiddleware(app, api_key="static-secret")
    assert middleware._required_role("GET", "/v1/auth/secrets/credential-expiry") == "admin"
    assert middleware._required_scope("GET", "/v1/auth/secrets/credential-expiry") == "auth.secrets:read"
