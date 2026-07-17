"""Tests for the operator self-posture surface (agent-bom audits itself)."""

from __future__ import annotations

from agent_bom.self_posture import (
    STATUS_FAIL,
    STATUS_PASS,
    STATUS_UNKNOWN,
    STATUS_WARN,
    self_posture,
)


def _by_id(report: dict[str, object]) -> dict[str, dict[str, str]]:
    return {c["id"]: c for c in report["checks"]}  # type: ignore[index,union-attr]


# ── Hardened deployment ──────────────────────────────────────────────────────


def _hardened_env() -> dict[str, str]:
    return {
        "AGENT_BOM_DEPLOYMENT_ENV": "production",
        # Unauthenticated API off (default), superuser DB off (default).
        "AGENT_BOM_AUDIT_HMAC_KEY_FILE": "/run/secrets/audit-hmac",
        "AGENT_BOM_CONNECTIONS_KEY_FILE": "/run/secrets/connections-key",
    }


def test_configured_production_reports_unverified_runtime_checks_honestly() -> None:
    report = self_posture(_hardened_env(), distribution_count=66)
    checks = _by_id(report)

    assert checks["auth.api_authentication"]["status"] == STATUS_PASS
    assert checks["database.rls_isolation"]["status"] == STATUS_UNKNOWN
    assert checks["audit.hmac_integrity"]["status"] == STATUS_PASS
    assert checks["secrets.audit_hmac_key"]["status"] == STATUS_PASS
    assert checks["secrets.connections_key"]["status"] == STATUS_PASS
    assert checks["deployment.env_declared"]["status"] == STATUS_PASS
    # Unknown runtime/supply-chain state is not proof that the deployment is hardened.
    assert report["hardened"] is False
    assert report["overall_status"] == "needs_review"
    assert report["counts"][STATUS_FAIL] == 0


# ── Misconfigured production deployment -> honest failures ───────────────────


def test_unauthenticated_api_in_production_is_a_failure() -> None:
    env = _hardened_env() | {"AGENT_BOM_ALLOW_UNAUTHENTICATED_API": "1"}
    report = self_posture(env, distribution_count=66)
    check = _by_id(report)["auth.api_authentication"]
    assert check["status"] == STATUS_FAIL
    assert report["overall_status"] == "at_risk"
    assert report["hardened"] is False


def test_superuser_db_in_production_is_a_failure() -> None:
    env = _hardened_env() | {"AGENT_BOM_ALLOW_SUPERUSER_DB": "true"}
    check = _by_id(self_posture(env, distribution_count=66))["database.rls_isolation"]
    assert check["status"] == STATUS_FAIL
    assert "isolation is NOT enforced" in check["detail"]


def test_missing_audit_hmac_key_in_production_is_a_failure() -> None:
    env = _hardened_env()
    del env["AGENT_BOM_AUDIT_HMAC_KEY_FILE"]
    check = _by_id(self_posture(env, distribution_count=66))["audit.hmac_integrity"]
    assert check["status"] == STATUS_FAIL


def test_missing_audit_hmac_required_by_multi_replica_even_without_prod() -> None:
    env = {
        "AGENT_BOM_DEPLOYMENT_ENV": "staging",
        "AGENT_BOM_CONTROL_PLANE_REPLICAS": "3",
    }
    check = _by_id(self_posture(env, distribution_count=10))["audit.hmac_integrity"]
    assert check["status"] == STATUS_FAIL


# ── Weakened-but-acknowledged -> warn, not silent pass ───────────────────────


def test_unauthenticated_api_in_dev_is_a_warning_not_failure() -> None:
    env = {"AGENT_BOM_DEPLOYMENT_ENV": "dev", "AGENT_BOM_ALLOW_UNAUTHENTICATED_API": "1"}
    check = _by_id(self_posture(env, distribution_count=10))["auth.api_authentication"]
    assert check["status"] == STATUS_WARN


def test_literal_secret_in_env_is_a_warning() -> None:
    env = {
        "AGENT_BOM_DEPLOYMENT_ENV": "dev",
        "AGENT_BOM_AUDIT_HMAC_KEY": "s0me-literal-secret",
    }
    check = _by_id(self_posture(env, distribution_count=10))["secrets.audit_hmac_key"]
    assert check["status"] == STATUS_WARN
    # The literal value must never leak into the report detail.
    assert "s0me-literal-secret" not in check["detail"]
    assert "s0me-literal-secret" not in check["remediation"]


def test_ephemeral_audit_hmac_acknowledged_is_a_warning() -> None:
    env = {
        "AGENT_BOM_DEPLOYMENT_ENV": "production",
        "AGENT_BOM_ALLOW_EPHEMERAL_AUDIT_HMAC": "1",
    }
    check = _by_id(self_posture(env, distribution_count=10))["audit.hmac_integrity"]
    assert check["status"] == STATUS_WARN


# ── Unknown is explicit, never an assumed pass ───────────────────────────────


def test_undeclared_deployment_env_is_unknown_not_pass() -> None:
    report = self_posture({}, distribution_count=10)
    check = _by_id(report)["deployment.env_declared"]
    assert check["status"] == STATUS_UNKNOWN
    assert report["deployment_env"] == "unknown"


def test_unconfigured_audit_hmac_in_dev_is_unknown_not_pass() -> None:
    # No prod, single replica, no key -> not required, but honestly unknown.
    check = _by_id(self_posture({"AGENT_BOM_DEPLOYMENT_ENV": "dev"}, distribution_count=10))["audit.hmac_integrity"]
    assert check["status"] == STATUS_UNKNOWN


def test_unconfigured_secret_is_unknown_not_pass() -> None:
    check = _by_id(self_posture({"AGENT_BOM_DEPLOYMENT_ENV": "dev"}, distribution_count=10))["secrets.audit_hmac_key"]
    assert check["status"] == STATUS_UNKNOWN


def test_external_secrets_enablement_alone_is_not_proof_a_secret_is_sealed() -> None:
    env = {
        "AGENT_BOM_DEPLOYMENT_ENV": "production",
        "AGENT_BOM_EXTERNAL_SECRETS_ENABLED": "1",
    }
    checks = _by_id(self_posture(env, distribution_count=10))
    assert checks["secrets.audit_hmac_key"]["status"] == STATUS_UNKNOWN
    assert checks["secrets.connections_key"]["status"] == STATUS_UNKNOWN


def test_unknown_or_warning_outcomes_never_set_hardened_true() -> None:
    unknown = self_posture(_hardened_env(), distribution_count=66)
    warning = self_posture(
        _hardened_env()
        | {
            "AGENT_BOM_DEPLOYMENT_ENV": "dev",
            "AGENT_BOM_ALLOW_UNAUTHENTICATED_API": "1",
        },
        distribution_count=66,
    )
    assert unknown["hardened"] is False
    assert warning["hardened"] is False


def test_supply_chain_is_context_only_never_a_fake_pass() -> None:
    report = self_posture(_hardened_env(), distribution_count=66)
    check = _by_id(report)["supply_chain.dependency_surface"]
    assert check["status"] == STATUS_UNKNOWN
    assert "66" in check["detail"]
    assert "self-scan" in check["remediation"]

    unknown = self_posture(_hardened_env(), distribution_count=None)
    assert _by_id(unknown)["supply_chain.dependency_surface"]["status"] == STATUS_UNKNOWN


def test_overall_status_precedence_fail_over_warn() -> None:
    env = _hardened_env() | {
        "AGENT_BOM_ALLOW_UNAUTHENTICATED_API": "1",  # fail (prod)
        "AGENT_BOM_ALLOW_EPHEMERAL_AUDIT_HMAC": "1",
    }
    assert self_posture(env, distribution_count=10)["overall_status"] == "at_risk"


def test_never_raises_on_garbage_replica_count() -> None:
    env = {
        "AGENT_BOM_DEPLOYMENT_ENV": "production",
        "AGENT_BOM_CONTROL_PLANE_REPLICAS": "not-a-number",
        "AGENT_BOM_AUDIT_HMAC_KEY_FILE": "/x",
    }
    report = self_posture(env, distribution_count=10)
    assert report["overall_status"] in {"hardened", "needs_review", "action_advised", "at_risk"}
