"""Tests for the cloud SDK freshness signal (issue #3835 coverage/deprecation lane).

Covers the pure posture function (fresh / outdated / missing / unparseable,
with and without an in-scope provider set), the compact agent-mode summary, and
the two consumer surfaces: ``agent-bom doctor`` and the ``--agent-mode`` scan
metadata built by ``_agent_mode._summary``.
"""

from __future__ import annotations

from click.testing import CliRunner

from agent_bom.cloud_sdk_freshness import (
    RECOMMENDED_FLOORS,
    cloud_sdk_freshness_summary,
    cloud_sdk_posture,
)

# A fully-fresh install: every anchor distribution comfortably above its floor.
FRESH = {
    "boto3": "1.40.0",
    "azure-identity": "1.20.0",
    "azure-mgmt-resource": "24.0.0",
    "google-cloud-resource-manager": "1.14.0",
    "snowflake-connector-python": "3.10.0",
}


def _with(overrides: dict[str, str | None]) -> dict[str, str | None]:
    merged: dict[str, str | None] = dict(FRESH)
    merged.update(overrides)
    return merged


# ---------------------------------------------------------------------------
# Pure posture
# ---------------------------------------------------------------------------


def test_all_fresh_is_ok_with_no_warnings():
    posture = cloud_sdk_posture(installed=FRESH)
    assert posture["status"] == "ok"
    assert posture["warnings"] == []
    assert posture["stale_count"] == 0
    assert posture["installed_count"] == len(RECOMMENDED_FLOORS)
    assert all(s["status"] == "ok" for s in posture["sdks"])


def test_outdated_sdk_is_degraded_with_warning():
    posture = cloud_sdk_posture(installed=_with({"boto3": "1.20.0"}))
    assert posture["status"] == "degraded"
    assert posture["stale_count"] == 1
    boto = next(s for s in posture["sdks"] if s["distribution"] == "boto3")
    assert boto["status"] == "outdated"
    codes = {w["code"] for w in posture["warnings"]}
    assert codes == {"sdk_outdated"}
    warning = posture["warnings"][0]
    assert warning["distribution"] == "boto3"
    assert warning["installed_version"] == "1.20.0"
    assert "agent-bom[aws]" in warning["message"]


def test_missing_sdk_without_scope_is_informational_not_a_warning():
    # No providers_in_scope: a missing SDK is informational, never a warning,
    # so a user who only scans AWS is not nagged about an absent Azure SDK.
    posture = cloud_sdk_posture(installed=_with({"azure-identity": None, "azure-mgmt-resource": None}))
    assert posture["status"] == "ok"
    assert posture["warnings"] == []
    azure = [s for s in posture["sdks"] if s["provider"] == "azure"]
    assert all(s["status"] == "not_installed" for s in azure)
    assert all(s["in_scope"] is None for s in posture["sdks"])


def test_missing_in_scope_provider_warns():
    posture = cloud_sdk_posture(
        installed=_with({"boto3": None}),
        providers_in_scope=["aws"],
    )
    assert posture["status"] == "degraded"
    assert posture["missing_in_scope_count"] == 1
    codes = {w["code"] for w in posture["warnings"]}
    assert codes == {"sdk_missing"}
    assert posture["warnings"][0]["provider"] == "aws"


def test_missing_out_of_scope_provider_does_not_warn():
    posture = cloud_sdk_posture(
        installed=_with({"azure-identity": None, "azure-mgmt-resource": None}),
        providers_in_scope=["aws"],
    )
    assert posture["status"] == "ok"
    assert posture["warnings"] == []
    assert posture["missing_in_scope_count"] == 0


def test_unparseable_version_is_unknown_not_stale():
    posture = cloud_sdk_posture(installed=_with({"boto3": "not-a-version"}))
    boto = next(s for s in posture["sdks"] if s["distribution"] == "boto3")
    assert boto["status"] == "unknown"
    assert posture["stale_count"] == 0
    assert posture["status"] == "ok"
    assert posture["warnings"] == []


def test_resolver_callable_and_mapping_agree():
    as_map = cloud_sdk_posture(installed=FRESH)
    as_callable = cloud_sdk_posture(installed=lambda dist: FRESH.get(dist))
    assert as_map == as_callable


def test_deterministic_for_fixed_input():
    a = cloud_sdk_posture(installed=_with({"boto3": "1.10.0"}))
    b = cloud_sdk_posture(installed=_with({"boto3": "1.10.0"}))
    assert a == b


def test_default_resolver_never_raises_and_is_json_shaped():
    # Runs against whatever is actually installed in the test env — must not
    # raise and must return the stable shape regardless of what is present.
    posture = cloud_sdk_posture()
    assert posture["schema_version"] == 1
    assert isinstance(posture["sdks"], list) and posture["sdks"]
    assert posture["status"] in {"ok", "degraded"}
    for entry in posture["sdks"]:
        assert entry["status"] in {"ok", "outdated", "not_installed", "unknown"}


# ---------------------------------------------------------------------------
# Compact agent-mode summary
# ---------------------------------------------------------------------------


def test_summary_trims_to_status_counts_and_messages():
    summary = cloud_sdk_freshness_summary(installed=_with({"boto3": "1.20.0"}))
    assert summary["status"] == "degraded"
    assert summary["stale_count"] == 1
    assert summary["outdated"] == [{"distribution": "boto3", "installed_version": "1.20.0", "recommended_floor": "1.34"}]
    assert summary["warnings"] and "boto3" in summary["warnings"][0]


def test_summary_ok_when_fresh():
    summary = cloud_sdk_freshness_summary(installed=FRESH)
    assert summary["status"] == "ok"
    assert summary["stale_count"] == 0
    assert summary["outdated"] == []
    assert summary["warnings"] == []


# ---------------------------------------------------------------------------
# Consumer surfaces
# ---------------------------------------------------------------------------


def test_agent_mode_summary_includes_cloud_sdk_freshness():
    from agent_bom.cli._agent_mode import _summary

    out = _summary({})
    assert "cloud_sdk_freshness" in out
    assert out["cloud_sdk_freshness"]["status"] in {"ok", "degraded"}


def test_doctor_renders_cloud_sdk_freshness_section():
    from agent_bom.cli._doctor import doctor_cmd

    result = CliRunner().invoke(doctor_cmd, [])
    assert result.exit_code == 0, result.output
    assert "Cloud SDK freshness" in result.output
