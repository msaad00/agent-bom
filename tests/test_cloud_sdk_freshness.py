"""Tests for the cloud SDK freshness signal (issue #3835 coverage/deprecation lane).

Covers the pure posture function (fresh / outdated / missing / unparseable,
with and without an in-scope provider set), the compact agent-mode summary, and
the two consumer surfaces: ``agent-bom doctor`` and the ``--agent-mode`` scan
metadata built by ``_agent_mode._summary``.
"""

from __future__ import annotations

from datetime import date, datetime, timezone

from click.testing import CliRunner

from agent_bom.cloud_sdk_freshness import (
    PROVIDER_API_DEPRECATIONS,
    RECOMMENDED_FLOORS,
    ProviderApiDeprecation,
    cloud_api_deprecation_posture,
    cloud_api_deprecation_summary,
    cloud_sdk_freshness_summary,
    cloud_sdk_posture,
    removed_provider_apis,
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


# ---------------------------------------------------------------------------
# Provider-API deprecation / removal posture
# ---------------------------------------------------------------------------

# A reference "now" comfortably after the Azure AD Graph retirement date so the
# entry evaluates as removed regardless of when the suite runs.
AFTER_AZURE_GRAPH = date(2026, 1, 1)
# A reference "now" before it, for the still-scheduled path.
BEFORE_AZURE_GRAPH = date(2025, 1, 1)


def test_catalog_entries_are_real_and_sourced():
    # Every shipped entry must carry a provider, a human API label, a
    # replacement, and an official reference URL — no unsourced/fabricated rows.
    assert PROVIDER_API_DEPRECATIONS
    for dep in PROVIDER_API_DEPRECATIONS:
        assert dep.provider and dep.api and dep.replacement
        assert dep.reference.startswith("https://")


def test_clear_when_no_legacy_sdk_installed():
    # Nothing legacy in the tree: every retirement is informational (clear),
    # status ok, no warnings — the honest "we use the modern replacement" state.
    posture = cloud_api_deprecation_posture(now=AFTER_AZURE_GRAPH, installed={})
    assert posture["status"] == "ok"
    assert posture["warnings"] == []
    assert posture["removed_count"] == 0
    assert posture["at_risk_count"] == 0
    assert posture["gated"] == []
    assert all(a["status"] == "clear" for a in posture["apis"])


def test_removed_api_with_legacy_sdk_is_gated():
    # azure-graphrbac present + past the retirement date → the Azure AD Graph
    # API is removed AND reachable via a legacy SDK, so it is gated (a check
    # using it must be skipped honestly, never silently passed).
    posture = cloud_api_deprecation_posture(
        now=AFTER_AZURE_GRAPH,
        installed={"azure-graphrbac": "0.61.1"},
    )
    assert posture["status"] == "degraded"
    assert posture["removed_count"] == 1
    graph = next(a for a in posture["apis"] if a["distribution"] == "azure-graphrbac")
    assert graph["status"] == "gated"
    assert graph["lifecycle"] == "removed"
    codes = {w["code"] for w in posture["warnings"]}
    assert "api_removed" in codes
    assert [g["api"] for g in posture["gated"]] == [graph["api"]]


def test_removed_api_without_legacy_sdk_is_clear_not_gated():
    posture = cloud_api_deprecation_posture(
        now=AFTER_AZURE_GRAPH,
        installed={},  # azure-graphrbac absent
    )
    graph = next(a for a in posture["apis"] if a["distribution"] == "azure-graphrbac")
    assert graph["lifecycle"] == "removed"
    assert graph["status"] == "clear"
    assert posture["gated"] == []


def test_scheduled_future_removal_with_legacy_sdk_is_at_risk_not_gated():
    posture = cloud_api_deprecation_posture(
        now=BEFORE_AZURE_GRAPH,
        installed={"azure-graphrbac": "0.61.1"},
    )
    graph = next(a for a in posture["apis"] if a["distribution"] == "azure-graphrbac")
    assert graph["lifecycle"] == "deprecating"
    assert graph["status"] == "at_risk"
    assert posture["at_risk_count"] == 1
    assert posture["gated"] == []
    codes = {w["code"] for w in posture["warnings"]}
    assert "api_deprecating" in codes


def test_undated_deprecation_with_legacy_sdk_is_at_risk():
    # oauth2client has no scheduled removal date → deprecating, not removed.
    posture = cloud_api_deprecation_posture(
        now=AFTER_AZURE_GRAPH,
        installed={"oauth2client": "4.1.3"},
    )
    entry = next(a for a in posture["apis"] if a["distribution"] == "oauth2client")
    assert entry["lifecycle"] == "deprecating"
    assert entry["status"] == "at_risk"


def test_now_accepts_date_and_datetime():
    as_date = cloud_api_deprecation_posture(now=AFTER_AZURE_GRAPH, installed={})
    as_dt = cloud_api_deprecation_posture(now=datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc), installed={})
    assert as_date == as_dt


def test_removed_provider_apis_gate_helper():
    gated = removed_provider_apis(now=AFTER_AZURE_GRAPH, installed={"azure-graphrbac": "0.61.1"})
    assert set(gated) == {"Azure AD Graph API (graph.windows.net)"}
    clear = removed_provider_apis(now=AFTER_AZURE_GRAPH, installed={})
    assert clear == {}


def test_custom_future_dated_entry_within_horizon_warns():
    dep = ProviderApiDeprecation(
        provider="aws",
        api="Fake service API",
        distribution="boto3",
        replacement="newer boto3",
        retirement_date="2026-03-01",
        note="test entry",
        reference="https://example.com/aws",
    )
    posture = cloud_api_deprecation_posture(
        now=date(2026, 1, 1),
        installed={"boto3": "1.40.0"},
        deprecations=[dep],
    )
    entry = posture["apis"][0]
    assert entry["lifecycle"] == "deprecating"
    assert entry["status"] == "at_risk"


def test_default_resolver_never_raises_and_is_json_shaped_deprecations():
    posture = cloud_api_deprecation_posture()
    assert posture["schema_version"] == 1
    assert isinstance(posture["apis"], list) and posture["apis"]
    assert posture["status"] in {"ok", "degraded"}
    for entry in posture["apis"]:
        assert entry["status"] in {"clear", "at_risk", "gated"}
        assert entry["lifecycle"] in {"removed", "deprecating"}


def test_deprecation_summary_trims_and_lists_gated():
    summary = cloud_api_deprecation_summary(now=AFTER_AZURE_GRAPH, installed={"azure-graphrbac": "0.61.1"})
    assert summary["status"] == "degraded"
    assert summary["removed_count"] == 1
    assert summary["gated"] == ["Azure AD Graph API (graph.windows.net)"]
    assert summary["warnings"] and "Azure AD Graph" in summary["warnings"][0]


def test_sdk_freshness_summary_nests_deprecations_block():
    summary = cloud_sdk_freshness_summary(installed=FRESH)
    assert "deprecations" in summary
    assert summary["deprecations"]["status"] in {"ok", "degraded"}


def test_doctor_renders_cloud_api_deprecations_section():
    from agent_bom.cli._doctor import doctor_cmd

    result = CliRunner().invoke(doctor_cmd, [])
    assert result.exit_code == 0, result.output
    assert "Cloud API deprecations" in result.output


def test_agent_mode_summary_includes_deprecations():
    from agent_bom.cli._agent_mode import _summary

    out = _summary({})
    assert "deprecations" in out["cloud_sdk_freshness"]
