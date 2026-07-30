"""Tests for the CIS structured remediation catalog (issue #665).

Every CIS check across AWS/Azure/GCP/Snowflake must produce a
``remediation`` dict with the full schema populated. Overrides are
validated against the same schema.
"""

from __future__ import annotations

import pytest

from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISCheckResult
from agent_bom.cloud.cis_remediation import (
    _OVERRIDES,
    GUARDRAIL_TAGS,
    attach_all,
    attach_remediation,
    build_remediation,
)

_REQUIRED_KEYS = {
    "why",
    "fix_cli",
    "fix_console",
    "effort",
    "priority",
    "docs",
    "guardrails",
    "requires_human_review",
}
_ALLOWED_EFFORT = {"low", "medium", "high", "manual"}


def _assert_schema(remediation: dict) -> None:
    missing = _REQUIRED_KEYS - set(remediation)
    assert not missing, f"remediation missing keys: {missing}"
    assert remediation["why"], "why must be a non-empty string"
    assert isinstance(remediation["fix_cli"], (str, type(None)))
    assert isinstance(remediation["fix_console"], str)
    assert remediation["effort"] in _ALLOWED_EFFORT
    assert remediation["priority"] in {1, 2, 3, 4}
    assert isinstance(remediation["docs"], str)
    assert isinstance(remediation["guardrails"], list)
    for tag in remediation["guardrails"]:
        assert tag in GUARDRAIL_TAGS, f"unknown guardrail tag: {tag}"
    assert isinstance(remediation["requires_human_review"], bool)


def test_build_remediation_universal_fallback_has_schema():
    rem = build_remediation(
        cloud="aws",
        check_id="9.99",
        title="Some unknown future check",
        severity="medium",
        recommendation="Review the policy.",
        cis_section="9 - Future",
    )
    _assert_schema(rem)
    # Fallback must default to manual + require human review.
    assert rem["fix_cli"] is None
    assert rem["effort"] == "manual"
    assert rem["requires_human_review"] is True


def test_all_overrides_validate_against_schema():
    for identity, override in _OVERRIDES.items():
        rem = build_remediation(
            cloud=identity.cloud,
            benchmark_version=identity.benchmark_version,
            check_id=identity.check_id,
            title=identity.title,
            severity="high",
            recommendation="",
            cis_section=identity.cis_section,
        )
        _assert_schema(rem)
        assert rem["why"] == override.why
        assert rem["fix_cli"] is None
        assert rem["effort"] == "manual"
        assert rem["requires_human_review"] is True


def test_priority_derives_from_severity():
    for severity, expected in [
        ("critical", 1),
        ("high", 1),
        ("medium", 2),
        ("low", 3),
        ("unknown", 3),
    ]:
        rem = build_remediation(
            cloud="aws",
            check_id="X.Y",
            title="t",
            severity=severity,
            recommendation="",
            cis_section="",
        )
        assert rem["priority"] == expected, severity


def test_attach_remediation_is_idempotent():
    result = CISCheckResult(
        check_id="1.4",
        title="No root account access keys",
        status=CheckStatus.FAIL,
        severity="high",
        recommendation="Remove root access keys.",
        cis_section="1 - Identity and Access Management",
    )
    attach_remediation(result, cloud="aws", benchmark_version="3.0")
    first = dict(result.remediation)
    attach_remediation(result, cloud="aws", benchmark_version="3.0")
    assert result.remediation == first


def test_override_applies_only_when_full_identity_matches():
    result = CISCheckResult(
        check_id="1.4",
        title="No root account access keys",
        status=CheckStatus.FAIL,
        severity="high",
        recommendation="",
        cis_section="1 - Identity and Access Management",
    )
    attach_remediation(result, cloud="aws", benchmark_version="3.0")
    assert result.remediation["fix_cli"] is None
    assert result.remediation["effort"] == "manual"
    assert result.remediation["requires_human_review"] is True
    assert "priv-escalation" in result.remediation["guardrails"]


def test_guardrails_inferred_from_iam_section():
    rem = build_remediation(
        cloud="aws",
        check_id="1.99",
        title="some IAM thing",
        severity="medium",
        recommendation="",
        cis_section="1 - Identity and Access Management",
    )
    assert "identity" in rem["guardrails"]
    assert "least-privilege" in rem["guardrails"]
    assert "zero-trust" in rem["guardrails"]


def test_guardrails_inferred_from_logging_section():
    rem = build_remediation(
        cloud="aws",
        check_id="3.99",
        title="some logging thing",
        severity="medium",
        recommendation="",
        cis_section="3 - Logging",
    )
    assert "logging-and-audit" in rem["guardrails"]
    assert "defense-in-depth" in rem["guardrails"]


@pytest.mark.parametrize("cloud", ["aws", "azure", "gcp", "snowflake"])
def test_fallback_fix_console_non_empty_for_known_clouds(cloud):
    rem = build_remediation(
        cloud=cloud,
        check_id="0.0",
        title="smoke",
        severity="low",
        recommendation="",
        cis_section="1 - Identity and Access Management",
    )
    assert rem["fix_console"], f"expected console path for {cloud}"


_AWS_ACCOUNT_PUBLIC_ACCESS = {
    "cloud": "aws",
    "check_id": "2.1.1",
    "title": "S3 account-level public access block configured",
    "severity": "high",
    "recommendation": "Enable all four S3 public access block settings at the account level.",
    "cis_section": "2 - Storage",
}


def test_matching_override_is_advisory_only_until_command_is_verified():
    rem = build_remediation(**_AWS_ACCOUNT_PUBLIC_ACCESS, benchmark_version="3.0")

    assert rem["fix_cli"] is None
    assert rem["effort"] == "manual"
    assert rem["requires_human_review"] is True
    assert "account-level" in rem["why"].lower()


@pytest.mark.parametrize(
    "changes",
    [
        {},
        {"benchmark_version": "2.0"},
        {"benchmark_version": "3.0", "title": "S3 bucket public access block configured"},
        {"benchmark_version": "3.0", "cis_section": "2 - Different storage section"},
    ],
)
def test_missing_or_drifted_control_identity_fails_closed(changes):
    args = {**_AWS_ACCOUNT_PUBLIC_ACCESS, **changes}
    rem = build_remediation(**args)

    assert rem["fix_cli"] is None
    assert rem["effort"] == "manual"
    assert rem["requires_human_review"] is True
    assert rem["why"] == f"Failure indicates: {args['title'].lower().rstrip('.')}."


def test_attach_all_propagates_report_benchmark_version():
    check = CISCheckResult(
        check_id="2.1.1",
        title="S3 account-level public access block configured",
        status=CheckStatus.FAIL,
        severity="high",
        recommendation="Enable all four S3 public access block settings at the account level.",
        cis_section="2 - Storage",
    )
    report = type("Report", (), {"benchmark_version": "3.0", "checks": [check]})()

    attach_all(report, cloud="aws")

    assert check.remediation["fix_cli"] is None
    assert "account-level" in check.remediation["why"].lower()
