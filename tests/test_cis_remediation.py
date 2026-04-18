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
    for (cloud, check_id), _override in _OVERRIDES.items():
        rem = build_remediation(
            cloud=cloud,
            check_id=check_id,
            title="override test",
            severity="high",
            recommendation="",
            cis_section="1 - Identity and Access Management",
        )
        _assert_schema(rem)


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
        title="Ensure no root user account access key exists",
        status=CheckStatus.FAIL,
        severity="high",
        recommendation="Remove root access keys.",
        cis_section="1 - Identity and Access Management",
    )
    attach_remediation(result, cloud="aws")
    first = dict(result.remediation)
    attach_remediation(result, cloud="aws")
    assert result.remediation == first


def test_override_applies_when_check_id_matches():
    result = CISCheckResult(
        check_id="1.4",
        title="Ensure no root user account access key exists",
        status=CheckStatus.FAIL,
        severity="high",
        recommendation="",
        cis_section="1 - Identity and Access Management",
    )
    attach_remediation(result, cloud="aws")
    # Hand-authored AWS 1.4 override has a concrete CLI.
    assert result.remediation["fix_cli"] is not None
    assert "delete-access-key" in result.remediation["fix_cli"]
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
