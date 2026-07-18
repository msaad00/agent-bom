from __future__ import annotations

from datetime import datetime, timezone

from agent_bom.cloud.aws_iam_evidence import (
    EvidenceCompleteness,
    IamRoleUsageEvidence,
    IamServiceUsageEvidence,
    UsageEvidenceState,
    normalize_iam_policy_document,
)


def test_normalizes_allow_deny_resource_and_conditions_deterministically() -> None:
    policy = normalize_iam_policy_document(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ScopedRead",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket", "s3:GetObject"],
                    "Resource": ["arn:aws:s3:::example/*", "arn:aws:s3:::example"],
                    "Condition": {
                        "StringEquals": {"aws:PrincipalOrgID": "o-example"},
                        "IpAddress": {"aws:SourceIp": ["10.0.0.0/8"]},
                    },
                },
                {"Effect": "Deny", "NotAction": "iam:Get*", "NotResource": "arn:aws:s3:::public/*"},
            ],
        },
        source_policy_arn="arn:aws:iam::123456789012:policy/example",
    )

    assert policy.completeness is EvidenceCompleteness.COMPLETE
    assert policy.statements[0].actions == ("s3:GetObject", "s3:ListBucket")
    assert policy.statements[0].resources == ("arn:aws:s3:::example", "arn:aws:s3:::example/*")
    assert policy.statements[0].conditions == (
        ("IpAddress", "aws:SourceIp", ("10.0.0.0/8",)),
        ("StringEquals", "aws:PrincipalOrgID", ("o-example",)),
    )
    assert policy.statements[1].effect == "Deny"
    assert policy.statements[1].not_actions == ("iam:Get*",)


def test_bool_and_numeric_condition_values_are_retained_not_dropped() -> None:
    policy = normalize_iam_policy_document(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                    "Condition": {
                        "Bool": {"aws:MultiFactorAuthPresent": True},
                        "NumericLessThan": {"s3:max-keys": 10},
                        "DateGreaterThan": {"aws:CurrentTime": "2026-01-01T00:00:00Z"},
                    },
                }
            ]
        }
    )

    # A JSON bool/number condition value must survive normalization so the
    # evaluator still sees the guardrail instead of an empty (unconditional) tuple.
    assert policy.statements[0].conditions == (
        ("Bool", "aws:MultiFactorAuthPresent", ("true",)),
        ("DateGreaterThan", "aws:CurrentTime", ("2026-01-01T00:00:00Z",)),
        ("NumericLessThan", "s3:max-keys", ("10",)),
    )


def test_invalid_provider_statements_are_partial_not_exceptions() -> None:
    policy = normalize_iam_policy_document(
        {
            "Statement": [
                {"Effect": "Maybe", "Action": "s3:*"},
                {"Effect": "Allow", "Action": "s3:GetObject", "NotAction": "s3:DeleteObject"},
                {"Effect": "Allow", "Action": "ec2:Describe*", "Resource": "*"},
            ]
        }
    )

    assert policy.completeness is EvidenceCompleteness.PARTIAL
    assert len(policy.statements) == 1
    assert policy.diagnostics == (
        "statement_0_invalid_effect",
        "statement_1_requires_exactly_one_action_form",
    )


def test_non_mapping_policy_is_unavailable() -> None:
    policy = normalize_iam_policy_document("not-a-document")
    assert policy.completeness is EvidenceCompleteness.UNAVAILABLE
    assert policy.statements == ()
    assert policy.diagnostics == ("policy_document_not_mapping",)


def test_usage_evidence_preserves_unknown_instead_of_inventing_dormancy() -> None:
    denied = IamServiceUsageEvidence(service_namespace="s3", state=UsageEvidenceState.ACCESS_DENIED)
    never_used = IamServiceUsageEvidence(service_namespace="iam", state=UsageEvidenceState.AVAILABLE)
    used = IamServiceUsageEvidence(
        service_namespace="lambda",
        state=UsageEvidenceState.AVAILABLE,
        last_accessed_at=datetime(2026, 7, 1, tzinfo=timezone.utc),
    )

    assert denied.observed is None
    assert never_used.observed is False
    assert used.observed is True


def test_role_usage_evidence_serializes_provenance_and_stable_diagnostic() -> None:
    collected_at = datetime(2026, 7, 17, 15, 30, tzinfo=timezone.utc)
    evidence = IamRoleUsageEvidence(
        principal_arn="arn:aws:iam::123456789012:role/scanner",
        usage_state=UsageEvidenceState.ACCESS_DENIED,
        records=(),
        diagnostic="access_advisor_denied",
        collected_at=collected_at,
    )

    assert evidence.to_dict() == {
        "principal_arn": "arn:aws:iam::123456789012:role/scanner",
        "state": "access_denied",
        "diagnostic": "access_advisor_denied",
        "collected_at": "2026-07-17T15:30:00+00:00",
        "records": [],
    }
