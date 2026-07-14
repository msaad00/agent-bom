from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from agent_bom.cloud.aws_iam_collector import collect_iam_role_evidence
from agent_bom.cloud.aws_iam_evidence import EvidenceCompleteness, UsageEvidenceState


class ProviderError(Exception):
    def __init__(self, code: str) -> None:
        self.response = {"Error": {"Code": code}}


class Paginator:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self.pages = pages

    def paginate(self, **kwargs: str) -> list[dict[str, Any]]:
        return self.pages


class IamClient:
    job_status = "COMPLETED"

    def get_paginator(self, operation: str) -> Paginator:
        pages = {
            "list_attached_role_policies": [{"AttachedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}]}],
            "list_role_policies": [{"PolicyNames": ["bounded-inline"]}],
        }
        return Paginator(pages[operation])

    def get_policy(self, **kwargs: str) -> dict[str, Any]:
        return {"Policy": {"DefaultVersionId": "v4"}}

    def get_policy_version(self, **kwargs: str) -> dict[str, Any]:
        return {"PolicyVersion": {"Document": {"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}}}}

    def get_role_policy(self, **kwargs: str) -> dict[str, Any]:
        return {"PolicyDocument": {"Statement": {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"}}}

    def generate_service_last_accessed_details(self, **kwargs: str) -> dict[str, str]:
        return {"JobId": "job-1"}

    def get_service_last_accessed_details(self, **kwargs: str) -> dict[str, Any]:
        return {
            "JobStatus": self.job_status,
            "ServicesLastAccessed": [
                {
                    "ServiceNamespace": "s3",
                    "LastAuthenticated": datetime(2026, 7, 1, tzinfo=timezone.utc),
                    "LastAuthenticatedRegion": "us-east-1",
                },
                {"ServiceNamespace": "kms"},
            ],
        }

    def get_role(self, **kwargs: str) -> dict[str, Any]:
        return {
            "Role": {
                "RoleLastUsed": {
                    "LastUsedDate": datetime(2026, 7, 2, tzinfo=timezone.utc),
                    "Region": "us-west-2",
                }
            }
        }


def test_collects_attached_inline_and_usage_evidence() -> None:
    evidence = collect_iam_role_evidence(IamClient(), principal_arn="arn:aws:iam::123456789012:role/scanner", role_name="scanner")

    assert evidence.policy_completeness is EvidenceCompleteness.COMPLETE
    assert len(evidence.policies) == 2
    assert evidence.policies[0].source_policy_arn == "arn:aws:iam::aws:policy/ReadOnlyAccess"
    assert evidence.policies[1].statements[0].effect == "Deny"
    assert evidence.usage_state is UsageEvidenceState.AVAILABLE
    assert [(item.service_namespace, item.observed) for item in evidence.usage] == [
        ("s3", True),
        ("kms", False),
        ("*", True),
    ]


def test_access_advisor_denied_is_not_clean_or_unused() -> None:
    client = IamClient()

    def denied(**kwargs: str) -> dict[str, str]:
        raise ProviderError("AccessDenied")

    client.generate_service_last_accessed_details = denied  # type: ignore[method-assign]
    evidence = collect_iam_role_evidence(client, principal_arn="arn:aws:iam::123456789012:role/scanner", role_name="scanner")

    assert evidence.usage_state is UsageEvidenceState.ACCESS_DENIED
    assert all(item.source == "role_last_used" for item in evidence.usage)


def test_access_advisor_pending_is_bounded_and_explicit() -> None:
    client = IamClient()
    client.job_status = "IN_PROGRESS"
    evidence = collect_iam_role_evidence(
        client,
        principal_arn="arn:aws:iam::123456789012:role/scanner",
        role_name="scanner",
        max_access_advisor_polls=2,
    )

    assert evidence.usage_state is UsageEvidenceState.PENDING


def test_policy_read_failure_makes_collection_partial_without_exception_text() -> None:
    client = IamClient()

    def failed(**kwargs: str) -> dict[str, Any]:
        raise RuntimeError("secret account path")

    client.get_policy_version = failed  # type: ignore[method-assign]
    evidence = collect_iam_role_evidence(client, principal_arn="arn:aws:iam::123456789012:role/scanner", role_name="scanner")

    assert evidence.policy_completeness is EvidenceCompleteness.PARTIAL
    assert evidence.policies[0].diagnostics == ("attached_policy_read_failed",)
    assert "secret" not in repr(evidence)


def test_successful_empty_policy_lists_are_complete_evidence() -> None:
    client = IamClient()

    def empty(operation: str) -> Paginator:
        page = {"AttachedPolicies": []} if operation == "list_attached_role_policies" else {"PolicyNames": []}
        return Paginator([page])

    client.get_paginator = empty  # type: ignore[method-assign]
    evidence = collect_iam_role_evidence(client, principal_arn="arn:aws:iam::123456789012:role/empty", role_name="empty")

    assert evidence.policies == ()
    assert evidence.policy_completeness is EvidenceCompleteness.COMPLETE
