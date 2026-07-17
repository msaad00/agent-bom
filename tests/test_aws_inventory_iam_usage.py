from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent_bom.cloud import aws_iam_collector, aws_inventory


class _Paginator:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self.pages = pages

    def paginate(self, **kwargs: Any) -> list[dict[str, Any]]:
        return self.pages


class _InventoryIam:
    def __init__(self, role_count: int = 1) -> None:
        self.role_count = role_count
        self.operations: list[str] = []
        self.generate_calls = 0

    def get_paginator(self, operation: str) -> _Paginator:
        self.operations.append(operation)
        if operation == "list_roles":
            return _Paginator(
                [
                    {
                        "Roles": [
                            {
                                "RoleName": f"role-{index}",
                                "Arn": f"arn:aws:iam::123456789012:role/role-{index}",
                            }
                            for index in range(self.role_count)
                        ]
                    }
                ]
            )
        if operation in {"list_groups", "list_users"}:
            return _Paginator([{"Groups": [], "Users": []}])
        if operation == "list_attached_role_policies":
            return _Paginator(
                [
                    {
                        "AttachedPolicies": [
                            {
                                "PolicyArn": "arn:aws:iam::123456789012:policy/read-data",
                                "PolicyName": "read-data",
                            }
                        ]
                    }
                ]
            )
        if operation == "list_role_policies":
            return _Paginator([{"PolicyNames": ["inline-read"]}])
        raise AssertionError(operation)

    def get_policy(self, **kwargs: Any) -> dict[str, Any]:
        self.operations.append("get_policy")
        return {"Policy": {"DefaultVersionId": "v1"}}

    def get_policy_version(self, **kwargs: Any) -> dict[str, Any]:
        self.operations.append("get_policy_version")
        return {"PolicyVersion": {"Document": {"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}}}}

    def get_role_policy(self, **kwargs: Any) -> dict[str, Any]:
        self.operations.append("get_role_policy")
        return {"PolicyDocument": {"Statement": {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*"}}}

    def get_role(self, **kwargs: Any) -> dict[str, Any]:
        self.operations.append("get_role")
        return {
            "Role": {
                "RoleName": kwargs["RoleName"],
                "RoleLastUsed": {
                    "LastUsedDate": datetime(2026, 7, 1, tzinfo=timezone.utc),
                    "Region": "us-east-1",
                },
            }
        }

    def generate_service_last_accessed_details(self, **kwargs: Any) -> dict[str, str]:
        self.generate_calls += 1
        return {"JobId": f"job-{self.generate_calls}"}

    def get_service_last_accessed_details(self, **kwargs: Any) -> dict[str, Any]:
        return {
            "JobStatus": "COMPLETED",
            "ServicesLastAccessed": [
                {
                    "ServiceNamespace": "s3",
                    "LastAuthenticated": datetime(2026, 7, 2, tzinfo=timezone.utc),
                    "LastAuthenticatedRegion": "us-east-1",
                }
            ],
            "IsTruncated": False,
        }


class _Session:
    def __init__(self, iam: _InventoryIam) -> None:
        self.iam = iam

    def client(self, name: str) -> _InventoryIam:
        assert name == "iam"
        return self.iam


class _DelayedInventoryIam(_InventoryIam):
    def __init__(self, *, role_count: int = 2) -> None:
        super().__init__(role_count=role_count)
        self.polls_by_job: dict[str, int] = {}

    def get_service_last_accessed_details(self, **kwargs: Any) -> dict[str, Any]:
        job_id = str(kwargs["JobId"])
        poll = self.polls_by_job.get(job_id, 0)
        self.polls_by_job[job_id] = poll + 1
        status = ("RUNNING", "PENDING", "COMPLETED")[min(poll, 2)]
        if status != "COMPLETED":
            return {"JobStatus": status}
        return {
            "JobStatus": "COMPLETED",
            "ServicesLastAccessed": [{"ServiceNamespace": f"service-{job_id}"}],
            "IsTruncated": False,
        }


def test_role_inventory_threads_usage_evidence_without_repeating_policy_reads() -> None:
    iam = _InventoryIam()
    role = {
        "RoleName": "role-0",
        "Arn": "arn:aws:iam::123456789012:role/role-0",
    }

    normalized = aws_inventory._normalize_role(iam, role, account_id="123456789012", warnings=[])

    assert normalized["usage_evidence"]["state"] == "available"
    assert normalized["usage_evidence"]["diagnostic"] == "access_advisor_available"
    assert [record["service_namespace"] for record in normalized["usage_evidence"]["records"]] == ["s3", "*"]
    assert iam.operations.count("list_attached_role_policies") == 1
    assert iam.operations.count("list_role_policies") == 1
    assert iam.operations.count("get_policy") == 1
    assert iam.operations.count("get_policy_version") == 1
    assert iam.operations.count("get_role_policy") == 1
    assert iam.operations.count("get_role") == 1


def test_role_usage_collection_has_an_estate_budget_and_marks_skips_unavailable(monkeypatch: Any) -> None:
    iam = _InventoryIam(role_count=2)
    monkeypatch.setattr(aws_inventory, "_MAX_IAM_USAGE_ROLES", 1)

    roles, users, groups = aws_inventory._discover_iam(_Session(iam), account_id="123456789012", warnings=[])

    assert users == []
    assert groups == []
    assert [role["usage_evidence"]["state"] for role in roles] == ["available", "unavailable"]
    assert roles[1]["usage_evidence"]["diagnostic"] == "role_collection_budget_exhausted"
    assert iam.generate_calls == 1


def test_role_usage_jobs_are_polled_in_shared_backoff_rounds(monkeypatch: Any) -> None:
    """Slow Access Advisor jobs remain useful without sleeping once per role."""
    iam = _DelayedInventoryIam(role_count=2)
    delays: list[float] = []
    monkeypatch.setattr(aws_iam_collector.time, "sleep", delays.append)

    roles, users, groups = aws_inventory._discover_iam(
        _Session(iam),
        account_id="123456789012",
        warnings=[],
    )

    assert users == [] and groups == []
    assert [role["usage_evidence"]["state"] for role in roles] == ["available", "available"]
    assert delays == [1.0, 2.0]
    assert iam.polls_by_job == {"job-1": 3, "job-2": 3}


def test_inventory_permission_envelope_declares_only_usage_reads_added_for_ciem() -> None:
    assert "iam:GetRole" in aws_inventory._AWS_IAM_PERMISSIONS
    assert "iam:GenerateServiceLastAccessedDetails" in aws_inventory._AWS_IAM_PERMISSIONS
    assert "iam:GetServiceLastAccessedDetails" in aws_inventory._AWS_IAM_PERMISSIONS
    assert not any(
        permission.startswith(("iam:Put", "iam:Create", "iam:Update", "iam:Delete")) for permission in aws_inventory._AWS_IAM_PERMISSIONS
    )


def test_provisioned_readonly_policy_grants_the_bounded_access_advisor_pair() -> None:
    policy_path = Path(__file__).parent.parent / "scripts" / "provision" / "aws_readonly_policy.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    actions = {action for statement in policy["Statement"] for action in statement.get("Action", []) if isinstance(action, str)}

    assert "iam:GenerateServiceLastAccessedDetails" in actions
    assert "iam:GetServiceLastAccessedDetails" in actions
