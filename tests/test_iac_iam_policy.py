"""Regression coverage for standalone AWS IAM policy artifacts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_bom.iac import is_iac_file, scan_iac_with_context


def _write_policy(path: Path, statement: dict[str, object]) -> Path:
    path.write_text(json.dumps({"Version": "2012-10-17", "Statement": [statement]}), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("name", "statement", "rule_id"),
    [
        (
            "wildcard.json",
            {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
            "IAM-001",
        ),
        (
            "pass-role.json",
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
            "IAM-002",
        ),
        (
            "assume-role.json",
            {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"},
            "IAM-003",
        ),
        (
            "trust-policy.json",
            {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": "*"}},
            "IAM-003",
        ),
    ],
)
def test_standalone_iam_policy_is_scanned(tmp_path: Path, name: str, statement: dict[str, object], rule_id: str) -> None:
    policy = _write_policy(tmp_path / name, statement)

    assert is_iac_file(policy, tmp_path) is True
    result = scan_iac_with_context(tmp_path)

    assert any(finding.rule_id == rule_id and finding.file_path == str(policy) for finding in result.findings)
    verdict = next(item for item in result.verdicts if item.scanner_id == "iam-policy")
    assert verdict.status == "ran"
    assert verdict.files_scanned == 1


def test_scoped_read_policy_is_scanned_without_false_positive(tmp_path: Path) -> None:
    policy = _write_policy(
        tmp_path / "scoped.json",
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::customer-data/reports/*",
        },
    )

    result = scan_iac_with_context(policy)

    assert result.findings == []
    verdict = next(item for item in result.verdicts if item.scanner_id == "iam-policy")
    assert verdict.status == "ran"


def test_generic_json_is_not_claimed_as_iam(tmp_path: Path) -> None:
    package_json = tmp_path / "package.json"
    package_json.write_text('{"name":"example","scripts":{"test":"pytest"}}', encoding="utf-8")

    assert is_iac_file(package_json, tmp_path) is False
    result = scan_iac_with_context(tmp_path)
    verdict = next(item for item in result.verdicts if item.scanner_id == "iam-policy")
    assert verdict.status == "not-applicable"
