"""Standalone AWS IAM identity and trust policy scanning.

CloudFormation policies are handled by the CloudFormation scanner. This module
covers local policy documents that contain a top-level ``Statement`` block but
no CloudFormation ``Resources`` envelope.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from agent_bom.iac.models import IaCFinding, IaCResourceType


def _load_iam_policy(path: Path) -> tuple[dict[str, Any], str] | None:
    """Return a standalone IAM policy and its source text when recognized."""
    if path.suffix.lower() != ".json":
        return None
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        raw = json.loads(content)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(raw, dict) or "Resources" in raw:
        return None

    policy: object = raw.get("PolicyDocument", raw)
    if not isinstance(policy, dict):
        return None
    statements = policy.get("Statement")
    if not isinstance(statements, (dict, list)):
        return None
    rows = [statements] if isinstance(statements, dict) else statements
    if not rows or not all(isinstance(row, dict) for row in rows):
        return None
    if not any("Action" in row or "NotAction" in row or "Principal" in row for row in rows):
        return None
    return policy, content


def is_iam_policy_document(path: Path) -> bool:
    """Return whether ``path`` is a standalone AWS IAM policy document."""
    return _load_iam_policy(path) is not None


def _string_values(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    if isinstance(value, Mapping):
        values: list[str] = []
        for nested in value.values():
            values.extend(_string_values(nested))
        return values
    return []


def _find_line(content: str, needles: list[str]) -> int:
    normalized = [needle.casefold() for needle in needles if needle]
    for number, line in enumerate(content.splitlines(), 1):
        lowered = line.casefold()
        if any(needle in lowered for needle in normalized):
            return number
    return 1


def _finding(
    *,
    rule_id: str,
    severity: str,
    title: str,
    message: str,
    path: Path,
    content: str,
    needles: list[str],
    remediation: str,
) -> IaCFinding:
    return IaCFinding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        message=message,
        file_path=str(path),
        line_number=_find_line(content, needles),
        category="iam-policy",
        compliance=["NIST-AC-6"],
        remediation=remediation,
        resource_type=IaCResourceType.IAM_POLICY,
    )


def scan_iam_policy(path: Path) -> list[IaCFinding]:
    """Detect broad permissions and role escalation in a standalone policy."""
    loaded = _load_iam_policy(path)
    if loaded is None:
        return []
    policy, content = loaded
    raw_statements = policy["Statement"]
    statements = [raw_statements] if isinstance(raw_statements, dict) else raw_statements
    findings: list[IaCFinding] = []

    for statement in statements:
        if not isinstance(statement, dict) or str(statement.get("Effect", "")).casefold() != "allow":
            continue
        actions = _string_values(statement.get("Action"))
        action_keys = {action.casefold() for action in actions}
        resources = _string_values(statement.get("Resource"))
        principals = _string_values(statement.get("Principal"))
        wildcard_resource = "*" in resources
        wildcard_principal = "*" in principals

        wildcard_actions = [action for action in actions if action == "*" or action.endswith(":*")]
        if wildcard_actions:
            findings.append(
                _finding(
                    rule_id="IAM-001",
                    severity="high",
                    title="IAM policy allows wildcard actions",
                    message="An Allow statement grants every action, or every action in a service namespace.",
                    path=path,
                    content=content,
                    needles=wildcard_actions,
                    remediation="Replace wildcard actions with the minimum explicit actions required by the workload.",
                )
            )

        if "iam:passrole" in action_keys and wildcard_resource:
            findings.append(
                _finding(
                    rule_id="IAM-002",
                    severity="critical",
                    title="iam:PassRole is allowed for every role",
                    message="The principal can pass any IAM role to a service, creating a privilege-escalation path.",
                    path=path,
                    content=content,
                    needles=["iam:PassRole"],
                    remediation="Scope iam:PassRole to approved role ARNs and constrain the destination service with iam:PassedToService.",
                )
            )

        if "sts:assumerole" in action_keys and (wildcard_resource or wildcard_principal):
            reason = "every principal" if wildcard_principal else "every role"
            findings.append(
                _finding(
                    rule_id="IAM-003",
                    severity="critical",
                    title="sts:AssumeRole has an unrestricted trust boundary",
                    message=f"The Allow statement permits {reason} in an sts:AssumeRole path.",
                    path=path,
                    content=content,
                    needles=["sts:AssumeRole"],
                    remediation="Scope the trusted principal or role resources to explicit ARNs and add least-privilege conditions.",
                )
            )

    return findings


__all__ = ["is_iam_policy_document", "scan_iam_policy"]
