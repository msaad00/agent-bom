"""Shape checks for untrusted CloudFormation values and partial coverage."""

from __future__ import annotations

import hashlib
from typing import Any

from agent_bom.scanners.state import record_coverage_warning


def report_input_gap(file_str: str) -> None:
    """Record one bounded warning per file without echoing imported content."""
    file_id = hashlib.sha256(file_str.encode("utf-8", errors="replace")).hexdigest()[:16]
    record_coverage_warning(
        {
            "ecosystem": "cloudformation",
            "release": f"cloudformation:{file_id}:unevaluated_template_input",
            "reason": "unevaluated_template_input",
            "detail": "CloudFormation input contains unreadable, malformed or unresolved values; affected checks were not evaluated.",
            "package_count": 0,
            "advisory_rows": 0,
        }
    )


def input_mapping(value: Any, file_str: str) -> dict[str, Any] | None:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        report_input_gap(file_str)
        return None
    return value


def mapping_sequence(value: Any, file_str: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        report_input_gap(file_str)
        return []
    result = []
    for entry in value:
        mapping = input_mapping(entry, file_str)
        if mapping is not None:
            result.append(mapping)
    return result


def _policy_documents(props: dict[str, Any], file_str: str) -> list[Any]:
    documents = [props["PolicyDocument"]] if "PolicyDocument" in props else []
    for policy in mapping_sequence(props.get("Policies", []), file_str):
        if "PolicyDocument" not in policy:
            report_input_gap(file_str)
        else:
            documents.append(policy["PolicyDocument"])
    return documents


def policy_statements(props: dict[str, Any], file_str: str) -> list[list[dict[str, Any]]]:
    """Preserve valid sibling policies and both IAM Statement container shapes."""
    result = []
    for value in _policy_documents(props, file_str):
        document = input_mapping(value, file_str)
        if document is None:
            continue
        statements = document.get("Statement")
        if isinstance(statements, dict):
            statements = [statements]
        result.append(mapping_sequence(statements, file_str))
    return result
