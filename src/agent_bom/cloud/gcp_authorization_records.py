"""Normalize GCP IAM API responses into stable authorization evidence records."""

from __future__ import annotations

import base64
from hashlib import sha256
from typing import Any, Mapping

from agent_bom.cloud.authorization_evidence import EvidenceSourceState


def _get(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _strings(value: Any) -> list[str]:
    return sorted({_text(item) for item in (value or []) if _text(item)})


def _ordered_strings(value: Any) -> list[str]:
    return list(dict.fromkeys(_text(item) for item in (value or []) if _text(item)))


def _etag(value: Any) -> str:
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    return _text(value)


def _condition(value: Any) -> dict[str, Any] | None:
    expression = _text(_get(value, "expression"))
    if not expression:
        return None
    return {
        "expression": expression,
        "title": _text(_get(value, "title")),
        "description": _text(_get(value, "description")),
        "location": _text(_get(value, "location")),
    }


def _bindings(policy: Any, resource: str) -> tuple[list[dict[str, Any]], int]:
    bindings: list[dict[str, Any]] = []
    dropped = 0
    for raw in _get(policy, "bindings", []) or []:
        role = _text(_get(raw, "role"))
        members = _strings(_get(raw, "members", []))
        if not role or not members:
            dropped += 1
            continue
        condition = _condition(_get(raw, "condition"))
        digest = sha256("\x1f".join((resource, role, *members, condition["expression"] if condition else "")).encode()).hexdigest()[:24]
        bindings.append(
            {
                "id": f"gcp:iam-binding:{digest}",
                "role": role,
                "members": members,
                "condition": condition,
            }
        )
    return sorted(bindings, key=lambda item: item["id"]), dropped


def _policy_record(resource: str, policy: Any, *, asset_type: str, ancestors: Any = None) -> dict[str, Any]:
    bindings, dropped = _bindings(policy, resource)
    return {
        "resource": resource,
        "asset_type": asset_type,
        "ancestors": _ordered_strings(ancestors),
        "version": int(_get(policy, "version", 0) or 0),
        "etag": _etag(_get(policy, "etag")),
        "bindings": bindings,
        "dropped_bindings": dropped,
    }


def _role_record(role: Any, role_id: str) -> dict[str, Any]:
    stage = _text(_get(role, "stage"))
    deleted = bool(_get(role, "deleted", False))
    disabled = stage.casefold() == "disabled"
    return {
        "id": _text(_get(role, "name")) or role_id,
        "title": _text(_get(role, "title")),
        "description": _text(_get(role, "description")),
        "stage": stage,
        "deleted": deleted,
        "permissions": [] if deleted or disabled else _strings(_get(role, "included_permissions", [])),
        "completeness": (EvidenceSourceState.UNAVAILABLE.value if deleted or disabled else EvidenceSourceState.COMPLETE.value),
        "diagnostics": [item for item, applies in (("role_deleted", deleted), ("role_disabled", disabled)) if applies],
    }


def _deny_rule(rule: Any) -> dict[str, Any] | None:
    denied_principals = _strings(_get(rule, "denied_principals", []))
    denied_permissions = _strings(_get(rule, "denied_permissions", []))
    if not denied_principals or not denied_permissions:
        return None
    return {
        "denied_principals": denied_principals,
        "exception_principals": _strings(_get(rule, "exception_principals", [])),
        "denied_permissions": denied_permissions,
        "exception_permissions": _strings(_get(rule, "exception_permissions", [])),
        "condition": _condition(_get(rule, "denial_condition")),
    }


def _deny_record(policy: Any, attachment_point: str) -> tuple[dict[str, Any] | None, int]:
    rules: list[dict[str, Any]] = []
    dropped = 0
    for wrapper in _get(policy, "rules", []) or []:
        rule = _get(wrapper, "deny_rule", wrapper)
        normalized = _deny_rule(rule)
        if normalized is None:
            dropped += 1
        else:
            rules.append(normalized)
    name = _text(_get(policy, "name"))
    if not name or not rules:
        return None, max(1, dropped)
    return {
        "name": name,
        "uid": _text(_get(policy, "uid")),
        "display_name": _text(_get(policy, "display_name")),
        "attachment_point": attachment_point,
        "rules": rules,
    }, dropped


def _pab_record(policy: Any) -> dict[str, Any]:
    details = _get(policy, "details")
    rules = [
        {
            "description": _text(_get(rule, "description")),
            "resources": _strings(_get(rule, "resources", [])),
            "effect": _text(_get(rule, "effect")),
        }
        for rule in (_get(details, "rules", []) or [])
    ]
    return {
        "name": _text(_get(policy, "name")),
        "uid": _text(_get(policy, "uid")),
        "display_name": _text(_get(policy, "display_name")),
        "enforcement_version": _text(_get(details, "enforcement_version")),
        "rules": rules,
    }


def _pab_binding_record(binding: Any) -> dict[str, Any]:
    target = _get(binding, "target")
    return {
        "name": _text(_get(binding, "name")),
        "uid": _text(_get(binding, "uid")),
        "target": _text(_get(target, "principal_set")),
        "policy_kind": _text(_get(binding, "policy_kind")),
        "policy": _text(_get(binding, "policy")),
        "policy_uid": _text(_get(binding, "policy_uid")),
        "condition": _condition(_get(binding, "condition")),
    }
