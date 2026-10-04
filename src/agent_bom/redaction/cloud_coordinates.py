"""Recognize native cloud coordinates without exempting their secret segments."""

from __future__ import annotations

import re

from agent_bom import security

_KEYS = frozenset(
    {
        "id",
        "ids",
        "name",
        "identifier",
        "canonical_id",
        "node_id",
        "node_ids",
        "source",
        "target",
        "source_id",
        "target_id",
        "resource_id",
        "resource_ids",
        "principal_id",
        "principal_ids",
        "self_link",
        "selflink",
        "resourceid",
        "resourceids",
        "principalids",
        "parent",
        "parent_id",
        "scope",
        "scopes",
        "scope_id",
    }
)
_SEGMENT = r"[^/\s?#\\]+"
_ARM = re.compile(
    rf"(?:/(?:subscriptions/{_SEGMENT}(?:/resourceGroups/{_SEGMENT})?|tenants/{_SEGMENT})"
    rf"(?:/providers/{_SEGMENT}(?:/{_SEGMENT}/{_SEGMENT})+)?|/providers/Microsoft.Management/managementGroups/{_SEGMENT})/?",
    re.I,
)
_GCP = re.compile(
    rf"(?://storage\.googleapis\.com/{_SEGMENT}|"
    rf"(?:(?://[a-z0-9.-]+\.googleapis\.com/)|(?:https://(?:www\.)?googleapis\.com/[a-z0-9]+/v[0-9a-z]+/)|"
    rf"(?:https://[a-z0-9-]+\.googleapis\.com/(?:(?:[a-z0-9]+/)?v[0-9a-z]+/)?))?"
    rf"(?:projects|folders|organizations)/{_SEGMENT}(?:/{_SEGMENT}/{_SEGMENT})*/?)"
)
_ARN = re.compile(r"arn:aws(?:-[a-z0-9-]+)?:[a-z0-9-]+:[^:\s]*:[^:\s]*:[^\s]+")


def sanitize_cloud_coordinate(value: str, key: str, max_len: int) -> str | None:
    """Return a safe coordinate, a redaction marker, or None for ordinary data.

    Restrict recognition by field and native shape. Check decoded path segments
    independently so namespace length does not look like an opaque token, while
    encoded credentials and high-entropy tokens still fail closed.
    """
    if security._key_looks_sensitive(key) or (
        key not in _KEYS and not key.endswith(("_arn", "_resource_id", "_resource_ids")) and key != "arn"
    ):
        return None
    if not (_ARM.fullmatch(value) or _GCP.fullmatch(value) or _ARN.fullmatch(value)):
        return security.sanitize_path_label(value) if security._looks_like_path_value(value) else None
    parts = [security._decode_reference_component(part) for part in re.split(r"[/:@|?&#><]", value) if part]
    if any(security._REFERENCE_ENCODED_OCTET_RE.search(part) or security._looks_sensitive_value(part) for part in parts):
        return "***REDACTED***"
    return security.sanitize_text(value, max_len=max_len)
