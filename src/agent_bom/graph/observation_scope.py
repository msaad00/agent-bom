"""Exact recorded namespaces for positive relationship observation continuity.

These helpers establish source comparability, never complete collection or
native revocation. Absence from a later scan cannot end an earlier observation.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any, Literal

_SCOPE_FIELDS = ("account_id", "cloud_account_id", "subscription_id", "project_id")


def _object(value: Any) -> Mapping[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return value if isinstance(value, Mapping) else {}


def _node_scope(attributes: Any, dimensions: Any) -> tuple[str, ...] | None:
    attrs, dims = _object(attributes), _object(dimensions)
    providers = (attrs.get("cloud_provider"), dims.get("cloud_provider"))
    if any(value is not None and not isinstance(value, str) for value in providers):
        return None
    provider = providers[0] or providers[1]
    if not isinstance(provider, str) or not provider.strip():
        return None
    if attrs.get("cloud_provider") and dims.get("cloud_provider") and attrs["cloud_provider"] != dims["cloud_provider"]:
        return None
    values = []
    for field in _SCOPE_FIELDS:
        value = attrs.get(field)
        if value is not None and not isinstance(value, str):
            return None
        values.append(value or "")
    if not any(value.strip() for value in values):
        return None
    return (provider, *values)


def observation_scope(
    evidence: Any, source_attributes: Any, source_dimensions: Any, target_attributes: Any, target_dimensions: Any
) -> tuple[Any, ...] | None:
    """Return exact collector and endpoint namespaces, or unknown (``None``)."""
    source = _object(evidence).get("source")
    left = _node_scope(source_attributes, source_dimensions)
    right = _node_scope(target_attributes, target_dimensions)
    if not isinstance(source, str) or not source.strip() or left is None or right is None:
        return None
    return (source, left, right)


def comparable_observation_sql(*, dialect: Literal["sqlite", "postgres"], previous: str, current: str) -> str:
    """Indexed endpoint lookups for exact positive scope, using static aliases.

    Callers provide internal SQL aliases only. Scope values are read from the
    stored JSON; there is no label matching or account/provider alias inference.
    """

    for alias in (previous, current):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", alias):
            raise ValueError("SQL alias must be a bounded identifier")

    def value(expression: str, field: str) -> str:
        if dialect == "sqlite":
            return f"json_extract({expression}, '$.{field}')"
        return f"({expression})::jsonb ->> '{field}'"

    def kind(expression: str, field: str) -> str:
        if dialect == "sqlite":
            return f"json_type({expression}, '$.{field}')"
        return f"jsonb_typeof(({expression})::jsonb -> '{field}')"

    string_kind = "text" if dialect == "sqlite" else "string"

    def text_value(expression: str, field: str) -> str:
        return f"COALESCE({value(expression, field)}, '')"

    def provider(alias: str) -> str:
        return (
            f"COALESCE(NULLIF({value(alias + '.attributes', 'cloud_provider')}, ''), {value(alias + '.dimensions', 'cloud_provider')}, '')"
        )

    def valid(alias: str) -> str:
        attrs = alias + ".attributes"
        dims = alias + ".dimensions"
        clauses = [
            f"TRIM({provider(alias)}) <> ''",
            f"({text_value(attrs, 'cloud_provider')} = '' OR {text_value(dims, 'cloud_provider')} = '' "
            f"OR {text_value(attrs, 'cloud_provider')} = {text_value(dims, 'cloud_provider')})",
        ]
        for expression, field in [(attrs, "cloud_provider"), (dims, "cloud_provider"), *((attrs, key) for key in _SCOPE_FIELDS)]:
            clauses.append(f"COALESCE({kind(expression, field)}, 'null') IN ('null', '{string_kind}')")
        clauses.append("(" + " OR ".join(f"TRIM({text_value(attrs, field)}) <> ''" for field in _SCOPE_FIELDS) + ")")
        return " AND ".join(clauses)

    def same(left: str, right: str) -> str:
        return " AND ".join(
            [
                valid(left),
                valid(right),
                f"{provider(left)} = {provider(right)}",
                *(f"{text_value(left + '.attributes', key)} = {text_value(right + '.attributes', key)}" for key in _SCOPE_FIELDS),
            ]
        )

    joins = []
    for alias in ("scope_ps", "scope_pt", "scope_cs", "scope_ct"):
        joins.append(f"graph_nodes AS {alias}")
    predicates = []
    for alias, edge_alias, endpoint in (
        ("scope_ps", previous, "source_id"),
        ("scope_pt", previous, "target_id"),
        ("scope_cs", current, "source_id"),
        ("scope_ct", current, "target_id"),
    ):
        predicates.append(
            f"{alias}.tenant_id = {edge_alias}.tenant_id AND {alias}.scan_id = {edge_alias}.scan_id "
            f"AND {alias}.id = {edge_alias}.{endpoint}"
        )
    old_source = value(previous + ".evidence", "source")
    new_source = value(current + ".evidence", "source")
    predicates.extend(
        [
            f"{kind(previous + '.evidence', 'source')} = '{string_kind}'",
            f"{kind(current + '.evidence', 'source')} = '{string_kind}'",
            f"TRIM({old_source}) <> ''",
            f"{old_source} = {new_source}",
            same("scope_ps", "scope_cs"),
            same("scope_pt", "scope_ct"),
        ]
    )
    # Scope values remain stored JSON expressions; interpolated identifiers are
    # fixed here or validated above, never arbitrary query fragments.
    return "EXISTS (SELECT 1 FROM " + ", ".join(joins) + " WHERE " + " AND ".join(predicates) + ")"  # nosec B608
