"""Canonical finding-list envelope (#3666).

Every finding-list surface returns this one shape so consumers learn a single
contract instead of a per-route dialect:

    ``/v1/findings``                 (scan.py, the reference contract)
    ``/v1/compliance/hub/findings``  (compliance.py)
    ``/v1/governance/findings``      (governance.py)

The envelope keys and their order are fixed by :data:`FINDING_LIST_ENVELOPE_KEYS`.
Keyset ``cursor``/``next_cursor`` is the forward-compatible pagination path
(the store walks rows without a deep ``OFFSET`` scan); ``limit``/``offset``
stay for backward compatibility and for computed lists that have no keyset
store to walk. ``total_approximate`` is appended only when the total is a
lower-bound estimate rather than an exact ``COUNT(*)``.
"""

from __future__ import annotations

from typing import Any

FINDING_LIST_SCHEMA_VERSION = "v1"

# Shared compatibility ceiling for ``limit``/``offset`` pagination across every
# finding-list surface (``/v1/findings`` and ``/v1/compliance/hub/findings``).
# Deep ``OFFSET`` scans linearly, so past this ceiling callers must follow
# ``next_cursor`` (the keyset path is the unbounded-depth contract). Lives here —
# the module both routes already import — so the two surfaces share ONE ceiling
# instead of a per-route constant that could drift.
HUB_LIST_OFFSET_CEILING = 10_000

# The canonical key set every finding-list envelope must expose. Contract tests
# assert equality against this so a new divergent shape fails loudly.
FINDING_LIST_ENVELOPE_KEYS: tuple[str, ...] = (
    "schema_version",
    "findings",
    "count",
    "total",
    "limit",
    "offset",
    "sort",
    "scan_id",
    "cursor",
    "next_cursor",
    "has_more",
    "filters",
    "warnings",
    "count_metadata",
)


def finding_list_envelope(
    *,
    findings: list[dict[str, Any]],
    total: int | None,
    limit: int,
    offset: int = 0,
    sort: str | None = None,
    scan_id: str | None = None,
    cursor: str = "",
    next_cursor: str = "",
    filters: dict[str, Any] | None = None,
    warnings: list[str] | None = None,
    total_approximate: bool = False,
    source: str = "unified_findings",
    scope: str = "tenant-scoped current findings",
    window: dict[str, Any] | None = None,
    schema_version: str = FINDING_LIST_SCHEMA_VERSION,
) -> dict[str, Any]:
    """Build the canonical finding-list envelope shared by every list surface.

    ``count`` and ``has_more`` are derived so callers cannot drift them out of
    sync with ``findings`` and ``next_cursor``.
    """
    applied_filters = filters if filters is not None else {}
    has_more = bool(next_cursor)
    if total is None:
        completeness = {"status": "unknown", "reason": "total_unavailable"}
    elif total_approximate:
        completeness = {"status": "partial", "reason": "total_is_lower_bound"}
    elif offset > 0 or has_more or len(findings) < total:
        completeness = {"status": "partial", "reason": "paginated_result"}
    else:
        completeness = {"status": "complete", "reason": ""}

    envelope: dict[str, Any] = {
        "schema_version": schema_version,
        "findings": findings,
        "count": len(findings),
        "total": total,
        "limit": limit,
        "offset": offset,
        "sort": sort,
        "scan_id": scan_id,
        "cursor": cursor,
        "next_cursor": next_cursor,
        "has_more": has_more,
        "filters": applied_filters,
        "warnings": warnings if warnings is not None else [],
        "count_metadata": {
            "definition": "Findings matching this endpoint's tenant, source, window, and filters.",
            "source": source,
            "scope": scope,
            "window": window,
            "filters": applied_filters,
            "returned": len(findings),
            "total": total,
            "total_kind": "unknown" if total is None else "lower_bound" if total_approximate else "exact",
            "completeness": completeness,
        },
    }
    if total_approximate:
        envelope["total_approximate"] = True
    return envelope
