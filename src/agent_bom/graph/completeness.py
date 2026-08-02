"""Completeness metadata shared by graph API and agent-facing projections."""

from __future__ import annotations

from typing import Any


def graph_completeness(
    *,
    returned: int,
    total: int | None = None,
    truncated: bool = False,
    sampled: bool = False,
    reason: str = "",
) -> dict[str, Any]:
    """Describe whether a graph response is exhaustive or intentionally bounded.

    ``sampled`` means the producer selected a deterministic representative
    subset; ``truncated`` means a caller/request limit cut off an otherwise
    exhaustive result. The booleans are retained alongside ``status`` so
    clients can branch without string parsing.
    """
    status = "truncated" if truncated else "sampled" if sampled else "complete"
    payload: dict[str, Any] = {
        "status": status,
        "complete": status == "complete",
        "sampled": sampled,
        "truncated": truncated,
        "returned": max(0, returned),
    }
    if total is not None:
        payload["total"] = max(0, total)
    if reason:
        payload["reason"] = reason
    return payload


def bounded_walk_reason(*, truncated: bool, depth_limited: bool) -> str:
    """Name the *stronger* loss a bounded graph walk suffered.

    A node/edge/deadline budget outranks a depth cap: raising ``max_depth``
    cannot recover nodes the budget never let the walk visit, so the budget
    reason must not be masked by the depth one.
    """
    if truncated:
        return "traversal_budget"
    return "depth_limit" if depth_limited else ""


def impact_completeness(*, affected_count: int, truncated: bool, depth_limited: bool) -> dict[str, Any]:
    """Completeness for a blast-radius walk.

    A bounded reverse walk knows how many ancestors it *reached*, never how many
    exist — so it reports no ``total``. Without this, ``affected_count`` read as
    the whole blast radius, which is the difference between "nothing else
    depends on this" and "we stopped looking".
    """
    bounded = truncated or depth_limited
    return graph_completeness(
        returned=affected_count,
        total=None if bounded else affected_count,
        truncated=bounded,
        reason=bounded_walk_reason(truncated=truncated, depth_limited=depth_limited),
    )
