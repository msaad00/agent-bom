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
