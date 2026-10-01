"""Shared HTTP graph paging bounds and response metadata."""

from fastapi import HTTPException

from agent_bom.api.graph_store import MAX_NODE_PAGE_OFFSET


def _paginate(items: list, offset: int, limit: int) -> tuple[list, dict]:
    """Apply offset/limit pagination and return (page, pagination_meta)."""
    total = len(items)
    page = items[offset : offset + limit]
    return page, {
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": offset + limit < total,
    }


def _page_meta(total: int, offset: int, limit: int, *, cursor: str | None = None, next_cursor: str | None = None) -> dict:
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "cursor": cursor or "",
        "next_cursor": next_cursor or "",
        "has_more": bool(next_cursor) if cursor else offset + limit < total,
    }


def _enforce_node_offset_cap(offset: int, cursor: str | None) -> None:
    """Reject deep OFFSET pagination that would force an O(offset) row scan.

    Offset paging past the cap costs seconds because the store still walks and
    discards every skipped row. Keyset ``cursor=`` pagination stays flat, so
    point callers there instead of silently serving a multi-second response.
    """
    if not cursor and offset > MAX_NODE_PAGE_OFFSET:
        raise HTTPException(
            status_code=422,
            detail=(
                f"offset={offset} exceeds the maximum supported node offset ({MAX_NODE_PAGE_OFFSET}). "
                "Use the cursor= keyset parameter (next_cursor from the previous page) for deep pagination."
            ),
        )


def _coalesce_alias(primary: str | None, alias: str | None, *, primary_name: str, alias_name: str) -> str:
    if primary and alias and primary != alias:
        raise HTTPException(status_code=422, detail=f"Conflicting query parameters: {primary_name} and {alias_name}")
    return primary or alias or ""
