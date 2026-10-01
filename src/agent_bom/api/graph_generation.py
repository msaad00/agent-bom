"""Fail-closed generation checks around multi-read graph responses."""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from agent_bom.api.graph_scan_ids import resolve_graph_scan_id

_PIN_UNSUPPORTED = "Generation-pinned pages require SQLite or Postgres; the experimental Neptune backend does not support them."


def pin_generation(store: Any, *, tenant: str, scan_id: str, generation: str | None, offset: int) -> tuple[str, str]:
    if offset and not generation:
        raise HTTPException(422, "Continuation requires snapshot_generation from the first page; restart the query.")
    reader = getattr(store, "snapshot_identity", None)
    if not callable(reader):
        raise HTTPException(501, _PIN_UNSUPPORTED)
    try:
        identity = reader(tenant_id=tenant, scan_id=resolve_graph_scan_id(tenant, scan_id), for_paging=True)
    except NotImplementedError as exc:
        raise HTTPException(501, _PIN_UNSUPPORTED) from exc
    if generation is not None and (not generation or generation != identity[1]):
        raise HTTPException(409, "Graph snapshot changed; restart the query from its first page.")
    return identity


def verify_generation(store: Any, *, tenant: str, identity: tuple[str, str], has_rows: bool) -> None:
    current = store.snapshot_identity(tenant_id=tenant, scan_id=identity[0], for_paging=True)
    if current != identity or (has_rows and not identity[1]):
        raise HTTPException(409, "Graph snapshot changed during the read; restart the query from its first page.")


def optional_generation(store: Any, *, tenant: str, scan_id: str, generation: str | None, offset: int) -> tuple[str, str] | None:
    """Allow an unpaged legacy rollup, but never an unpinned continuation."""
    try:
        return pin_generation(store, tenant=tenant, scan_id=scan_id, generation=generation, offset=offset)
    except HTTPException as exc:
        if exc.status_code == 501 and not offset and generation is None:
            return None
        raise
