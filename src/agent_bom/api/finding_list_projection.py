"""Row projection for ``GET /v1/findings`` list pages.

Full compliance control mappings average several KB per finding, dominating
list payloads. List rows keep ``framework_tags`` (the flat
``framework:control`` ids used for filtering and labels) plus a
``controls_count``; callers that need the per-control provenance opt in with
``?include=controls``. The choice is carried in a context variable so the
worker-thread read path applies it before redaction without widening every
internal signature.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Annotated, Any

from fastapi import HTTPException, Query

LIST_INCLUDE_OPTIONS: tuple[str, ...] = ("controls",)

FindingListInclude = Annotated[
    str | None,
    Query(max_length=64, description="Comma-separated opt-ins; `controls` returns full per-finding control mappings"),
]

_include_controls: ContextVar[bool] = ContextVar("finding_list_include_controls", default=True)


def parse_list_include(value: str | None) -> tuple[str, ...]:
    """Parse a comma-separated ``include`` value; raise ``ValueError`` on unknown parts."""
    if not value:
        return ()
    parts = sorted({part.strip().lower() for part in value.split(",") if part.strip()})
    unknown = [part for part in parts if part not in LIST_INCLUDE_OPTIONS]
    if unknown:
        raise ValueError(f"invalid include; accepted values: {', '.join(LIST_INCLUDE_OPTIONS)}")
    return tuple(parts)


def list_include_or_422(value: str | None) -> tuple[str, ...]:
    try:
        return parse_list_include(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


@contextmanager
def finding_list_projection(*, include_controls: bool) -> Iterator[None]:
    token = _include_controls.set(include_controls)
    try:
        yield
    finally:
        _include_controls.reset(token)


def _control_count(controls: object) -> int:
    if not isinstance(controls, list):
        return 0
    return sum(1 for item in controls if isinstance(item, Mapping) and item.get("framework") and item.get("control"))


def project_list_row(row: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return ``row`` with full control mappings replaced by a count unless opted in."""
    if "controls" not in row:
        return row
    count = _control_count(row.get("controls"))
    if _include_controls.get():
        projected = dict(row)
        projected["controls_count"] = count
        return projected
    projected = {key: value for key, value in row.items() if key != "controls"}
    projected["controls_count"] = count
    return projected
