"""Reuse source analysis only within one scan, replaying its coverage evidence."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any, Iterator

_results: ContextVar[dict[str, tuple[Any, list[dict]]] | None] = ContextVar("project_analysis", default=None)


@contextmanager
def project_analysis_scope() -> Iterator[None]:
    """A fresh source snapshot for each scan; never reuse it across invocations."""
    token = _results.set({})
    try:
        yield
    finally:
        _results.reset(token)


def analyze_project_once(project_path: str | Path) -> Any:
    from agent_bom.ast_analyzer import analyze_project
    from agent_bom.scanners.state import capture_coverage_warnings, record_coverage_warning

    cache = _results.get()
    if cache is None:
        return analyze_project(project_path)
    key = str(Path(project_path).resolve())
    if key not in cache:
        with capture_coverage_warnings() as warnings:
            result = analyze_project(project_path)
        cache[key] = (result, warnings)
    result, warnings = cache[key]
    for warning in warnings:
        record_coverage_warning(dict(warning))
    return result
