"""Normalize optional Gremlin driver responses without importing the driver."""

from typing import Any


def normalize_neptune_result(result: Any) -> list[Any]:
    """Normalize gremlin-python futures and simple fake-client lists."""

    if hasattr(result, "all"):
        result = result.all()
    if hasattr(result, "result"):
        result = result.result()
    if result is None:
        return []
    if isinstance(result, list):
        return result
    return [result]
