"""Analytics sink ownership shared by audit, ingestion and API composition.

This registry has no dependency on graph/job stores or HTTP routes. Durable
writers keep their primary transaction independent of the optional analytics
sink; callers retain their existing best-effort analytics failure policy.
"""

from __future__ import annotations

import threading
from typing import Any

_analytics_store: Any = None
_lock = threading.Lock()


def get_analytics_store() -> Any:
    """Return one process-local sink, with a no-op default when unconfigured."""
    global _analytics_store
    with _lock:
        if _analytics_store is None:
            from agent_bom.api.clickhouse_store import NullAnalyticsStore

            _analytics_store = NullAnalyticsStore()
        return _analytics_store


def set_analytics_store(store: Any) -> None:
    """Configure the sink before serving traffic; None restores the default."""
    global _analytics_store
    with _lock:
        _analytics_store = store


def peek_analytics_store() -> Any:
    """Inspect lifecycle state without initializing a default sink."""
    with _lock:
        return _analytics_store
