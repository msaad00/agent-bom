"""Tenant-scoped in-memory store for hub-ingested findings (#1044 PR C).

Persists external compliance findings (SARIF / CycloneDX / CSV / JSON
imports) alongside native scan results so dashboard / API aggregations
can render unified posture.

In-memory for now — durable persistence (Postgres / ClickHouse) lands
in a follow-up. The store is single-process; multi-replica deployments
should treat ingested findings as ephemeral until persistence ships.
"""

from __future__ import annotations

import threading
from typing import Any


class ComplianceHubStore:
    """Tenant-scoped append-only ledger of hub-ingested findings.

    Each finding is stored as its serialised dict (Finding.to_dict()) so
    the API can return the canonical payload without re-serialising on
    every read.
    """

    def __init__(self) -> None:
        self._by_tenant: dict[str, list[dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def add(self, tenant_id: str, findings: list[dict[str, Any]]) -> int:
        """Append findings for a tenant. Returns the new total count."""
        with self._lock:
            bucket = self._by_tenant.setdefault(tenant_id, [])
            bucket.extend(findings)
            return len(bucket)

    def list(self, tenant_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._by_tenant.get(tenant_id, []))

    def count(self, tenant_id: str) -> int:
        with self._lock:
            return len(self._by_tenant.get(tenant_id, []))

    def clear(self, tenant_id: str) -> int:
        with self._lock:
            removed = len(self._by_tenant.get(tenant_id, []))
            self._by_tenant[tenant_id] = []
            return removed


_HUB_STORE: ComplianceHubStore | None = None


def get_compliance_hub_store() -> ComplianceHubStore:
    """Return the process-wide hub store, lazily constructed."""
    global _HUB_STORE
    if _HUB_STORE is None:
        _HUB_STORE = ComplianceHubStore()
    return _HUB_STORE


def reset_compliance_hub_store() -> None:
    """Reset the store — for tests only."""
    global _HUB_STORE
    _HUB_STORE = None
