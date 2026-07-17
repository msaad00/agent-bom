"""Shared off-loop Compliance-Hub ingest write path.

The bulk/connector ingest route (`/v1/findings/bulk`) and the external-scan
ingest route (`/v1/compliance/ingest`) both run the same blocking psycopg write
sequence — ledger append (``hub_store.add``), current-state upsert
(``upsert_current_batch``), absent reconciliation, and hub delta emission.

Running that sequence directly on the event loop froze unrelated requests
(``/health``, ``/version``) for seconds under concurrent ingest. Both routes now
funnel the sequence through :func:`hub_store_call` (an ``anyio.to_thread``
offload, mirroring the read path) around a single shared body,
:func:`hub_ingest_store_writes`, so the two ingest paths cannot diverge.
"""

from __future__ import annotations

from functools import partial
from typing import Any

import anyio.to_thread


async def hub_store_call(fn, /, *args, **kwargs):
    """Run blocking Compliance-Hub store writes off the event loop.

    The ingest paths call synchronous psycopg (``hub_store.add`` /
    ``upsert_current_batch`` / reconcile / delta emission). Running them on the
    loop froze unrelated requests under concurrent ingest. This mirrors the read
    path's ``anyio.to_thread`` offload so a single deep write cannot block the
    loop. No backpressure/429 is applied: writes are bounded per batch and
    shedding an ingest would silently drop findings.
    """
    return await anyio.to_thread.run_sync(partial(fn, *args, **kwargs))


def hub_ingest_store_writes(
    hub_store: Any,
    tenant_id: str,
    payloads: list[dict[str, Any]],
    *,
    observed_at: str,
    batch_id: str,
    source: str,
    reconcile_absent: bool,
) -> dict[str, Any]:
    """Synchronous body of the hub ingest store writes (runs in a worker thread).

    Captures prior snapshots (when reconciliation needs them), appends the batch
    to the ledger, upserts current-state, reconciles absent findings, and emits
    hub deltas — all the blocking psycopg work — in one off-loop call. Shared by
    the bulk ingest and compliance ingest routes so their write path stays
    identical.
    """
    from agent_bom.api.finding_lifecycle import collect_present_canonical_ids
    from agent_bom.delta_stream import (
        capture_hub_snapshots,
        emit_hub_finding_deltas_if_enabled,
        needs_hub_prior_snapshots,
        resolved_canonical_ids,
    )

    prior_snapshots: dict[str, Any] = {}
    if needs_hub_prior_snapshots(reconcile_absent=reconcile_absent):
        prior_snapshots = capture_hub_snapshots(hub_store, tenant_id, source=source)

    # ``present_canonical_ids`` for absent-reconciliation (and the delta
    # ``resolved_ids`` derived from it) is pure Python — computed before the
    # write so the atomic seam can run the reconcile inside the same transaction.
    present: set[str] = collect_present_canonical_ids(payloads, source=source) if reconcile_absent else set()

    atomic = getattr(hub_store, "ingest_batch_atomic", None)
    if callable(atomic):
        # Ledger append + current upsert (+ reconcile) commit in ONE transaction
        # so a mid-batch failure rolls back BOTH — the ledger can no longer
        # inflate while findings stay invisible (wave-2 residual #1).
        new_total, reconciled = atomic(
            tenant_id,
            payloads,
            observed_at=observed_at,
            batch_id=batch_id,
            source=source,
            reconcile_absent=reconcile_absent,
            present_canonical_ids=present,
        )
    else:
        new_total = hub_store.add(tenant_id, payloads)
        hub_store.upsert_current_batch(
            tenant_id,
            payloads,
            observed_at=observed_at,
            batch_id=batch_id,
            source=source,
        )
        reconciled = 0
        if reconcile_absent:
            reconciled = hub_store.reconcile_current_absent(
                tenant_id,
                present_canonical_ids=present,
                observed_at=observed_at,
                scope_source=source,
            )
    resolved_ids: set[str] = resolved_canonical_ids(prior_snapshots, present) if reconcile_absent else set()
    delta_results = emit_hub_finding_deltas_if_enabled(
        tenant_id=tenant_id,
        hub_store=hub_store,
        prior=prior_snapshots,
        batch_findings=payloads,
        resolved_canonical_ids=resolved_ids,
        observed_at=observed_at,
        batch_id=batch_id,
        source=source,
    )
    return {
        "new_total": new_total,
        "reconciled": reconciled,
        "delta_results": delta_results,
    }
