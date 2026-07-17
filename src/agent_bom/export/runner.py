"""Streaming findings export runner (#4040).

Streams a tenant's current findings from the compliance hub via the same keyset
cursor the async report export uses (``list_current_page``) — bounded, never
materializing the whole result set — and hands the row stream to a destination
adapter. Read-only on the source; audit-logged; tenant-scoped.
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import Iterable, Iterator
from typing import Any

from agent_bom.export.destinations import ExportDestination, ExportPublicationIndeterminateError, ExportResult, build_destination

logger = logging.getLogger(__name__)

# Page size for the keyset cursor. Matches the async report worker so the read
# path stays bounded and sargable at scale.
_PAGE_SIZE = 500


def iter_current_findings(
    tenant_id: str,
    *,
    sort: str = "effective_reach",
    severity: str | None = None,
    since: str | None = None,
    page_size: int = _PAGE_SIZE,
    hub: Any | None = None,
) -> Iterator[dict[str, Any]]:
    """Yield current findings for ``tenant_id`` one row at a time (bounded).

    Pages ``hub.list_current_page`` with a keyset cursor so memory stays flat
    regardless of finding count. Tenant scope is enforced by passing
    ``tenant_id`` into the store query (never a client-supplied filter).
    """
    if hub is None:
        from agent_bom.api.compliance_hub_store import get_compliance_hub_store

        hub = get_compliance_hub_store()
    list_page = getattr(hub, "list_current_page", None)
    if not callable(list_page):
        raise RuntimeError("Compliance hub store does not support current-state finding exports")

    cursor: str | None = None
    first = True
    while True:
        page, _total, next_cursor = list_page(
            tenant_id,
            limit=page_size,
            sort=sort,
            severity=severity,
            since=since,
            include_total=first,
            cursor=cursor,
        )
        yield from page
        if not next_cursor:
            break
        cursor = next_cursor
        first = False


def run_findings_export(
    *,
    tenant_id: str,
    kind: str,
    config: dict[str, Any],
    secret: str | None = None,
    destination_id: str = "",
    sort: str = "effective_reach",
    severity: str | None = None,
    since: str | None = None,
    run_id: str | None = None,
    actor: str = "scheduler",
    destination: ExportDestination | None = None,
    findings: Iterable[dict[str, Any]] | None = None,
    hub: Any | None = None,
) -> ExportResult:
    """Stream a tenant's findings to a configured destination and audit the run.

    The destination is built from the connect-once connection (``kind`` +
    ``config`` + decrypted ``secret``) unless one is injected. ``findings``
    defaults to the live keyset stream; both keep memory bounded. Emits a
    ``export.run`` audit entry on success or failure and never leaks the secret.
    """
    resolved_run_id = run_id or secrets.token_hex(16)
    dest = destination if destination is not None else build_destination(kind, config, secret)
    rows: Iterable[dict[str, Any]]
    if findings is not None:
        rows = findings
    else:
        rows = iter_current_findings(tenant_id, sort=sort, severity=severity, since=since, hub=hub)

    try:
        result = dest.write_findings(rows, tenant_id=tenant_id, run_id=resolved_run_id)
    except ExportPublicationIndeterminateError:
        _audit(
            actor,
            tenant_id,
            destination_id=destination_id,
            kind=kind,
            run_id=resolved_run_id,
            outcome="indeterminate",
        )
        raise
    except Exception:
        _audit(
            actor,
            tenant_id,
            destination_id=destination_id,
            kind=kind,
            run_id=resolved_run_id,
            outcome="failure",
        )
        raise

    _audit(
        actor,
        tenant_id,
        destination_id=destination_id,
        kind=result.kind,
        run_id=resolved_run_id,
        outcome="success",
        row_count=result.row_count,
        destination_uri=result.destination_uri,
    )
    return result


def _audit(actor: str, tenant_id: str, **details: Any) -> None:
    """Best-effort audit log for an export run (never raises, never leaks secrets)."""
    try:
        from agent_bom.api.audit_log import log_action

        log_action("export.run", actor=actor, tenant_id=tenant_id, details=details)
    except Exception:  # noqa: BLE001 - audit must never break the export path
        logger.debug("export.run audit log skipped", exc_info=True)
