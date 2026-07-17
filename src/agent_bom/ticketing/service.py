"""Connect-once ticketing service — file a ticket / sync status through a stored
connection, never a per-action credential.

The public entry points take a finding/issue reference + a target project only.
Auth and the base URL are resolved **exclusively** from the stored, encrypted,
tenant-scoped connection (sealed with the shared ``connection_crypto`` key). A
call with no stored connection fails with a "connect …first" error — never a
credential prompt.

Idempotency is a claim-first dedupe on ``(tenant_id, connection_id, dedupe_key)``:
the first caller claims the ledger row and files the ticket; a concurrent or
repeat caller for the same finding gets the same ticket back and no second ticket
is ever created (cross-process safe via the store's unique constraint).
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Any

from agent_bom.security import sanitize_error, sanitize_text
from agent_bom.ticketing.connection_store import TicketingStore, TicketLink, get_ticketing_store
from agent_bom.ticketing.factory import build_transport
from agent_bom.ticketing.models import (
    PROVIDER_JIRA,
    TicketDraft,
    TicketingConnectionRecord,
    TicketRef,
    TicketStatus,
)
from agent_bom.ticketing.transport import TicketingTransportError

logger = logging.getLogger(__name__)

_McpCaller = Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]


class TicketingError(RuntimeError):
    """A ticketing action failed. ``code`` classifies it for the API layer."""

    def __init__(self, message: str, *, code: str = "error") -> None:
        super().__init__(message)
        self.code = code


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resolve_connection(store: TicketingStore, tenant_id: str, connection_id: str) -> TicketingConnectionRecord:
    """Resolve the connection to act through, else guide the user to connect.

    Never prompts for a credential: if no connection exists for the tenant (or the
    named one is missing), it raises a "connect first" error.
    """
    if connection_id:
        record = store.get_connection(tenant_id, connection_id)
        if record is None:
            raise TicketingError(
                "No ticketing connection is configured. Connect Jira (or another ITSM) once in the "
                "Connections hub, then file tickets through it — no credential is entered per action.",
                code="no_connection",
            )
        return record
    # No explicit id: use the tenant's single connection if unambiguous.
    connections = store.list_connections(tenant_id)
    if not connections:
        raise TicketingError(
            "No ticketing connection is configured. Connect Jira (or another ITSM) once in the Connections hub first.",
            code="no_connection",
        )
    if len(connections) > 1:
        raise TicketingError(
            "Multiple ticketing connections are configured; specify which connection to use.",
            code="ambiguous_connection",
        )
    return connections[0]


def _resolve_project(record: TicketingConnectionRecord, project: str) -> str:
    resolved = (project or "").strip() or str(record.auth_params.get("default_project") or "").strip()
    if not resolved and record.provider == PROVIDER_JIRA:
        raise TicketingError(
            "A target Jira project is required. Pass it, or set a default project on the connection.",
            code="missing_project",
        )
    return resolved


def _decrypt(record: TicketingConnectionRecord) -> str:
    from agent_bom.api.connection_crypto import ConnectionSecretError, decrypt_secret

    if not record.secret_encrypted:
        return ""
    try:
        return decrypt_secret(record.secret_encrypted)
    except ConnectionSecretError as exc:
        raise TicketingError(
            "The ticketing connection secret could not be accessed. Reconnect the ITSM connection.",
            code="secret_unavailable",
        ) from exc


async def create_ticket_for_finding(
    *,
    tenant_id: str,
    connection_id: str = "",
    finding: dict[str, Any],
    project: str = "",
    finding_id: str = "",
    issue_type: str = "",
    source_url: str = "",
    actor: str = "system",
    store: TicketingStore | None = None,
    mcp_caller: _McpCaller | None = None,
    rest_client_factory: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """File a ticket for ``finding`` through the stored connection (idempotent)."""
    store = store or get_ticketing_store()
    record = _resolve_connection(store, tenant_id, connection_id)
    target_project = _resolve_project(record, project)
    draft = TicketDraft.from_finding(finding, project=target_project, finding_id=finding_id, issue_type=issue_type, source_url=source_url)
    if not draft.finding_id:
        raise TicketingError(
            "A finding id is required so a repeat request does not create a duplicate ticket.",
            code="missing_finding_id",
        )

    now = _now()
    claim = TicketLink(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        connection_id=record.id,
        dedupe_key=draft.finding_id,
        provider=record.provider,
        status="pending",
        created_at=now,
        updated_at=now,
    )
    won, link = store.claim_ticket_link(claim)
    if not won:
        # Idempotent: a ticket already exists for this finding on this connection.
        return _result(link, record, deduplicated=True)

    secret = _decrypt(record)
    try:
        transport = build_transport(record, secret, mcp_caller=mcp_caller, rest_client_factory=rest_client_factory)
        ref = await transport.create_ticket(draft)
    except Exception as exc:  # noqa: BLE001 - roll back the claim so a retry can re-file
        store.delete_ticket_link(tenant_id, claim.id)
        _audit("ticketing.create", actor=actor, tenant_id=tenant_id, connection=record, outcome="failure")
        logger.warning("Ticketing create failed for connection %s", record.id)
        raise TicketingError(_safe_detail(exc), code="transport_error") from exc
    finally:
        secret = ""  # drop the plaintext reference

    link.external_id = ref.external_id
    link.key = ref.key
    link.url = ref.url
    link.status = ref.status.value
    link.updated_at = _now()
    store.update_ticket_link(link)
    _audit(
        "ticketing.create",
        actor=actor,
        tenant_id=tenant_id,
        connection=record,
        outcome="success",
        ticket_key=ref.key or ref.external_id,
    )
    return _result(link, record, deduplicated=False)


async def sync_ticket_status(
    *,
    tenant_id: str,
    ticket_id: str,
    actor: str = "system",
    store: TicketingStore | None = None,
    mcp_caller: _McpCaller | None = None,
    rest_client_factory: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Read the current status of a filed ticket and persist it on the link."""
    store = store or get_ticketing_store()
    link = store.get_ticket_link(tenant_id, ticket_id)
    if link is None:
        raise TicketingError(f"Ticket '{ticket_id}' not found for this tenant.", code="not_found")
    record = store.get_connection(tenant_id, link.connection_id)
    if record is None:
        raise TicketingError(
            "The ticketing connection for this ticket was revoked; reconnect the ITSM connection.",
            code="no_connection",
        )
    secret = _decrypt(record)
    try:
        transport = build_transport(record, secret, mcp_caller=mcp_caller, rest_client_factory=rest_client_factory)
        ref = TicketRef(
            provider=record.provider,
            external_id=link.external_id,
            key=link.key,
            url=link.url,
            status=_coerce_status(link.status),
        )
        status = await transport.get_status(ref)
    except Exception as exc:  # noqa: BLE001
        _audit("ticketing.sync", actor=actor, tenant_id=tenant_id, connection=record, outcome="failure")
        logger.warning("Ticketing status sync failed for ticket %s", sanitize_text(ticket_id, max_len=200))
        raise TicketingError(_safe_detail(exc), code="transport_error") from exc
    finally:
        secret = ""

    link.status = status.value
    link.updated_at = _now()
    store.update_ticket_link(link)
    _audit("ticketing.sync", actor=actor, tenant_id=tenant_id, connection=record, outcome="success", ticket_key=link.key)
    return _result(link, record, deduplicated=False)


def _coerce_status(value: str) -> TicketStatus:
    try:
        return TicketStatus(value)
    except ValueError:
        return TicketStatus.UNKNOWN


def _result(link: TicketLink, record: TicketingConnectionRecord, *, deduplicated: bool) -> dict[str, Any]:
    return {
        "schema_version": "ticketing.ticket.v1",
        "ticket": link.to_public_dict(),
        "connection_id": record.id,
        "provider": record.provider,
        "transport": record.transport,
        "deduplicated": deduplicated,
        "audit_metadata": {
            "connect_once": True,
            "per_action_credential": False,
            "note": "Filed through a stored, scoped, encrypted connection; no credential was entered for this action.",
        },
    }


def _safe_detail(exc: Exception) -> str:
    if isinstance(exc, TicketingTransportError):
        return sanitize_error(exc, generic=False)
    return sanitize_error(exc, generic=True)


def _audit(
    action: str,
    *,
    actor: str,
    tenant_id: str,
    connection: TicketingConnectionRecord,
    outcome: str,
    ticket_key: str = "",
) -> None:
    try:
        from agent_bom.api.audit_log import log_action

        log_action(
            action,
            actor=actor or "system",
            resource=f"ticketing-connection/{connection.id}",
            tenant_id=tenant_id,
            provider=connection.provider,
            transport=connection.transport,
            outcome=outcome,
            ticket_key=ticket_key,
        )
    except Exception:  # noqa: BLE001 - audit must never break the action
        logger.debug("ticketing audit log failed for %s", action, exc_info=True)
