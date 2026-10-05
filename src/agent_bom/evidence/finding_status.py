"""Public lifecycle and suppression receipts without exception free text."""

from collections.abc import Mapping
from typing import Any

_STATUSES = frozenset({"open", "reopened", "resolved", "suppressed", "accepted", "not_affected", "fixed"})


def public_finding_status(row: Mapping[str, Any]) -> dict[str, Any]:
    from agent_bom.security import sanitize_text

    payload: dict[str, Any] = {}
    lifecycle = str(row.get("lifecycle_status") or row.get("status") or "").strip().lower()
    if lifecycle in _STATUSES:
        payload.update(status=lifecycle, lifecycle_status=lifecycle)
    suppressed = row.get("suppressed")
    if isinstance(suppressed, bool):
        payload["suppressed"] = suppressed
        receipt = row.get("suppression_id")
        payload["suppression_id"] = (
            sanitize_text(receipt.strip(), max_len=128) if suppressed and isinstance(receipt, str) and receipt.strip() else None
        )
        if suppressed and lifecycle in {"", "open", "reopened", "suppressed"}:
            payload["status"] = "suppressed"
    if isinstance(row.get("actionable"), bool):
        payload["actionable"] = row["actionable"]
    return payload
