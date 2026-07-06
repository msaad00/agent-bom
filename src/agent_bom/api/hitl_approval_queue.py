"""Build HITL approval queue items from blocked runtime spans."""

from __future__ import annotations

from typing import Any, Mapping

from agent_bom.api.hitl_approval_store import (
    HitlApprovalRecord,
    HitlApprovalStore,
    HitlDecisionStatus,
    hitl_item_id,
)


def _finding_ids(span: Mapping[str, Any]) -> list[str]:
    ids: list[str] = []
    for row in span.get("linked_findings") or []:
        if not isinstance(row, Mapping):
            continue
        fid = str(row.get("finding_id") or row.get("vulnerability_id") or "").strip()
        if fid:
            ids.append(fid)
    return ids


def build_hitl_queue_items(
    *,
    tenant_id: str,
    trace_payload: Mapping[str, Any],
    store: HitlApprovalStore,
    status_filter: str | None = None,
) -> list[dict[str, Any]]:
    """Merge blocked spans with persisted approval decisions."""
    decisions = {row.item_id: row for row in store.list_for_tenant(tenant_id)}
    items: list[dict[str, Any]] = []

    for session in trace_payload.get("sessions") or []:
        if not isinstance(session, Mapping):
            continue
        session_id = str(session.get("session_id") or "")
        for span in session.get("spans") or []:
            if not isinstance(span, Mapping):
                continue
            if str(span.get("verdict") or "") != "blocked":
                continue
            span_id = str(span.get("span_id") or "")
            if not span_id:
                continue
            item_id = hitl_item_id(tenant_id=tenant_id, span_id=span_id)
            existing = decisions.get(item_id)
            status = existing.status.value if existing else HitlDecisionStatus.PENDING.value
            if status_filter and status != status_filter:
                continue
            items.append(
                {
                    "item_id": item_id,
                    "tenant_id": tenant_id,
                    "span_id": span_id,
                    "session_id": session_id,
                    "agent": str(span.get("agent") or ""),
                    "tool": str(span.get("tool") or ""),
                    "timestamp": span.get("timestamp"),
                    "detail": str((existing.detail if existing else span.get("detail")) or ""),
                    "source": span.get("source"),
                    "status": status,
                    "linked_findings": span.get("linked_findings") or [],
                    "linked_finding_ids": existing.linked_finding_ids if existing else _finding_ids(span),
                    "compliance_controls": span.get("compliance_controls") or [],
                    "decided_by": existing.decided_by if existing else "",
                    "decided_at": existing.decided_at if existing else "",
                    "note": existing.note if existing else "",
                }
            )

    items.sort(key=lambda row: str(row.get("timestamp") or ""), reverse=True)
    return items


def apply_hitl_decision(
    *,
    tenant_id: str,
    item_id: str,
    decision: str,
    actor: str,
    note: str,
    queue_item: Mapping[str, Any],
    store: HitlApprovalStore,
) -> HitlApprovalRecord:
    normalized = decision.strip().lower()
    if normalized not in {"approve", "deny"}:
        raise ValueError("decision must be approve or deny")
    status = HitlDecisionStatus.APPROVED if normalized == "approve" else HitlDecisionStatus.DENIED
    from datetime import datetime, timezone

    record = HitlApprovalRecord(
        item_id=item_id,
        tenant_id=tenant_id,
        span_id=str(queue_item.get("span_id") or ""),
        session_id=str(queue_item.get("session_id") or ""),
        agent=str(queue_item.get("agent") or ""),
        tool=str(queue_item.get("tool") or ""),
        status=status,
        detail=str(queue_item.get("detail") or ""),
        linked_finding_ids=[str(fid) for fid in (queue_item.get("linked_finding_ids") or []) if str(fid).strip()],
        compliance_controls=[str(tag) for tag in (queue_item.get("compliance_controls") or []) if str(tag).strip()],
        decided_by=actor,
        decided_at=datetime.now(timezone.utc).isoformat(),
        note=note.strip(),
    )
    store.upsert(record)
    return record
