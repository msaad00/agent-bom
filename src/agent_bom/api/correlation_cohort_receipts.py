"""Signed assignments for push-driven members of an immutable correlation cohort."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Mapping

from agent_bom.api.audit_log import sign_export_payload, verify_export_payload

if TYPE_CHECKING:
    from agent_bom.api.models import CorrelationCohortChildReceipt, ScanJob

_SCHEMA_VERSION = "agent-bom.correlation-cohort-child/v1"


class CorrelationCohortReceiptError(RuntimeError):
    """A bounded cohort-assignment validation failure."""


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise CorrelationCohortReceiptError("invalid_receipt") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _canonical_payload(receipt: Mapping[str, Any]) -> bytes:
    payload = {key: value for key, value in receipt.items() if key != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def issue_correlation_cohort_child_receipt(
    *,
    parent: ScanJob,
    child: ScanJob,
    source_kind: str,
) -> CorrelationCohortChildReceipt:
    """Issue one inspectable HMAC receipt bound to the exact reserved child."""

    from agent_bom.api.models import CorrelationCohortChildReceipt

    cohort_id = parent.correlation_cohort_id or ""
    manifest_hash = parent.correlation_cohort_manifest_hash or ""
    max_age_hours = int(parent.correlation_max_age_hours or 0)
    if (
        not cohort_id
        or len(manifest_hash) != 64
        or not max_age_hours
        or child.parent_job_id != parent.job_id
        or child.job_id not in parent.child_job_ids
        or child.correlation_cohort_id != cohort_id
        or child.correlation_cohort_manifest_hash != manifest_hash
        or child.correlation_max_age_hours != max_age_hours
        or not child.source_id
    ):
        raise CorrelationCohortReceiptError("invalid_cohort_state")
    issued_at = _parse_timestamp(child.created_at)
    unsigned: dict[str, Any] = {
        "schema_version": _SCHEMA_VERSION,
        "tenant_id": parent.tenant_id,
        "correlation_cohort_id": cohort_id,
        "cohort_manifest_hash": manifest_hash,
        "parent_job_id": parent.job_id,
        "child_job_id": child.job_id,
        "source_id": child.source_id,
        "source_kind": source_kind,
        "max_age_hours": max_age_hours,
        "issued_at": issued_at.isoformat(),
        "expires_at": (issued_at + timedelta(hours=max_age_hours)).isoformat(),
    }
    unsigned["signature"] = f"sha256:{sign_export_payload(_canonical_payload(unsigned))}"
    return CorrelationCohortChildReceipt.model_validate(unsigned)


def verify_correlation_cohort_child_receipt(
    receipt: CorrelationCohortChildReceipt,
    *,
    tenant_id: str,
    correlation_cohort_id: str,
    source_id: str,
    allowed_source_kinds: set[str],
    at: datetime | None = None,
) -> None:
    """Fail closed when a signed child assignment is stale or mismatched."""

    payload = receipt.model_dump(mode="json")
    supplied = str(payload.pop("signature", ""))
    if not supplied.startswith("sha256:") or not verify_export_payload(_canonical_payload(payload), supplied[7:]):
        raise CorrelationCohortReceiptError("invalid_receipt")
    now = (at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    issued_at = _parse_timestamp(receipt.issued_at)
    expires_at = _parse_timestamp(receipt.expires_at)
    expected_expiry = issued_at + timedelta(hours=receipt.max_age_hours)
    if expires_at != expected_expiry or now >= expires_at:
        raise CorrelationCohortReceiptError("expired_receipt")
    if (
        receipt.schema_version != _SCHEMA_VERSION
        or receipt.tenant_id != tenant_id
        or receipt.correlation_cohort_id != correlation_cohort_id
        or receipt.source_id != source_id
        or receipt.source_kind not in allowed_source_kinds
    ):
        raise CorrelationCohortReceiptError("invalid_receipt")


__all__ = [
    "CorrelationCohortReceiptError",
    "issue_correlation_cohort_child_receipt",
    "verify_correlation_cohort_child_receipt",
]
