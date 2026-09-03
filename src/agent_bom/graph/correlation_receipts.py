"""Persisted, tenant-bound signatures for graph-correlation source receipts."""

from __future__ import annotations

import hashlib
import hmac
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

_SCHEMA = "agent-bom.correlation-receipt-signature/v1"
_ALGORITHM = "hmac-sha256"
_MIN_KEY_BYTES = 32
_MAX_KEY_BYTES = 4096


class CorrelationReceiptError(RuntimeError):
    """Machine-readable correlation receipt signing failure."""


def _validated_key(signing_key: bytes) -> bytes:
    key = signing_key.strip()
    if not _MIN_KEY_BYTES <= len(key) <= _MAX_KEY_BYTES:
        raise CorrelationReceiptError("invalid_signing_key")
    return key


def _payload(
    receipt: Mapping[str, Any],
    *,
    tenant_id: str,
    correlation_id: str,
    correlation_created_at: str,
    max_age_hours: int,
    allow_stale: bool,
) -> dict[str, Any]:
    return {
        "schema_version": "agent-bom.correlation-receipt/v1",
        "tenant_id": tenant_id,
        "correlation_id": correlation_id,
        "correlation_created_at": correlation_created_at,
        "freshness_policy": {
            "max_age_hours": int(max_age_hours),
            "allow_stale": bool(allow_stale),
        },
        "source_snapshot": {
            "scan_id": str(receipt.get("scan_id") or ""),
            "created_at": str(receipt.get("created_at") or ""),
            "digest": str(receipt.get("digest") or ""),
            "node_count": int(receipt.get("node_count") or 0),
            "edge_count": int(receipt.get("edge_count") or 0),
            "source_kinds": sorted(str(item) for item in receipt.get("source_kinds") or []),
            "freshness": str(receipt.get("freshness") or ""),
            "age_hours": float(receipt.get("age_hours") or 0.0),
        },
    }


def _canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_correlation_receipt(
    receipt: Mapping[str, Any],
    *,
    signing_key: bytes,
    key_id: str,
    tenant_id: str,
    correlation_id: str,
    correlation_created_at: str,
    max_age_hours: int,
    allow_stale: bool,
) -> dict[str, Any]:
    """Return a receipt with an HMAC envelope bound to its run and tenant."""

    key = _validated_key(signing_key)
    signed = deepcopy(dict(receipt))
    signed.pop("signature", None)
    digest = hmac.new(
        key,
        _canonical_bytes(
            _payload(
                signed,
                tenant_id=tenant_id,
                correlation_id=correlation_id,
                correlation_created_at=correlation_created_at,
                max_age_hours=max_age_hours,
                allow_stale=allow_stale,
            )
        ),
        hashlib.sha256,
    ).hexdigest()
    signed["signature"] = {
        "schema_version": _SCHEMA,
        "algorithm": _ALGORITHM,
        "key_id": key_id.strip(),
        "value": f"sha256:{digest}",
    }
    return signed


def verify_correlation_receipt(
    receipt: Mapping[str, Any],
    *,
    signing_key: bytes,
    tenant_id: str,
    correlation_id: str,
    correlation_created_at: str,
    max_age_hours: int,
    allow_stale: bool,
) -> bool:
    """Verify a receipt without leaking signature or key material in errors."""

    signature = receipt.get("signature")
    if not isinstance(signature, Mapping):
        return False
    if signature.get("schema_version") != _SCHEMA or signature.get("algorithm") != _ALGORITHM:
        return False
    supplied = str(signature.get("value") or "")
    if not supplied.startswith("sha256:") or len(supplied) != 71:
        return False
    try:
        expected = sign_correlation_receipt(
            receipt,
            signing_key=signing_key,
            key_id=str(signature.get("key_id") or ""),
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            correlation_created_at=correlation_created_at,
            max_age_hours=max_age_hours,
            allow_stale=allow_stale,
        )
    except CorrelationReceiptError:
        return False
    expected_signature = expected.get("signature")
    return isinstance(expected_signature, Mapping) and hmac.compare_digest(
        supplied,
        str(expected_signature.get("value") or ""),
    )


def _receipt_verification(
    receipt: Mapping[str, Any],
    *,
    signing_key: bytes | None,
    tenant_id: str,
    correlation_id: str,
    correlation_created_at: str,
    max_age_hours: int,
    allow_stale: bool,
) -> str:
    if not isinstance(receipt.get("signature"), Mapping):
        return "legacy_hash_bound"
    if signing_key is None:
        return "verification_key_unavailable"
    return (
        "verified"
        if verify_correlation_receipt(
            receipt,
            signing_key=signing_key,
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            correlation_created_at=correlation_created_at,
            max_age_hours=max_age_hours,
            allow_stale=allow_stale,
        )
        else "invalid"
    )


def correlation_run_receipt_payload(run: Mapping[str, Any], *, signing_key: bytes | None) -> dict[str, Any]:
    """Decorate a stored run with server-computed receipt verification state."""

    payload = deepcopy(dict(run))
    context = {
        "signing_key": signing_key,
        "tenant_id": str(payload.get("tenant_id") or ""),
        "correlation_id": str(payload.get("correlation_id") or ""),
        "correlation_created_at": str(payload.get("created_at") or ""),
        "max_age_hours": int(payload.get("max_age_hours") or 0),
        "allow_stale": bool(payload.get("allow_stale", False)),
    }

    receipts: list[dict[str, Any]] = []
    for item in payload.get("input_manifest") or []:
        if not isinstance(item, Mapping):
            continue
        receipt = deepcopy(dict(item))
        receipt["verification"] = _receipt_verification(receipt, **context)
        receipts.append(receipt)
    payload["input_manifest"] = receipts

    result_manifest = payload.get("result_manifest")
    if isinstance(result_manifest, Mapping):
        result_copy = deepcopy(dict(result_manifest))
        execution_receipts: list[dict[str, Any]] = []
        for item in result_copy.get("input_snapshots") or []:
            if not isinstance(item, Mapping):
                continue
            receipt = deepcopy(dict(item))
            receipt["verification"] = _receipt_verification(receipt, **context)
            execution_receipts.append(receipt)
        if "input_snapshots" in result_copy:
            result_copy["input_snapshots"] = execution_receipts
        payload["result_manifest"] = result_copy

    statuses = [str(item["verification"]) for item in receipts]
    counts = {
        "verified": statuses.count("verified"),
        "legacy_hash_bound": statuses.count("legacy_hash_bound"),
        "invalid": statuses.count("invalid"),
        "verification_key_unavailable": statuses.count("verification_key_unavailable"),
        "total": len(statuses),
    }
    present = [name for name in counts if name != "total" and counts[name]]
    status = present[0] if len(present) == 1 else "mixed" if present else "none"
    payload["receipt_verification"] = {"status": status, **counts}
    return payload


def configured_receipt_signing_key() -> bytes | None:
    """Resolve the runtime-facts key used to bind correlation receipts."""

    from agent_bom import config as agent_config

    key_file = agent_config.RUNTIME_FACTS_HMAC_KEY_FILE.strip()
    raw = b""
    if key_file:
        try:
            raw = Path(key_file).expanduser().read_bytes()[: _MAX_KEY_BYTES + 1]
        except OSError as exc:
            raise CorrelationReceiptError("signing_key_unavailable") from exc
        if len(raw) > _MAX_KEY_BYTES:
            raise CorrelationReceiptError("invalid_signing_key")
        raw = raw.strip()
    if not raw:
        raw = agent_config.RUNTIME_FACTS_HMAC_KEY.encode("utf-8").strip()
    return _validated_key(raw) if raw else None


__all__ = [
    "CorrelationReceiptError",
    "correlation_run_receipt_payload",
    "configured_receipt_signing_key",
    "sign_correlation_receipt",
    "verify_correlation_receipt",
]
