"""Cryptographic binding for persisted graph-correlation source receipts."""

from __future__ import annotations

from copy import deepcopy

import pytest

from agent_bom.graph.correlation_receipts import (
    CorrelationReceiptError,
    sign_correlation_receipt,
    verify_correlation_receipt,
)

KEY = b"correlation-receipt-test-key-material-32-bytes"
RECEIPT = {
    "scan_id": "image-sbom-1",
    "created_at": "2026-09-03T01:00:00+00:00",
    "digest": "sha256:" + "a" * 64,
    "node_count": 3,
    "edge_count": 2,
    "source_kinds": ["cyclonedx_sbom", "bundled_advisory_scanner"],
    "freshness": "fresh",
    "age_hours": 1.25,
}


def _signed() -> dict[str, object]:
    return sign_correlation_receipt(
        RECEIPT,
        signing_key=KEY,
        key_id="lab-v1",
        tenant_id="tenant-a",
        correlation_id="corr-1",
        correlation_created_at="2026-09-03T02:15:00+00:00",
        max_age_hours=168,
        allow_stale=False,
    )


def test_receipt_signature_is_persistable_and_verifiable() -> None:
    signed = _signed()

    assert signed["signature"] == {
        "schema_version": "agent-bom.correlation-receipt-signature/v1",
        "algorithm": "hmac-sha256",
        "key_id": "lab-v1",
        "value": signed["signature"]["value"],
    }
    assert str(signed["signature"]["value"]).startswith("sha256:")
    assert verify_correlation_receipt(
        signed,
        signing_key=KEY,
        tenant_id="tenant-a",
        correlation_id="corr-1",
        correlation_created_at="2026-09-03T02:15:00+00:00",
        max_age_hours=168,
        allow_stale=False,
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("scan_id", "other-scan"),
        ("digest", "sha256:" + "b" * 64),
        ("node_count", 4),
        ("freshness", "stale_allowed"),
    ],
)
def test_receipt_signature_rejects_tampering(field: str, value: object) -> None:
    signed = deepcopy(_signed())
    signed[field] = value

    assert not verify_correlation_receipt(
        signed,
        signing_key=KEY,
        tenant_id="tenant-a",
        correlation_id="corr-1",
        correlation_created_at="2026-09-03T02:15:00+00:00",
        max_age_hours=168,
        allow_stale=False,
    )


@pytest.mark.parametrize(
    ("tenant_id", "correlation_id"),
    [("tenant-b", "corr-1"), ("tenant-a", "corr-2")],
)
def test_receipt_signature_rejects_cross_tenant_and_cross_run_replay(tenant_id: str, correlation_id: str) -> None:
    assert not verify_correlation_receipt(
        _signed(),
        signing_key=KEY,
        tenant_id=tenant_id,
        correlation_id=correlation_id,
        correlation_created_at="2026-09-03T02:15:00+00:00",
        max_age_hours=168,
        allow_stale=False,
    )


def test_receipt_signing_rejects_short_keys() -> None:
    with pytest.raises(CorrelationReceiptError, match="invalid_signing_key"):
        sign_correlation_receipt(
            RECEIPT,
            signing_key=b"short",
            key_id="lab-v1",
            tenant_id="tenant-a",
            correlation_id="corr-1",
            correlation_created_at="2026-09-03T02:15:00+00:00",
            max_age_hours=168,
            allow_stale=False,
        )


def test_receipt_signature_rejects_key_id_tampering() -> None:
    signed = deepcopy(_signed())
    assert isinstance(signed["signature"], dict)
    signed["signature"]["key_id"] = "attacker-key"

    assert not verify_correlation_receipt(
        signed,
        signing_key=KEY,
        tenant_id="tenant-a",
        correlation_id="corr-1",
        correlation_created_at="2026-09-03T02:15:00+00:00",
        max_age_hours=168,
        allow_stale=False,
    )
