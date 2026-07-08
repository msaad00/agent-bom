"""Test chain-hashed audit log tamper detection."""

from agent_bom.api.audit_log import AuditEntry, InMemoryAuditLog, SQLiteAuditLog


def test_chain_hash_integrity():
    log = InMemoryAuditLog()
    log.append(AuditEntry(action="scan", actor="test", resource="pkg-a"))
    log.append(AuditEntry(action="scan", actor="test", resource="pkg-b"))
    log.append(AuditEntry(action="scan", actor="test", resource="pkg-c"))
    verified, tampered = log.verify_integrity()
    assert verified == 3
    assert tampered == 0


def test_chain_hash_detects_tamper():
    log = InMemoryAuditLog()
    log.append(AuditEntry(action="scan", actor="test", resource="pkg-a"))
    log.append(AuditEntry(action="scan", actor="test", resource="pkg-b"))
    # Tamper with first entry — change the resource after signing
    log._entries[0].resource = "tampered"
    verified, tampered = log.verify_integrity()
    assert tampered > 0


def test_chain_hash_detects_details_tamper():
    log = InMemoryAuditLog()
    log.append(AuditEntry(action="scan", actor="test", resource="pkg-a", details={"tenant_id": "tenant-alpha", "severity": "high"}))
    log.append(AuditEntry(action="scan", actor="test", resource="pkg-b", details={"tenant_id": "tenant-alpha"}))

    log._entries[0].details["severity"] = "critical"

    verified, tampered = log.verify_integrity()
    assert tampered > 0


def test_chain_hash_detects_leading_truncation():
    """Lazy deletion of oldest entries without re-signing must fail verification."""
    log = InMemoryAuditLog()
    log.append(AuditEntry(action="scan", actor="test", resource="pkg-a"))
    log.append(AuditEntry(action="scan", actor="test", resource="pkg-b"))
    log.append(AuditEntry(action="scan", actor="test", resource="pkg-c"))
    log._entries.pop(0)
    verified, tampered = log.verify_integrity()
    assert verified == 1
    assert tampered == 2


def test_chain_hash_head_deletion_detected_with_checkpoint():
    """Deleting newest entries without updating the checkpoint must fail verification."""
    log = InMemoryAuditLog()
    for i in range(3):
        log.append(AuditEntry(action="scan", actor="test", resource=f"pkg-{i}"))
    log._entries.pop()
    verified, tampered = log.verify_integrity()
    assert verified == 2
    assert tampered == 1


def test_sqlite_audit_hydrates_last_signature_after_restart(tmp_path):
    db = str(tmp_path / "audit.db")
    first = SQLiteAuditLog(db)
    first.append(AuditEntry(action="scan", actor="alice", resource="pkg-a", details={"tenant_id": "tenant-alpha"}))
    first_sig = first._last_sig_by_tenant["tenant-alpha"]

    restarted = SQLiteAuditLog(db)
    assert restarted._last_sig_by_tenant["tenant-alpha"] == first_sig
    restarted.append(AuditEntry(action="scan", actor="alice", resource="pkg-b", details={"tenant_id": "tenant-alpha"}))

    entries = list(reversed(restarted.list_entries(limit=10, tenant_id="tenant-alpha")))
    assert entries[1].prev_signature == entries[0].hmac_signature
