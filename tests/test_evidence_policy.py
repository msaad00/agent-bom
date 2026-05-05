"""Tests for the two-bucket evidence redaction policy (issue #2261).

Coverage:

* Classification: every TIER_A whitelist entry classifies SAFE_TO_STORE,
  arbitrary unknown fields default to REPLAY_ONLY.
* Redaction (property test): a synthetic 30+ field payload routed through
  every persistence path emits zero TIER_B fields when the target tier is
  SAFE_TO_STORE.
* TTL: a TIER_B row with ``not_after`` in the past is deleted by the
  cleanup hook on both in-memory and SQLite stores.
* Capture-replay opt-in: with capture-replay disabled, no TIER_B field
  reaches the replay store.
* Tier badge helper: produces the three documented states.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from agent_bom.api.audit_log import (
    InMemoryAuditLog,
    log_action,
    set_audit_log,
)
from agent_bom.api.compliance_hub_store import (
    InMemoryComplianceHubStore,
    SQLiteComplianceHubStore,
)
from agent_bom.api.proxy_replay_store import (
    InMemoryProxyReplayStore,
    SQLiteProxyReplayStore,
    capture_replay_enabled,
    capture_tier_b,
    reset_proxy_replay_store,
    set_capture_replay,
    set_proxy_replay_store,
)
from agent_bom.evidence import (
    DEFAULT_REPLAY_TTL_DAYS,
    REPLAY_TTL_ENV,
    TIER_A_FIELDS,
    TIER_B_FIELDS,
    EvidenceTier,
    classify_field,
    has_tier_b_fields,
    redact_for_persistence,
    replay_not_after,
    replay_ttl_days,
    tier_badge,
)

# ─── Synthetic payload covering every documented evidence key ──────────────


SYNTHETIC_PAYLOAD: dict[str, object] = {
    # Tier A — safe to store
    "package_version": "1.2.3",
    "packages": 42,
    "lockfile_source": "package-lock.json",
    "tool_name": "fs.read",
    "tool": "fs.read",
    "scope": "fs:read",
    "command_name": "node",
    "hostname": "agent-prod-1",
    "env_var_name": "AWS_SECRET_ACCESS_KEY",
    "client_id": "client-a",
    "agent_id": "agent-7",
    "timestamp": "2026-05-03T12:00:00Z",
    "status_code": 200,
    "state": "accepted_risk",
    "lifecycle_state": "discovered",
    "batch_size": 2,
    "class_counts": {"2004": 1, "4001": 1},
    "source_ids": ["splunk", "datadog"],
    "trace_id": "0af7651916cd43dd8448eb211c80319c",
    "span_id": "b7ad6b7169203331",
    "request_id": "req-42",
    "tenant_id": "acme",
    "session_id": "sess-9",
    "ts": "2026-05-03T12:00:00Z",
    "policy": "allowed",
    "severity": "high",
    "ecosystem": "npm",
    "purl": "pkg:npm/foo@1.2.3",
    "framework": "iso27001",
    "control_id": "A.5.1",
    "cvss_score": 7.5,
    "epss_score": 0.04,
    "is_kev": False,
    "fixed_version": "1.2.4",
    "payload_sha256": "deadbeef",
    "rule_id": "RULE-1",
    "check_id": "CHECK-2",
    # Tier B — replay-only
    "prompt": "you are a helpful assistant",
    "raw_prompt": "system: ...",
    "tool_input": {"path": "/etc/passwd"},
    "tool_output": "root:x:0:0:root:/root:/bin/bash",
    "args": {"--key": "secret"},
    "command_args": ["--token", "abc"],
    "file_path": "/Users/me/secrets.txt",
    "url": "https://api.example.com/keys?token=abc",
    "request_body": '{"prompt":"..."}',
    "response_body": '{"completion":"hello"}',
    "user_workspace_content": "passwords.csv contents",
    "stdout": "long stdout dump",
    "stderr": "long stderr dump",
    # Unknown key — default tier B (conservative)
    "ad_hoc_random_key": "should not survive tier-A",
}


# Fields the issue body lists explicitly as tier-B + the obvious
# super-set that downstream tooling shovels into evidence rows.
EXPECTED_TIER_B_KEYS = {
    "prompt",
    "raw_prompt",
    "tool_input",
    "tool_output",
    "args",
    "command_args",
    "file_path",
    "url",
    "request_body",
    "response_body",
    "user_workspace_content",
    "stdout",
    "stderr",
    "ad_hoc_random_key",
}


# ─── Classification ────────────────────────────────────────────────────────


def test_classification_tier_a_whitelist():
    """Every documented tier-A field classifies SAFE_TO_STORE."""
    for field in TIER_A_FIELDS:
        assert classify_field(field) is EvidenceTier.SAFE_TO_STORE, field


def test_classification_unknown_defaults_to_tier_b():
    """Unknown / novel field names are conservatively REPLAY_ONLY."""
    assert classify_field("brand_new_evidence_key") is EvidenceTier.REPLAY_ONLY
    assert classify_field("user_pii_blob") is EvidenceTier.REPLAY_ONLY
    assert classify_field("") is EvidenceTier.REPLAY_ONLY


def test_free_text_and_raw_location_fields_are_replay_only():
    """Durable evidence must not become a secret/workspace-content store."""
    for field in (
        "description",
        "summary",
        "reason",
        "recommendation",
        "remediation",
        "result",
        "asset_name",
        "name",
        "lockfile_path",
        "endpoint",
    ):
        assert classify_field(field) is EvidenceTier.REPLAY_ONLY, field


def test_classification_documented_tier_b_set():
    """Every entry in the explicit TIER_B set classifies REPLAY_ONLY."""
    for field in TIER_B_FIELDS:
        assert classify_field(field) is EvidenceTier.REPLAY_ONLY, field


def test_classification_case_insensitive():
    assert classify_field("Tool_Name") is EvidenceTier.SAFE_TO_STORE
    assert classify_field("PROMPT") is EvidenceTier.REPLAY_ONLY


# ─── Redaction ─────────────────────────────────────────────────────────────


def test_redact_drops_all_tier_b_fields_for_safe_to_store():
    """The core property: tier-A redaction emits zero tier-B field names."""
    redacted = redact_for_persistence(SYNTHETIC_PAYLOAD, EvidenceTier.SAFE_TO_STORE)
    leaked = [k for k in redacted if classify_field(str(k)) is EvidenceTier.REPLAY_ONLY]
    assert not leaked, f"tier-B fields leaked into tier-A storage: {leaked}"

    # And every documented tier-B field is gone:
    for tb in EXPECTED_TIER_B_KEYS:
        assert tb not in redacted, f"{tb} should have been dropped"


def test_redact_preserves_tier_a_fields():
    redacted = redact_for_persistence(SYNTHETIC_PAYLOAD, EvidenceTier.SAFE_TO_STORE)
    for field in [
        "package_version",
        "packages",
        "tool_name",
        "agent_id",
        "tenant_id",
        "trace_id",
        "status_code",
        "state",
        "lifecycle_state",
        "batch_size",
        "class_counts",
        "source_ids",
        "policy",
    ]:
        assert field in redacted, field
    assert redacted["class_counts"] == {"2004": 1, "4001": 1}


def test_redact_for_replay_only_keeps_everything():
    redacted = redact_for_persistence(SYNTHETIC_PAYLOAD, EvidenceTier.REPLAY_ONLY)
    assert set(redacted) == set(SYNTHETIC_PAYLOAD)


def test_redact_recursion_into_lists_and_dicts():
    payload = {
        "tenant_id": "acme",
        "args": {"prompt": "x", "tool_name": "fs.read"},
        "events": [
            {"prompt": "secret", "agent_id": "a-1"},
            {"file_path": "/etc/passwd", "trace_id": "t-1"},
        ],
    }
    redacted = redact_for_persistence(payload, EvidenceTier.SAFE_TO_STORE)
    assert redacted == {"tenant_id": "acme"}


def test_redact_does_not_mutate_input():
    snapshot = json.dumps(SYNTHETIC_PAYLOAD, default=str, sort_keys=True)
    redact_for_persistence(SYNTHETIC_PAYLOAD, EvidenceTier.SAFE_TO_STORE)
    assert json.dumps(SYNTHETIC_PAYLOAD, default=str, sort_keys=True) == snapshot


# ─── Persistence-path coverage ─────────────────────────────────────────────


def test_audit_log_drops_tier_b_fields():
    """log_action() routes details through tier-A redaction before HMAC sign."""
    store = InMemoryAuditLog()
    set_audit_log(store)
    try:
        log_action(
            "scan",
            actor="api",
            resource="job/123",
            tenant_id="acme",
            agent_id="a-1",
            tool_name="fs.read",
            prompt="this is a tier-B prompt that must be dropped",
            tool_output="this should never be persisted",
            url="https://example.com/secret?key=abc",
            ad_hoc_key="conservative-default-drops-me",
        )
        entries = store.list_entries()
        assert entries, "audit entry was not appended"
        details = entries[0].details
        for tb in ("prompt", "tool_output", "url", "ad_hoc_key"):
            assert tb not in details, f"tier-B field {tb} leaked into audit log"
        # Tier-A fields preserved
        assert details["agent_id"] == "a-1"
        assert details["tool_name"] == "fs.read"
        assert details["tenant_id"] == "acme"
    finally:
        set_audit_log(InMemoryAuditLog())


def test_compliance_hub_drops_tier_b_fields():
    store = InMemoryComplianceHubStore()
    store.add(
        "acme",
        [
            {
                "id": "f-1",
                "source": "scanner",
                "tool_name": "kube-bench",
                "severity": "high",
                "framework": "iso27001",
                # Tier-B noise
                "prompt": "leak me",
                "tool_output": "raw kubelet config",
                "file_path": "/etc/kubernetes/config",
                "url": "https://api/secret",
            }
        ],
    )
    [finding] = store.list("acme")
    for tb in ("prompt", "tool_output", "file_path", "url"):
        assert tb not in finding, tb
    assert finding["id"] == "f-1"
    assert finding["source"] == "scanner"
    assert finding["tool_name"] == "kube-bench"


def test_compliance_hub_sqlite_backend_redacts(tmp_path):
    db = tmp_path / "compliance.db"
    store = SQLiteComplianceHubStore(str(db))
    store.add(
        "acme",
        [
            {"id": "f-1", "source": "s", "framework": "iso", "prompt": "leak", "tool_output": "leak"},
        ],
    )
    [finding] = store.list("acme")
    assert "prompt" not in finding
    assert "tool_output" not in finding
    assert finding["id"] == "f-1"


def test_proxy_audit_drops_tier_b_into_chain(tmp_path):
    """write_audit_record emits tier-A only; tier-B drops out of the chain."""
    from agent_bom.proxy_audit import RotatingAuditLog, write_audit_record

    log_path = str(tmp_path / "audit.jsonl")
    log = RotatingAuditLog(log_path)
    try:
        write_audit_record(
            log,
            {
                "ts": "2026-05-03T12:00:00Z",
                "type": "tools/call",
                "tool": "fs.read",
                "agent_id": "a-1",
                "tenant_id": "acme",
                "args": {"path": "/etc/passwd"},
                "prompt": "this must be dropped",
                "url": "https://example.com/x?k=v",
                "policy": "allowed",
                "reason": "ok",
            },
        )
    finally:
        log.close()
    written = [json.loads(line) for line in open(log_path).read().splitlines()]
    assert written, "no audit record written"
    record = written[0]
    for tb in ("args", "prompt", "url"):
        assert tb not in record, f"tier-B field {tb} leaked into proxy audit chain"
    assert record["tool"] == "fs.read"
    assert record["agent_id"] == "a-1"
    assert record["policy"] == "allowed"
    # Structural / chain header stays present
    assert "record_hash" in record
    assert record["type"] == "tools/call"


# ─── TTL + cleanup ─────────────────────────────────────────────────────────


def test_replay_ttl_default_and_env_override(monkeypatch):
    monkeypatch.delenv(REPLAY_TTL_ENV, raising=False)
    assert replay_ttl_days() == DEFAULT_REPLAY_TTL_DAYS
    monkeypatch.setenv(REPLAY_TTL_ENV, "30")
    assert replay_ttl_days() == 30
    monkeypatch.setenv(REPLAY_TTL_ENV, "not-a-number")
    assert replay_ttl_days() == DEFAULT_REPLAY_TTL_DAYS
    monkeypatch.setenv(REPLAY_TTL_ENV, "0")
    assert replay_ttl_days() == DEFAULT_REPLAY_TTL_DAYS
    monkeypatch.setenv(REPLAY_TTL_ENV, "-1")
    assert replay_ttl_days() == DEFAULT_REPLAY_TTL_DAYS


def test_replay_not_after_offsets_ttl():
    base = datetime(2026, 5, 3, 12, 0, 0, tzinfo=timezone.utc)
    expected = base + timedelta(days=7)
    assert replay_not_after(base, ttl_days=7) == expected


def test_inmemory_replay_cleanup_deletes_expired_rows():
    store = InMemoryProxyReplayStore()
    past = datetime.now(timezone.utc) - timedelta(days=1)
    future = datetime.now(timezone.utc) + timedelta(days=1)
    store.add("acme", {"prompt": "old"}, not_after=past)
    store.add("acme", {"prompt": "fresh"}, not_after=future)
    assert store.count() == 2
    removed = store.cleanup_expired()
    assert removed == 1
    assert store.count() == 1


def test_sqlite_replay_cleanup_deletes_expired_rows(tmp_path):
    store = SQLiteProxyReplayStore(str(tmp_path / "replay.db"))
    past = datetime.now(timezone.utc) - timedelta(days=1)
    future = datetime.now(timezone.utc) + timedelta(days=1)
    store.add("acme", {"prompt": "old"}, not_after=past)
    store.add("acme", {"prompt": "fresh"}, not_after=future)
    assert store.count() == 2
    removed = store.cleanup_expired()
    assert removed == 1
    assert store.count() == 1


# ─── Capture-replay opt-in gate ───────────────────────────────────────────


def test_capture_replay_disabled_blocks_tier_b_writes(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_CAPTURE_REPLAY", raising=False)
    set_capture_replay(False)
    store = InMemoryProxyReplayStore()
    set_proxy_replay_store(store)
    try:
        assert capture_replay_enabled() is False
        result = capture_tier_b("acme", {"prompt": "leak"})
        assert result is None
        assert store.count() == 0
    finally:
        reset_proxy_replay_store()
        set_capture_replay(False)


def test_capture_replay_enabled_persists_with_ttl(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_CAPTURE_REPLAY", raising=False)
    set_capture_replay(True)
    store = InMemoryProxyReplayStore()
    set_proxy_replay_store(store)
    try:
        assert capture_replay_enabled() is True
        row_id = capture_tier_b("acme", {"prompt": "ok-with-ttl"})
        assert row_id is not None
        assert store.count() == 1
        rows = store.list("acme")
        assert rows[0]["record"]["prompt"] == "ok-with-ttl"
        # not_after is set roughly 7 days out by default
        not_after = datetime.fromisoformat(rows[0]["not_after"].replace("Z", "+00:00"))
        delta = not_after - datetime.now(timezone.utc)
        assert timedelta(days=6) < delta <= timedelta(days=8)
    finally:
        reset_proxy_replay_store()
        set_capture_replay(False)


# ─── Tier badge helper ────────────────────────────────────────────────────


def test_tier_badge_safe_to_store_state():
    badge = tier_badge(EvidenceTier.SAFE_TO_STORE)
    assert badge["label"] == "Safe to store"
    assert badge["persisted"] is True


def test_tier_badge_not_persisted_state():
    badge = tier_badge(EvidenceTier.REPLAY_ONLY, capture_replay=False)
    assert badge["label"] == "Not persisted"
    assert badge["persisted"] is False


def test_tier_badge_rotates_in_state():
    base = datetime(2026, 5, 3, 12, 0, 0, tzinfo=timezone.utc)
    not_after = base + timedelta(days=7)
    badge = tier_badge(
        EvidenceTier.REPLAY_ONLY,
        capture_replay=True,
        not_after=not_after,
        now=base,
    )
    assert badge["label"] == "Rotates in 7 days"
    assert badge["rotates_in_days"] == 7
    assert badge["persisted"] is True


# ─── has_tier_b_fields helper used by proxy_audit ─────────────────────────


def test_has_tier_b_fields_detects_unknown_keys():
    assert has_tier_b_fields({"agent_id": "a", "made_up_key": "b"}) is True
    assert has_tier_b_fields({"agent_id": "a", "tenant_id": "x"}) is False
    assert has_tier_b_fields({}) is False
