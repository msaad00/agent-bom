"""Contract tests for the CWPP runtime/EDR workload-evidence subsystem (stage 3).

Runtime evidence is optional, read-only, and ADDITIVE. These tests pin the
non-negotiable honesty + security properties from issue #4158 stage 3:

* ingest authenticates sources, records freshness/provenance, deduplicates, and
  fails closed on a stale signal or an incomplete identity binding;
* evidence enriches workloads/findings without fabricating reachability;
* absence of a runtime signal is NEVER rendered as a clean workload;
* tenant/account/subscription/project isolation holds in ingest, persistence,
  and graph joins.
"""

from __future__ import annotations

import pytest

from agent_bom.cloud.runtime_workload_evidence import (
    DEFAULT_MAX_SIGNAL_AGE_SECONDS,
    RUNTIME_EVIDENCE_SCHEMA_VERSION,
    STATE_HAS_IOC,
    STATE_NO_SIGNAL,
    STATE_OBSERVED,
    IngestResult,
    RuntimeEvidenceSource,
    RuntimeSignalType,
    RuntimeSourceRegistry,
    RuntimeWorkloadEvidenceIndex,
    RuntimeWorkloadSignal,
    SourceAuthenticationError,
    attach_workload_runtime_evidence_to_finding,
    attach_workload_runtime_evidence_to_node,
    canonical_workload_id,
    ingest_runtime_signals,
    no_runtime_signal_summary,
)

_T0 = "2026-07-18T12:00:00Z"


def _source(secret: str = "s3cr3t-token-value") -> tuple[RuntimeSourceRegistry, RuntimeEvidenceSource, str]:
    registry = RuntimeSourceRegistry()
    src = RuntimeEvidenceSource.register(
        source_id="edr-1",
        tenant_id="tenant-a",
        provider="aws",
        account_id="123456789012",
        kind="edr",
        secret=secret,
    )
    registry.add(src)
    return registry, src, secret


def _raw(**over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "workload_ref": "i-0abc",
        "signal_type": "ioc_detection",
        "severity": "high",
        "observed_at": _T0,
        "dedup_key": "evt-1",
        "title": "known C2 domain contacted",
        "evidence": {"ioc_type": "domain", "indicator_ref": "redacted:domain#7f3a"},
    }
    base.update(over)
    return base


# ── canonical identity ───────────────────────────────────────────────────────


def test_canonical_workload_id_is_deterministic_and_scope_bound():
    a = canonical_workload_id("aws", "123456789012", "i-0abc")
    assert a == canonical_workload_id("aws", "123456789012", "i-0abc")
    assert a != canonical_workload_id("aws", "999999999999", "i-0abc")
    assert a != canonical_workload_id("azure", "123456789012", "i-0abc")


# ── source authentication ────────────────────────────────────────────────────


def test_ingest_rejects_unknown_source():
    registry, _src, secret = _source()
    with pytest.raises(SourceAuthenticationError):
        ingest_runtime_signals(registry=registry, source_id="ghost", secret=secret, raw_signals=[_raw()])


def test_ingest_rejects_wrong_secret():
    registry, _src, _secret = _source()
    with pytest.raises(SourceAuthenticationError):
        ingest_runtime_signals(registry=registry, source_id="edr-1", secret="wrong", raw_signals=[_raw()])


def test_source_authenticate_is_constant_time_hash_not_plaintext():
    _registry, src, secret = _source()
    assert src.authenticate(secret) is True
    assert src.authenticate("nope") is False
    # the shared secret is never stored in the clear
    assert secret not in src.secret_hash
    assert len(src.secret_hash) == 64


def test_source_registry_rejects_conflicting_source_id_rebinding():
    registry, original, _secret = _source()
    conflicting = RuntimeEvidenceSource.register(
        source_id=original.source_id,
        tenant_id="tenant-b",
        provider="gcp",
        account_id="project-b",
        kind="edr",
        secret="different-secret-value",
    )

    with pytest.raises(ValueError, match="already registered"):
        registry.add(conflicting)

    assert registry.get(original.source_id) == original


# ── identity binding: fail closed ────────────────────────────────────────────


def test_ingest_binds_identity_from_source_not_from_client_claim():
    registry, _src, secret = _source()
    # a spoofed account/provider on the raw signal must not steer persistence
    result = ingest_runtime_signals(
        registry=registry,
        source_id="edr-1",
        secret=secret,
        raw_signals=[_raw(provider="gcp", account_id="000000000000")],
        now=_T0,
    )
    assert result.rejected_incomplete == 1
    assert not result.accepted


def test_ingest_fails_closed_on_missing_workload_ref():
    registry, _src, secret = _source()
    result = ingest_runtime_signals(
        registry=registry,
        source_id="edr-1",
        secret=secret,
        raw_signals=[_raw(workload_ref="")],
        now=_T0,
    )
    assert result.rejected_incomplete == 1
    assert not result.accepted


# ── freshness: fail closed on stale ──────────────────────────────────────────


def test_ingest_rejects_stale_signal():
    registry, _src, secret = _source()
    now = "2026-07-18T13:30:00Z"  # 90 min after observed_at, window is 60 min
    result = ingest_runtime_signals(
        registry=registry,
        source_id="edr-1",
        secret=secret,
        raw_signals=[_raw()],
        now=now,
        max_age_seconds=DEFAULT_MAX_SIGNAL_AGE_SECONDS,
    )
    assert result.rejected_stale == 1
    assert not result.accepted


def test_ingest_rejects_unparseable_timestamp_as_incomplete():
    registry, _src, secret = _source()
    result = ingest_runtime_signals(
        registry=registry,
        source_id="edr-1",
        secret=secret,
        raw_signals=[_raw(observed_at="not-a-time")],
        now=_T0,
    )
    assert result.accepted == []
    assert result.rejected_incomplete == 1


def test_ingest_rejects_missing_observation_timestamp_as_incomplete():
    registry, _src, secret = _source()
    result = ingest_runtime_signals(
        registry=registry,
        source_id="edr-1",
        secret=secret,
        raw_signals=[_raw(observed_at="")],
        now=_T0,
    )
    assert result.accepted == []
    assert result.rejected_incomplete == 1


def test_ingest_rejects_future_observation_timestamp():
    registry, _src, secret = _source()
    result = ingest_runtime_signals(
        registry=registry,
        source_id="edr-1",
        secret=secret,
        raw_signals=[_raw(observed_at="2026-07-18T12:00:01Z")],
        now=_T0,
    )
    assert result.accepted == []
    assert result.rejected_stale == 1


def test_ingest_rejects_secret_shaped_or_unbounded_identity_values():
    registry, _src, secret = _source()
    credential = "gl" + "pat-abcdefghijklmnopqrst"
    secret_result = ingest_runtime_signals(
        registry=registry,
        source_id="edr-1",
        secret=secret,
        raw_signals=[_raw(dedup_key=credential)],
        now=_T0,
    )
    oversized_result = ingest_runtime_signals(
        registry=registry,
        source_id="edr-1",
        secret=secret,
        raw_signals=[_raw(dedup_key="e" * 513)],
        now=_T0,
    )

    assert secret_result.accepted == []
    assert secret_result.rejected_incomplete == 1
    assert credential not in str(secret_result.to_dict())
    assert oversized_result.accepted == []
    assert oversized_result.rejected_incomplete == 1


def test_ingest_normalizes_observation_timestamps_to_utc_before_ordering():
    registry, _src, secret = _source()
    result = ingest_runtime_signals(
        registry=registry,
        source_id="edr-1",
        secret=secret,
        raw_signals=[
            _raw(observed_at="2026-07-18T12:30:00+01:00", dedup_key="older-offset"),
            _raw(observed_at="2026-07-18T12:00:00Z", dedup_key="newer-zulu"),
        ],
        now=_T0,
    )

    assert [signal.observed_at for signal in result.accepted] == [
        "2026-07-18T11:30:00.000000Z",
        "2026-07-18T12:00:00.000000Z",
    ]
    index = RuntimeWorkloadEvidenceIndex.from_signals("tenant-a", result.accepted)
    summary = index.summary_for("aws", "123456789012", "i-0abc")
    assert summary["latest_observed_at"] == "2026-07-18T12:00:00.000000Z"


# ── dedup + provenance/freshness recorded ────────────────────────────────────


def test_ingest_deduplicates_within_and_across_batches():
    registry, _src, secret = _source()
    r1 = ingest_runtime_signals(registry=registry, source_id="edr-1", secret=secret, raw_signals=[_raw(), _raw()], now=_T0)
    assert len(r1.accepted) == 1
    assert r1.deduped == 1
    seen = {sig.dedup_scope for sig in r1.accepted}
    r2 = ingest_runtime_signals(registry=registry, source_id="edr-1", secret=secret, raw_signals=[_raw()], now=_T0, dedup_seen=seen)
    assert r2.accepted == []
    assert r2.deduped == 1


def test_signal_records_provenance_and_freshness():
    registry, _src, secret = _source()
    result = ingest_runtime_signals(registry=registry, source_id="edr-1", secret=secret, raw_signals=[_raw()], now=_T0)
    sig = result.accepted[0]
    assert sig.source_id == "edr-1"
    assert sig.source_kind == "edr"
    assert sig.observed_at == "2026-07-18T12:00:00.000000Z"
    assert sig.tenant_id == "tenant-a"
    assert sig.provider == "aws"
    assert sig.account_id == "123456789012"
    ev = sig.to_evidence_dict()
    assert ev["schema_version"] == RUNTIME_EVIDENCE_SCHEMA_VERSION
    assert ev["clean_workload_assertion"] is False


# ── redaction: no data-plane bytes persisted ─────────────────────────────────


def test_signal_redacts_oversized_and_forbidden_evidence():
    registry, _src, secret = _source()
    result = ingest_runtime_signals(
        registry=registry,
        source_id="edr-1",
        secret=secret,
        raw_signals=[
            _raw(
                evidence={
                    "ioc_type": "hash",
                    "raw_bytes": "A" * 100000,
                    "file_contents": "SECRET DATA",
                    "indicator_ref": "redacted:sha256#abcd",
                }
            )
        ],
        now=_T0,
    )
    sig = result.accepted[0]
    dumped = str(sig.to_dict())
    assert "SECRET DATA" not in dumped
    assert "A" * 1000 not in dumped
    assert "raw_bytes" not in sig.evidence
    assert "file_contents" not in sig.evidence
    assert sig.evidence.get("ioc_type") == "hash"


def test_signal_persists_only_allowlisted_non_secret_metadata():
    registry, _src, secret = _source()
    result = ingest_runtime_signals(
        registry=registry,
        source_id="edr-1",
        secret=secret,
        raw_signals=[
            _raw(
                evidence={
                    "ioc_type": "domain",
                    "indicator_ref": "redacted:domain#7f3a",
                    "rule_id": "edr-rule-7",
                    "process_ref": "process#123",
                    "source_ref": "Authorization: Bearer credential-in-allowed-key",
                    "alert_ref": {"credential": "nested-secret"},
                    "password": "correct-horse-battery-staple",
                    "api_token": "token-that-must-not-persist",
                    "secretValue": "camel-case-secret",
                    "command_line": "curl -H 'Author" + "ization: Bearer credential-value'",
                    "unknown_metadata": "not-contracted",
                }
            )
        ],
        now=_T0,
    )

    signal = result.accepted[0]
    assert signal.evidence == {
        "indicator_ref": "redacted:domain#7f3a",
        "ioc_type": "domain",
        "process_ref": "process#123",
        "rule_id": "edr-rule-7",
    }
    dumped = str(signal.to_dict())
    assert "correct-horse-battery-staple" not in dumped
    assert "token-that-must-not-persist" not in dumped
    assert "camel-case-secret" not in dumped
    assert "credential-value" not in dumped
    assert "credential-in-allowed-key" not in dumped
    assert "nested-secret" not in dumped


def test_signal_redacts_secret_shaped_title():
    registry, _src, secret = _source()
    result = ingest_runtime_signals(
        registry=registry,
        source_id="edr-1",
        secret=secret,
        raw_signals=[_raw(title="Authorization: Bearer credential-in-title")],
        now=_T0,
    )

    signal = result.accepted[0]
    assert signal.title == "<redacted>"
    assert "credential-in-title" not in str(signal.to_dict())


@pytest.mark.parametrize(
    "credential",
    [
        "AKIAIOSFODNN7EXAMPLE",
        "gh" + "p_0123456789abcdefghijklmnopqrstuvwxyzAB",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIn0.signature",
        "xox" + "b-0123456789-abcdefghijklmnop",
        "-----BEGIN PRIVATE KEY-----not-for-persistence-----END PRIVATE KEY-----",
        "postgresql://runtime-user:runtime-password@example.invalid/evidence",
        "gl" + "pat-abcdefghijklmnopqrst",
        "gl" + "cbt-abcdefghijklmnopqrstuv",
        "gl" + "dt-abcdefghijklmnopqrstuvwx",
        "gl" + "rt-abcdefghijklmnopqrstuvwx",
        "gl" + "ptt-abcdefghijklmnopqrstuvwx",
        "gl" + "agent-abcdefghijklmnopqrstuv",
        "ya" + "29.a0AfH6SMBabcdefghijklmnopqrstuv",
    ],
)
def test_signal_drops_known_credential_shapes_from_allowlisted_values(credential: str):
    registry, _src, secret = _source()
    result = ingest_runtime_signals(
        registry=registry,
        source_id="edr-1",
        secret=secret,
        raw_signals=[_raw(evidence={"indicator_ref": credential})],
        now=_T0,
    )

    signal = result.accepted[0]
    assert "indicator_ref" not in signal.evidence
    assert credential not in str(signal.to_dict())


def test_signal_scans_full_oversized_value_before_bounding():
    credential = "A" * 220 + "postgresql://runtime-user:supersecretpassword@example.invalid/db"
    registry, _src, secret = _source()
    result = ingest_runtime_signals(
        registry=registry,
        source_id="edr-1",
        secret=secret,
        raw_signals=[_raw(evidence={"indicator_ref": credential})],
        now=_T0,
    )

    signal = result.accepted[0]
    assert "indicator_ref" not in signal.evidence
    dumped = str(signal.to_dict())
    assert "runtime-user" not in dumped
    assert "supersecret" not in dumped


def test_signal_preserves_non_secret_security_taxonomy_labels():
    registry, _src, secret = _source()
    result = ingest_runtime_signals(
        registry=registry,
        source_id="edr-1",
        secret=secret,
        raw_signals=[
            _raw(
                evidence={
                    "category": "credential_access",
                    "event_type": "token_theft",
                    "action": "rotate_password",
                    "indicator_ref": "redacted:token#abcd",
                    "alert_ref": "arn:aws:guardduty:us-east-1:123456789012:detector/abc/finding/def",
                    "hash_ref": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
                    "count": 0,
                    "outcome": False,
                }
            )
        ],
        now=_T0,
    )

    assert result.accepted[0].evidence == {
        "action": "rotate_password",
        "alert_ref": "arn:aws:guardduty:us-east-1:123456789012:detector/abc/finding/def",
        "category": "credential_access",
        "count": "0",
        "event_type": "token_theft",
        "hash_ref": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        "indicator_ref": "redacted:token#abcd",
        "outcome": "False",
    }


# ── honesty: absence of signal is NOT clean ──────────────────────────────────


def test_no_runtime_signal_summary_never_asserts_clean():
    summary = no_runtime_signal_summary()
    assert summary["state"] == STATE_NO_SIGNAL
    assert summary["clean_workload_assertion"] is False
    assert summary["signal_count"] == 0
    # the note must communicate additivity, never cleanliness
    assert "clean" in summary["note"].lower()


def test_finding_with_no_matching_runtime_evidence_is_marked_no_signal_not_clean():
    index = RuntimeWorkloadEvidenceIndex.from_signals("tenant-a", [])
    row = {"provider": "aws", "account_ref": "aws:123456789012", "resource_id": "i-0abc", "cve_id": "CVE-2026-1"}
    attach_workload_runtime_evidence_to_finding(row, index)
    ev = row["workload_runtime_evidence"]
    assert ev["state"] == STATE_NO_SIGNAL
    assert ev["clean_workload_assertion"] is False


def test_finding_without_workload_identity_is_left_untouched():
    index = RuntimeWorkloadEvidenceIndex.from_signals("tenant-a", [])
    row = {"cve_id": "CVE-2026-2"}  # no workload scope resolvable
    attach_workload_runtime_evidence_to_finding(row, index)
    assert "workload_runtime_evidence" not in row


# ── enrichment: additive, no fabricated reachability ─────────────────────────


def _signal(**over: object) -> RuntimeWorkloadSignal:
    registry, _src, secret = _source()
    result = ingest_runtime_signals(registry=registry, source_id="edr-1", secret=secret, raw_signals=[_raw(**over)], now=_T0)
    return result.accepted[0]


def test_finding_enrichment_attaches_ioc_state_and_counts():
    sig = _signal()
    index = RuntimeWorkloadEvidenceIndex.from_signals("tenant-a", [sig])
    row = {"provider": "aws", "account_ref": "aws:123456789012", "resource_id": "i-0abc"}
    attach_workload_runtime_evidence_to_finding(row, index)
    ev = row["workload_runtime_evidence"]
    assert ev["state"] == STATE_HAS_IOC
    assert ev["signal_count"] == 1
    assert ev["clean_workload_assertion"] is False
    # enrichment never invents a reachability verdict
    assert "reachable" not in ev
    assert "effective_reach" not in row


def test_process_exec_signal_yields_observed_state_not_ioc():
    sig = _signal(signal_type="process_exec", severity="info", dedup_key="p-1", title="sshd started")
    index = RuntimeWorkloadEvidenceIndex.from_signals("tenant-a", [sig])
    row = {"provider": "aws", "account_ref": "aws:123456789012", "resource_id": "i-0abc"}
    attach_workload_runtime_evidence_to_finding(row, index)
    assert row["workload_runtime_evidence"]["state"] == STATE_OBSERVED


def test_node_enrichment_matches_workload_and_never_adds_reachability():
    sig = _signal()
    index = RuntimeWorkloadEvidenceIndex.from_signals("tenant-a", [sig])
    node = {
        "entity_type": "cloud_resource",
        "attributes": {
            "resource_type": "workload_disk",
            "cloud_provider": "aws",
            "account_id": "123456789012",
            "resource_id": "i-0abc",
        },
    }
    changed = attach_workload_runtime_evidence_to_node(node, index)
    assert changed is True
    assert node["attributes"]["runtime_evidence"]["state"] == STATE_HAS_IOC
    assert node["attributes"]["runtime_evidence"]["clean_workload_assertion"] is False


# ── tenant isolation in the enrichment index ─────────────────────────────────


def test_index_never_leaks_signals_across_tenants():
    sig = _signal()  # tenant-a
    # An index built for tenant-b must not include tenant-a's signal.
    index_b = RuntimeWorkloadEvidenceIndex.from_signals("tenant-b", [sig])
    row = {"provider": "aws", "account_ref": "aws:123456789012", "resource_id": "i-0abc"}
    attach_workload_runtime_evidence_to_finding(row, index_b)
    assert row["workload_runtime_evidence"]["state"] == STATE_NO_SIGNAL


def test_signal_type_enum_is_bounded():
    assert RuntimeSignalType("ioc_detection") is RuntimeSignalType.IOC_DETECTION
    with pytest.raises(ValueError):
        RuntimeSignalType("made_up")


def test_ingest_result_summary_is_serializable_and_non_secret():
    registry, _src, secret = _source()
    result = ingest_runtime_signals(registry=registry, source_id="edr-1", secret=secret, raw_signals=[_raw()], now=_T0)
    assert isinstance(result, IngestResult)
    summary = result.to_dict()
    assert summary["accepted"] == 1
    assert secret not in str(summary)
