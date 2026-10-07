"""Full compliance recovery preserves lifecycle and reference evidence."""

import os
from uuid import uuid4

import pytest

from agent_bom.api.compliance_hub_store import SQLiteComplianceHubStore
from agent_bom.api.storage.registry_import import import_registries, read_source


def seed(path):
    store = SQLiteComplianceHubStore(str(path))
    finding = {
        "id": "finding",
        "canonical_id": "finding",
        "severity": "high",
        "source": "scan",
        "scan_id": "scan-old",
        "graph_reachable": False,
    }
    store.ingest_batch_atomic(
        "source",
        [finding],
        observed_at="2026-01-01T00:00:00Z",
        batch_id="scan-old",
        source="scan",
        reconcile_absent=False,
        present_canonical_ids={"finding"},
    )
    store.reconcile_current_absent("source", present_canonical_ids=set(), observed_at="2026-01-02T00:00:00Z", scope_source="scan")
    return store


def test_compliance_recovery_reads_full_snapshot_without_mutating_source(tmp_path):
    path = tmp_path / "compliance.db"
    seed(path)
    before = path.read_bytes()
    records = read_source(path, {"source": "target"}, ["compliance_hub"])
    assert len(records) == 1 and records[0][1].tenant_id == "target"
    assert path.read_bytes() == before


def test_compliance_recovery_accepts_canonical_reference_payloads(tmp_path):
    from tests.test_hub_reference_normalization import _shared_intel_finding

    path = tmp_path / "references.db"
    source = SQLiteComplianceHubStore(str(path))
    source.add("source", [_shared_intel_finding("finding")])
    records = read_source(path, {"source": "target"}, ["compliance_hub"])
    assert records[0][1].tables["hub_cve_intel"][0]["payload"]["advisory_sources"] == ["osv", "ghsa", "nvd"]


@pytest.mark.parametrize("table", ["compliance_hub_findings", "hub_cve_intel", "hub_framework_refs"])
def test_compliance_recovery_rejects_secret_payloads(tmp_path, table):
    import sqlite3

    from agent_bom.api.hub_payload_codec import decode_hub_payload, encode_hub_payload
    from tests.test_hub_reference_normalization import _shared_intel_finding

    path = tmp_path / "references.db"
    SQLiteComplianceHubStore(str(path)).add("source", [_shared_intel_finding("finding")])
    with sqlite3.connect(path) as conn:
        payload = decode_hub_payload(conn.execute(f"SELECT payload FROM {table}").fetchone()[0])
        payload["password"] = "private-recovery-value"
        conn.execute(f"UPDATE {table} SET payload=?", (encode_hub_payload(payload),))
    with pytest.raises(ValueError, match="redaction"):
        read_source(path, {"source": "target"}, ["compliance_hub"])


@pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires restricted-role Postgres")
def test_compliance_recovery_preserves_resolved_lifecycle_and_is_repeatable(tmp_path):
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore
    from tests.test_postgres_job_evidence_revision import tenant_scope

    path = tmp_path / "compliance.db"
    source = seed(path)
    target = "recovery-" + uuid4().hex
    pool = _new_application_pool(min_size=1, max_size=2)
    try:
        dry = import_registries(path, {"source": target}, ["compliance_hub"], pool=pool)
        assert not dry["committed"] and dry["conflicts"] == 0
        with tenant_scope(target):
            owner = PostgresComplianceHubStore(pool=pool)
            assert owner.count(target) == 0
        applied = import_registries(path, {"source": target}, ["compliance_hub"], apply=True, pool=pool)
        assert applied["committed"] and applied["inserted"] > 0
        with tenant_scope(target):
            current = owner.get_current(target, "finding")
            assert current["status"] == "resolved"
            assert current["resolved_at"] == "2026-01-02T00:00:00Z"
            assert current["first_seen"] == "2026-01-01T00:00:00Z"
            assert current["scan_count"] == 1
            assert current["payload"]["graph_reachable"] is False
            assert owner.overview_evidence_revision(target) == source.overview_evidence_revision("source")
        repeat = import_registries(path, {"source": target}, ["compliance_hub"], apply=True, pool=pool)
        assert repeat["committed"] and repeat["unchanged"] == applied["inserted"]
    finally:
        pool.close()


@pytest.mark.parametrize("damage", ["pointer", "missing_observation", "missing_reference", "counter", "schema"])
def test_compliance_recovery_rejects_inconsistent_history_before_target_access(tmp_path, damage):
    import sqlite3

    path = tmp_path / "compliance.db"
    seed(path)
    with sqlite3.connect(path) as conn:
        if damage == "pointer":
            conn.execute("UPDATE hub_findings_current SET ledger_finding_id='missing'")
        elif damage == "missing_observation":
            conn.execute("DELETE FROM hub_findings_current_observations")
        elif damage == "missing_reference":
            conn.execute("UPDATE compliance_hub_findings SET payload=json_set(payload,'$.intel_ref','missing')")
        elif damage == "counter":
            conn.execute("UPDATE hub_ledger_ingest_state SET finding_count=2")
        else:
            conn.execute("ALTER TABLE hub_findings_current ADD COLUMN unsupported TEXT")
    with pytest.raises(ValueError):
        read_source(path, {"source": "target"}, ["compliance_hub"])


@pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires restricted-role Postgres")
def test_compliance_recovery_refuses_conflicts_without_overwriting_or_losing_isolation(tmp_path):
    from agent_bom.api.credential_store import SQLiteCredentialRefStore
    from agent_bom.api.models import CredentialRefRecord
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore
    from agent_bom.api.postgres_policy import PostgresCredentialRefStore
    from tests.test_postgres_job_evidence_revision import tenant_scope

    path = tmp_path / "compliance.db"
    seed(path)
    target = "recovery-" + uuid4().hex
    other = "other-" + uuid4().hex
    credential = CredentialRefRecord(
        credential_ref_id=uuid4().hex, tenant_id="source", display_name="Preserved", provider="test", external_ref="ref"
    )
    SQLiteCredentialRefStore(str(path)).put(credential, tenant_id="source")
    pool = _new_application_pool(min_size=1, max_size=2)
    try:
        for tenant in (target, other):
            with tenant_scope(tenant):
                PostgresComplianceHubStore(pool=pool).add(tenant, [{"id": "finding", "severity": "critical"}])
        receipt = import_registries(path, {"source": target}, ["compliance_hub", "credential_refs"], apply=True, pool=pool)
        assert receipt["conflicts"] == 1 and not receipt["committed"]
        for tenant in (target, other):
            with tenant_scope(tenant):
                assert PostgresComplianceHubStore(pool=pool).list(tenant)[0]["severity"] == "critical"
                assert PostgresCredentialRefStore(pool=pool).get(credential.credential_ref_id, tenant_id=tenant) is None
    finally:
        pool.close()


@pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires restricted-role Postgres")
def test_concurrent_compliance_recovery_is_idempotent_across_replicas(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    from agent_bom.api.postgres_common import _new_application_pool

    path = tmp_path / "compliance.db"
    seed(path)
    target = "recovery-" + uuid4().hex
    pools = [_new_application_pool(min_size=1, max_size=2) for _ in range(2)]
    try:
        with ThreadPoolExecutor(max_workers=2) as workers:
            receipts = list(
                workers.map(lambda pool: import_registries(path, {"source": target}, ["compliance_hub"], apply=True, pool=pool), pools)
            )
        assert all(receipt["committed"] for receipt in receipts)
        assert sorted(receipt["inserted"] for receipt in receipts) == [0, receipts[0]["row_count"]]
    finally:
        for pool in pools:
            pool.close()


@pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires restricted-role Postgres")
def test_compliance_recovery_preserves_compact_reference_payloads(tmp_path):
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore
    from tests.test_hub_reference_normalization import _shared_intel_finding
    from tests.test_postgres_job_evidence_revision import tenant_scope

    path = tmp_path / "references.db"
    source = SQLiteComplianceHubStore(str(path))
    source.add("source", [_shared_intel_finding("finding")])
    target = "recovery-" + uuid4().hex
    pool = _new_application_pool(min_size=1, max_size=2)
    try:
        receipt = import_registries(path, {"source": target}, ["compliance_hub"], apply=True, pool=pool)
        assert receipt["committed"]
        with tenant_scope(target):
            restored = PostgresComplianceHubStore(pool=pool).list(target)
            assert restored == source.list("source")
    finally:
        pool.close()
