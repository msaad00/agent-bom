"""Explicit control-plane import preserves lifecycle state through store owners."""

from __future__ import annotations

import os
from uuid import uuid4

import pytest

from agent_bom.api.access_review import AccessReviewCampaign, AccessReviewItem, SQLiteAccessReviewStore
from agent_bom.api.credential_store import SQLiteCredentialRefStore
from agent_bom.api.models import CredentialRefRecord, SourceCredentialMode, SourceRecord
from agent_bom.api.schedule_store import ScanSchedule, SQLiteScheduleStore
from agent_bom.api.source_store import SQLiteSourceStore
from agent_bom.api.storage.registry_import import import_registries, read_source

TABLES = ["credential_refs", "sources", "scan_schedules", "access_review_campaigns", "access_review_items"]


def seed(path, suffix=""):
    records = [
        CredentialRefRecord(
            credential_ref_id="credential" + suffix,
            tenant_id="source",
            display_name="External reference",
            provider="test",
            external_ref="secrets/credential",
            enabled=False,
            status="retired",
        ),
        SourceRecord(
            source_id="source" + suffix, tenant_id="source", display_name="Repository", kind="scan.repo", enabled=False, status="disabled"
        ),
        ScanSchedule(
            schedule_id="schedule" + suffix,
            tenant_id="source",
            name="Paused",
            cron_expression="0 1 * * *",
            scan_config={},
            enabled=False,
            last_run="2026-10-01T00:00:00Z",
        ),
        AccessReviewCampaign(
            "review" + suffix,
            "source",
            "Completed review",
            "completed",
            "2026-10-01T00:00:00Z",
            completed_at="2026-10-02T00:00:00Z",
            item_count=1,
            decided_count=1,
        ),
        AccessReviewItem(
            "item" + suffix,
            "review" + suffix,
            "source",
            "identity",
            "Subject",
            "service_account",
            decision="revoke_recommended",
            decided_by="reviewer",
            decided_at="2026-10-02T00:00:00Z",
            decision_note="Recorded recommendation",
        ),
    ]
    SQLiteCredentialRefStore(str(path)).put(records[0], tenant_id="source")
    SQLiteSourceStore(str(path)).put(records[1], tenant_id="source")
    SQLiteScheduleStore(str(path)).put(records[2], tenant_id="source")
    reviews = SQLiteAccessReviewStore(str(path))
    reviews.put_campaign(records[3])
    reviews.put_item(records[4])
    return records


def test_control_plane_import_reads_models_without_changing_source(tmp_path):
    path = tmp_path / "legacy.db"
    seed(path)
    before = path.read_bytes()
    records = read_source(path, {"source": "target"}, TABLES)
    assert len(records) == 5
    assert all(r.tenant_id == "target" for _, r, _ in records)
    assert path.read_bytes() == before
    item = next(payload for table, _, payload in records if table == "access_review_items")
    assert item["decision"] == "revoke_recommended" and item["decided_by"] == "reviewer"


@pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires restricted-role Postgres")
def test_control_plane_import_dry_run_repeat_and_conflict_roll_back_all_stores(tmp_path):
    from agent_bom.api.postgres_access_review import PostgresAccessReviewStore
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.postgres_policy import PostgresCredentialRefStore, PostgresScheduleStore
    from agent_bom.api.source_postgres import PostgresSourceStore
    from tests.test_postgres_job_evidence_revision import tenant_scope

    suffix = uuid4().hex
    path = tmp_path / "legacy.db"
    source = seed(path, suffix)
    target = "import-" + uuid4().hex
    pool = _new_application_pool(min_size=1, max_size=2)
    try:
        dry = import_registries(path, {"source": target}, TABLES, pool=pool)
        assert dry["inserted"] == 5 and not dry["committed"]
        with tenant_scope(target):
            assert PostgresSourceStore(pool=pool).get(source[1].source_id, tenant_id=target) is None
        done = import_registries(path, {"source": target}, TABLES, apply=True, pool=pool)
        assert done["committed"] and done["inserted"] == 5
        repeated = import_registries(path, {"source": target}, TABLES, apply=True, pool=pool)
        assert repeated["unchanged"] == 5 and repeated["committed"]
        with tenant_scope(target):
            assert PostgresCredentialRefStore(pool=pool).get(source[0].credential_ref_id, tenant_id=target).status.value == "retired"
            assert not PostgresScheduleStore(pool=pool).get(source[2].schedule_id, tenant_id=target).enabled
            assert PostgresAccessReviewStore(pool=pool).get_item(source[4].item_id, tenant_id=target).decided_by == "reviewer"
        SQLiteSourceStore(str(path)).put(source[1].model_copy(update={"display_name": "conflict"}), tenant_id="source")
        extra = source[0].model_copy(update={"credential_ref_id": "extra" + suffix})
        SQLiteCredentialRefStore(str(path)).put(extra, tenant_id="source")
        rejected = import_registries(path, {"source": target}, TABLES, apply=True, pool=pool)
        assert rejected["conflicts"] == 1 and not rejected["committed"]
        with tenant_scope(target):
            assert PostgresCredentialRefStore(pool=pool).get(extra.credential_ref_id, tenant_id=target) is None
            assert PostgresSourceStore(pool=pool).get(source[1].source_id, tenant_id=target).display_name == "Repository"
    finally:
        pool.close()


@pytest.mark.parametrize("damage", ["orphan", "count", "actor", "unknown_field", "scalar_state"])
def test_control_plane_import_rejects_inconsistent_source_without_target_access(tmp_path, damage):
    import json
    import sqlite3

    path = tmp_path / "legacy.db"
    seed(path)
    with sqlite3.connect(path) as conn:
        if damage in {"orphan", "actor"}:
            payload = json.loads(conn.execute("SELECT data FROM access_review_items").fetchone()[0])
            if damage == "orphan":
                payload["campaign_id"] = "missing"
                conn.execute("UPDATE access_review_items SET campaign_id='missing'")
            else:
                payload["decided_by"] = ""
            conn.execute("UPDATE access_review_items SET data=?", (json.dumps(payload),))
        elif damage == "count":
            conn.execute("UPDATE access_review_campaigns SET data=json_set(data,'$.item_count',2)")
        elif damage == "unknown_field":
            conn.execute("UPDATE sources SET data=json_set(data,'$.unrecognized_state',1)")
        else:
            conn.execute("UPDATE sources SET enabled=1")
    with pytest.raises(ValueError):
        read_source(path, {"source": "target"}, TABLES)


def test_access_reviews_require_both_tables_explicitly(tmp_path):
    path = tmp_path / "legacy.db"
    seed(path)
    with pytest.raises(ValueError, match="both access-review"):
        read_source(path, {"source": "target"}, ["access_review_campaigns"])


@pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires restricted-role Postgres")
def test_import_refuses_global_identity_owned_by_another_tenant(tmp_path):
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.source_postgres import PostgresSourceStore
    from tests.test_postgres_job_evidence_revision import tenant_scope

    path = tmp_path / "legacy.db"
    source = seed(path, uuid4().hex)[1]
    pool = _new_application_pool(min_size=1, max_size=2)
    original_tenant = "owner-" + uuid4().hex
    target = "import-" + uuid4().hex
    try:
        with tenant_scope(original_tenant):
            PostgresSourceStore(pool=pool).put(source.model_copy(update={"tenant_id": original_tenant}), tenant_id=original_tenant)
        for apply in (False, True):
            receipt = import_registries(path, {"source": target}, ["sources"], apply=apply, pool=pool)
            assert receipt["conflicts"] == 1 and not receipt["committed"]
        with tenant_scope(original_tenant):
            assert PostgresSourceStore(pool=pool).get(source.source_id, tenant_id=original_tenant).tenant_id == original_tenant
        with tenant_scope(target):
            assert PostgresSourceStore(pool=pool).get(source.source_id, tenant_id=target) is None
    finally:
        pool.close()


@pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires restricted-role Postgres")
def test_import_source_requires_credential_reference_in_target_tenant(tmp_path):
    from agent_bom.api.postgres_common import _new_application_pool

    path = tmp_path / "legacy.db"
    records = seed(path, uuid4().hex)
    linked = records[1].model_copy(
        update={"credential_mode": SourceCredentialMode.REFERENCE, "credential_ref": records[0].credential_ref_id}
    )
    SQLiteSourceStore(str(path)).put(linked, tenant_id="source")
    pool = _new_application_pool(min_size=1, max_size=2)
    try:
        target = "import-" + uuid4().hex
        missing = import_registries(path, {"source": target}, ["sources"], pool=pool)
        assert missing["conflicts"] == 1
        restored = import_registries(path, {"source": target}, ["sources", "credential_refs"], apply=True, pool=pool)
        assert restored["committed"] and restored["inserted"] == 2
    finally:
        pool.close()
