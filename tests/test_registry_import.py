"""Explicit SQLite import preserves evidence and fails closed on conflicts."""

import json
import os
from dataclasses import replace
from uuid import uuid4

import pytest

from agent_bom.api.dataset_version_store import DatasetVersionRecord, SQLiteDatasetVersionStore
from agent_bom.api.storage.registry_import import import_registries, read_source
from tests.test_postgres_job_evidence_revision import tenant_scope


def test_import_requires_mapping_and_preserves_source(tmp_path):
    path = tmp_path / "source.db"
    source = SQLiteDatasetVersionStore(str(path))
    source.put(DatasetVersionRecord("source", "ds", "v1", "now", "fixture"))
    before = source.get("source", "ds", "v1")
    with pytest.raises(ValueError, match="explicit mapping"):
        read_source(path, {}, ["dataset_versions"])
    assert source.get("source", "ds", "v1") == before
    source._conn.execute("UPDATE dataset_versions SET data=json_set(data,'$.tenant_id','other')")
    source._conn.commit()
    with pytest.raises(ValueError, match="tenant disagree"):
        read_source(path, {"source": "target"}, ["dataset_versions"])


@pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires restricted-role Postgres")
def test_import_dry_run_repeat_conflict_and_atomic_rollback(tmp_path):
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.storage.registry_stores import PostgresDatasetVersionStore

    path = tmp_path / "source.db"
    source = SQLiteDatasetVersionStore(str(path))
    original = DatasetVersionRecord("source", "ds", "v1", "now", "fixture")
    source.put(original)
    target = "import-" + uuid4().hex
    mapping = {"source": target}
    pool = _new_application_pool(min_size=1, max_size=2)
    try:
        store = PostgresDatasetVersionStore(pool=pool)
        dry = import_registries(path, mapping, ["dataset_versions"], pool=pool)
        assert dry["inserted"] == 1 and not dry["committed"]
        with tenant_scope(target):
            assert store.get(target, "ds", "v1") is None
        done = import_registries(path, mapping, ["dataset_versions"], apply=True, pool=pool)
        assert done["committed"] and done["inserted"] == 1
        repeated = import_registries(path, mapping, ["dataset_versions"], apply=True, pool=pool)
        assert repeated["committed"] and repeated["unchanged"] == 1
        assert done["source_snapshot_sha256"] == repeated["source_snapshot_sha256"]
        source.put(replace(original, version_id="v2"))
        source.put(replace(original, source="conflicting"))
        rejected = import_registries(path, mapping, ["dataset_versions"], apply=True, pool=pool)
        assert rejected["conflicts"] == 1 and not rejected["committed"]
        with tenant_scope(target):
            assert store.get(target, "ds", "v1").source == "fixture"
            assert store.get(target, "ds", "v2") is None
        assert source.get("source", "ds", "v1").source == "conflicting"
        assert not any("source" == key or "path" in key for key in done)
        json.dumps(done)
    finally:
        pool.close()


def test_import_rejects_mapping_collisions_before_target_access(tmp_path):
    path = tmp_path / "source.db"
    source = SQLiteDatasetVersionStore(str(path))
    source.put(DatasetVersionRecord("first", "ds", "v1", "now", "one"))
    source.put(DatasetVersionRecord("second", "ds", "v1", "now", "two"))
    with pytest.raises(ValueError, match="mapping collision"):
        read_source(path, {"first": "target", "second": "target"}, ["dataset_versions"])


@pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires restricted-role Postgres")
def test_import_dry_run_reports_existing_secondary_identity_conflict(tmp_path):
    from agent_bom.api.issue_mapping_store import SQLiteIssueMappingStore
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.storage.observation_registries import PostgresIssueMappingStore

    path = tmp_path / "source.db"
    source = SQLiteIssueMappingStore(str(path))
    fields = dict(target_kind="finding", target_id="same", provider="test", external_id="one", external_url="https://example.com")
    source.put(tenant_id="source", **fields)
    target = "import-" + uuid4().hex
    pool = _new_application_pool(min_size=1, max_size=2)
    try:
        with tenant_scope(target):
            PostgresIssueMappingStore(pool=pool).put(tenant_id=target, **fields)
        receipt = import_registries(path, {"source": target}, ["issue_mappings"], pool=pool)
        assert receipt["conflicts"] == 1
        assert not receipt["committed"]
    finally:
        pool.close()


@pytest.mark.parametrize(
    "table",
    [
        "audit_log",
        "idempotency_keys",
        "graph_snapshots",
        "trend_snapshots",
        "tenant_score_config_overrides",
        "tenant_graph_retention_overrides",
        "tenant_quota_overrides",
        "scan_snapshot_jobs",
        "scan_snapshot_rows",
    ],
)
def test_unsupported_recovery_is_rejected_before_source_or_target_access(tmp_path, table):
    source = tmp_path / "preserved.db"
    source.write_bytes(b"preserved source evidence")

    class NoTargetAccess:
        def connection(self):
            pytest.fail("unsupported recovery must not access the target")

    with pytest.raises(ValueError, match="supported registry tables"):
        import_registries(source, {"source": "target"}, [table], apply=True, pool=NoTargetAccess())
    assert source.read_bytes() == b"preserved source evidence"


def test_sqlite_recovery_validation_does_not_require_postgres_driver(tmp_path):
    import subprocess
    import sys

    source = tmp_path / "source.db"
    store = SQLiteDatasetVersionStore(str(source))
    store.put(DatasetVersionRecord("source", "ds", "v1", "now", "fixture"))
    script = """
import importlib.abc
import sys
from pathlib import Path
class NoPostgres(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'psycopg', 'psycopg_pool'}:
            raise ModuleNotFoundError('Postgres extra deliberately absent')
sys.meta_path.insert(0, NoPostgres())
from agent_bom.api.storage.registry_import import read_source
rows = read_source(Path(sys.argv[1]), {'source': 'target'}, ['dataset_versions'])
assert len(rows) == 1 and rows[0][1].tenant_id == 'target'
assert not any(name.split('.')[0] in {'psycopg', 'psycopg_pool'} for name in sys.modules)
"""
    result = subprocess.run([sys.executable, "-c", script, str(source)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
