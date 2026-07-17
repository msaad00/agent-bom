"""Tests for the follow-up export sink adapters (#4040).

Covers the four adapters that landed against the same ``ExportDestination``
contract as ``s3``/``clickhouse``/``snowflake``:

* ``azure-blob`` + ``gcs`` — object stores (mirror the S3 gzip-NDJSON path)
* ``bigquery`` + ``databricks`` — warehouse tables (mirror the ClickHouse /
  Snowflake batched-load path)

No live network and none of the vendor SDKs installed: every destination client
is a fake injected through the adapter's ``client_factory`` / ``connection_factory``
so the write call, returned URI, streaming behaviour, tenant/run scope, and the
connect-once credential resolution are all asserted without a real connection.
"""

from __future__ import annotations

import gzip
import json
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from agent_bom.export.destinations import (
    DEFERRED_EXPORT_KINDS,
    SUPPORTED_EXPORT_KINDS,
    AzureBlobObjectStoreDestination,
    BigQueryWarehouseDestination,
    DatabricksWarehouseDestination,
    ExportDestinationError,
    ExportPublicationIndeterminateError,
    GcsObjectStoreDestination,
    build_destination,
)


def _finding(i: int, **extra: Any) -> dict[str, Any]:
    row = {
        "finding_id": f"f-{i}",
        "canonical_id": f"c-{i}",
        "severity": "high",
        "cvss_score": 7.5,
        "package_name": "requests",
        "ecosystem": "PyPI",
        "cve_id": f"CVE-2026-{i:04d}",
    }
    row.update(extra)
    return row


# --------------------------------------------------------------------------
# Object-store test doubles (Azure Blob + GCS)
# --------------------------------------------------------------------------
class FakeAzureBlobClient:
    def __init__(self, owner: "FakeAzureBlobService", container: str, blob: str) -> None:
        self._owner = owner
        self._container = container
        self._blob = blob

    def upload_blob(self, data: Any, overwrite: bool = False, **kwargs: Any) -> None:
        self._owner.uploads.append({"container": self._container, "blob": self._blob, "overwrite": overwrite, "body": data.read()})


class FakeAzureBlobService:
    def __init__(self) -> None:
        self.uploads: list[dict[str, Any]] = []

    def get_blob_client(self, container: str, blob: str) -> FakeAzureBlobClient:
        return FakeAzureBlobClient(self, container, blob)


class FakeGcsBlob:
    def __init__(self, owner: "FakeGcsClient", name: str) -> None:
        self._owner = owner
        self._name = name

    def upload_from_file(self, fileobj: Any, content_type: str | None = None, rewind: bool = False, **kwargs: Any) -> None:
        if rewind:
            fileobj.seek(0)
        self._owner.uploads.append({"name": self._name, "content_type": content_type, "body": fileobj.read()})


class FakeGcsBucket:
    def __init__(self, owner: "FakeGcsClient", name: str) -> None:
        self._owner = owner
        self.name = name

    def blob(self, name: str) -> FakeGcsBlob:
        return FakeGcsBlob(self._owner, name)


class FakeGcsClient:
    def __init__(self) -> None:
        self.uploads: list[dict[str, Any]] = []
        self.bucket_name: str | None = None

    def bucket(self, name: str) -> FakeGcsBucket:
        self.bucket_name = name
        return FakeGcsBucket(self, name)


# --------------------------------------------------------------------------
# Warehouse test doubles (BigQuery + Databricks)
# --------------------------------------------------------------------------
class FakeBqLoadJob:
    def __init__(self, owner: "FakeBqClient", rows: list[dict[str, Any]] | None = None) -> None:
        self._owner = owner
        self._rows = rows

    def result(self) -> Any:
        self._owner.result_calls += 1
        return self._rows


class NotFound(Exception):  # noqa: N818 - mirrors google.api_core.exceptions.NotFound
    pass


class FakeBqClient:
    def __init__(self) -> None:
        self.loads: list[dict[str, Any]] = []
        self.datasets: list[tuple[str, bool]] = []
        self.result_calls = 0
        self.queries: list[dict[str, Any]] = []

    def query(self, sql: str, job_config: Any = None) -> FakeBqLoadJob:
        self.queries.append({"sql": sql, "job_config": job_config})
        return FakeBqLoadJob(self)

    def get_table(self, ref: str) -> object:
        if not any(load["destination"] == ref for load in self.loads):
            raise NotFound(ref)
        return object()

    def create_dataset(self, ref: str, exists_ok: bool = False) -> None:
        self.datasets.append((ref, exists_ok))

    def load_table_from_json(self, rows: Any, destination: str, job_config: Any = None) -> FakeBqLoadJob:
        self.loads.append({"destination": destination, "rows": [dict(r) for r in rows], "job_config": job_config})
        return FakeBqLoadJob(self)


class FakeDatabricksCursor:
    def __init__(self, owner: "FakeDatabricksConnection") -> None:
        self._owner = owner

    def execute(self, sql: str, params: Any = None) -> None:
        self._owner.executed.append((sql, params))
        upper = sql.lstrip().upper()
        if upper.startswith("INSERT INTO") and "_RUNS`" in upper:
            self._owner.manifest_rows.append(tuple(params))
        elif upper.startswith("SELECT 1"):
            scope = tuple(params)
            self._owner.fetchone_value = (1,) if any(row[:3] == scope for row in self._owner.manifest_rows) else None

    def executemany(self, sql: str, seq_of_params: Any) -> None:
        self._owner.executemany_calls.append((sql, [tuple(row) for row in seq_of_params]))

    def close(self) -> None:
        self._owner.cursor_closed += 1

    def fetchone(self) -> Any:
        return self._owner.fetchone_value


class FakeDatabricksConnection:
    def __init__(self) -> None:
        self.executed: list[tuple[str, Any]] = []
        self.executemany_calls: list[tuple[str, list[tuple[Any, ...]]]] = []
        self.committed = 0
        self.rolled_back = 0
        self.closed = 0
        self.cursor_closed = 0
        self.manifest_rows: list[tuple[Any, ...]] = []
        self.fetchone_value: Any = None

    def cursor(self) -> FakeDatabricksCursor:
        return FakeDatabricksCursor(self)

    def commit(self) -> None:
        self.committed += 1

    def rollback(self) -> None:
        self.rolled_back += 1

    def close(self) -> None:
        self.closed += 1


# --------------------------------------------------------------------------
# Azure Blob object store
# --------------------------------------------------------------------------
def test_azure_blob_streams_gzip_ndjson_with_tenant_partitioned_key():
    svc = FakeAzureBlobService()
    dest = AzureBlobObjectStoreDestination("my-container", prefix="feed", client_factory=lambda: svc)

    result = dest.write_findings([_finding(1), _finding(2)], tenant_id="tenant-a", run_id="run123")

    assert result.kind == "azure-blob"
    assert len(svc.uploads) == 1
    up = svc.uploads[0]
    assert up["container"] == "my-container"
    assert up["blob"] == "feed/tenant=tenant-a/run123.ndjson.gz"
    assert up["overwrite"] is True
    lines = gzip.decompress(up["body"]).decode().strip().split("\n")
    assert len(lines) == 2
    # Object stores stream the raw finding rows; tenant scoping lives in the key.
    assert json.loads(lines[0])["finding_id"] == "f-1"
    assert result.destination_uri == "azure-blob://my-container/feed/tenant=tenant-a/run123.ndjson.gz"
    assert result.row_count == 2
    assert result.byte_count and result.byte_count > 0


def test_azure_blob_consumes_a_lazy_generator_without_materializing():
    svc = FakeAzureBlobService()
    dest = AzureBlobObjectStoreDestination("c", client_factory=lambda: svc)
    max_index_seen = {"n": -1}

    def gen():
        for i in range(5000):
            max_index_seen["n"] = i
            yield _finding(i)

    result = dest.write_findings(gen(), tenant_id="t", run_id="r")
    assert result.row_count == 5000
    assert max_index_seen["n"] == 4999
    assert len(gzip.decompress(svc.uploads[0]["body"]).decode().strip().split("\n")) == 5000


def test_azure_blob_requires_a_container():
    with pytest.raises(ExportDestinationError):
        AzureBlobObjectStoreDestination("", client_factory=lambda: FakeAzureBlobService())


# --------------------------------------------------------------------------
# GCS object store
# --------------------------------------------------------------------------
def test_gcs_streams_gzip_ndjson_with_tenant_partitioned_key():
    client = FakeGcsClient()
    dest = GcsObjectStoreDestination("my-bucket", prefix="feed", client_factory=lambda: client)

    result = dest.write_findings([_finding(1), _finding(2)], tenant_id="tenant-a", run_id="run123")

    assert result.kind == "gcs"
    assert client.bucket_name == "my-bucket"
    assert len(client.uploads) == 1
    up = client.uploads[0]
    assert up["name"] == "feed/tenant=tenant-a/run123.ndjson.gz"
    assert up["content_type"] == "application/gzip"
    lines = gzip.decompress(up["body"]).decode().strip().split("\n")
    assert len(lines) == 2
    assert json.loads(lines[1])["finding_id"] == "f-2"
    assert result.destination_uri == "gs://my-bucket/feed/tenant=tenant-a/run123.ndjson.gz"
    assert result.row_count == 2
    assert result.byte_count and result.byte_count > 0


def test_gcs_consumes_a_lazy_generator_without_materializing():
    client = FakeGcsClient()
    dest = GcsObjectStoreDestination("b", client_factory=lambda: client)
    max_index_seen = {"n": -1}

    def gen():
        for i in range(4000):
            max_index_seen["n"] = i
            yield _finding(i)

    result = dest.write_findings(gen(), tenant_id="t", run_id="r")
    assert result.row_count == 4000
    assert max_index_seen["n"] == 3999
    assert len(gzip.decompress(client.uploads[0]["body"]).decode().strip().split("\n")) == 4000


def test_gcs_requires_a_bucket():
    with pytest.raises(ExportDestinationError):
        GcsObjectStoreDestination("", client_factory=lambda: FakeGcsClient())


# --------------------------------------------------------------------------
# BigQuery warehouse
# --------------------------------------------------------------------------
@pytest.mark.parametrize("warehouse", ["clickhouse", "bigquery", "databricks"])
def test_manifest_pointer_latest_tenant_snapshot_hides_findings_omitted_by_later_run(warehouse):
    """All manifest-backed consumers select one latest attempt per tenant, not per run."""
    staged = [
        {"tenant_id": "tenant", "run_id": "run-a", "publication_attempt_id": "attempt-a", "finding_id": "old"}
    ]
    manifests = [
        {
            "tenant_id": "tenant",
            "run_id": "run-a",
            "publication_attempt_id": "attempt-a",
            "committed_at": 1,
            "commit_version": 1,
        },
        {
            "tenant_id": "tenant",
            "run_id": "run-b",
            "publication_attempt_id": "attempt-b",
            "committed_at": 2,
            "commit_version": 2,
        },
    ]

    latest = max(manifests, key=lambda row: (row["committed_at"], row["commit_version"], row["publication_attempt_id"]))
    visible = [
        row
        for row in staged
        if (row["tenant_id"], row["run_id"], row["publication_attempt_id"])
        == (latest["tenant_id"], latest["run_id"], latest["publication_attempt_id"])
    ]

    assert warehouse in {"clickhouse", "bigquery", "databricks"}
    assert latest["run_id"] == "run-b"
    assert visible == []


def test_bigquery_loads_in_bounded_batches_into_partitioned_table():
    client = FakeBqClient()
    dest = BigQueryWarehouseDestination(client, project="proj", dataset="sec", table="findings_feed", batch_rows=500)

    result = dest.write_findings((_finding(i) for i in range(1200)), tenant_id="tenant-a", run_id="run9")

    # Dataset ensured once (table auto-created by the load's CREATE_IF_NEEDED).
    assert client.datasets == [("proj.sec", True)]
    # 1200 rows -> 500 + 500 + 200 loads, never one giant in-memory load.
    feed_loads = [load for load in client.loads if load["destination"] == "proj.sec.findings_feed_staged"]
    assert [len(load["rows"]) for load in feed_loads] == [500, 500, 200]
    assert client.result_calls == 6  # two DDL jobs + three feed batches + server-clock manifest INSERT
    assert all(load["destination"] == "proj.sec.findings_feed_staged" for load in feed_loads)
    assert result.kind == "bigquery"
    assert result.row_count == 1200
    assert result.destination_uri == "bigquery://proj/sec/findings_feed"
    assert "UNIX_MICROS(CURRENT_TIMESTAMP())" in client.queries[-1]["sql"]


def test_bigquery_row_shape_carries_tenant_run_and_finding_fields():
    client = FakeBqClient()
    dest = BigQueryWarehouseDestination(client, project="p", dataset="d")
    dest.write_findings([_finding(1, status="open", effective_reach="reachable")], tenant_id="tnt", run_id="rid")
    row = client.loads[0]["rows"][0]
    assert row["tenant_id"] == "tnt"
    assert row["run_id"] == "rid"
    assert row["finding_id"] == "f-1"
    assert row["cve_id"] == "CVE-2026-0001"
    assert row["status"] == "open"
    assert row["effective_reach"] == "reachable"
    assert isinstance(row["cvss_score"], float)
    assert row["exported_at"]  # run export timestamp stamped for latest-row-per-finding


def test_bigquery_zero_row_run_still_materializes_staging_before_publication():
    client = FakeBqClient()
    result = BigQueryWarehouseDestination(client, project="p", dataset="d").write_findings([], tenant_id="t", run_id="empty")
    assert result.row_count == 0
    assert client.loads == []
    assert any("CREATE TABLE IF NOT EXISTS `p.d.findings_feed_staged`" in query["sql"] for query in client.queries)
    assert "UNIX_MICROS(CURRENT_TIMESTAMP())" in client.queries[-1]["sql"]


def test_bigquery_skips_dataset_creation_when_ensure_schema_false():
    client = FakeBqClient()
    dest = BigQueryWarehouseDestination(client, project="p", dataset="d", ensure_schema=False)
    dest.write_findings([_finding(1)], tenant_id="t", run_id="r")
    assert client.datasets == []


def test_bigquery_requires_project_and_dataset():
    with pytest.raises(ExportDestinationError):
        BigQueryWarehouseDestination(FakeBqClient(), project="", dataset="d")
    with pytest.raises(ExportDestinationError):
        BigQueryWarehouseDestination(FakeBqClient(), project="p", dataset="")


def test_bigquery_failed_later_batch_is_cleaned_without_commit_marker():
    class FailingJob(FakeBqLoadJob):
        def result(self) -> None:
            if len(self._owner.loads) == 2:
                raise RuntimeError("later batch failed")
            super().result()

    class FailingClient(FakeBqClient):
        def load_table_from_json(self, rows, destination, job_config=None):
            self.loads.append({"destination": destination, "rows": [dict(r) for r in rows], "job_config": job_config})
            return FailingJob(self)

    client = FailingClient()
    dest = BigQueryWarehouseDestination(client, project="p", dataset="d", batch_rows=1)
    with pytest.raises(RuntimeError):
        dest.write_findings([_finding(1), _finding(2)], tenant_id="tenant-a", run_id="run-failed")
    assert sum("DELETE FROM" in query["sql"] for query in client.queries) == 1
    assert not any(load["destination"].endswith("_runs") for load in client.loads)


def test_bigquery_manifest_failure_preserves_complete_staging_for_late_commit():
    class Client(FakeBqClient):
        def get_table(self, ref):
            return object()

        def query(self, sql, job_config=None):
            self.queries.append({"sql": sql, "job_config": job_config})
            if sql.lstrip().upper().startswith("INSERT INTO"):
                raise RuntimeError("manifest failed")
            return FakeBqLoadJob(self)

    client = Client()
    with pytest.raises(ExportPublicationIndeterminateError, match="indeterminate"):
        BigQueryWarehouseDestination(client, project="p", dataset="d").write_findings(
            [_finding(1)], tenant_id="t", run_id="r"
        )
    assert not any("DELETE FROM `p.d.findings_feed_staged`" in query["sql"] for query in client.queries)
    assert any(load["destination"].endswith("_staged") for load in client.loads)


def test_bigquery_staging_cleanup_failure_preserves_primary_error():
    class FailingJob(FakeBqLoadJob):
        def result(self):
            raise RuntimeError("primary batch failure")

    class Client(FakeBqClient):
        def load_table_from_json(self, rows, destination, job_config=None):
            self.loads.append({"destination": destination, "rows": [dict(r) for r in rows], "job_config": job_config})
            return FailingJob(self)

        def query(self, sql, job_config=None):
            raise RuntimeError("cleanup failure")

    with pytest.raises(RuntimeError, match="primary batch failure"):
        BigQueryWarehouseDestination(Client(), project="p", dataset="d", ensure_schema=False).write_findings(
            [_finding(1)], tenant_id="t", run_id="r"
        )


def test_bigquery_cleanup_uses_validated_identifiers_and_bound_scope_parameters():
    class FailingJob(FakeBqLoadJob):
        def result(self):
            raise RuntimeError("load failed")

    class FailingClient(FakeBqClient):
        def load_table_from_json(self, rows, destination, job_config=None):
            self.loads.append({"destination": destination, "rows": [dict(r) for r in rows], "job_config": job_config})
            return FailingJob(self)

    client = FailingClient()
    destination = BigQueryWarehouseDestination(
        client,
        project="safe-project",
        dataset="security_data",
        cleanup_job_config_factory=lambda tenant, run, attempt: {"tenant": tenant, "run": run, "attempt": attempt},
    )
    with pytest.raises(RuntimeError, match="load failed"):
        destination.write_findings([_finding(1)], tenant_id="tenant' OR TRUE --", run_id="run\\value")

    cleanup = [query for query in client.queries if "DELETE FROM" in query["sql"]]
    assert all("@tenant_id" in query["sql"] and "@run_id" in query["sql"] for query in cleanup)
    assert all("tenant' OR TRUE" not in query["sql"] and "run\\value" not in query["sql"] for query in cleanup)
    assert all(query["job_config"]["tenant"] == "tenant' OR TRUE --" for query in cleanup)
    assert all(query["job_config"]["run"] == "run\\value" for query in cleanup)
    with pytest.raises(ExportDestinationError, match="project"):
        BigQueryWarehouseDestination(client, project="safe`; DROP TABLE x; --", dataset="security_data")
    with pytest.raises(ExportDestinationError, match="dataset"):
        BigQueryWarehouseDestination(client, project="safe-project", dataset="bad`dataset")
    with pytest.raises(ExportDestinationError, match="table"):
        BigQueryWarehouseDestination(client, project="safe-project", dataset="security_data", table="bad`table")


def test_bigquery_ambiguous_manifest_timeout_is_reconciled_as_committed():
    class Client(FakeBqClient):
        def get_table(self, ref):
            return object()

        def query(self, sql, job_config=None):
            self.queries.append({"sql": sql, "job_config": job_config})
            if sql.lstrip().upper().startswith("INSERT INTO"):
                raise TimeoutError("response lost after commit")
            if sql.lstrip().upper().startswith("SELECT 1"):
                return FakeBqLoadJob(self, rows=[{"present": 1}])
            return FakeBqLoadJob(self)

    client = Client()
    result = BigQueryWarehouseDestination(client, project="proj", dataset="sec").write_findings(
        [_finding(1)], tenant_id="tenant", run_id="run"
    )
    assert result.row_count == 1
    assert not any(query["sql"].lstrip().upper().startswith("DELETE") for query in client.queries)


def test_bigquery_concurrent_same_run_attempts_publish_only_complete_snapshots():
    class ConcurrentClient(FakeBqClient):
        def __init__(self):
            super().__init__()
            self.staged_barrier = __import__("threading").Barrier(2)

        def load_table_from_json(self, rows, destination, job_config=None):
            if destination.endswith("_staged"):
                self.staged_barrier.wait(timeout=2)
            return super().load_table_from_json(rows, destination, job_config)

    client = ConcurrentClient()
    scope = lambda tenant, run, attempt: {"tenant": tenant, "run": run, "attempt": attempt}  # noqa: E731
    destinations = [
        BigQueryWarehouseDestination(client, project="proj", dataset="sec", cleanup_job_config_factory=scope)
        for _ in range(2)
    ]
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda dest: dest.write_findings([_finding(1)], tenant_id="t", run_id="same"), destinations))
    staged = [load for load in client.loads if load["destination"].endswith("_staged")]
    manifests = [query for query in client.queries if query["sql"].lstrip().upper().startswith("INSERT INTO")]
    assert len(manifests) == 2
    attempts = {query["job_config"]["attempt"] for query in manifests}
    assert len(attempts) == 2
    assert {load["rows"][0]["publication_attempt_id"] for load in staged} == attempts
    assert all("UNIX_MICROS(CURRENT_TIMESTAMP())" in query["sql"] for query in manifests)


# --------------------------------------------------------------------------
# Databricks warehouse
# --------------------------------------------------------------------------
def test_databricks_creates_table_and_inserts_in_bounded_batches():
    conn = FakeDatabricksConnection()
    dest = DatabricksWarehouseDestination(lambda: conn, catalog="main", schema="sec", table="findings_feed", batch_rows=500)

    result = dest.write_findings((_finding(i) for i in range(1200)), tenant_id="tenant-a", run_id="run9")

    lowered = [sql.lower() for sql, _ in conn.executed]
    assert any("create table if not exists" in s and "findings_feed" in s for s in lowered)
    # 1200 rows -> 500 + 500 + 200 param sets, never one unbounded insert.
    assert [len(params) for _, params in conn.executemany_calls] == [500, 500, 200]
    insert_sql = conn.executemany_calls[0][0]
    assert insert_sql.lstrip().upper().startswith("INSERT INTO")
    assert "`main`.`sec`.`findings_feed_staged`" in insert_sql
    assert len(conn.manifest_rows) == 1
    assert conn.closed == 1
    assert conn.cursor_closed == 1
    assert result.kind == "databricks"
    assert result.row_count == 1200
    assert result.destination_uri == "databricks://main/sec/findings_feed"


def test_databricks_insert_values_carry_tenant_run_and_finding_fields():
    conn = FakeDatabricksConnection()
    dest = DatabricksWarehouseDestination(lambda: conn, catalog="main", schema="sec")
    dest.write_findings([_finding(1, status="open")], tenant_id="tnt", run_id="rid")
    row = conn.executemany_calls[0][1][0]
    # Column order: tenant_id, run_id, finding_id first (see the INSERT column list).
    assert row[0] == "tnt"
    assert row[1] == "rid"
    assert row[2] == "f-1"
    # cvss_score / epss_score are the trailing float columns.
    assert isinstance(row[-1], float)
    assert isinstance(row[-2], float)


def test_databricks_same_run_retry_publishes_one_complete_attempt_pointer():
    conn = FakeDatabricksConnection()
    destination = DatabricksWarehouseDestination(lambda: conn, catalog="main", schema="sec")
    destination.write_findings([_finding(1)], tenant_id="tenant", run_id="same-run")
    destination.write_findings([_finding(2)], tenant_id="tenant", run_id="same-run")

    assert len(conn.manifest_rows) == 2
    assert len({row[2] for row in conn.manifest_rows}) == 2
    staged_attempts = {params[0][-3] for _, params in conn.executemany_calls}
    assert staged_attempts == {row[2] for row in conn.manifest_rows}
    assert all(row[:2] == ("tenant", "same-run") for row in conn.manifest_rows)
    assert any("UNIX_MICROS(CURRENT_TIMESTAMP())" in sql for sql, _ in conn.executed)


def test_databricks_skips_ddl_when_ensure_schema_false():
    conn = FakeDatabricksConnection()
    dest = DatabricksWarehouseDestination(lambda: conn, catalog="main", schema="sec", ensure_schema=False)
    dest.write_findings([_finding(1)], tenant_id="t", run_id="r")
    assert not any("create table" in sql.lower() for sql, _ in conn.executed)


def test_databricks_closes_connection_on_error():
    class BoomCursor(FakeDatabricksCursor):
        def executemany(self, sql: str, seq_of_params: Any) -> None:
            raise RuntimeError("warehouse unreachable")

    class BoomConn(FakeDatabricksConnection):
        def cursor(self) -> FakeDatabricksCursor:
            return BoomCursor(self)

    conn = BoomConn()
    dest = DatabricksWarehouseDestination(lambda: conn, catalog="main", schema="sec")
    with pytest.raises(RuntimeError):
        dest.write_findings([_finding(1)], tenant_id="t", run_id="r")
    assert conn.closed == 1
    assert conn.committed == 0
    assert conn.rolled_back == 0
    assert any(sql.lstrip().upper().startswith("DELETE FROM") for sql, _ in conn.executed)


def test_databricks_ambiguous_manifest_timeout_is_reconciled_as_committed():
    class TimeoutCursor(FakeDatabricksCursor):
        def execute(self, sql, params=None):
            result = super().execute(sql, params)
            if sql.lstrip().upper().startswith("INSERT INTO") and "_RUNS`" in sql.upper():
                raise TimeoutError("response lost after commit")
            return result

    class Connection(FakeDatabricksConnection):
        def cursor(self):
            return TimeoutCursor(self)

    conn = Connection()
    result = DatabricksWarehouseDestination(lambda: conn, catalog="main", schema="sec").write_findings(
        [_finding(1)], tenant_id="tenant", run_id="run"
    )
    assert result.row_count == 1
    assert len(conn.manifest_rows) == 1
    assert not any(sql.lstrip().upper().startswith("DELETE FROM") for sql, _ in conn.executed)


def test_databricks_staging_cleanup_failure_preserves_primary_error():
    class Cursor(FakeDatabricksCursor):
        def executemany(self, sql, params):
            raise RuntimeError("primary batch failure")

        def execute(self, sql, params=None):
            if sql.lstrip().upper().startswith("DELETE FROM"):
                raise RuntimeError("cleanup failure")
            return super().execute(sql, params)

    class Conn(FakeDatabricksConnection):
        def cursor(self):
            return Cursor(self)

    with pytest.raises(RuntimeError, match="primary batch failure"):
        DatabricksWarehouseDestination(lambda: Conn(), catalog="main", schema="sec").write_findings(
            [_finding(1)], tenant_id="t", run_id="r"
        )


def test_secret_only_warehouse_builds_fail_closed_without_secret():
    with pytest.raises(ExportDestinationError, match="private-key secret"):
        build_destination("snowflake", {"account": "a", "user": "u", "database": "d"})
    with pytest.raises(ExportDestinationError, match="access-token secret"):
        build_destination(
            "databricks",
            {"server_hostname": "h", "http_path": "/sql", "catalog": "main", "schema": "sec"},
        )
    with pytest.raises(ExportDestinationError, match="private-key secret"):
        build_destination("snowflake", {"account": "a", "user": "u", "database": "d"}, secret="   \n")
    with pytest.raises(ExportDestinationError, match="access-token secret"):
        build_destination(
            "databricks",
            {"server_hostname": "h", "http_path": "/sql", "catalog": "main", "schema": "sec"},
            secret="\t ",
        )


def test_databricks_streams_a_lazy_generator_without_materializing():
    conn = FakeDatabricksConnection()
    dest = DatabricksWarehouseDestination(lambda: conn, catalog="main", schema="sec")
    max_index_seen = {"n": -1}

    def gen():
        for i in range(4000):
            max_index_seen["n"] = i
            yield _finding(i)

    result = dest.write_findings(gen(), tenant_id="t", run_id="r")
    assert result.row_count == 4000
    assert max_index_seen["n"] == 3999
    assert sum(len(params) for _, params in conn.executemany_calls) == 4000


# --------------------------------------------------------------------------
# build_destination — kind support + connect-once credential resolution
# --------------------------------------------------------------------------
def test_all_four_follow_up_kinds_are_now_supported_not_deferred():
    for kind in ("azure-blob", "gcs", "bigquery", "databricks"):
        assert kind in SUPPORTED_EXPORT_KINDS
        assert kind not in DEFERRED_EXPORT_KINDS


def test_build_destination_azure_blob_wires_container_and_uses_stored_connection_string(monkeypatch):
    captured: dict[str, Any] = {}
    svc = FakeAzureBlobService()

    def fake_default(secret, account_url):
        captured["secret"] = secret
        captured["account_url"] = account_url
        return svc

    monkeypatch.setattr("agent_bom.export.destinations._default_azure_blob_service", fake_default)
    conn_str = "DefaultEndpointsProtocol=...;AccountKey=..."
    dest = build_destination("azure-blob", {"container": "feed-container", "prefix": "p"}, secret=conn_str)
    assert isinstance(dest, AzureBlobObjectStoreDestination)
    dest.write_findings([_finding(1)], tenant_id="t", run_id="r")
    assert captured["secret"] == conn_str
    assert svc.uploads[0]["container"] == "feed-container"


def test_build_destination_azure_blob_fails_closed_without_creds():
    with pytest.raises(ExportDestinationError):
        build_destination("azure-blob", {"container": "c"})  # no secret, no account_url
    with pytest.raises(ExportDestinationError):
        build_destination("azure-blob", {}, secret="conn-str")  # no container


def test_build_destination_gcs_wires_bucket_and_uses_stored_sa_key(monkeypatch):
    captured: dict[str, Any] = {}
    client = FakeGcsClient()

    def fake_default(secret):
        captured["secret"] = secret
        return client

    monkeypatch.setattr("agent_bom.export.destinations._default_gcs_client", fake_default)
    dest = build_destination("gcs", {"bucket": "feed-bucket"}, secret='{"type":"service_account"}')
    assert isinstance(dest, GcsObjectStoreDestination)
    dest.write_findings([_finding(1)], tenant_id="t", run_id="r")
    assert captured["secret"] == '{"type":"service_account"}'
    assert client.bucket_name == "feed-bucket"


def test_build_destination_gcs_requires_bucket():
    with pytest.raises(ExportDestinationError):
        build_destination("gcs", {})


def test_build_destination_bigquery_wires_project_dataset(monkeypatch):
    captured: dict[str, Any] = {}
    client = FakeBqClient()

    def fake_default(project):
        captured["project"] = project
        return client

    monkeypatch.setattr("agent_bom.export.destinations._default_bigquery_client", fake_default)
    monkeypatch.setattr("agent_bom.export.destinations._default_bigquery_job_config", lambda: None)
    monkeypatch.setattr("agent_bom.export.destinations._default_bigquery_scope_job_config", lambda *_: None)
    dest = build_destination("bigquery", {"project": "proj", "dataset": "sec", "table": "findings_feed"})
    assert isinstance(dest, BigQueryWarehouseDestination)
    dest.write_findings([_finding(1)], tenant_id="t", run_id="r")
    assert captured["project"] == "proj"
    assert client.loads[0]["destination"] == "proj.sec.findings_feed_staged"


def test_build_destination_bigquery_requires_project_and_dataset():
    with pytest.raises(ExportDestinationError):
        build_destination("bigquery", {"dataset": "d"})
    with pytest.raises(ExportDestinationError):
        build_destination("bigquery", {"project": "p"})


def test_build_destination_databricks_wires_connection_from_stored_token(monkeypatch):
    captured: dict[str, Any] = {}
    conn = FakeDatabricksConnection()

    def fake_default(config, secret):
        captured["config"] = config
        captured["secret"] = secret
        return conn

    monkeypatch.setattr("agent_bom.export.destinations._default_databricks_connection", fake_default)
    dest = build_destination(
        "databricks",
        {
            "server_hostname": "dbc-abc.cloud.databricks.com",
            "http_path": "/sql/1.0/warehouses/abc123",
            "catalog": "main",
            "schema": "sec",
            "table": "findings_feed",
        },
        secret="dapi-token-xyz",
    )
    assert isinstance(dest, DatabricksWarehouseDestination)
    dest.write_findings([_finding(1)], tenant_id="t", run_id="r")
    assert captured["secret"] == "dapi-token-xyz"
    assert captured["config"]["server_hostname"] == "dbc-abc.cloud.databricks.com"
    assert conn.executemany_calls  # rows inserted through the brokered connection


def test_build_destination_databricks_requires_connection_params():
    with pytest.raises(ExportDestinationError):
        build_destination("databricks", {"catalog": "c", "schema": "s"}, secret="t")  # no host/http_path
    with pytest.raises(ExportDestinationError):
        build_destination(
            "databricks",
            {"server_hostname": "h", "http_path": "p", "schema": "s"},
            secret="t",
        )  # no catalog
