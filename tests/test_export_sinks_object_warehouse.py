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
from typing import Any

import pytest

from agent_bom.export.destinations import (
    DEFERRED_EXPORT_KINDS,
    SUPPORTED_EXPORT_KINDS,
    AzureBlobObjectStoreDestination,
    BigQueryWarehouseDestination,
    DatabricksWarehouseDestination,
    ExportDestinationError,
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
    def __init__(self, owner: "FakeBqClient") -> None:
        self._owner = owner

    def result(self) -> None:
        self._owner.result_calls += 1


class FakeBqClient:
    def __init__(self) -> None:
        self.loads: list[dict[str, Any]] = []
        self.datasets: list[tuple[str, bool]] = []
        self.result_calls = 0

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

    def executemany(self, sql: str, seq_of_params: Any) -> None:
        self._owner.executemany_calls.append((sql, [tuple(row) for row in seq_of_params]))

    def close(self) -> None:
        self._owner.cursor_closed += 1


class FakeDatabricksConnection:
    def __init__(self) -> None:
        self.executed: list[tuple[str, Any]] = []
        self.executemany_calls: list[tuple[str, list[tuple[Any, ...]]]] = []
        self.committed = 0
        self.closed = 0
        self.cursor_closed = 0

    def cursor(self) -> FakeDatabricksCursor:
        return FakeDatabricksCursor(self)

    def commit(self) -> None:
        self.committed += 1

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
def test_bigquery_loads_in_bounded_batches_into_partitioned_table():
    client = FakeBqClient()
    dest = BigQueryWarehouseDestination(client, project="proj", dataset="sec", table="findings_feed", batch_rows=500)

    result = dest.write_findings((_finding(i) for i in range(1200)), tenant_id="tenant-a", run_id="run9")

    # Dataset ensured once (table auto-created by the load's CREATE_IF_NEEDED).
    assert client.datasets == [("proj.sec", True)]
    # 1200 rows -> 500 + 500 + 200 loads, never one giant in-memory load.
    assert [len(load["rows"]) for load in client.loads] == [500, 500, 200]
    assert client.result_calls == 3
    assert all(load["destination"] == "proj.sec.findings_feed" for load in client.loads)
    assert result.kind == "bigquery"
    assert result.row_count == 1200
    assert result.destination_uri == "bigquery://proj/sec/findings_feed"


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
    assert "`main`.`sec`.`findings_feed`" in insert_sql
    assert conn.committed == 1
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
    dest = build_destination("bigquery", {"project": "proj", "dataset": "sec", "table": "findings_feed"})
    assert isinstance(dest, BigQueryWarehouseDestination)
    dest.write_findings([_finding(1)], tenant_id="t", run_id="r")
    assert captured["project"] == "proj"
    assert client.loads[0]["destination"] == "proj.sec.findings_feed"


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
