"""Tests for the scheduled findings/report lake-export engine (#4040).

Covers the streaming destination adapters (mocked S3 + mocked ClickHouse), the
connect-once credential path, tenant isolation, and bounded/streaming memory.
No live network: both destination clients are mocked.
"""

from __future__ import annotations

import gzip
import json
from typing import Any

import pytest

from agent_bom.export.destinations import (
    DEFERRED_EXPORT_KINDS,
    SUPPORTED_EXPORT_KINDS,
    ClickHouseWarehouseDestination,
    ExportDestinationError,
    S3ObjectStoreDestination,
    build_destination,
)
from agent_bom.export.runner import iter_current_findings, run_findings_export


# --------------------------------------------------------------------------
# Test doubles
# --------------------------------------------------------------------------
class FakeS3Client:
    """Records upload_fileobj calls and captures the streamed bytes."""

    def __init__(self) -> None:
        self.uploads: list[dict[str, Any]] = []

    def upload_fileobj(self, fileobj: Any, bucket: str, key: str, ExtraArgs: dict[str, Any] | None = None) -> None:  # noqa: N803 - boto3 API param name
        self.uploads.append({"bucket": bucket, "key": key, "extra": ExtraArgs, "body": fileobj.read()})


class FakeClickHouseClient:
    """Records insert_json batches and ensure_tables calls."""

    database = "agent_bom"

    def __init__(self) -> None:
        self.batches: list[list[dict[str, Any]]] = []
        self.ensured = 0

    def ensure_tables(self) -> None:
        self.ensured += 1

    def insert_json(self, table: str, rows: list[dict[str, Any]]) -> None:
        self.table = table
        # Copy so later mutation of the caller's buffer can't corrupt the record.
        self.batches.append([dict(r) for r in rows])


class FakeHub:
    """Keyset-paged findings store scoped by tenant."""

    def __init__(self, rows_by_tenant: dict[str, list[dict[str, Any]]]) -> None:
        self._rows = rows_by_tenant
        self.calls: list[dict[str, Any]] = []

    def list_current_page(self, tenant_id, *, limit, sort, severity=None, since=None, include_total=True, cursor=None):
        self.calls.append({"tenant_id": tenant_id, "cursor": cursor, "severity": severity, "since": since})
        rows = self._rows.get(tenant_id, [])
        start = int(cursor) if cursor else 0
        page = rows[start : start + limit]
        next_start = start + limit
        next_cursor = str(next_start) if next_start < len(rows) else None
        total = len(rows) if include_total else None
        return page, total, next_cursor


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
# S3 object-store destination
# --------------------------------------------------------------------------
def test_s3_destination_streams_gzip_ndjson_with_tenant_partitioned_key():
    client = FakeS3Client()
    dest = S3ObjectStoreDestination("my-bucket", prefix="feed", client_factory=lambda: client)

    result = dest.write_findings([_finding(1), _finding(2)], tenant_id="tenant-a", run_id="run123")

    assert result.kind == "s3"
    assert len(client.uploads) == 1
    up = client.uploads[0]
    assert up["bucket"] == "my-bucket"
    assert up["key"] == "feed/tenant=tenant-a/run123.ndjson.gz"
    assert up["extra"]["ServerSideEncryption"] == "AES256"
    # Body is real gzip NDJSON with one JSON object per line.
    lines = gzip.decompress(up["body"]).decode().strip().split("\n")
    assert len(lines) == 2
    assert json.loads(lines[0])["finding_id"] == "f-1"
    assert result.row_count == 2
    assert result.byte_count and result.byte_count > 0


def test_s3_destination_consumes_a_lazy_generator_without_materializing():
    """Feeding a generator (no len/indexing) proves the write path streams."""
    client = FakeS3Client()
    dest = S3ObjectStoreDestination("b", client_factory=lambda: client)
    max_index_seen = {"n": -1}

    def gen():
        for i in range(5000):
            max_index_seen["n"] = i
            yield _finding(i)

    result = dest.write_findings(gen(), tenant_id="t", run_id="r")
    assert result.row_count == 5000
    assert max_index_seen["n"] == 4999  # generator fully driven, sequentially
    assert len(gzip.decompress(client.uploads[0]["body"]).decode().strip().split("\n")) == 5000


# --------------------------------------------------------------------------
# ClickHouse warehouse destination
# --------------------------------------------------------------------------
def test_clickhouse_destination_flushes_in_bounded_batches():
    client = FakeClickHouseClient()
    dest = ClickHouseWarehouseDestination(client, batch_rows=500)

    result = dest.write_findings((_finding(i) for i in range(1200)), tenant_id="tenant-a", run_id="run9")

    assert client.ensured == 1
    # 1200 rows -> 500 + 500 + 200, never one giant insert (bounded memory).
    assert [len(b) for b in client.batches] == [500, 500, 200]
    assert all(len(b) <= 500 for b in client.batches)
    assert result.row_count == 1200
    assert client.table == "findings_feed"


def test_clickhouse_row_shape_carries_tenant_run_and_finding_fields():
    client = FakeClickHouseClient()
    dest = ClickHouseWarehouseDestination(client)
    dest.write_findings([_finding(1, status="open", effective_reach="reachable")], tenant_id="tnt", run_id="rid")
    row = client.batches[0][0]
    assert row["tenant_id"] == "tnt"
    assert row["run_id"] == "rid"
    assert row["finding_id"] == "f-1"
    assert row["cve_id"] == "CVE-2026-0001"
    assert row["status"] == "open"
    assert row["effective_reach"] == "reachable"
    assert isinstance(row["cvss_score"], float)


# --------------------------------------------------------------------------
# build_destination — connect-once credential resolution
# --------------------------------------------------------------------------
def test_build_destination_clickhouse_uses_stored_secret_as_access_token():
    dest = build_destination(
        "clickhouse",
        {"url": "http://ch:8123", "user": "svc", "database": "agent_bom"},
        secret="stored-token-xyz",
    )
    assert isinstance(dest, ClickHouseWarehouseDestination)
    assert dest._client.access_token == "stored-token-xyz"
    assert dest._client.url == "http://ch:8123"


def test_build_destination_rejects_deferred_and_unknown_kinds():
    assert set(DEFERRED_EXPORT_KINDS).isdisjoint(SUPPORTED_EXPORT_KINDS)
    with pytest.raises(ExportDestinationError):
        build_destination("bigquery", {})
    with pytest.raises(ExportDestinationError):
        build_destination("mystery", {})


# --------------------------------------------------------------------------
# Streaming findings source + tenant isolation
# --------------------------------------------------------------------------
def test_iter_current_findings_streams_all_pages_for_tenant_only():
    hub = FakeHub(
        {
            "tenant-a": [_finding(i) for i in range(1100)],
            "tenant-b": [_finding(9999)],
        }
    )
    rows = list(iter_current_findings("tenant-a", page_size=500, hub=hub))
    assert len(rows) == 1100
    assert all(c["tenant_id"] == "tenant-a" for c in hub.calls)
    # Paged, not one giant read: 500 + 500 + 100 -> 3 calls.
    assert len(hub.calls) == 3


def test_run_findings_export_end_to_end_uses_connect_once_secret(monkeypatch):
    captured: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "agent_bom.api.audit_log.log_action",
        lambda action, actor="system", resource="", **details: captured.append({"action": action, **details}),
    )
    ch_client = FakeClickHouseClient()
    dest = ClickHouseWarehouseDestination(ch_client)
    hub = FakeHub({"tenant-a": [_finding(i) for i in range(30)]})

    result = run_findings_export(
        tenant_id="tenant-a",
        kind="clickhouse",
        config={},
        secret="unused-because-destination-injected",
        destination_id="dest-1",
        destination=dest,
        hub=hub,
    )
    assert result.row_count == 30
    assert captured and captured[0]["action"] == "export.run"
    assert captured[0]["details"]["outcome"] == "success"
    assert captured[0]["details"]["row_count"] == 30


def test_run_findings_export_audits_failure_and_reraises(monkeypatch):
    captured: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "agent_bom.api.audit_log.log_action",
        lambda action, actor="system", resource="", **details: captured.append({"action": action, **details}),
    )

    class Boom:
        kind = "clickhouse"

        def write_findings(self, rows, *, tenant_id, run_id):
            raise RuntimeError("warehouse unreachable")

    with pytest.raises(RuntimeError):
        run_findings_export(tenant_id="t", kind="clickhouse", config={}, destination=Boom(), findings=[])
    assert captured[0]["details"]["outcome"] == "failure"
