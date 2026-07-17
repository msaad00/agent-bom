"""Tests for the scheduled findings/report lake-export engine (#4040).

Covers the streaming destination adapters (mocked S3 + mocked ClickHouse), the
connect-once credential path, tenant isolation, and bounded/streaming memory.
No live network: both destination clients are mocked.
"""

from __future__ import annotations

import gzip
import json
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from agent_bom.export.destinations import (
    DEFERRED_EXPORT_KINDS,
    SUPPORTED_EXPORT_KINDS,
    ClickHouseWarehouseDestination,
    ExportDestinationError,
    ExportPublicationIndeterminateError,
    S3ObjectStoreDestination,
    SnowflakeWarehouseDestination,
    build_destination,
)
from agent_bom.export.runner import iter_current_findings, run_findings_export


def _rsa_private_pem() -> str:
    """Generate a throwaway PKCS8 RSA private key at runtime.

    Never commit key material — even a fake PEM header trips secret scanners.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


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
        self.commands: list[str] = []
        self.committed_runs: list[dict[str, Any]] = []

    def ensure_tables(self) -> None:
        self.ensured += 1

    def execute(self, sql: str) -> str:
        self.commands.append(sql)
        return ""

    def insert_json(self, table: str, rows: list[dict[str, Any]]) -> None:
        if table.endswith("_runs"):
            self.committed_runs.extend(dict(r) for r in rows)
            return
        self.table = table
        # Copy so later mutation of the caller's buffer can't corrupt the record.
        self.batches.append([dict(r) for r in rows])


class FakeSnowflakeCursor:
    """Records executed SQL and, on PUT, decompresses the staged gzip NDJSON."""

    def __init__(self, owner: "FakeSnowflakeConnection") -> None:
        self._owner = owner

    def execute(self, sql: str, params: Any = None) -> "FakeSnowflakeCursor":
        self._owner.executed.append(sql)
        self._owner.execute_params.append(params)
        stripped = sql.lstrip()
        if stripped.upper() == "COMMIT":
            self._owner.committed += 1
        elif stripped.upper() == "ROLLBACK":
            self._owner.rolled_back += 1
        if stripped[:4].upper() == "PUT ":
            # PUT 'file://<abspath>' @%table ... — read the staged file the same
            # way a real Snowflake PUT would, proving the stream landed on disk.
            start = sql.find("file://") + len("file://")
            end = sql.find("'", start)
            path = sql[start:end] if end != -1 else sql[start:].split()[0]
            with gzip.open(path, "rt", encoding="utf-8") as gz:
                self._owner.staged_rows = [json.loads(line) for line in gz if line.strip()]
        return self

    def close(self) -> None:
        self._owner.cursor_closed += 1


class FakeSnowflakeConnection:
    """Minimal snowflake.connector-shaped connection double (no network)."""

    def __init__(self) -> None:
        self.executed: list[str] = []
        self.execute_params: list[Any] = []
        self.staged_rows: list[dict[str, Any]] = []
        self.committed = 0
        self.rolled_back = 0
        self.closed = 0
        self.cursor_closed = 0

    def cursor(self) -> FakeSnowflakeCursor:
        return FakeSnowflakeCursor(self)

    def commit(self) -> None:
        self.committed += 1

    def rollback(self) -> None:
        self.rolled_back += 1

    def close(self) -> None:
        self.closed += 1


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
    assert client.table == "findings_feed_staged"


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
# Snowflake warehouse destination — staged gzip NDJSON -> PUT -> COPY INTO
# --------------------------------------------------------------------------
def test_snowflake_destination_stages_and_copies_into_findings_feed():
    conn = FakeSnowflakeConnection()
    dest = SnowflakeWarehouseDestination(lambda: conn, database="ANALYTICS", schema="SEC", table="findings_feed")

    result = dest.write_findings(
        [_finding(1, status="open", effective_reach="reachable"), _finding(2)],
        tenant_id="tenant-a",
        run_id="run77",
    )

    assert result.kind == "snowflake"
    assert result.row_count == 2
    assert result.destination_uri == "snowflake://ANALYTICS/SEC/findings_feed"
    lowered = [s.lower() for s in conn.executed]
    # Idempotent-shape landing table created before load.
    assert any("create table if not exists" in s and "findings_feed" in s for s in lowered)
    # Bulk load path: PUT the gzip file to the table stage, then COPY INTO.
    assert any(s.lstrip().startswith("put ") and "@%findings_feed" in s.replace('"', "") for s in [x.lower() for x in conn.executed])
    copy = next(s for s in conn.executed if s.lstrip().upper().startswith("COPY INTO"))
    assert "MATCH_BY_COLUMN_NAME = CASE_INSENSITIVE" in copy.upper()
    assert "PURGE = TRUE" in copy.upper()
    assert "TYPE = JSON" in copy.upper()
    # Connection is opened once and always closed (connect-once, no per-run creds).
    assert conn.committed == 1
    assert conn.closed == 1
    assert conn.cursor_closed == 1
    put_index = next(i for i, sql in enumerate(conn.executed) if sql.lstrip().upper().startswith("PUT "))
    begin_index = conn.executed.index("BEGIN")
    delete_index = next(i for i, sql in enumerate(conn.executed) if sql.lstrip().upper().startswith("DELETE FROM"))
    copy_index = next(i for i, sql in enumerate(conn.executed) if sql.lstrip().upper().startswith("COPY INTO"))
    commit_index = conn.executed.index("COMMIT")
    assert put_index < begin_index < delete_index < copy_index < commit_index
    # Staged rows carry tenant/run scope and the finding fields.
    assert {r["finding_id"] for r in conn.staged_rows} == {"f-1", "f-2"}
    assert all(r["tenant_id"] == "tenant-a" and r["run_id"] == "run77" for r in conn.staged_rows)
    r0 = next(r for r in conn.staged_rows if r["finding_id"] == "f-1")
    assert r0["status"] == "open"
    assert r0["effective_reach"] == "reachable"
    assert r0["cve_id"] == "CVE-2026-0001"
    assert isinstance(r0["cvss_score"], float)


def test_snowflake_destination_streams_a_lazy_generator_without_materializing():
    """A generator feed proves rows stream to the staged file, bounded memory."""
    conn = FakeSnowflakeConnection()
    dest = SnowflakeWarehouseDestination(lambda: conn, database="DB", schema="S", table="findings_feed")
    max_index_seen = {"n": -1}

    def gen():
        for i in range(4000):
            max_index_seen["n"] = i
            yield _finding(i)

    result = dest.write_findings(gen(), tenant_id="t", run_id="r")
    assert result.row_count == 4000
    assert max_index_seen["n"] == 3999  # driven sequentially, never buffered whole
    assert len(conn.staged_rows) == 4000


def test_snowflake_destination_skips_ddl_when_ensure_schema_false():
    conn = FakeSnowflakeConnection()
    dest = SnowflakeWarehouseDestination(lambda: conn, database="DB", schema="S", ensure_schema=False)
    dest.write_findings([_finding(1)], tenant_id="t", run_id="r")
    assert not any("create table" in s.lower() for s in conn.executed)


def test_snowflake_destination_closes_connection_on_error():
    """A failure mid-load still closes the connection (no leaked session)."""

    class BoomCursor(FakeSnowflakeCursor):
        def execute(self, sql: str, params: Any = None):
            if sql.lstrip().upper().startswith("COPY INTO"):
                raise RuntimeError("copy failed")
            result = super().execute(sql, params)
            if sql.lstrip().upper().startswith("DELETE FROM"):
                self._owner.visible_rows = []
            elif sql.lstrip().upper() == "ROLLBACK":
                self._owner.visible_rows = list(self._owner.prior_rows)
            return result

    class BoomConn(FakeSnowflakeConnection):
        def __init__(self):
            super().__init__()
            self.visible_rows = ["prior-snapshot"]
            self.prior_rows = list(self.visible_rows)

        def cursor(self):
            return BoomCursor(self)

    conn = BoomConn()
    dest = SnowflakeWarehouseDestination(lambda: conn, database="DB", schema="S")
    with pytest.raises(RuntimeError):
        dest.write_findings([_finding(1)], tenant_id="t", run_id="r")
    assert conn.closed == 1
    assert conn.committed == 0
    assert conn.rolled_back == 1
    assert conn.visible_rows == ["prior-snapshot"]
    assert any(sql.lstrip().upper().startswith("REMOVE ") for sql in conn.executed)


def test_snowflake_same_run_retry_deletes_then_replaces_in_one_transaction():
    conn = FakeSnowflakeConnection()
    destination = SnowflakeWarehouseDestination(lambda: conn, database="DB", schema="S")
    destination.write_findings([_finding(1)], tenant_id="tenant", run_id="same-run")
    destination.write_findings([_finding(2)], tenant_id="tenant", run_id="same-run")

    deletes = [
        (sql, params)
        for sql, params in zip(conn.executed, conn.execute_params, strict=True)
        if sql.lstrip().upper().startswith("DELETE FROM")
    ]
    assert len(deletes) == 2
    assert all(params == ("tenant",) for _, params in deletes)
    assert conn.committed == 2
    for start in (0, conn.executed.index("BEGIN", 1)):
        begin = conn.executed.index("BEGIN", start)
        delete = next(i for i in range(begin + 1, len(conn.executed)) if conn.executed[i].lstrip().upper().startswith("DELETE FROM"))
        commit = conn.executed.index("COMMIT", delete)
        assert begin < delete < commit


def test_snowflake_zero_row_snapshot_replaces_whole_tenant_and_commits_marker():
    conn = FakeSnowflakeConnection()
    result = SnowflakeWarehouseDestination(lambda: conn, database="DB").write_findings(
        [], tenant_id="tenant", run_id="empty-run"
    )
    assert result.row_count == 0
    delete_idx = next(i for i, sql in enumerate(conn.executed) if sql.lstrip().upper().startswith("DELETE FROM"))
    marker_idx = next(
        i for i, sql in enumerate(conn.executed) if sql.lstrip().upper().startswith("INSERT INTO") and "_RUNS" in sql.upper()
    )
    commit_idx = conn.executed.index("COMMIT")
    assert conn.execute_params[delete_idx] == ("tenant",)
    assert conn.execute_params[marker_idx][:2] == ("tenant", "empty-run")
    assert conn.execute_params[marker_idx][3] == 0
    assert delete_idx < marker_idx < commit_idx
    assert not any(sql.lstrip().upper().startswith("COPY INTO") for sql in conn.executed)
    assert any(sql.lstrip().upper().startswith("REMOVE ") for sql in conn.executed)


def test_snowflake_lost_commit_response_reconciles_durable_marker():
    markers: set[tuple[str, str, str]] = set()

    class Cursor(FakeSnowflakeCursor):
        def execute(self, sql, params=None):
            result = super().execute(sql, params)
            upper = sql.lstrip().upper()
            if upper.startswith("INSERT INTO") and "_RUNS" in upper:
                markers.add(tuple(params[:3]))
            if upper == "COMMIT":
                raise TimeoutError("commit response lost")
            if upper.startswith("SELECT 1"):
                self._selected = tuple(params) in markers
            return result

        def fetchone(self):
            return (1,) if getattr(self, "_selected", False) else None

    class Conn(FakeSnowflakeConnection):
        def cursor(self):
            return Cursor(self)

    connections: list[Conn] = []

    def factory():
        conn = Conn()
        connections.append(conn)
        return conn

    result = SnowflakeWarehouseDestination(factory, database="DB").write_findings(
        [_finding(1)], tenant_id="tenant", run_id="run"
    )
    assert result.row_count == 1
    assert len(connections) == 2
    assert markers
    assert connections[0].rolled_back == 0


def test_snowflake_rollback_and_remove_failures_preserve_primary_error():
    class Cursor(FakeSnowflakeCursor):
        def execute(self, sql, params=None):
            upper = sql.lstrip().upper()
            if upper.startswith("COPY INTO"):
                raise RuntimeError("primary copy failure")
            if upper == "ROLLBACK" or upper.startswith("REMOVE"):
                raise RuntimeError("cleanup failure")
            return super().execute(sql, params)

    class Conn(FakeSnowflakeConnection):
        def cursor(self):
            return Cursor(self)

    with pytest.raises(RuntimeError, match="primary copy failure"):
        SnowflakeWarehouseDestination(lambda: Conn(), database="DB").write_findings(
            [_finding(1)], tenant_id="t", run_id="r"
        )


def test_clickhouse_failed_later_batch_is_cleaned_without_commit_marker():
    class Boom(FakeClickHouseClient):
        def insert_json(self, table, rows):
            if table == "findings_feed_staged" and self.batches:
                raise RuntimeError("later batch failed")
            super().insert_json(table, rows)

    client = Boom()
    dest = ClickHouseWarehouseDestination(client, batch_rows=1)
    with pytest.raises(RuntimeError):
        dest.write_findings([_finding(1), _finding(2)], tenant_id="tenant-a", run_id="run-failed")
    assert client.committed_runs == []
    assert any(command.startswith("ALTER TABLE findings_feed_staged DELETE") for command in client.commands)
    assert all("mutations_sync = 1" in command for command in client.commands if command.startswith("ALTER TABLE"))


def test_clickhouse_custom_table_creates_matching_manifest_and_escapes_scope():
    client = FakeClickHouseClient()
    dest = ClickHouseWarehouseDestination(client, table="custom_feed")

    def rows():
        yield _finding(1)
        raise RuntimeError("producer failed")

    with pytest.raises(RuntimeError, match="producer failed"):
        dest.write_findings(rows(), tenant_id="tenant\\x\n'", run_id="run\t\\'")
    assert any("CREATE TABLE IF NOT EXISTS custom_feed_runs" in command for command in client.commands)
    cleanup = next(command for command in client.commands if command.startswith("ALTER TABLE custom_feed_staged DELETE"))
    assert "tenant\\\\x\\n\\'" in cleanup
    assert "run\\t\\\\\\'" in cleanup


def test_clickhouse_manifest_failure_preserves_complete_staging_for_late_commit():
    class Boom(FakeClickHouseClient):
        def insert_json(self, table, rows):
            if table.endswith("_runs"):
                raise RuntimeError("manifest failed")
            super().insert_json(table, rows)

    client = Boom()
    with pytest.raises(ExportPublicationIndeterminateError, match="indeterminate"):
        ClickHouseWarehouseDestination(client).write_findings([_finding(1)], tenant_id="t", run_id="r")
    assert client.committed_runs == []
    assert not any(command.startswith("ALTER TABLE findings_feed_staged DELETE") for command in client.commands)
    assert client.batches


def test_clickhouse_staging_cleanup_failure_preserves_primary_error():
    class Boom(FakeClickHouseClient):
        def insert_json(self, table, rows):
            if table.endswith("_staged"):
                raise RuntimeError("primary batch failure")
            super().insert_json(table, rows)

        def execute(self, sql):
            if sql.startswith("ALTER TABLE"):
                raise RuntimeError("cleanup failure")
            return super().execute(sql)

    with pytest.raises(RuntimeError, match="primary batch failure"):
        ClickHouseWarehouseDestination(Boom()).write_findings([_finding(1)], tenant_id="t", run_id="r")


def test_clickhouse_concurrent_same_run_attempts_publish_only_complete_snapshots():
    class ConcurrentClient(FakeClickHouseClient):
        def __init__(self):
            super().__init__()
            self.staged_barrier = __import__("threading").Barrier(2)

        def insert_json(self, table, rows):
            if table.endswith("_staged"):
                self.staged_barrier.wait(timeout=2)
            return super().insert_json(table, rows)

    client = ConcurrentClient()
    destinations = [ClickHouseWarehouseDestination(client) for _ in range(2)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda dest: dest.write_findings([_finding(1)], tenant_id="t", run_id="same"), destinations))
    assert len(client.committed_runs) == 2
    assert len({run["publication_attempt_id"] for run in client.committed_runs}) == 2
    assert {batch[0]["publication_attempt_id"] for batch in client.batches} == {
        run["publication_attempt_id"] for run in client.committed_runs
    }
    assert all("commit_version" not in run for run in client.committed_runs)
    assert any("DEFAULT toUnixTimestamp64Nano(now64(9))" in command for command in client.commands)


def test_clickhouse_runs_ddl_is_identical_across_runtime_client_and_deployment_init():
    from agent_bom.cloud.clickhouse import _TABLE_DDL

    client = FakeClickHouseClient()
    ClickHouseWarehouseDestination(client).write_findings([], tenant_id="t", run_id="r")
    runtime = next(command for command in client.commands if command.startswith("CREATE TABLE IF NOT EXISTS findings_feed_runs"))
    client_ddl = next(ddl for ddl in _TABLE_DDL if ddl.startswith("CREATE TABLE IF NOT EXISTS findings_feed_runs"))
    init_sql = (Path(__file__).parents[1] / "deploy/supabase/clickhouse/init.sql").read_text()
    deployed = re.search(
        r"CREATE TABLE IF NOT EXISTS agent_bom\.findings_feed_runs \(.*?ORDER BY \(tenant_id, run_id\)",
        init_sql,
        re.DOTALL,
    )
    assert deployed is not None

    def normalize(ddl: str) -> str:
        compact = " ".join(ddl.replace("agent_bom.", "").split())
        return compact.replace("( ", "(").replace(" )", ")")

    assert normalize(runtime) == normalize(client_ddl) == normalize(deployed.group(0))
    assert "commit_version UInt64 DEFAULT toUnixTimestamp64Nano(now64(9))" in runtime
    assert "committed_at DateTime64(6) DEFAULT now64(6)" in runtime


def test_clickhouse_ambiguous_manifest_timeout_is_reconciled_as_committed():
    class Client(FakeClickHouseClient):
        def insert_json(self, table, rows):
            super().insert_json(table, rows)
            if table.endswith("_runs"):
                raise TimeoutError("response lost after commit")

        def execute(self, sql):
            self.commands.append(sql)
            if sql.lstrip().upper().startswith("SELECT COUNT()"):
                return "1\n"
            return ""

    client = Client()
    result = ClickHouseWarehouseDestination(client).write_findings([_finding(1)], tenant_id="t", run_id="r")
    assert result.row_count == 1
    assert not any(command.startswith("ALTER TABLE findings_feed_staged DELETE") for command in client.commands)


def test_build_destination_snowflake_wires_keypair_connection_from_stored_secret(monkeypatch):
    """build_destination('snowflake', ...) reuses the key-pair connect path with
    the stored PEM secret and non-secret account/warehouse config — no per-run
    credential, connect-once."""
    captured: dict[str, Any] = {}

    def fake_connect(**kwargs):
        captured.update(kwargs)
        return FakeSnowflakeConnection()

    monkeypatch.setattr("agent_bom.export.destinations.connect_snowflake_keypair", fake_connect)

    dest = build_destination(
        "snowflake",
        {
            "account": "acme-xy12345",
            "user": "ABOM_EXPORT",
            "role": "ABOM_EXPORT_WRITER",
            "warehouse": "ABOM_WH",
            "database": "ANALYTICS",
            "schema": "SEC",
            "table": "findings_feed",
        },
        secret=_rsa_private_pem(),
    )
    assert isinstance(dest, SnowflakeWarehouseDestination)
    # Force the lazy connection factory to fire so we can assert the wiring.
    dest.write_findings([_finding(1)], tenant_id="t", run_id="r")
    assert captured["account"] == "acme-xy12345"
    assert captured["user"] == "ABOM_EXPORT"
    assert captured["role"] == "ABOM_EXPORT_WRITER"
    assert captured["warehouse"] == "ABOM_WH"
    assert captured["database"] == "ANALYTICS"
    assert captured["schema"] == "SEC"
    assert captured["private_key_pem"].startswith("-----BEGIN PRIVATE KEY-----")


def test_build_destination_snowflake_requires_account_and_user():
    with pytest.raises(ExportDestinationError):
        build_destination("snowflake", {"user": "u", "database": "DB"}, secret="pem")
    with pytest.raises(ExportDestinationError):
        build_destination("snowflake", {"account": "a", "database": "DB"}, secret="pem")


def test_snowflake_is_a_supported_kind_not_deferred():
    assert "snowflake" in SUPPORTED_EXPORT_KINDS
    assert "snowflake" not in DEFERRED_EXPORT_KINDS


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


def test_run_findings_export_audits_ambiguous_publish_as_indeterminate(monkeypatch):
    captured: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "agent_bom.api.audit_log.log_action",
        lambda action, actor="system", resource="", **details: captured.append({"action": action, **details}),
    )

    class Ambiguous:
        kind = "bigquery"

        def write_findings(self, rows, *, tenant_id, run_id):
            raise ExportPublicationIndeterminateError("manifest may still commit")

    with pytest.raises(ExportPublicationIndeterminateError):
        run_findings_export(tenant_id="t", kind="bigquery", config={}, destination=Ambiguous(), findings=[])
    assert captured[0]["details"]["outcome"] == "indeterminate"
