"""Pluggable export destinations for scheduled findings delivery (#4040).

A *destination* is where a scheduled export lands a tenant's findings feed: an
object store (``s3``) or an analytics warehouse (``clickhouse``). Every adapter
implements one contract — :class:`ExportDestination` — whose ``write_findings``
consumes a **bounded, streaming** iterable of finding rows and never
materializes the whole result set in memory:

* :class:`S3ObjectStoreDestination` streams rows through a gzip writer backed by
  a spooled temp file (RAM-bounded, spills to disk past a threshold) and uploads
  with boto3's managed multipart transfer (``upload_fileobj``), which itself
  streams the file object rather than buffering it in memory.
* :class:`ClickHouseWarehouseDestination` flushes rows to the warehouse in
  bounded batches, so at most one batch is held at a time.
* :class:`SnowflakeWarehouseDestination` streams rows to a gzip NDJSON file,
  ``PUT``\\ s it to the table's internal stage, and ``COPY INTO``\\ s the
  ``findings_feed`` table — Snowflake's recommended bulk-load, bounded in RAM.

Landed adapters:

* object stores — ``s3``, ``azure-blob``, ``gcs`` (all stream the same gzip
  NDJSON snapshot to a tenant/run-partitioned object key).
* warehouses — ``clickhouse``, ``snowflake``, ``bigquery``, ``databricks`` (all
  land the same ``findings_feed`` row shape via the vendor's bulk-load path).

Destination credentials come from a stored, encrypted, revocable connection
(connect-once): the caller decrypts the single secret once and passes it to
:func:`build_destination`; adapters never prompt for a per-run credential.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from tempfile import NamedTemporaryFile, SpooledTemporaryFile
from typing import Any, Protocol, runtime_checkable

from agent_bom.cloud.connection_broker import connect_snowflake_keypair

logger = logging.getLogger(__name__)

# Kinds with a shipped adapter. Object stores: s3 / azure-blob / gcs. Warehouses:
# clickhouse / snowflake / bigquery / databricks.
SUPPORTED_EXPORT_KINDS: tuple[str, ...] = (
    "s3",
    "azure-blob",
    "gcs",
    "clickhouse",
    "snowflake",
    "bigquery",
    "databricks",
)
# No follow-up adapters remain queued behind the ExportDestination contract.
DEFERRED_EXPORT_KINDS: tuple[str, ...] = ()

# Rows spill to disk past this many bytes so upload RAM stays flat regardless of
# how many findings a tenant has.
_SPOOL_MAX_BYTES = 8 * 1024 * 1024
# ClickHouse insert batch size: rows are flushed every N so we never hold the
# full feed in memory.
_CH_BATCH_ROWS = 500

# String columns of the ``findings_feed`` landing table, shared by every
# warehouse adapter (ClickHouse + Snowflake) so the feed shape is identical
# across destinations. Mapping stays tolerant of missing keys.
_FEED_STRING_FIELDS = (
    "canonical_id",
    "severity",
    "package_name",
    "package_version",
    "ecosystem",
    "cve_id",
    "source",
    "status",
    "effective_reach",
    "first_seen",
    "last_seen",
)


class ExportDestinationError(RuntimeError):
    """Raised when a destination cannot be built or written to."""


@dataclass(frozen=True)
class ExportResult:
    """Outcome of a single findings export run."""

    kind: str
    destination_uri: str
    row_count: int
    byte_count: int | None = None


@runtime_checkable
class ExportDestination(Protocol):
    """Contract every export destination adapter implements."""

    kind: str

    def write_findings(self, rows: Iterable[dict[str, Any]], *, tenant_id: str, run_id: str) -> ExportResult:
        """Stream ``rows`` to the destination and return the run outcome."""
        ...


def _finding_id(row: dict[str, Any]) -> str:
    """Best-effort stable identifier for a finding row."""
    for key in ("finding_id", "canonical_id", "id", "canonical_finding_id"):
        value = row.get(key)
        if value:
            return str(value)
    return ""


def _feed_row(finding: dict[str, Any], *, tenant_id: str, run_id: str) -> dict[str, Any]:
    """Normalize a finding into the shared ``findings_feed`` row shape.

    Every warehouse adapter lands the same columns so the feed is identical
    across destinations; ``tenant_id`` / ``run_id`` scope each row.
    """
    row: dict[str, Any] = {
        "tenant_id": tenant_id,
        "run_id": run_id,
        "finding_id": _finding_id(finding),
        "cvss_score": float(finding.get("cvss_score") or 0.0),
        "epss_score": float(finding.get("epss_score") or 0.0),
    }
    for field in _FEED_STRING_FIELDS:
        row[field] = str(finding.get(field, "") or "")
    return row


def _warehouse_feed_row(finding: dict[str, Any], *, tenant_id: str, run_id: str, exported_at: str) -> dict[str, Any]:
    """Feed row plus the run's ``exported_at`` stamp, shared by warehouse adapters.

    ``exported_at`` lets a query keep the latest row per (tenant_id, finding_id)
    since every warehouse landing is append-only.
    """
    feed = _feed_row(finding, tenant_id=tenant_id, run_id=run_id)
    feed["exported_at"] = exported_at
    return feed


def _object_key(prefix: str, tenant_id: str, run_id: str) -> str:
    """Tenant/run-partitioned object key for an object-store export."""
    safe_tenant = (tenant_id or "default").replace("/", "_").replace("\\", "_")
    clean_prefix = prefix.strip("/")
    name = f"{run_id}.ndjson.gz"
    if clean_prefix:
        return f"{clean_prefix}/tenant={safe_tenant}/{name}"
    return f"tenant={safe_tenant}/{name}"


class S3ObjectStoreDestination:
    """Stream a gzip NDJSON findings snapshot to an S3 object store.

    Uses the ambient boto3 credential chain (IRSA / instance role / brokered
    short-lived creds) — no static access key is held in the trust path. The
    connect-once *connection* stores the non-secret bucket/prefix/region config;
    ``client_factory`` is injectable for tests.
    """

    kind = "s3"

    def __init__(
        self,
        bucket: str,
        *,
        prefix: str = "findings-feed",
        region: str | None = None,
        client_factory: Callable[[], Any] | None = None,
    ) -> None:
        if not bucket:
            raise ExportDestinationError("S3 export destination requires a bucket")
        self._bucket = bucket
        self._prefix = prefix
        self._region = region
        self._client_factory = client_factory or self._default_client_factory

    def _default_client_factory(self) -> Any:
        try:
            import boto3
        except ImportError as exc:  # pragma: no cover - optional extra
            raise ExportDestinationError("S3 export requires boto3; install with: pip install 'agent-bom[aws]'") from exc
        kwargs: dict[str, str] = {}
        if self._region:
            kwargs["region_name"] = self._region
        return boto3.client("s3", **kwargs)

    def write_findings(self, rows: Iterable[dict[str, Any]], *, tenant_id: str, run_id: str) -> ExportResult:
        key = _object_key(self._prefix, tenant_id, run_id)
        row_count = 0
        # SpooledTemporaryFile keeps small exports in RAM but spills to disk past
        # the threshold, so a huge tenant never inflates process memory.
        with SpooledTemporaryFile(max_size=_SPOOL_MAX_BYTES) as spool:
            with gzip.GzipFile(fileobj=spool, mode="wb") as gz:
                for row in rows:
                    line = json.dumps(row, separators=(",", ":"), ensure_ascii=True, default=str)
                    gz.write(line.encode("utf-8"))
                    gz.write(b"\n")
                    row_count += 1
            byte_count = spool.tell()
            spool.seek(0)
            client = self._client_factory()
            client.upload_fileobj(
                spool,
                self._bucket,
                key,
                ExtraArgs={"ContentType": "application/gzip", "ServerSideEncryption": "AES256"},
            )
        uri = f"s3://{self._bucket}/{key}"
        logger.info("Exported %d findings to %s", row_count, uri)
        return ExportResult(kind=self.kind, destination_uri=uri, row_count=row_count, byte_count=byte_count)


def _stream_gzip_ndjson(rows: Iterable[dict[str, Any]], spool: Any) -> int:
    """Write ``rows`` as gzip NDJSON into ``spool`` and return the row count.

    Shared by every object-store adapter so the on-disk snapshot shape is
    byte-identical across s3 / azure-blob / gcs. Streaming: at most one row is
    materialized at a time, so RAM stays flat regardless of tenant size.
    """
    row_count = 0
    with gzip.GzipFile(fileobj=spool, mode="wb") as gz:
        for row in rows:
            line = json.dumps(row, separators=(",", ":"), ensure_ascii=True, default=str)
            gz.write(line.encode("utf-8"))
            gz.write(b"\n")
            row_count += 1
    return row_count


class AzureBlobObjectStoreDestination:
    """Stream a gzip NDJSON findings snapshot to an Azure Blob container.

    Mirrors :class:`S3ObjectStoreDestination`: rows stream through a gzip writer
    backed by a spooled temp file (RAM-bounded, spills to disk past a threshold),
    then the blob is uploaded with ``overwrite=True``. The client is built once
    from the connect-once connection (a stored, encrypted Azure Storage
    connection string, or ambient managed identity against ``account_url``) — no
    per-run credential. ``client_factory`` is injectable for tests.
    """

    kind = "azure-blob"

    def __init__(
        self,
        container: str,
        *,
        prefix: str = "findings-feed",
        client_factory: Callable[[], Any],
    ) -> None:
        if not container:
            raise ExportDestinationError("Azure Blob export destination requires a container")
        self._container = container
        self._prefix = prefix
        self._client_factory = client_factory

    def write_findings(self, rows: Iterable[dict[str, Any]], *, tenant_id: str, run_id: str) -> ExportResult:
        key = _object_key(self._prefix, tenant_id, run_id)
        with SpooledTemporaryFile(max_size=_SPOOL_MAX_BYTES) as spool:
            row_count = _stream_gzip_ndjson(rows, spool)
            byte_count = spool.tell()
            spool.seek(0)
            service = self._client_factory()
            blob = service.get_blob_client(container=self._container, blob=key)
            blob.upload_blob(spool, overwrite=True)
        uri = f"azure-blob://{self._container}/{key}"
        logger.info("Exported %d findings to %s", row_count, uri)
        return ExportResult(kind=self.kind, destination_uri=uri, row_count=row_count, byte_count=byte_count)


class GcsObjectStoreDestination:
    """Stream a gzip NDJSON findings snapshot to a Google Cloud Storage bucket.

    Mirrors :class:`S3ObjectStoreDestination`. The client is built once from the
    connect-once connection (a stored service-account key JSON, or ambient
    Application Default Credentials) — no per-run credential. The blob is uploaded
    from the spooled file object (streamed, not buffered). ``client_factory`` is
    injectable for tests.
    """

    kind = "gcs"

    def __init__(
        self,
        bucket: str,
        *,
        prefix: str = "findings-feed",
        client_factory: Callable[[], Any],
    ) -> None:
        if not bucket:
            raise ExportDestinationError("GCS export destination requires a bucket")
        self._bucket = bucket
        self._prefix = prefix
        self._client_factory = client_factory

    def write_findings(self, rows: Iterable[dict[str, Any]], *, tenant_id: str, run_id: str) -> ExportResult:
        key = _object_key(self._prefix, tenant_id, run_id)
        with SpooledTemporaryFile(max_size=_SPOOL_MAX_BYTES) as spool:
            row_count = _stream_gzip_ndjson(rows, spool)
            byte_count = spool.tell()
            spool.seek(0)
            client = self._client_factory()
            blob = client.bucket(self._bucket).blob(key)
            blob.upload_from_file(spool, content_type="application/gzip", rewind=True)
        uri = f"gs://{self._bucket}/{key}"
        logger.info("Exported %d findings to %s", row_count, uri)
        return ExportResult(kind=self.kind, destination_uri=uri, row_count=row_count, byte_count=byte_count)


class ClickHouseWarehouseDestination:
    """Stream findings into a ClickHouse warehouse table in bounded batches.

    Reuses the existing zero-dependency analytics client
    (:class:`agent_bom.cloud.clickhouse.ClickHouseClient`) and its
    ``findings_feed`` table. Rows are inserted in batches of at most
    ``batch_rows`` so only one batch is ever held in memory.
    """

    kind = "clickhouse"

    def __init__(
        self,
        client: Any,
        *,
        table: str = "findings_feed",
        ensure_schema: bool = True,
        batch_rows: int = _CH_BATCH_ROWS,
    ) -> None:
        self._client = client
        self._table = table
        self._ensure_schema = ensure_schema
        self._batch_rows = max(1, batch_rows)

    def _to_row(self, finding: dict[str, Any], *, tenant_id: str, run_id: str) -> dict[str, Any]:
        return _feed_row(finding, tenant_id=tenant_id, run_id=run_id)

    def write_findings(self, rows: Iterable[dict[str, Any]], *, tenant_id: str, run_id: str) -> ExportResult:
        if self._ensure_schema:
            self._client.ensure_tables()
        row_count = 0
        batch: list[dict[str, Any]] = []
        for finding in rows:
            batch.append(self._to_row(finding, tenant_id=tenant_id, run_id=run_id))
            if len(batch) >= self._batch_rows:
                self._client.insert_json(self._table, batch)
                row_count += len(batch)
                batch = []
        if batch:
            self._client.insert_json(self._table, batch)
            row_count += len(batch)
        uri = f"clickhouse://{getattr(self._client, 'database', 'agent_bom')}/{self._table}"
        logger.info("Exported %d findings to %s", row_count, uri)
        return ExportResult(kind=self.kind, destination_uri=uri, row_count=row_count)


# Column DDL for the Snowflake ``findings_feed`` landing table. Order mirrors the
# shared feed-row shape; ``exported_at`` carries the run's export timestamp.
_SF_STRING_COLUMNS = ("tenant_id", "run_id", "finding_id", *_FEED_STRING_FIELDS, "exported_at")
_SF_FLOAT_COLUMNS = ("cvss_score", "epss_score")


def _sf_ident(name: str) -> str:
    """Quote a Snowflake identifier, escaping embedded quotes (case-preserving)."""
    return '"' + str(name).replace('"', '""') + '"'


class SnowflakeWarehouseDestination:
    """Stream findings into a Snowflake ``findings_feed`` table via staged COPY.

    Bulk-load path (verified against Snowflake docs): stream rows to a gzip
    NDJSON file (bounded — the whole feed is never held in RAM), ``PUT`` it to the
    table's internal stage, then ``COPY INTO`` with ``MATCH_BY_COLUMN_NAME =
    CASE_INSENSITIVE`` so each newline-delimited JSON object lands as one typed
    row. ``PURGE = TRUE`` clears the stage after a successful load. This is
    Snowflake's recommended bulk-ingest shape (COPY INTO from an internal stage),
    not row-at-a-time INSERT, so it scales to millions of findings on a cadence.

    Each run appends its snapshot tagged with ``run_id`` + ``exported_at`` (COPY
    INTO is append-only — Snowflake has no ReplacingMergeTree). The table is
    ``CLUSTER BY (tenant_id, finding_id)`` so the current state is the latest row
    per finding, e.g.::

        SELECT * FROM findings_feed
        QUALIFY ROW_NUMBER() OVER (
            PARTITION BY tenant_id, finding_id ORDER BY exported_at DESC) = 1

    The connection comes from ``connection_factory`` — built once from the stored,
    encrypted, revocable connect-once connection (key-pair auth reused from the
    cloud connection broker). No per-run credential is passed. The connection is
    always closed, and committed only on a fully successful load.
    """

    kind = "snowflake"

    def __init__(
        self,
        connection_factory: Callable[[], Any],
        *,
        database: str,
        schema: str = "PUBLIC",
        table: str = "findings_feed",
        ensure_schema: bool = True,
    ) -> None:
        if not database:
            raise ExportDestinationError("Snowflake export destination requires a database")
        self._connection_factory = connection_factory
        self._database = database
        self._schema = schema or "PUBLIC"
        self._table = table or "findings_feed"
        self._ensure_schema = ensure_schema

    def _create_table_sql(self) -> str:
        cols = [f"{_sf_ident(name)} STRING" for name in _SF_STRING_COLUMNS]
        cols += [f"{_sf_ident(name)} FLOAT" for name in _SF_FLOAT_COLUMNS]
        return f"CREATE TABLE IF NOT EXISTS {_sf_ident(self._table)} (\n  " + ",\n  ".join(cols) + "\n) CLUSTER BY (tenant_id, finding_id)"

    def write_findings(self, rows: Iterable[dict[str, Any]], *, tenant_id: str, run_id: str) -> ExportResult:
        from datetime import datetime, timezone

        exported_at = datetime.now(timezone.utc).isoformat()
        table_ref = _sf_ident(self._table)
        stage_ref = f"@%{_sf_ident(self._table)}"

        conn = self._connection_factory()
        tmp_path = ""
        try:
            cursor = conn.cursor()
            try:
                if self._ensure_schema:
                    cursor.execute(self._create_table_sql())
                # Stream rows to a gzip NDJSON file: bounded RAM, spills to disk,
                # so a huge tenant never inflates process memory.
                with NamedTemporaryFile(suffix=".ndjson.gz", delete=False) as handle:
                    tmp_path = handle.name
                row_count = 0
                with gzip.open(tmp_path, "wt", encoding="utf-8") as gz:
                    for finding in rows:
                        feed = _feed_row(finding, tenant_id=tenant_id, run_id=run_id)
                        feed["exported_at"] = exported_at
                        gz.write(json.dumps(feed, separators=(",", ":"), ensure_ascii=True, default=str))
                        gz.write("\n")
                        row_count += 1
                # PUT the pre-gzipped file to the table stage (no re-compression),
                # then bulk COPY INTO and purge the stage on success.
                cursor.execute(f"PUT 'file://{tmp_path}' {stage_ref} AUTO_COMPRESS=FALSE SOURCE_COMPRESSION=GZIP OVERWRITE=TRUE")
                cursor.execute(
                    f"COPY INTO {table_ref} FROM {stage_ref} "
                    "FILE_FORMAT = (TYPE = JSON) "
                    "MATCH_BY_COLUMN_NAME = CASE_INSENSITIVE "
                    "PURGE = TRUE"
                )
                conn.commit()
            finally:
                cursor.close()
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:  # pragma: no cover - best-effort temp cleanup
                    logger.debug("temp export file cleanup skipped", exc_info=True)
            conn.close()

        uri = f"snowflake://{self._database}/{self._schema}/{self._table}"
        logger.info("Exported %d findings to %s", row_count, uri)
        return ExportResult(kind=self.kind, destination_uri=uri, row_count=row_count)


class BigQueryWarehouseDestination:
    """Load findings into a BigQuery ``findings_feed`` table in bounded batches.

    Mirrors :class:`ClickHouseWarehouseDestination`: rows are loaded in batches of
    at most ``batch_rows`` via ``client.load_table_from_json`` (BigQuery's native
    JSON bulk-load), so at most one batch is held in memory. The load's
    ``CREATE_IF_NEEDED`` disposition creates the table with the explicit feed
    schema; the dataset is ensured up front (a load cannot create a dataset). Each
    run appends its snapshot tagged with ``run_id`` + ``exported_at`` (append-only
    — the latest row per finding is the current state). ``client`` and
    ``job_config`` are injected so the adapter itself is SDK-free and testable.
    """

    kind = "bigquery"

    def __init__(
        self,
        client: Any,
        *,
        project: str,
        dataset: str,
        table: str = "findings_feed",
        job_config: Any = None,
        ensure_schema: bool = True,
        batch_rows: int = _CH_BATCH_ROWS,
    ) -> None:
        if not project:
            raise ExportDestinationError("BigQuery export destination requires a project")
        if not dataset:
            raise ExportDestinationError("BigQuery export destination requires a dataset")
        self._client = client
        self._project = project
        self._dataset = dataset
        self._table = table or "findings_feed"
        self._job_config = job_config
        self._ensure_schema = ensure_schema
        self._batch_rows = max(1, batch_rows)

    def _load(self, table_ref: str, batch: list[dict[str, Any]]) -> None:
        # load_table_from_json returns a LoadJob; .result() blocks until the load
        # finishes (or raises), so a failed batch surfaces immediately.
        self._client.load_table_from_json(batch, table_ref, job_config=self._job_config).result()

    def write_findings(self, rows: Iterable[dict[str, Any]], *, tenant_id: str, run_id: str) -> ExportResult:
        from datetime import datetime, timezone

        exported_at = datetime.now(timezone.utc).isoformat()
        table_ref = f"{self._project}.{self._dataset}.{self._table}"
        if self._ensure_schema:
            self._client.create_dataset(f"{self._project}.{self._dataset}", exists_ok=True)
        row_count = 0
        batch: list[dict[str, Any]] = []
        for finding in rows:
            batch.append(_warehouse_feed_row(finding, tenant_id=tenant_id, run_id=run_id, exported_at=exported_at))
            if len(batch) >= self._batch_rows:
                self._load(table_ref, batch)
                row_count += len(batch)
                batch = []
        if batch:
            self._load(table_ref, batch)
            row_count += len(batch)
        uri = f"bigquery://{self._project}/{self._dataset}/{self._table}"
        logger.info("Exported %d findings to %s", row_count, uri)
        return ExportResult(kind=self.kind, destination_uri=uri, row_count=row_count)


def _dbx_ident(name: str) -> str:
    """Quote a Databricks (Unity Catalog) identifier with backticks."""
    return "`" + str(name).replace("`", "``") + "`"


class DatabricksWarehouseDestination:
    """Insert findings into a Databricks ``findings_feed`` Delta table in batches.

    Mirrors :class:`SnowflakeWarehouseDestination`: a DBAPI connection is opened
    once from the connect-once connection (``databricks-sql-connector``,
    key/OAuth token from the stored secret — no per-run credential), a
    ``CREATE TABLE IF NOT EXISTS`` lands the feed schema, then rows are inserted
    with parameterized ``executemany`` in bounded batches (native ``?`` binding,
    injection-safe). The connection is always closed and committed only on a
    fully successful load. Append-only, tagged with ``run_id`` + ``exported_at``.
    ``connection_factory`` is injected so the adapter is SDK-free and testable.
    """

    kind = "databricks"

    def __init__(
        self,
        connection_factory: Callable[[], Any],
        *,
        catalog: str,
        schema: str,
        table: str = "findings_feed",
        ensure_schema: bool = True,
        batch_rows: int = _CH_BATCH_ROWS,
    ) -> None:
        if not catalog:
            raise ExportDestinationError("Databricks export destination requires a catalog")
        if not schema:
            raise ExportDestinationError("Databricks export destination requires a schema")
        self._connection_factory = connection_factory
        self._catalog = catalog
        self._schema = schema
        self._table = table or "findings_feed"
        self._ensure_schema = ensure_schema
        self._batch_rows = max(1, batch_rows)

    def _full_table(self) -> str:
        return f"{_dbx_ident(self._catalog)}.{_dbx_ident(self._schema)}.{_dbx_ident(self._table)}"

    def _create_table_sql(self) -> str:
        cols = [f"{_dbx_ident(c)} STRING" for c in _SF_STRING_COLUMNS]
        cols += [f"{_dbx_ident(c)} DOUBLE" for c in _SF_FLOAT_COLUMNS]
        return f"CREATE TABLE IF NOT EXISTS {self._full_table()} (\n  " + ",\n  ".join(cols) + "\n) USING DELTA"

    def _insert_sql(self) -> str:
        columns = _SF_STRING_COLUMNS + _SF_FLOAT_COLUMNS
        col_list = ", ".join(_dbx_ident(c) for c in columns)
        placeholders = ", ".join("?" for _ in columns)
        return f"INSERT INTO {self._full_table()} ({col_list}) VALUES ({placeholders})"

    @staticmethod
    def _row_tuple(feed: dict[str, Any]) -> tuple[Any, ...]:
        strings = tuple(str(feed.get(c, "") or "") for c in _SF_STRING_COLUMNS)
        floats = tuple(float(feed.get(c) or 0.0) for c in _SF_FLOAT_COLUMNS)
        return strings + floats

    def write_findings(self, rows: Iterable[dict[str, Any]], *, tenant_id: str, run_id: str) -> ExportResult:
        from datetime import datetime, timezone

        exported_at = datetime.now(timezone.utc).isoformat()
        insert_sql = self._insert_sql()
        row_count = 0
        conn = self._connection_factory()
        try:
            cursor = conn.cursor()
            try:
                if self._ensure_schema:
                    cursor.execute(self._create_table_sql())
                batch: list[tuple[Any, ...]] = []
                for finding in rows:
                    feed = _warehouse_feed_row(finding, tenant_id=tenant_id, run_id=run_id, exported_at=exported_at)
                    batch.append(self._row_tuple(feed))
                    if len(batch) >= self._batch_rows:
                        cursor.executemany(insert_sql, batch)
                        row_count += len(batch)
                        batch = []
                if batch:
                    cursor.executemany(insert_sql, batch)
                    row_count += len(batch)
                if hasattr(conn, "commit"):
                    conn.commit()
            finally:
                cursor.close()
        finally:
            conn.close()
        uri = f"databricks://{self._catalog}/{self._schema}/{self._table}"
        logger.info("Exported %d findings to %s", row_count, uri)
        return ExportResult(kind=self.kind, destination_uri=uri, row_count=row_count)


# ── Default SDK client factories ─────────────────────────────────────────────
# Each lazily imports its vendor SDK so the base package stays slim; the import
# only fires when a real export runs. Module-level (not nested in
# build_destination) so tests can monkeypatch the SDK boundary without a network.
def _default_azure_blob_service(secret: str | None, account_url: str) -> Any:
    try:
        from azure.storage.blob import BlobServiceClient
    except ImportError as exc:  # pragma: no cover - optional extra
        raise ExportDestinationError("Azure Blob export requires azure-storage-blob; install with: pip install 'agent-bom[azure]'") from exc
    if secret:
        return BlobServiceClient.from_connection_string(secret)
    try:
        from azure.identity import DefaultAzureCredential
    except ImportError as exc:  # pragma: no cover - optional extra
        raise ExportDestinationError(
            "Azure Blob managed-identity export requires azure-identity; install with: pip install 'agent-bom[azure]'"
        ) from exc
    return BlobServiceClient(account_url=account_url, credential=DefaultAzureCredential())


def _default_gcs_client(secret: str | None) -> Any:
    try:
        from google.cloud import storage
    except ImportError as exc:  # pragma: no cover - optional extra
        raise ExportDestinationError("GCS export requires google-cloud-storage; install with: pip install 'agent-bom[gcp]'") from exc
    if secret:
        return storage.Client.from_service_account_info(json.loads(secret))
    return storage.Client()


def _default_bigquery_client(project: str) -> Any:
    try:
        from google.cloud import bigquery
    except ImportError as exc:  # pragma: no cover - optional extra
        raise ExportDestinationError("BigQuery export requires google-cloud-bigquery; install with: pip install 'agent-bom[gcp]'") from exc
    return bigquery.Client(project=project)


def _default_bigquery_job_config() -> Any:
    from google.cloud import bigquery

    schema = [bigquery.SchemaField(c, "STRING") for c in _SF_STRING_COLUMNS]
    schema += [bigquery.SchemaField(c, "FLOAT64") for c in _SF_FLOAT_COLUMNS]
    return bigquery.LoadJobConfig(
        schema=schema,
        write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
        create_disposition=bigquery.CreateDisposition.CREATE_IF_NEEDED,
        source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
    )


def _default_databricks_connection(config: dict[str, Any], secret: str | None) -> Any:
    try:
        from databricks import sql as databricks_sql
    except ImportError as exc:  # pragma: no cover - optional extra
        raise ExportDestinationError(
            "Databricks export requires databricks-sql-connector; install with: pip install 'agent-bom[databricks]'"
        ) from exc
    return databricks_sql.connect(
        server_hostname=config["server_hostname"],
        http_path=config["http_path"],
        access_token=secret or "",
    )


def build_destination(kind: str, config: dict[str, Any], secret: str | None = None) -> ExportDestination:
    """Build a destination adapter from a connect-once connection record.

    ``config`` carries the non-secret parameters (bucket/container/prefix/region,
    or warehouse project/dataset/catalog/schema/table). ``secret`` is the single
    decrypted secret from the stored connection (warehouse access token, Snowflake
    PEM, Azure connection string, or GCS service-account key JSON). ``s3`` uses the
    ambient credential chain and ignores it; ``gcs`` / ``azure-blob`` fall back to
    ambient credentials (ADC / managed identity) when no secret is stored.
    """
    normalized = (kind or "").strip().lower()
    if normalized == "s3":
        return S3ObjectStoreDestination(
            bucket=str(config.get("bucket", "")),
            prefix=str(config.get("prefix", "findings-feed")),
            region=(str(config["region"]) if config.get("region") else None),
        )
    if normalized == "azure-blob":
        container = str(config.get("container", "")).strip()
        if not container:
            raise ExportDestinationError("Azure Blob export destination requires 'container' in config")
        account_url = str(config.get("account_url", "") or "").strip()
        if not secret and not account_url:
            raise ExportDestinationError("Azure Blob export requires a connection-string secret or an 'account_url' for managed identity")
        prefix = str(config.get("prefix", "findings-feed") or "findings-feed")

        def _azure_factory() -> Any:
            return _default_azure_blob_service(secret, account_url)

        return AzureBlobObjectStoreDestination(container, prefix=prefix, client_factory=_azure_factory)
    if normalized == "gcs":
        bucket = str(config.get("bucket", "")).strip()
        if not bucket:
            raise ExportDestinationError("GCS export destination requires 'bucket' in config")
        prefix = str(config.get("prefix", "findings-feed") or "findings-feed")

        def _gcs_factory() -> Any:
            return _default_gcs_client(secret)

        return GcsObjectStoreDestination(bucket, prefix=prefix, client_factory=_gcs_factory)
    if normalized == "clickhouse":
        from agent_bom.cloud.clickhouse import ClickHouseClient

        client = ClickHouseClient(
            url=(str(config["url"]) if config.get("url") else None),
            user=(str(config["user"]) if config.get("user") else None),
            access_token=secret or None,
            database=str(config.get("database", "agent_bom")),
        )
        return ClickHouseWarehouseDestination(client, table=str(config.get("table", "findings_feed")))
    if normalized == "snowflake":
        account = str(config.get("account", "")).strip()
        user = str(config.get("user", "")).strip()
        database = str(config.get("database", "")).strip()
        if not account or not user:
            raise ExportDestinationError("Snowflake export destination requires 'account' and 'user' in config")
        if not database:
            raise ExportDestinationError("Snowflake export destination requires 'database' in config")
        schema = str(config.get("schema", "") or "PUBLIC").strip() or "PUBLIC"
        role = str(config.get("role", "") or "").strip()
        warehouse = str(config.get("warehouse", "") or "").strip()
        table = str(config.get("table", "findings_feed") or "findings_feed").strip()
        pem = secret or ""

        def _factory() -> Any:
            # Connect-once: key-pair PEM comes from the stored, decrypted secret;
            # the session is scoped to the configured write role/warehouse/schema.
            return connect_snowflake_keypair(
                account=account,
                user=user,
                private_key_pem=pem,
                role=role,
                warehouse=warehouse,
                database=database,
                schema=schema,
            )

        return SnowflakeWarehouseDestination(_factory, database=database, schema=schema, table=table)
    if normalized == "bigquery":
        project = str(config.get("project", "")).strip()
        dataset = str(config.get("dataset", "")).strip()
        if not project:
            raise ExportDestinationError("BigQuery export destination requires 'project' in config")
        if not dataset:
            raise ExportDestinationError("BigQuery export destination requires 'dataset' in config")
        table = str(config.get("table", "findings_feed") or "findings_feed").strip()
        # Client + job config are built eagerly (mirrors the ClickHouse path); the
        # google-cloud-bigquery import fires only here, at export-run time.
        client = _default_bigquery_client(project)
        job_config = _default_bigquery_job_config()
        return BigQueryWarehouseDestination(client, project=project, dataset=dataset, table=table, job_config=job_config)
    if normalized == "databricks":
        server_hostname = str(config.get("server_hostname", "")).strip()
        http_path = str(config.get("http_path", "")).strip()
        catalog = str(config.get("catalog", "")).strip()
        schema = str(config.get("schema", "")).strip()
        if not server_hostname or not http_path:
            raise ExportDestinationError("Databricks export destination requires 'server_hostname' and 'http_path' in config")
        if not catalog:
            raise ExportDestinationError("Databricks export destination requires 'catalog' in config")
        if not schema:
            raise ExportDestinationError("Databricks export destination requires 'schema' in config")
        table = str(config.get("table", "findings_feed") or "findings_feed").strip()
        conn_config = {"server_hostname": server_hostname, "http_path": http_path}

        def _dbx_factory() -> Any:
            # Connect-once: the DBAPI connection is opened from the stored,
            # decrypted access token; no per-run credential is passed.
            return _default_databricks_connection(conn_config, secret)

        return DatabricksWarehouseDestination(_dbx_factory, catalog=catalog, schema=schema, table=table)
    raise ExportDestinationError(f"Unknown export destination kind {normalized!r}; supported: {', '.join(SUPPORTED_EXPORT_KINDS)}")
