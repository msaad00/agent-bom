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
import hashlib
import json
import logging
import os
import re
import uuid
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
_RUNS_SUFFIX = "_runs"
_STAGED_SUFFIX = "_staged"
_ATTEMPT_COLUMN = "publication_attempt_id"
_WAREHOUSE_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_BIGQUERY_PROJECT_IDENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")


def _warehouse_ident(value: str, *, field: str) -> str:
    if not _WAREHOUSE_IDENT.fullmatch(value):
        raise ExportDestinationError(f"Warehouse export {field} must be a simple SQL identifier")
    return value


def _bigquery_project_ident(value: str) -> str:
    if not _BIGQUERY_PROJECT_IDENT.fullmatch(value):
        raise ExportDestinationError("BigQuery export project must be a simple project identifier")
    return value


def _clickhouse_literal(value: str) -> str:
    """Escape a ClickHouse single-quoted string literal."""
    return (
        value.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t").replace("\0", "\\0")
    )


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


class ExportPublicationIndeterminateError(ExportDestinationError):
    """Publication may still complete; callers must not classify it as failed."""


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
    """Stage findings in ClickHouse and publish a complete attempt pointer.

    Reuses the existing zero-dependency analytics client
    (:class:`agent_bom.cloud.clickhouse.ClickHouseClient`) and its
    Rows are inserted into an attempt-scoped staging table in batches of at
    most ``batch_rows``. A single manifest row publishes the complete attempt,
    so concurrent processes never expose each other's partial batches.
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
        self._table = _warehouse_ident(table, field="table")
        self._ensure_schema = ensure_schema
        self._batch_rows = max(1, batch_rows)

    def _to_row(self, finding: dict[str, Any], *, tenant_id: str, run_id: str) -> dict[str, Any]:
        return _feed_row(finding, tenant_id=tenant_id, run_id=run_id)

    def write_findings(self, rows: Iterable[dict[str, Any]], *, tenant_id: str, run_id: str) -> ExportResult:
        if self._ensure_schema:
            self._client.ensure_tables()
        staged_table = f"{self._table}{_STAGED_SUFFIX}"
        runs_table = f"{self._table}{_RUNS_SUFFIX}"
        attempt_id = uuid.uuid4().hex
        escaped_tenant = _clickhouse_literal(tenant_id)
        escaped_run = _clickhouse_literal(run_id)
        escaped_attempt = _clickhouse_literal(attempt_id)
        self._client.execute(
            f"CREATE TABLE IF NOT EXISTS {runs_table} ("
            "tenant_id String, run_id String, publication_attempt_id String, row_count UInt64, "
            "commit_version UInt64 DEFAULT toUnixTimestamp64Nano(now64(9)), "
            "committed_at DateTime64(6) DEFAULT now64(6)"
            ") ENGINE = ReplacingMergeTree(commit_version) ORDER BY (tenant_id, run_id)"
        )
        self._client.execute(
            f"CREATE TABLE IF NOT EXISTS {staged_table} ("
            "tenant_id String, run_id String, publication_attempt_id String, exported_at DateTime DEFAULT now(), "
            "finding_id String, canonical_id String, severity LowCardinality(String), cvss_score Float32, "
            "epss_score Float32, package_name String, package_version String, ecosystem LowCardinality(String), "
            "cve_id String, source LowCardinality(String), status LowCardinality(String), effective_reach String, "
            "first_seen String, last_seen String"
            ") ENGINE = MergeTree() ORDER BY (tenant_id, run_id, publication_attempt_id, finding_id) "
            "PARTITION BY toYYYYMM(exported_at)"
        )
        cleanup_attempt = (
            f"ALTER TABLE {staged_table} DELETE WHERE tenant_id = '{escaped_tenant}' "
            f"AND run_id = '{escaped_run}' AND publication_attempt_id = '{escaped_attempt}' SETTINGS mutations_sync = 1"
        )
        row_count = 0
        batch: list[dict[str, Any]] = []
        try:
            for finding in rows:
                row = self._to_row(finding, tenant_id=tenant_id, run_id=run_id)
                row[_ATTEMPT_COLUMN] = attempt_id
                batch.append(row)
                if len(batch) >= self._batch_rows:
                    self._client.insert_json(staged_table, batch)
                    row_count += len(batch)
                    batch = []
            if batch:
                self._client.insert_json(staged_table, batch)
                row_count += len(batch)
        except Exception:
            # No publication was attempted: this is a definitive staging
            # failure. Cleanup is best-effort and must not mask the load error.
            try:
                self._client.execute(cleanup_attempt)
            except Exception:
                logger.warning("ClickHouse failed-attempt cleanup deferred")
            raise
        try:
            self._client.insert_json(
                runs_table,
                [
                    {
                        "tenant_id": tenant_id,
                        "run_id": run_id,
                        _ATTEMPT_COLUMN: attempt_id,
                        "row_count": row_count,
                    }
                ],
            )
        except Exception:
            # A publication timeout is ambiguous: the INSERT can still finish
            # after this process observes no marker. Never delete its immutable
            # staging rows. A present exact marker is safely reconciled; absent
            # or unavailable status preserves staging and the primary error.
            try:
                committed = self._client.execute(
                    f"SELECT count() FROM {runs_table} WHERE tenant_id = '{escaped_tenant}' "
                    f"AND run_id = '{escaped_run}' AND publication_attempt_id = '{escaped_attempt}' FORMAT TabSeparated"
                )
                if str(committed).strip() == "1":
                    return ExportResult(
                        kind=self.kind,
                        destination_uri=f"clickhouse://{getattr(self._client, 'database', 'agent_bom')}/{self._table}",
                        row_count=row_count,
                    )
            except Exception:
                logger.warning("ClickHouse publication status is indeterminate")
            raise ExportPublicationIndeterminateError("ClickHouse publication status is indeterminate") from None
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

    Each completed run atomically replaces the tenant snapshot and inserts an
    exact durable marker in ``<table>_runs``. The marker reconciles a lost COMMIT
    response; zero-row runs delete the prior tenant snapshot without exposing a
    partial replacement.

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
        self._table = _warehouse_ident(table or "findings_feed", field="table")
        self._ensure_schema = ensure_schema

    def _create_table_sql(self) -> str:
        cols = [f"{_sf_ident(name)} STRING" for name in _SF_STRING_COLUMNS]
        cols += [f"{_sf_ident(name)} FLOAT" for name in _SF_FLOAT_COLUMNS]
        return f"CREATE TABLE IF NOT EXISTS {_sf_ident(self._table)} (\n  " + ",\n  ".join(cols) + "\n) CLUSTER BY (tenant_id, finding_id)"

    def _create_runs_table_sql(self) -> str:
        return (
            f"CREATE TABLE IF NOT EXISTS {_sf_ident(self._table + _RUNS_SUFFIX)} ("
            '"tenant_id" STRING, "run_id" STRING, "publication_attempt_id" STRING, '
            '"row_count" INTEGER, "committed_at" TIMESTAMP_TZ)'
        )

    def _manifest_exists(self, *, tenant_id: str, run_id: str, attempt_id: str) -> bool:
        """Read an exact durable marker on a fresh session after COMMIT ambiguity."""
        check_conn = self._connection_factory()
        try:
            check_cursor = check_conn.cursor()
            try:
                check_cursor.execute(
                    f"SELECT 1 FROM {_sf_ident(self._table + _RUNS_SUFFIX)} WHERE "
                    '"tenant_id" = %s AND "run_id" = %s AND "publication_attempt_id" = %s LIMIT 1',
                    (tenant_id, run_id, attempt_id),
                )
                return check_cursor.fetchone() is not None
            finally:
                check_cursor.close()
        finally:
            check_conn.close()

    def write_findings(self, rows: Iterable[dict[str, Any]], *, tenant_id: str, run_id: str) -> ExportResult:
        from datetime import datetime, timezone

        exported_at = datetime.now(timezone.utc).isoformat()
        attempt_id = uuid.uuid4().hex
        table_ref = _sf_ident(self._table)
        stage_scope = hashlib.sha256(f"{tenant_id}\0{run_id}".encode()).hexdigest()
        stage_ref = f"@%{_sf_ident(self._table)}/agent_bom/{stage_scope}/{uuid.uuid4().hex}"

        conn = self._connection_factory()
        tmp_path = ""
        transaction_started = False
        try:
            cursor = conn.cursor()
            try:
                if self._ensure_schema:
                    cursor.execute(self._create_table_sql())
                    cursor.execute(self._create_runs_table_sql())
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
                # then start the replacement transaction. Snowflake connections
                # default to autocommit, so BEGIN/COMMIT are explicit SQL rather
                # than relying on the connector's no-op commit() method.
                cursor.execute(f"PUT 'file://{tmp_path}' {stage_ref} AUTO_COMPRESS=FALSE SOURCE_COMPRESSION=GZIP OVERWRITE=TRUE")
                cursor.execute("BEGIN")
                transaction_started = True
                cursor.execute(
                    f"DELETE FROM {table_ref} WHERE {_sf_ident('tenant_id')} = %s",
                    (tenant_id,),
                )
                if row_count:
                    cursor.execute(
                        f"COPY INTO {table_ref} FROM {stage_ref} "
                        "FILE_FORMAT = (TYPE = JSON) "
                        "MATCH_BY_COLUMN_NAME = CASE_INSENSITIVE "
                        "PURGE = TRUE"
                    )
                cursor.execute(
                    f"INSERT INTO {_sf_ident(self._table + _RUNS_SUFFIX)} "
                    '("tenant_id", "run_id", "publication_attempt_id", "row_count", "committed_at") '
                    "VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP())",
                    (tenant_id, run_id, attempt_id, row_count),
                )
                try:
                    cursor.execute("COMMIT")
                    transaction_started = False
                except Exception:
                    # The marker and replacement commit atomically. A fresh
                    # session can therefore reconcile a lost COMMIT response.
                    try:
                        committed = self._manifest_exists(tenant_id=tenant_id, run_id=run_id, attempt_id=attempt_id)
                    except Exception:
                        logger.warning("Snowflake publication status is indeterminate")
                        committed = False
                    if committed:
                        transaction_started = False
                    else:
                        raise ExportPublicationIndeterminateError("Snowflake COMMIT status is indeterminate") from None
                if row_count == 0:
                    try:
                        cursor.execute(f"REMOVE {stage_ref}")
                    except Exception:
                        logger.warning("Snowflake empty-attempt stage cleanup deferred")
            except Exception:
                if transaction_started:
                    try:
                        cursor.execute("ROLLBACK")
                    except Exception:
                        logger.warning("Snowflake rollback status is indeterminate")
                try:
                    cursor.execute(f"REMOVE {stage_ref}")
                except Exception:
                    logger.warning("Snowflake stage cleanup deferred")
                raise
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
    """Stage findings in BigQuery and publish a complete attempt pointer.

    Mirrors :class:`ClickHouseWarehouseDestination`: rows are loaded in batches of
    at most ``batch_rows`` via ``client.load_table_from_json`` (BigQuery's native
    JSON bulk-load), so at most one batch is held in memory. The load's
    ``CREATE_IF_NEEDED`` disposition creates the table with the explicit feed
    schema; the dataset is ensured up front (a load cannot create a dataset).
    Each invocation gets a unique attempt ID. One manifest load publishes the
    attempt after every data batch succeeds; an exact-attempt read reconciles a
    manifest response timeout. ``client`` and job configs are injected so the
    adapter itself is SDK-free and testable.
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
        cleanup_job_config_factory: Callable[[str, str, str], Any] | None = None,
        ensure_schema: bool = True,
        batch_rows: int = _CH_BATCH_ROWS,
    ) -> None:
        if not project:
            raise ExportDestinationError("BigQuery export destination requires a project")
        if not dataset:
            raise ExportDestinationError("BigQuery export destination requires a dataset")
        self._client = client
        self._project = _bigquery_project_ident(project)
        self._dataset = _warehouse_ident(dataset, field="dataset")
        self._table = _warehouse_ident(table or "findings_feed", field="table")
        self._job_config = job_config
        self._cleanup_job_config_factory = cleanup_job_config_factory or (lambda _tenant, _run, _attempt: None)
        self._ensure_schema = ensure_schema
        self._batch_rows = max(1, batch_rows)

    def _load(self, table_ref: str, batch: list[dict[str, Any]]) -> None:
        # load_table_from_json returns a LoadJob; .result() blocks until the load
        # finishes (or raises), so a failed batch surfaces immediately.
        self._client.load_table_from_json(batch, table_ref, job_config=self._job_config).result()

    def _table_exists(self, table_ref: str) -> bool:
        try:
            self._client.get_table(table_ref)
        except Exception as exc:
            if exc.__class__.__name__ == "NotFound":
                return False
            raise
        return True

    def _scope_query(self, sql: str, *, tenant_id: str, run_id: str, attempt_id: str) -> Any:
        return self._client.query(
            sql,
            job_config=self._cleanup_job_config_factory(tenant_id, run_id, attempt_id),
        ).result()

    def _manifest_exists(self, runs_ref: str, *, tenant_id: str, run_id: str, attempt_id: str) -> bool:
        if not self._table_exists(runs_ref):
            return False
        rows = self._scope_query(
            f"SELECT 1 FROM `{runs_ref}` WHERE tenant_id = @tenant_id AND run_id = @run_id "
            "AND publication_attempt_id = @attempt_id LIMIT 1",
            tenant_id=tenant_id,
            run_id=run_id,
            attempt_id=attempt_id,
        )
        if rows is None:
            return False
        return next(iter(rows), None) is not None

    def write_findings(self, rows: Iterable[dict[str, Any]], *, tenant_id: str, run_id: str) -> ExportResult:
        from datetime import datetime, timezone

        exported_at = datetime.now(timezone.utc).isoformat()
        table_ref = f"{self._project}.{self._dataset}.{self._table}"
        if self._ensure_schema:
            self._client.create_dataset(f"{self._project}.{self._dataset}", exists_ok=True)
        staged_ref = f"{table_ref}{_STAGED_SUFFIX}"
        runs_ref = f"{table_ref}{_RUNS_SUFFIX}"
        attempt_id = uuid.uuid4().hex
        if self._ensure_schema:
            feed_columns = [f"`{column}` STRING" for column in (*_SF_STRING_COLUMNS, _ATTEMPT_COLUMN)]
            feed_columns += [f"`{column}` FLOAT64" for column in _SF_FLOAT_COLUMNS]
            self._scope_query(
                f"CREATE TABLE IF NOT EXISTS `{staged_ref}` ({', '.join(feed_columns)})",
                tenant_id=tenant_id,
                run_id=run_id,
                attempt_id=attempt_id,
            )
            self._scope_query(
                f"CREATE TABLE IF NOT EXISTS `{runs_ref}` (tenant_id STRING NOT NULL, run_id STRING NOT NULL, "
                "publication_attempt_id STRING NOT NULL, row_count INT64 NOT NULL, commit_version INT64 NOT NULL, "
                "committed_at TIMESTAMP NOT NULL)",
                tenant_id=tenant_id,
                run_id=run_id,
                attempt_id=attempt_id,
            )
        cleanup_sql = (
            f"DELETE FROM `{staged_ref}` WHERE tenant_id = @tenant_id AND run_id = @run_id AND publication_attempt_id = @attempt_id"
        )
        row_count = 0
        batch: list[dict[str, Any]] = []
        publication_started = False
        try:
            for finding in rows:
                row = _warehouse_feed_row(finding, tenant_id=tenant_id, run_id=run_id, exported_at=exported_at)
                row[_ATTEMPT_COLUMN] = attempt_id
                batch.append(row)
                if len(batch) >= self._batch_rows:
                    self._load(staged_ref, batch)
                    row_count += len(batch)
                    batch = []
            if batch:
                self._load(staged_ref, batch)
                row_count += len(batch)
            publication_started = True
            self._scope_query(
                f"INSERT INTO `{runs_ref}` (tenant_id, run_id, publication_attempt_id, row_count, "
                "commit_version, committed_at) VALUES "
                f"(@tenant_id, @run_id, @attempt_id, {row_count}, UNIX_MICROS(CURRENT_TIMESTAMP()), CURRENT_TIMESTAMP())",
                tenant_id=tenant_id,
                run_id=run_id,
                attempt_id=attempt_id,
            )
        except Exception:
            if publication_started:
                try:
                    if self._manifest_exists(runs_ref, tenant_id=tenant_id, run_id=run_id, attempt_id=attempt_id):
                        return ExportResult(
                            kind=self.kind,
                            destination_uri=f"bigquery://{self._project}/{self._dataset}/{self._table}",
                            row_count=row_count,
                        )
                except Exception:
                    logger.warning("BigQuery publication status is indeterminate")
                # The manifest load may still be running. Preserve staging so a
                # late commit can only publish a complete immutable attempt.
                raise ExportPublicationIndeterminateError("BigQuery publication status is indeterminate") from None
            try:
                if self._table_exists(staged_ref):
                    self._scope_query(
                        cleanup_sql,
                        tenant_id=tenant_id,
                        run_id=run_id,
                        attempt_id=attempt_id,
                    )
            except Exception:
                logger.warning("BigQuery failed-attempt cleanup deferred")
            raise
        uri = f"bigquery://{self._project}/{self._dataset}/{self._table}"
        logger.info("Exported %d findings to %s", row_count, uri)
        return ExportResult(kind=self.kind, destination_uri=uri, row_count=row_count)


def _dbx_ident(name: str) -> str:
    """Quote a Databricks (Unity Catalog) identifier with backticks."""
    return "`" + str(name).replace("`", "``") + "`"


class DatabricksWarehouseDestination:
    """Stage findings in Delta and publish a complete attempt pointer.

    Mirrors :class:`SnowflakeWarehouseDestination`: a DBAPI connection is opened
    once from the connect-once connection (``databricks-sql-connector``,
    key/OAuth token from the stored secret — no per-run credential). Rows land
    in an attempt-scoped Delta staging table through bounded, parameterized
    ``executemany`` calls. One atomic manifest INSERT publishes the complete
    attempt. This does not depend on multi-statement transaction support, which
    is limited to catalog-managed tables and newer Databricks runtimes.
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
        self._table = _warehouse_ident(table or "findings_feed", field="table")
        self._ensure_schema = ensure_schema
        self._batch_rows = max(1, batch_rows)

    def _full_table(self, suffix: str = "") -> str:
        return f"{_dbx_ident(self._catalog)}.{_dbx_ident(self._schema)}.{_dbx_ident(self._table + suffix)}"

    def _create_staged_table_sql(self) -> str:
        cols = [f"{_dbx_ident(c)} STRING" for c in _SF_STRING_COLUMNS]
        cols.append(f"{_dbx_ident(_ATTEMPT_COLUMN)} STRING")
        cols += [f"{_dbx_ident(c)} DOUBLE" for c in _SF_FLOAT_COLUMNS]
        return f"CREATE TABLE IF NOT EXISTS {self._full_table(_STAGED_SUFFIX)} (\n  " + ",\n  ".join(cols) + "\n) USING DELTA"

    def _create_runs_table_sql(self) -> str:
        return (
            f"CREATE TABLE IF NOT EXISTS {self._full_table(_RUNS_SUFFIX)} ("
            f"{_dbx_ident('tenant_id')} STRING, {_dbx_ident('run_id')} STRING, "
            f"{_dbx_ident(_ATTEMPT_COLUMN)} STRING, {_dbx_ident('row_count')} BIGINT, "
            f"{_dbx_ident('commit_version')} BIGINT, {_dbx_ident('committed_at')} TIMESTAMP) USING DELTA"
        )

    def _insert_sql(self) -> str:
        columns = (*_SF_STRING_COLUMNS, _ATTEMPT_COLUMN, *_SF_FLOAT_COLUMNS)
        col_list = ", ".join(_dbx_ident(c) for c in columns)
        placeholders = ", ".join("?" for _ in columns)
        return f"INSERT INTO {self._full_table(_STAGED_SUFFIX)} ({col_list}) VALUES ({placeholders})"  # nosec B608 - table/columns are backtick-escaped via _dbx_ident and columns are a fixed constant; row values use "?" placeholders (parameterized)

    @staticmethod
    def _row_tuple(feed: dict[str, Any], attempt_id: str) -> tuple[Any, ...]:
        strings = tuple(str(feed.get(c, "") or "") for c in _SF_STRING_COLUMNS)
        floats = tuple(float(feed.get(c) or 0.0) for c in _SF_FLOAT_COLUMNS)
        return strings + (attempt_id,) + floats

    def write_findings(self, rows: Iterable[dict[str, Any]], *, tenant_id: str, run_id: str) -> ExportResult:
        from datetime import datetime, timezone

        exported_at = datetime.now(timezone.utc).isoformat()
        attempt_id = uuid.uuid4().hex
        insert_sql = self._insert_sql()
        row_count = 0
        publication_started = False
        conn = self._connection_factory()
        try:
            cursor = conn.cursor()
            try:
                if self._ensure_schema:
                    cursor.execute(self._create_staged_table_sql())
                    cursor.execute(self._create_runs_table_sql())
                batch: list[tuple[Any, ...]] = []
                for finding in rows:
                    feed = _warehouse_feed_row(finding, tenant_id=tenant_id, run_id=run_id, exported_at=exported_at)
                    batch.append(self._row_tuple(feed, attempt_id))
                    if len(batch) >= self._batch_rows:
                        cursor.executemany(insert_sql, batch)
                        row_count += len(batch)
                        batch = []
                if batch:
                    cursor.executemany(insert_sql, batch)
                    row_count += len(batch)
                publication_started = True
                cursor.execute(
                    f"INSERT INTO {self._full_table(_RUNS_SUFFIX)} ("
                    f"{_dbx_ident('tenant_id')}, {_dbx_ident('run_id')}, {_dbx_ident(_ATTEMPT_COLUMN)}, "
                    f"{_dbx_ident('row_count')}, {_dbx_ident('commit_version')}, {_dbx_ident('committed_at')}) "
                    "VALUES (?, ?, ?, ?, UNIX_MICROS(CURRENT_TIMESTAMP()), CURRENT_TIMESTAMP())",
                    (tenant_id, run_id, attempt_id, row_count),
                )
            except Exception:
                if publication_started:
                    try:
                        cursor.execute(
                            f"SELECT 1 FROM {self._full_table(_RUNS_SUFFIX)} WHERE {_dbx_ident('tenant_id')} = ? "
                            f"AND {_dbx_ident('run_id')} = ? AND {_dbx_ident(_ATTEMPT_COLUMN)} = ? LIMIT 1",
                            (tenant_id, run_id, attempt_id),
                        )
                        if cursor.fetchone() is not None:
                            return ExportResult(
                                kind=self.kind,
                                destination_uri=f"databricks://{self._catalog}/{self._schema}/{self._table}",
                                row_count=row_count,
                            )
                    except Exception:
                        logger.warning("Databricks publication status is indeterminate")
                    # Preserve staging: the manifest INSERT can still complete.
                    raise ExportPublicationIndeterminateError("Databricks publication status is indeterminate") from None
                try:
                    cursor.execute(
                        f"DELETE FROM {self._full_table(_STAGED_SUFFIX)} WHERE {_dbx_ident('tenant_id')} = ? "
                        f"AND {_dbx_ident('run_id')} = ? AND {_dbx_ident(_ATTEMPT_COLUMN)} = ?",
                        (tenant_id, run_id, attempt_id),
                    )
                except Exception:
                    logger.warning("Databricks failed-attempt cleanup deferred")
                raise
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
    schema.append(bigquery.SchemaField(_ATTEMPT_COLUMN, "STRING"))
    schema += [bigquery.SchemaField(c, "FLOAT64") for c in _SF_FLOAT_COLUMNS]
    return bigquery.LoadJobConfig(
        schema=schema,
        write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
        create_disposition=bigquery.CreateDisposition.CREATE_IF_NEEDED,
        source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
    )


def _default_bigquery_scope_job_config(tenant_id: str, run_id: str, attempt_id: str) -> Any:
    from google.cloud import bigquery

    return bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("tenant_id", "STRING", tenant_id),
            bigquery.ScalarQueryParameter("run_id", "STRING", run_id),
            bigquery.ScalarQueryParameter("attempt_id", "STRING", attempt_id),
        ]
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
        autocommit=True,
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
        if not secret or not secret.strip():
            raise ExportDestinationError("Snowflake export destination requires a stored private-key secret")
        schema = str(config.get("schema", "") or "PUBLIC").strip() or "PUBLIC"
        role = str(config.get("role", "") or "").strip()
        warehouse = str(config.get("warehouse", "") or "").strip()
        table = str(config.get("table", "findings_feed") or "findings_feed").strip()
        pem = secret.strip()

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
        return BigQueryWarehouseDestination(
            client,
            project=project,
            dataset=dataset,
            table=table,
            job_config=job_config,
            cleanup_job_config_factory=_default_bigquery_scope_job_config,
        )
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
        if not secret or not secret.strip():
            raise ExportDestinationError("Databricks export destination requires a stored access-token secret")
        table = str(config.get("table", "findings_feed") or "findings_feed").strip()
        conn_config = {"server_hostname": server_hostname, "http_path": http_path}

        def _dbx_factory() -> Any:
            # Connect-once: the DBAPI connection is opened from the stored,
            # decrypted access token; no per-run credential is passed.
            return _default_databricks_connection(conn_config, secret.strip())

        return DatabricksWarehouseDestination(_dbx_factory, catalog=catalog, schema=schema, table=table)
    raise ExportDestinationError(f"Unknown export destination kind {normalized!r}; supported: {', '.join(SUPPORTED_EXPORT_KINDS)}")
