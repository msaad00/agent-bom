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

Landed adapters: ``s3`` (object store), ``clickhouse`` + ``snowflake``
(warehouses). Follow-up adapters against this same contract (tracked in #4040):
``azure-blob``, ``gcs``, ``bigquery``, ``databricks``.

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

# Kinds with a shipped adapter in this slice.
SUPPORTED_EXPORT_KINDS: tuple[str, ...] = ("s3", "clickhouse", "snowflake")
# Follow-up adapters that plug into the same ExportDestination contract (#4040).
DEFERRED_EXPORT_KINDS: tuple[str, ...] = ("azure-blob", "gcs", "bigquery", "databricks")

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


def build_destination(kind: str, config: dict[str, Any], secret: str | None = None) -> ExportDestination:
    """Build a destination adapter from a connect-once connection record.

    ``config`` carries the non-secret parameters (bucket/prefix/region, or
    ClickHouse url/user/database/table). ``secret`` is the single decrypted
    secret from the stored connection (the ClickHouse access token); ``s3`` uses
    the ambient credential chain and ignores it.
    """
    normalized = (kind or "").strip().lower()
    if normalized == "s3":
        return S3ObjectStoreDestination(
            bucket=str(config.get("bucket", "")),
            prefix=str(config.get("prefix", "findings-feed")),
            region=(str(config["region"]) if config.get("region") else None),
        )
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
    if normalized in DEFERRED_EXPORT_KINDS:
        raise ExportDestinationError(
            f"Export destination kind {normalized!r} is a planned follow-up adapter (#4040); "
            f"supported kinds are {', '.join(SUPPORTED_EXPORT_KINDS)}."
        )
    raise ExportDestinationError(f"Unknown export destination kind {normalized!r}; supported: {', '.join(SUPPORTED_EXPORT_KINDS)}")
