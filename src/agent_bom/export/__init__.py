"""Scheduled findings/report export to object stores and warehouses (#4040).

This package turns the on-demand export formats into a *scheduled, streaming*
delivery of a tenant's findings feed into the destinations security teams
centralize on:

* object stores — ``s3`` (landed); ``azure-blob`` / ``gcs`` are follow-up
  adapters against the same :class:`~agent_bom.export.destinations.ExportDestination`
  contract.
* analytics warehouses / lakehouses — ``clickhouse`` (landed, extends the
  existing analytics client) and ``snowflake`` (landed, staged gzip-NDJSON ->
  ``PUT`` -> ``COPY INTO`` reusing the key-pair connection broker); ``bigquery``
  / ``databricks`` are follow-up adapters against the same contract.

Every destination consumes a *bounded, streaming* iterator of finding rows and
never materializes the whole result set in memory, so the scheduler can push
millions of findings on a cadence. Destination credentials are resolved from a
stored, encrypted, revocable connection (connect-once) — never a per-run secret.
"""

from __future__ import annotations

from agent_bom.export.destinations import (
    DEFERRED_EXPORT_KINDS,
    SUPPORTED_EXPORT_KINDS,
    ClickHouseWarehouseDestination,
    ExportDestination,
    ExportResult,
    S3ObjectStoreDestination,
    SnowflakeWarehouseDestination,
    build_destination,
)
from agent_bom.export.runner import iter_current_findings, run_findings_export

__all__ = [
    "DEFERRED_EXPORT_KINDS",
    "SUPPORTED_EXPORT_KINDS",
    "ClickHouseWarehouseDestination",
    "ExportDestination",
    "ExportResult",
    "S3ObjectStoreDestination",
    "SnowflakeWarehouseDestination",
    "build_destination",
    "iter_current_findings",
    "run_findings_export",
]
