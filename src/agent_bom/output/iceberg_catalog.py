"""Iceberg REST-catalog registration for the findings lake table (#3499).

Complements ``parquet_fmt`` (flat ``.parquet`` files) by registering the same
findings as an Apache Iceberg table snapshot through the Iceberg REST Catalog
API: create the namespace and table if needed, append the finding rows as a
data file, and commit a new snapshot. Lake consumers then query one consistent,
versioned table instead of loose files.

Design: this reuses ``pyiceberg``'s ``RestCatalog`` rather than hand-rolling an
Avro manifest writer. Iceberg's on-disk format needs manifest + manifest-list
Avro files and column statistics for every commit; ``pyiceberg`` already writes
those and speaks the REST protocol. The dependency is optional and imported
lazily, mirroring ``parquet_fmt._require_pyarrow`` — nothing here runs unless a
catalog URL is configured and the operator installed ``pyiceberg``.

Configuration is env-driven and disabled by default:

- ``AGENT_BOM_ICEBERG_CATALOG_URL`` / ``--iceberg-catalog-url`` (required to enable)
- ``AGENT_BOM_ICEBERG_NAMESPACE`` / ``--iceberg-namespace`` (default ``agent_bom``)
- ``AGENT_BOM_ICEBERG_TABLE`` / ``--iceberg-table`` (default ``findings``)
- ``AGENT_BOM_ICEBERG_CREDENTIAL`` — OAuth2 ``client_id:client_secret``
- ``AGENT_BOM_ICEBERG_TOKEN`` — bearer token
- ``AGENT_BOM_ICEBERG_WAREHOUSE`` — warehouse location / identifier
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from agent_bom import config as app_config
from agent_bom.models import AIBOMReport, BlastRadius
from agent_bom.output.parquet_fmt import to_arrow_table

DEFAULT_NAMESPACE = "agent_bom"
DEFAULT_TABLE = "findings"


def _require_pyiceberg():
    try:
        from pyiceberg.catalog.rest import RestCatalog  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - exercised via test monkeypatch
        raise RuntimeError("Iceberg catalog export requires pyiceberg. Install with: pip install pyiceberg") from exc
    return RestCatalog


@dataclass(frozen=True)
class IcebergCatalogConfig:
    """Connection + target-table settings for the Iceberg REST catalog."""

    catalog_url: str | None = None
    namespace: str = DEFAULT_NAMESPACE
    table: str = DEFAULT_TABLE
    credential: str | None = None
    token: str | None = None
    warehouse: str | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.catalog_url)

    @property
    def identifier(self) -> str:
        return f"{self.namespace}.{self.table}"

    @classmethod
    def from_env(
        cls,
        *,
        catalog_url: str | None = None,
        namespace: str | None = None,
        table: str | None = None,
    ) -> IcebergCatalogConfig:
        """Build config from explicit args, falling back to ``AGENT_BOM_ICEBERG_*`` env."""
        return cls(
            catalog_url=catalog_url or os.environ.get("AGENT_BOM_ICEBERG_CATALOG_URL") or app_config.ICEBERG_CATALOG_URL or None,
            namespace=namespace or os.environ.get("AGENT_BOM_ICEBERG_NAMESPACE") or app_config.ICEBERG_NAMESPACE or DEFAULT_NAMESPACE,
            table=table or os.environ.get("AGENT_BOM_ICEBERG_TABLE") or app_config.ICEBERG_TABLE or DEFAULT_TABLE,
            credential=os.environ.get("AGENT_BOM_ICEBERG_CREDENTIAL") or None,
            token=os.environ.get("AGENT_BOM_ICEBERG_TOKEN") or None,
            warehouse=os.environ.get("AGENT_BOM_ICEBERG_WAREHOUSE") or app_config.ICEBERG_WAREHOUSE or None,
        )

    def catalog_properties(self) -> dict[str, str]:
        """REST-catalog property map passed to ``RestCatalog(name, **props)``."""
        if not self.catalog_url:
            raise RuntimeError("Iceberg catalog export requires a catalog URL. Set --iceberg-catalog-url or AGENT_BOM_ICEBERG_CATALOG_URL.")
        props: dict[str, str] = {"uri": self.catalog_url}
        if self.credential:
            props["credential"] = self.credential
        if self.token:
            props["token"] = self.token
        if self.warehouse:
            props["warehouse"] = self.warehouse
        return props


def _build_catalog(config: IcebergCatalogConfig):
    rest_catalog_cls = _require_pyiceberg()
    return rest_catalog_cls("agent-bom", **config.catalog_properties())


def register_findings(
    report: AIBOMReport,
    config: IcebergCatalogConfig,
    blast_radii: list[BlastRadius] | None = None,
    *,
    catalog: Any | None = None,
) -> dict[str, Any]:
    """Append the report's CVE findings to the Iceberg table as a new snapshot.

    Creates the namespace and table (matching the shared 27-col Parquet schema)
    if they do not yet exist, then appends a data file and commits a snapshot.
    Returns a small summary dict for logging.

    ``catalog`` is injectable for tests; production callers leave it ``None`` so
    a :class:`RestCatalog` is built from ``config``.
    """
    if not config.enabled:
        raise RuntimeError(
            "Iceberg catalog export is not configured. Set --iceberg-catalog-url or AGENT_BOM_ICEBERG_CATALOG_URL to enable it."
        )

    arrow_table = to_arrow_table(report, blast_radii)
    catalog = catalog if catalog is not None else _build_catalog(config)

    catalog.create_namespace_if_not_exists((config.namespace,))
    iceberg_table = catalog.create_table_if_not_exists(config.identifier, schema=arrow_table.schema)
    iceberg_table.append(arrow_table)

    snapshot = None
    current = getattr(iceberg_table, "current_snapshot", None)
    if callable(current):
        snap = current()
        snapshot = getattr(snap, "snapshot_id", None) if snap is not None else None

    return {
        "identifier": config.identifier,
        "rows": arrow_table.num_rows,
        "snapshot_id": snapshot,
        "catalog_url": config.catalog_url,
    }


def maybe_register_iceberg(
    report: AIBOMReport,
    blast_radii: list[BlastRadius] | None = None,
    *,
    catalog_url: str | None = None,
    namespace: str | None = None,
    table: str | None = None,
) -> dict[str, Any] | None:
    """Register findings to Iceberg iff a catalog is configured; else no-op.

    Returns the summary dict on success, or ``None`` when disabled (the common
    default path). Used by the CLI output layer as a best-effort side-write
    alongside the flat ``.parquet`` file.
    """
    config = IcebergCatalogConfig.from_env(catalog_url=catalog_url, namespace=namespace, table=table)
    if not config.enabled:
        return None
    return register_findings(report, config, blast_radii)


__all__ = [
    "IcebergCatalogConfig",
    "maybe_register_iceberg",
    "register_findings",
]
