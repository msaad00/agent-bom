"""Support tiers for the storage backends a deployment selects.

agent-bom can persist to five engines, but they do not carry the same evidence:

* **supported** — Postgres (system of record for servers; tenant isolation is
  enforced by forced row-level security plus application predicates) and
  SQLite (local, CLI and single-node pilots). The in-memory fallback is listed
  here too, because it is the local default, but it is not durable.
* **analytics_sink** — ClickHouse. An optional mirror for OLAP reads; it is
  never the system of record for jobs, fleet, policy, audit or graph state.
* **experimental** — the Snowflake control-plane stores and the Neptune graph
  backend. They work, but their tenant isolation is tested only against
  mocked clients, not proven against a live database.

:func:`classify_storage` is a pure function over a :class:`StorageSelection`,
so the precedence it mirrors (``api/server.py`` lifespan wiring,
``api/storage/job_backends.py`` and ``api/stores._get_graph_store``) is unit
tested without opening a database. :func:`preflight_storage_backends` runs it
at control-plane startup: an experimental backend logs one structured warning,
and ``AGENT_BOM_REQUIRE_SUPPORTED_STORAGE=1`` turns that warning into a refusal
to start. The default stays advisory so existing deployments (including the
Snowflake Native App) keep starting. See ``docs/STORAGE_BACKENDS.md``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Final

from agent_bom.core.settings import env_bool, env_flag, env_is_set, env_str
from agent_bom.storage.factory import validate_configured_sqlite_path

logger = logging.getLogger(__name__)

STORAGE_TIERS_DOC: Final = "https://github.com/msaad00/agent-bom/blob/main/docs/STORAGE_BACKENDS.md"
REQUIRE_SUPPORTED_STORAGE_ENV: Final = "AGENT_BOM_REQUIRE_SUPPORTED_STORAGE"


class StorageTier(str, Enum):
    """How much the project stands behind a storage backend."""

    SUPPORTED = "supported"
    ANALYTICS_SINK = "analytics_sink"
    EXPERIMENTAL = "experimental"


BACKEND_TIERS: Final[dict[str, StorageTier]] = {
    "postgres": StorageTier.SUPPORTED,
    "sqlite": StorageTier.SUPPORTED,
    "memory": StorageTier.SUPPORTED,
    "clickhouse": StorageTier.ANALYTICS_SINK,
    "snowflake": StorageTier.EXPERIMENTAL,
    "neptune": StorageTier.EXPERIMENTAL,
}


class UnsupportedStorageBackendError(RuntimeError):
    """Raised when strict mode is on and an experimental backend is selected."""


@dataclass(frozen=True)
class StorageSelection:
    """The storage-relevant configuration, decoupled from the environment."""

    snowflake: bool = False
    postgres: bool = False
    sqlite: bool = False
    graph_backend: str = ""
    analytics_backend: str = "disabled"
    multi_tenant: bool = False


@dataclass(frozen=True)
class ComponentTier:
    """One persisted component, the backend serving it and that backend's tier."""

    component: str
    backend: str
    tier: StorageTier

    def as_dict(self) -> dict[str, str]:
        return {"component": self.component, "backend": self.backend, "tier": self.tier.value}


@dataclass(frozen=True)
class StorageTierReport:
    """Classification of every storage component the deployment selected."""

    components: tuple[ComponentTier, ...]
    multi_tenant: bool = False

    @property
    def experimental(self) -> tuple[ComponentTier, ...]:
        return tuple(item for item in self.components if item.tier is StorageTier.EXPERIMENTAL)

    def as_dict(self) -> dict[str, object]:
        return {
            "components": [item.as_dict() for item in self.components],
            "experimental": [item.backend for item in self.experimental],
            "multi_tenant": self.multi_tenant,
            "docs": STORAGE_TIERS_DOC,
        }


def _control_plane_backend(selection: StorageSelection) -> str:
    # Same precedence as api/storage/job_backends.configured_job_store: selecting
    # Neptune keeps jobs in process memory even when Postgres or SQLite is set.
    if selection.snowflake:
        return "snowflake"
    if selection.graph_backend == "neptune":
        return "memory"
    if selection.postgres:
        return "postgres"
    if selection.sqlite:
        return "sqlite"
    return "memory"


def _graph_backend(selection: StorageSelection) -> str:
    # Same precedence as api/stores._get_graph_store (SQLite is its lazy default).
    if selection.graph_backend == "neptune":
        return "neptune"
    return "postgres" if selection.postgres else "sqlite"


def classify_storage(selection: StorageSelection) -> StorageTierReport:
    """Classify the selected control-plane, graph and analytics backends."""
    control = _control_plane_backend(selection)
    graph = _graph_backend(selection)
    components = [
        ComponentTier("control_plane", control, BACKEND_TIERS[control]),
        ComponentTier("graph", graph, BACKEND_TIERS[graph]),
    ]
    if selection.analytics_backend == "clickhouse":
        components.append(ComponentTier("analytics", "clickhouse", BACKEND_TIERS["clickhouse"]))
    return StorageTierReport(components=tuple(components), multi_tenant=selection.multi_tenant)


def _multi_tenant_signals_present() -> bool:
    """Deployment signals that more than one tenant shares this control plane.

    Mirrors ``cli/_tenant.py`` (explicit tenant boundary or more than one API
    replica) and adds tenant-bound OIDC issuers.
    """
    replicas = env_str("AGENT_BOM_CONTROL_PLANE_REPLICAS")
    return (
        env_flag("AGENT_BOM_REQUIRE_TENANT_BOUNDARY")
        or (replicas.isdigit() and int(replicas) > 1)
        or env_is_set("AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON")
    )


def storage_selection_from_env() -> StorageSelection:
    """Read the storage selection from the process environment."""
    db = env_str("AGENT_BOM_DB")
    db_is_postgres = db.lower().startswith(("postgres://", "postgresql://"))
    analytics = env_str("AGENT_BOM_ANALYTICS_BACKEND").lower()
    if analytics in {"", "auto"}:
        analytics = "clickhouse" if env_is_set("AGENT_BOM_CLICKHOUSE_URL") else "disabled"
    return StorageSelection(
        snowflake=env_is_set("SNOWFLAKE_ACCOUNT"),
        postgres=env_is_set("AGENT_BOM_POSTGRES_URL") or db_is_postgres,
        sqlite=bool(db) and not db_is_postgres,
        graph_backend=env_str("AGENT_BOM_GRAPH_BACKEND").lower(),
        analytics_backend=analytics,
        multi_tenant=_multi_tenant_signals_present(),
    )


def enforce_storage_tiers(report: StorageTierReport, *, strict: bool) -> None:
    """Warn once about experimental backends; refuse them when *strict*.

    Fail mode: advisory (warn and continue) by default. With strict mode the
    caller's startup fails closed before any store is initialized.
    """
    experimental = report.experimental
    if not experimental:
        return
    names = ", ".join(f"{item.backend} ({item.component})" for item in experimental)
    isolation = (
        " This deployment looks multi-tenant; tenant isolation for these backends is not proven."
        if report.multi_tenant
        else " Tenant isolation for these backends is not proven; use Postgres for multi-tenant servers."
    )
    if strict:
        raise UnsupportedStorageBackendError(
            f"Experimental storage backend selected: {names}. {REQUIRE_SUPPORTED_STORAGE_ENV}=1 allows only "
            f"supported backends (Postgres, SQLite) and the ClickHouse analytics sink. See {STORAGE_TIERS_DOC}"
        )
    logger.warning(
        "STORAGE: experimental storage backend selected: %s; tier=experimental.%s See %s",
        names,
        isolation,
        STORAGE_TIERS_DOC,
        extra={"context": {"event": "storage_tier_experimental", **report.as_dict()}},
    )


def preflight_storage_backends() -> StorageTierReport:
    """Validate storage configuration at control-plane startup.

    Rejects a remote DSN in the SQLite path, then classifies the selected
    backends and applies :func:`enforce_storage_tiers`. An invalid value for
    ``AGENT_BOM_REQUIRE_SUPPORTED_STORAGE`` also refuses startup.
    """
    validate_configured_sqlite_path()
    report = classify_storage(storage_selection_from_env())
    enforce_storage_tiers(report, strict=env_bool(REQUIRE_SUPPORTED_STORAGE_ENV, False))
    return report
