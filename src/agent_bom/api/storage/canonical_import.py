"""Canonical store adapters for explicit control-plane SQLite recovery."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass, is_dataclass
from typing import Any, cast

from psycopg.errors import InsufficientPrivilege, UniqueViolation

from agent_bom.api.access_review import _VALID_DECISIONS, DECISION_PENDING, AccessReviewCampaign, AccessReviewItem
from agent_bom.api.exception_store import ExceptionStatus, VulnException
from agent_bom.api.fleet_store import FleetAgent, FleetEndpoint
from agent_bom.api.models import CredentialRefRecord, SourceRecord
from agent_bom.api.policy_store import GatewayPolicy
from agent_bom.api.postgres_access import PostgresExceptionStore
from agent_bom.api.postgres_access_review import PostgresAccessReviewStore
from agent_bom.api.postgres_fleet_store import PostgresFleetStore
from agent_bom.api.postgres_policy import PostgresCredentialRefStore, PostgresPolicyStore, PostgresScheduleStore
from agent_bom.api.postgres_runtime_event import PostgresRuntimeEventStore
from agent_bom.api.postgres_scim import PostgresSCIMStore
from agent_bom.api.runtime_event_store import RuntimeObservationRecord, RuntimeSessionRecord
from agent_bom.api.schedule_store import ScanSchedule
from agent_bom.api.scim_store import SCIMGroup, SCIMUser
from agent_bom.api.source_postgres import PostgresSourceStore
from agent_bom.api.storage_schema import postgres_deployment_configured
from agent_bom.api.tenant_worker import tenant_bound_context


def payload_of(record: Any) -> dict[str, Any]:
    return asdict(cast(Any, record)) if is_dataclass(record) else record.model_dump(mode="json")


@dataclass(frozen=True)
class ImportAdapter:
    keys: tuple[str, ...]
    record_type: Any
    owner: Any
    scalar_fields: tuple[str, ...]
    get_method: str = "get"
    put_method: str = "put"
    tenant_on_put: bool = True
    target_table: str = ""

    def decode(self, payload: dict[str, Any]) -> Any:
        values = dict(payload)
        if self.record_type is VulnException:
            values["status"] = ExceptionStatus(values["status"])
        record = self.record_type(**values)
        if set(payload) - set(payload_of(record)):
            raise ValueError("Source has fields unsupported by the current store model")
        return record


CONTROL_TABLES = {
    "scim_users": ImportAdapter(
        ("user_id",), SCIMUser, PostgresSCIMStore, ("external_id", "user_name", "active", "updated_at"), "get_user", "restore_user", False
    ),
    "scim_groups": ImportAdapter(
        ("group_id",), SCIMGroup, PostgresSCIMStore, ("external_id", "display_name", "updated_at"), "get_group", "restore_group", False
    ),
    "fleet_agents": ImportAdapter(
        ("agent_id",),
        FleetAgent,
        PostgresFleetStore,
        ("canonical_id", "name", "lifecycle_state", "trust_score", "updated_at", "device_fingerprint"),
        tenant_on_put=False,
    ),
    "fleet_endpoints": ImportAdapter(
        ("endpoint_id",), FleetEndpoint, PostgresFleetStore, ("completeness", "updated_at"), "get_endpoint", "put_endpoint", False
    ),
    "gateway_policies": ImportAdapter(
        ("policy_id",), GatewayPolicy, PostgresPolicyStore, ("name", "mode", "enabled", "updated_at"), "get_policy", "put_policy", False
    ),
    "exceptions": ImportAdapter(
        ("exception_id",),
        VulnException,
        PostgresExceptionStore,
        ("status", "approved_by", "approved_at", "revoked_at", "expires_at", "approval_version"),
    ),
    "runtime_observations": ImportAdapter(
        ("observation_id",), RuntimeObservationRecord, PostgresRuntimeEventStore, ("session_id", "observed_at")
    ),
    "runtime_sessions": ImportAdapter(("session_id",), RuntimeSessionRecord, PostgresRuntimeEventStore, ("last_seen",)),
    "credential_refs": ImportAdapter(("credential_ref_id",), CredentialRefRecord, PostgresCredentialRefStore, ("enabled", "updated_at")),
    "sources": ImportAdapter(
        ("source_id",), SourceRecord, PostgresSourceStore, ("enabled", "updated_at"), target_table="control_plane_sources"
    ),
    "scan_schedules": ImportAdapter(("schedule_id",), ScanSchedule, PostgresScheduleStore, ("enabled", "next_run")),
    "access_review_campaigns": ImportAdapter(
        ("campaign_id",),
        AccessReviewCampaign,
        PostgresAccessReviewStore,
        ("status", "created_at", "due_at"),
        "get_campaign",
        "put_campaign",
        False,
    ),
    "access_review_items": ImportAdapter(
        ("item_id",), AccessReviewItem, PostgresAccessReviewStore, ("campaign_id", "subject_id", "decision"), "get_item", "put_item", False
    ),
}
REVIEW_TABLES = {"access_review_campaigns", "access_review_items"}


def validate_groups(records: list[tuple[str, Any, dict[str, Any]]], tables: list[str]) -> None:
    if REVIEW_TABLES.intersection(tables) and not REVIEW_TABLES.issubset(tables):
        raise ValueError("Select both access-review campaign and item tables together")
    campaigns = {(r.tenant_id, r.campaign_id): r for t, r, _ in records if t == "access_review_campaigns"}
    items: dict[tuple[str, str], list[Any]] = {key: [] for key in campaigns}
    for table, record, _ in records:
        if table != "access_review_items":
            continue
        key = record.tenant_id, record.campaign_id
        if key not in campaigns:
            raise ValueError("Access-review item has no matching selected campaign")
        if record.decision not in _VALID_DECISIONS | {DECISION_PENDING}:
            raise ValueError("Access-review decision is invalid")
        if record.decision != DECISION_PENDING and (not record.decided_by or not record.decided_at):
            raise ValueError("Access-review decision lacks actor or timestamp evidence")
        items[key].append(record)
    for key, campaign in campaigns.items():
        decided = sum(item.decision != DECISION_PENDING for item in items[key])
        if campaign.item_count != len(items[key]) or campaign.decided_count != decided:
            raise ValueError("Access-review campaign counts disagree with selected items")
        if campaign.status not in {"open", "in_progress", "completed", "overdue"}:
            raise ValueError("Access-review campaign status is invalid")
        if campaign.status == "completed" and (decided != len(items[key]) or not campaign.completed_at):
            raise ValueError("Completed access review lacks complete decision evidence")


class _PinnedConnection:
    """Keep canonical writers inside the import's outer transaction."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def execute(self, *args: Any, **kwargs: Any) -> Any:
        return self._connection.execute(*args, **kwargs)

    def commit(self) -> None:
        # Only import_registries owns the final commit after every row verifies.
        pass


class PinnedImportPool:
    def __init__(self, connection: Any) -> None:
        self._connection = _PinnedConnection(connection)

    @contextmanager
    def connection(self):
        yield self._connection


def import_canonical_row(conn: Any, table: str, record: Any, expected: dict[str, Any]) -> str:
    """Stage one owner-validated row; the outer transaction decides apply/dry-run."""
    if not postgres_deployment_configured():
        raise ValueError("Configure the Postgres deployment before importing control-plane state")
    adapter = CONTROL_TABLES[table]
    # The outer table lock prevents a concurrent writer from changing the row
    # between conflict comparison and the canonical owner's upsert.
    with tenant_bound_context(record.tenant_id):
        owner = adapter.owner(pool=cast(Any, PinnedImportPool(conn)))
        getter = getattr(owner, adapter.get_method)
        key = getattr(record, adapter.keys[0])
        if table == "sources":
            mode = str(getattr(record.credential_mode, "value", record.credential_mode))
            if bool(record.credential_ref) != (mode == "reference"):
                return "conflicts"
            if (
                record.credential_ref
                and PostgresCredentialRefStore(pool=cast(Any, PinnedImportPool(conn))).get(
                    record.credential_ref, tenant_id=record.tenant_id
                )
                is None
            ):
                return "conflicts"
        current = getter(**{adapter.keys[0]: key, "tenant_id": record.tenant_id})
        if current is not None:
            return "unchanged" if payload_of(current) == expected else "conflicts"
        try:
            with conn.transaction():
                kwargs = {"tenant_id": record.tenant_id} if adapter.tenant_on_put else {}
                getattr(owner, adapter.put_method)(record, **kwargs)
                written = getter(**{adapter.keys[0]: key, "tenant_id": record.tenant_id})
                if written is None or payload_of(written) != expected:
                    raise ValueError("Canonical store import did not preserve the selected record")
        except (InsufficientPrivilege, UniqueViolation, ValueError):
            # Includes a global identity already owned by a hidden tenant.
            return "conflicts"
    return "inserted"


def validate_target_groups(conn: Any, records: list[tuple[str, Any, dict[str, Any]]]) -> int:
    """A same-id target campaign must not contain unselected member records."""
    conflicts = 0
    for table, campaign, _ in records:
        if table != "access_review_campaigns":
            continue
        with tenant_bound_context(campaign.tenant_id):
            owner = PostgresAccessReviewStore(pool=cast(Any, PinnedImportPool(conn)))
            items = owner.list_items(campaign.campaign_id, tenant_id=campaign.tenant_id, limit=campaign.item_count + 1)
            expected = {
                r.item_id
                for t, r, _ in records
                if t == "access_review_items" and r.tenant_id == campaign.tenant_id and r.campaign_id == campaign.campaign_id
            }
            conflicts += {item.item_id for item in items} != expected
    return conflicts
