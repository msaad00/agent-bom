"""Postgres persistence for MCP observations, skills results, and issue links."""

from dataclasses import asdict
from uuid import uuid4

from agent_bom.api import postgres_common
from agent_bom.api.issue_mapping_store import IssueMapping, _utcnow
from agent_bom.api.kspm_posture_store import KspmPostureRun
from agent_bom.api.mcp_observation_store import MCPObservation
from agent_bom.api.skills_scan_store import SkillsScanRun
from agent_bom.api.storage.registry_stores import RegistryStore
from agent_bom.core.tenancy import require_explicit_tenant_id


class PostgresMCPObservationStore(RegistryStore):
    table = "mcp_observations"
    keys = ("observation_id",)
    columns = ("observation_id", "server_canonical_id", "server_name", "updated_at")
    record_type = MCPObservation

    def put(self, observation: MCPObservation) -> None:
        normalized = MCPObservation.model_validate(observation.model_dump())
        self._put_payload(normalized, normalized.model_dump(mode="json"))

    def get(self, tenant_id: str, observation_id: str) -> MCPObservation | None:
        return self._get(tenant_id, observation_id)

    def get_by_server_canonical_id(self, tenant_id: str, server_canonical_id: str) -> MCPObservation | None:
        rows = self._list(tenant_id, "AND server_canonical_id=%s", (server_canonical_id,), "updated_at DESC, observation_id", 1)
        return rows[0] if rows else None

    def list_by_tenant(self, tenant_id: str) -> list[MCPObservation]:
        return self._list(tenant_id, "", (), "server_name, updated_at DESC, observation_id", 2147483647)


class PostgresSkillsScanStore(RegistryStore):
    put = RegistryStore._put_record
    table = "skills_scan_run"
    keys = ("run_id",)
    columns = ("run_id", "created_at")
    record_type = SkillsScanRun

    def init_schema(self) -> None:
        # RegistryStore validates migration authority on construction.
        return None

    def list_for_tenant(self, tenant_id: str, *, limit: int = 100) -> list[SkillsScanRun]:
        return self._list(tenant_id, "", (), "created_at DESC, run_id DESC", limit)

    def latest_for_tenant(self, tenant_id: str) -> SkillsScanRun | None:
        rows = self.list_for_tenant(tenant_id, limit=1)
        return rows[0] if rows else None


class PostgresKspmPostureStore(RegistryStore):
    put = RegistryStore._put_record
    keys = ("run_id",)

    def init_schema(self) -> None:
        return None

    table = "kspm_cluster_posture"
    columns = ("run_id", "cluster_ref", "created_at")
    record_type = KspmPostureRun

    def list_for_tenant(self, tenant_id: str, *, limit: int = 100) -> list[KspmPostureRun]:
        return self._list(tenant_id, "", (), "created_at DESC, run_id DESC", limit)

    def latest_for_tenant(self, tenant_id: str) -> KspmPostureRun | None:
        rows = self.list_for_tenant(tenant_id, limit=1)
        return rows[0] if rows else None


class PostgresIssueMappingStore(RegistryStore):
    table = "issue_mappings"
    keys = ("mapping_id",)
    columns = ("mapping_id", "target_kind", "target_id", "provider")
    record_type = IssueMapping

    def get(self, mapping_id: str, *, tenant_id: str) -> IssueMapping | None:
        return self._get(tenant_id, mapping_id)

    def find(self, *, tenant_id: str, target_kind: str, target_id: str, provider: str) -> IssueMapping | None:
        rows = self._list(
            tenant_id, "AND target_kind=%s AND target_id=%s AND provider=%s", (target_kind, target_id, provider), "mapping_id", 1
        )
        return rows[0] if rows else None

    def put(
        self, *, tenant_id: str, target_kind: str, target_id: str, provider: str, external_id: str, external_url: str, status: str = "open"
    ) -> IssueMapping:
        from psycopg.types.json import Jsonb

        require_explicit_tenant_id(tenant_id)
        now = _utcnow()
        record = IssueMapping(
            "issue-map-" + uuid4().hex, tenant_id, target_kind, target_id, provider, external_id, external_url, status, now, now
        )
        with postgres_common._tenant_connection(self._pool) as conn:
            row = conn.execute(
                "INSERT INTO issue_mappings (tenant_id,mapping_id,target_kind,target_id,provider,data) VALUES (%s,%s,%s,%s,%s,%s) "
                "ON CONFLICT (tenant_id,target_kind,target_id,provider) DO UPDATE SET data=excluded.data || "
                "jsonb_build_object('mapping_id',issue_mappings.mapping_id,'created_at',issue_mappings.data->'created_at') RETURNING data",
                (tenant_id, record.mapping_id, target_kind, target_id, provider, Jsonb(asdict(record))),
            ).fetchone()
            conn.commit()
        assert row is not None
        return IssueMapping(**row[0])

    def update_status(self, mapping_id: str, *, tenant_id: str, status: str) -> IssueMapping | None:
        from psycopg.types.json import Jsonb

        require_explicit_tenant_id(tenant_id)
        with postgres_common._tenant_connection(self._pool) as conn:
            row = conn.execute(
                "UPDATE issue_mappings SET data=data || %s WHERE tenant_id=%s AND mapping_id=%s RETURNING data",
                (Jsonb({"status": status, "updated_at": _utcnow()}), tenant_id, mapping_id),
            ).fetchone()
            conn.commit()
        return IssueMapping(**row[0]) if row else None
