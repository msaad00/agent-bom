from __future__ import annotations

import json

from click.testing import CliRunner

from agent_bom.cli import main


class _Result:
    def __init__(self, row: tuple[object, ...]) -> None:
        self._row = row

    def fetchone(self) -> tuple[object, ...]:
        return self._row


class _Connection:
    def execute(self, query: str) -> _Result:
        assert "server_version" in query
        assert "rolsuper" in query
        assert "pg_stat_ssl" in query
        assert "alembic_version" in query
        assert "control_plane_schema_versions" in query
        return _Result(("16.4", 160004, True, False, False, True, True))

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None


class _Pool:
    def connection(self) -> _Connection:
        return _Connection()


def test_provider_posture_normalizes_aliases_without_inflating_certification(monkeypatch) -> None:
    from agent_bom.storage.postgres_capabilities import declared_postgres_portability

    monkeypatch.setenv("AGENT_BOM_POSTGRES_PROVIDER", "snowflake-pg")
    posture = declared_postgres_portability()

    assert posture.provider == "snowflake_postgres"
    assert posture.contract == "postgresql"
    assert posture.evidence == "compatible_unverified"
    assert posture.next_action == "agent-bom doctor"

    monkeypatch.setenv("AGENT_BOM_POSTGRES_PROVIDER", "clickhouse")
    posture = declared_postgres_portability()
    assert posture.provider == "clickhouse_postgres"
    assert posture.evidence == "compatible_unverified"


def test_provider_posture_keeps_unknown_provider_explicit(monkeypatch) -> None:
    from agent_bom.storage.postgres_capabilities import declared_postgres_portability

    monkeypatch.setenv("AGENT_BOM_POSTGRES_PROVIDER", "private-pg-service")
    posture = declared_postgres_portability()

    assert posture.provider == "other"
    assert posture.evidence == "provider_unverified"
    assert posture.declared_hint == "private-pg-service"


def test_live_postgres_probe_checks_portable_contract_without_exposing_identity(monkeypatch) -> None:
    from agent_bom.storage.postgres_capabilities import probe_postgres_portability

    monkeypatch.setenv("AGENT_BOM_POSTGRES_PROVIDER", "postgres")
    monkeypatch.setenv("AGENT_BOM_POSTGRES_MAINTENANCE_URL", "postgresql://maintenance:secret@db/agent_bom")

    probe = probe_postgres_portability(pool=_Pool())
    payload = probe.to_dict()

    assert payload == {
        "schema_version": "postgres-portability.v1",
        "status": "ready",
        "provider": "postgres",
        "contract": "postgresql",
        "evidence": "controlled_verified",
        "server_version": "16.4",
        "server_version_num": 160004,
        "tls": True,
        "runtime_role_rls_safe": True,
        "alembic_schema_present": True,
        "control_plane_schema_present": True,
        "maintenance_role_configured": True,
        "reasons": [],
        "next_action": None,
    }
    assert "secret" not in json.dumps(payload)
    assert "current_user" not in payload


def test_live_postgres_probe_sanitizes_connection_failure(monkeypatch) -> None:
    from agent_bom.storage.postgres_capabilities import probe_postgres_portability

    class BrokenPool:
        def connection(self):
            raise RuntimeError("postgresql://user:top-secret@private-db.internal/customer")

    monkeypatch.setenv("AGENT_BOM_POSTGRES_PROVIDER", "aws-rds")
    probe = probe_postgres_portability(pool=BrokenPool())
    payload = probe.to_dict()

    assert payload["status"] == "unavailable"
    assert payload["reasons"] == ["database_unavailable"]
    assert payload["next_action"] == "verify the Postgres secret, network policy, and TLS settings; then rerun agent-bom doctor"
    assert "top-secret" not in json.dumps(payload)
    assert "private-db" not in json.dumps(payload)


def test_doctor_surfaces_postgres_portability_in_human_and_agent_modes(monkeypatch) -> None:
    from agent_bom.storage.postgres_capabilities import PostgresPortabilityProbe

    probe = PostgresPortabilityProbe(
        status="ready",
        provider="snowflake_postgres",
        contract="postgresql",
        evidence="compatible_unverified",
        server_version="17.2",
        server_version_num=170002,
        tls=True,
        runtime_role_rls_safe=True,
        alembic_schema_present=True,
        control_plane_schema_present=True,
        maintenance_role_configured=True,
    )
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://app:redacted@example/agent_bom")
    monkeypatch.setattr("agent_bom.storage.postgres_capabilities.probe_postgres_portability", lambda: probe)

    human = CliRunner().invoke(main, ["doctor"])
    assert human.exit_code == 0, human.output
    assert "Postgres portability" in human.output
    assert "snowflake_postgres" in human.output
    assert "compatible_unverified" in human.output

    agent = CliRunner().invoke(main, ["--agent-mode", "doctor"])
    assert agent.exit_code == 0, agent.output
    payload = json.loads(agent.stdout)
    assert payload["data"]["postgres_portability"]["provider"] == "snowflake_postgres"
    assert payload["data"]["postgres_portability"]["status"] == "ready"


def test_authenticated_health_model_has_additive_postgres_posture(monkeypatch) -> None:
    from agent_bom.api.server import _postgres_portability_health

    monkeypatch.setenv("AGENT_BOM_POSTGRES_PROVIDER", "clickhouse-postgres")
    health = _postgres_portability_health("postgres")

    assert health is not None
    assert health.provider == "clickhouse_postgres"
    assert health.contract == "postgresql"
    assert health.evidence == "compatible_unverified"
    assert _postgres_portability_health("sqlite") is None
