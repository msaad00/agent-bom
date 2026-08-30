"""SQLite durability contracts for immutable graph correlation runs."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

import pytest

from agent_bom.db import graph_store
from agent_bom.graph import EntityType, UnifiedGraph, UnifiedNode
from agent_bom.graph.correlation import CorrelationRunStatus, GraphCorrelationRun


def _run(*, tenant_id: str = "acme", correlation_id: str = "corr-1", idempotency_key: str = "idem-1") -> GraphCorrelationRun:
    return GraphCorrelationRun(
        correlation_id=correlation_id,
        tenant_id=tenant_id,
        idempotency_key=idempotency_key,
        name="reference lab",
        status=CorrelationRunStatus.PENDING,
        max_age_hours=168,
        allow_stale=False,
        input_manifest=[{"scan_id": "scan-1"}, {"scan_id": "scan-2"}],
        created_at="2026-08-30T00:00:00+00:00",
    )


def test_sqlite_migration_adds_snapshot_metadata_and_correlation_table(tmp_path) -> None:
    db = tmp_path / "graph.db"
    with graph_store.open_graph_db(db) as conn:
        snapshot_columns = {row["name"] for row in conn.execute("PRAGMA table_info(graph_snapshots)")}
        run_columns = {row["name"] for row in conn.execute("PRAGMA table_info(graph_correlation_runs)")}
        version = conn.execute("SELECT MAX(version) FROM graph_schema_version").fetchone()[0]

    assert {"snapshot_kind", "correlation_id", "evidence_manifest_sha256"} <= snapshot_columns
    assert {
        "correlation_id",
        "tenant_id",
        "idempotency_key",
        "status",
        "max_age_hours",
        "allow_stale",
        "input_manifest",
        "manifest_sha256",
        "output_scan_id",
        "failure_code",
    } <= run_columns
    assert version >= 4


def test_correlation_run_is_tenant_isolated_and_idempotent(tmp_path) -> None:
    db = tmp_path / "graph.db"
    with graph_store.open_graph_db(db) as conn:
        created, was_created = graph_store.create_correlation_run(conn, _run())
        replayed, replay_created = graph_store.create_correlation_run(conn, replace(_run(), correlation_id="corr-retry"))
        other, other_created = graph_store.create_correlation_run(
            conn,
            _run(tenant_id="other", correlation_id="corr-other", idempotency_key="idem-1"),
        )

        assert was_created is True
        assert replay_created is False
        assert replayed.correlation_id == created.correlation_id == "corr-1"
        assert other_created is True
        assert other.correlation_id == "corr-other"
        assert graph_store.get_correlation_run(conn, tenant_id="other", correlation_id="corr-1") is None
        assert [item.correlation_id for item in graph_store.list_correlation_runs(conn, tenant_id="acme")] == ["corr-1"]


def test_idempotency_key_rejects_a_different_request(tmp_path) -> None:
    db = tmp_path / "graph.db"
    with graph_store.open_graph_db(db) as conn:
        graph_store.create_correlation_run(conn, _run())
        with pytest.raises(ValueError, match="different correlation request"):
            graph_store.create_correlation_run(conn, replace(_run(), max_age_hours=24))


def test_run_contract_rejects_duplicate_inputs_and_unsanitized_failure_text() -> None:
    with pytest.raises(ValueError, match="non-empty and unique"):
        replace(_run(), input_manifest=[{"scan_id": "scan-1"}, {"scan_id": "scan-1"}])
    with pytest.raises(ValueError, match="sanitized machine-readable code"):
        replace(_run(), status=CorrelationRunStatus.FAILED, failure_code="database failed: /secret/path")


def test_correlation_request_is_immutable_but_status_progresses_monotonically(tmp_path) -> None:
    db = tmp_path / "graph.db"
    with graph_store.open_graph_db(db) as conn:
        graph_store.create_correlation_run(conn, _run())
        with pytest.raises(ValueError, match="sanitized machine-readable code"):
            graph_store.update_correlation_run(
                conn,
                tenant_id="acme",
                correlation_id="corr-1",
                status=CorrelationRunStatus.FAILED,
                failure_code="database failed: /secret/path",
            )
        assert graph_store.get_correlation_run(conn, tenant_id="acme", correlation_id="corr-1").status is CorrelationRunStatus.PENDING
        running = graph_store.update_correlation_run(
            conn,
            tenant_id="acme",
            correlation_id="corr-1",
            status=CorrelationRunStatus.RUNNING,
            started_at="2026-08-30T00:01:00+00:00",
        )
        complete = graph_store.update_correlation_run(
            conn,
            tenant_id="acme",
            correlation_id="corr-1",
            status=CorrelationRunStatus.COMPLETE,
            output_scan_id="corr-1",
            manifest_sha256="sha256:" + "a" * 64,
            completed_at="2026-08-30T00:02:00+00:00",
        )

        assert running.status is CorrelationRunStatus.RUNNING
        assert complete.status is CorrelationRunStatus.COMPLETE
        assert complete.input_manifest == _run().input_manifest
        with pytest.raises(ValueError, match="terminal"):
            graph_store.update_correlation_run(
                conn,
                tenant_id="acme",
                correlation_id="corr-1",
                status=CorrelationRunStatus.RUNNING,
            )


def test_complete_requires_manifest_and_output_equal_to_correlation_id(tmp_path) -> None:
    db = tmp_path / "graph.db"
    with graph_store.open_graph_db(db) as conn:
        graph_store.create_correlation_run(conn, _run())
        graph_store.update_correlation_run(
            conn,
            tenant_id="acme",
            correlation_id="corr-1",
            status=CorrelationRunStatus.RUNNING,
        )
        with pytest.raises(ValueError, match="output snapshot must equal"):
            graph_store.update_correlation_run(
                conn,
                tenant_id="acme",
                correlation_id="corr-1",
                status=CorrelationRunStatus.COMPLETE,
                output_scan_id="other",
                manifest_sha256="sha256:" + "a" * 64,
            )
        with pytest.raises(ValueError, match="requires a sha256"):
            graph_store.update_correlation_run(
                conn,
                tenant_id="acme",
                correlation_id="corr-1",
                status=CorrelationRunStatus.COMPLETE,
                output_scan_id="corr-1",
            )


def test_snapshot_metadata_round_trips_without_changing_legacy_defaults(tmp_path) -> None:
    db = tmp_path / "graph.db"
    with graph_store.open_graph_db(db) as conn:
        legacy = UnifiedGraph(scan_id="scan-legacy", tenant_id="acme")
        legacy.add_node(UnifiedNode(id="agent:one", entity_type=EntityType.AGENT, label="one"))
        graph_store.save_graph(conn, legacy)

        correlated = UnifiedGraph(scan_id="corr-1", tenant_id="acme")
        correlated.add_node(UnifiedNode(id="agent:two", entity_type=EntityType.AGENT, label="two"))
        graph_store.save_graph_streaming(
            conn,
            scan_id="corr-1",
            tenant_id="acme",
            nodes=correlated.nodes.values(),
            edges=(),
            snapshot_kind="correlation",
            correlation_id="corr-1",
            evidence_manifest_sha256="sha256:" + "b" * 64,
        )

        by_id = {item["scan_id"]: item for item in graph_store.list_snapshots(conn, tenant_id="acme")}

    assert by_id["scan-legacy"]["snapshot_kind"] == "scan"
    assert by_id["scan-legacy"]["correlation_id"] == ""
    assert by_id["corr-1"]["snapshot_kind"] == "correlation"
    assert by_id["corr-1"]["correlation_id"] == "corr-1"
    assert by_id["corr-1"]["evidence_manifest_sha256"] == "sha256:" + "b" * 64


def test_retention_purges_correlated_snapshot_but_keeps_immutable_run_receipt(tmp_path) -> None:
    db = tmp_path / "graph.db"
    with graph_store.open_graph_db(db) as conn:
        graph_store.create_correlation_run(conn, _run())
        correlated = UnifiedGraph(
            scan_id="corr-1",
            tenant_id="acme",
            created_at="2026-08-29T00:00:00+00:00",
        )
        correlated.add_node(UnifiedNode(id="agent:two", entity_type=EntityType.AGENT, label="two"))
        graph_store.save_graph_streaming(
            conn,
            scan_id="corr-1",
            tenant_id="acme",
            nodes=correlated.nodes.values(),
            edges=(),
            created_at=correlated.created_at,
            snapshot_kind="correlation",
            correlation_id="corr-1",
        )
        conn.execute(
            "UPDATE graph_snapshots SET created_at = ? WHERE tenant_id = ? AND scan_id = ?",
            ("2026-01-01T00:00:00+00:00", "acme", "corr-1"),
        )

        result = graph_store.purge_expired_graph_snapshots(
            conn,
            retention_days=1,
            now=datetime(2026, 8, 30, tzinfo=timezone.utc),
            tenant_id="acme",
        )

        assert result["purged_snapshots"] == [{"scan_id": "corr-1", "tenant_id": "acme"}]
        assert graph_store.get_correlation_run(conn, tenant_id="acme", correlation_id="corr-1") is not None
        assert graph_store.list_snapshots(conn, tenant_id="acme") == []
