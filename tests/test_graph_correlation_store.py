"""SQLite durability contracts for immutable graph correlation runs."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from agent_bom.db import graph_store
from agent_bom.graph import AttackPath, EntityType, UnifiedGraph, UnifiedNode
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
        "result_manifest",
        "manifest_sha256",
        "output_scan_id",
        "failure_code",
    } <= run_columns
    assert version >= 5


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


def test_active_correlation_count_is_exact_and_tenant_scoped(tmp_path) -> None:
    db = tmp_path / "graph.db"
    with graph_store.open_graph_db(db) as conn:
        graph_store.create_correlation_run(conn, _run())
        graph_store.create_correlation_run(
            conn,
            _run(tenant_id="acme", correlation_id="corr-2", idempotency_key="idem-2"),
        )
        graph_store.create_correlation_run(
            conn,
            _run(tenant_id="other", correlation_id="corr-other", idempotency_key="idem-other"),
        )
        graph_store.update_correlation_run(
            conn,
            tenant_id="acme",
            correlation_id="corr-2",
            status=CorrelationRunStatus.FAILED,
            failure_code="analysis_failed",
            completed_at="2026-08-30T00:01:00+00:00",
        )

        assert graph_store.count_active_correlation_runs(conn, tenant_id="acme") == 1
        assert graph_store.count_active_correlation_runs(conn, tenant_id="other") == 1
        assert graph_store.count_active_correlation_runs(conn, tenant_id="missing") == 0


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
        result_manifest = {"correlation_id": "corr-1"}
        manifest_sha256 = (
            "sha256:" + hashlib.sha256(json.dumps(result_manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        )
        complete = graph_store.update_correlation_run(
            conn,
            tenant_id="acme",
            correlation_id="corr-1",
            status=CorrelationRunStatus.COMPLETE,
            output_scan_id="corr-1",
            manifest_sha256=manifest_sha256,
            result_manifest=result_manifest,
            completed_at="2026-08-30T00:02:00+00:00",
        )

        assert running.status is CorrelationRunStatus.RUNNING
        assert complete.status is CorrelationRunStatus.COMPLETE
        assert complete.input_manifest == _run().input_manifest
        assert complete.result_manifest == result_manifest
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


def test_latest_snapshot_selection_is_scoped_by_kind_and_tenant(tmp_path) -> None:
    db = tmp_path / "graph.db"
    with graph_store.open_graph_db(db) as conn:
        prior = UnifiedGraph(
            scan_id="scan-0",
            tenant_id="acme",
            created_at="2026-08-29T23:59:00+00:00",
        )
        prior.add_node(UnifiedNode(id="agent:prior", entity_type=EntityType.AGENT, label="prior"))
        graph_store.save_graph(conn, prior)

        scan = UnifiedGraph(
            scan_id="scan-1",
            tenant_id="acme",
            created_at="2026-08-30T00:00:00+00:00",
        )
        scan.add_node(UnifiedNode(id="agent:scan", entity_type=EntityType.AGENT, label="scan"))
        graph_store.save_graph(conn, scan)

        correlated = UnifiedGraph(
            scan_id="corr-1",
            tenant_id="acme",
            created_at="2026-08-30T00:01:00+00:00",
        )
        correlated.add_node(UnifiedNode(id="agent:corr", entity_type=EntityType.AGENT, label="correlation"))
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

        other = UnifiedGraph(
            scan_id="scan-other",
            tenant_id="other",
            created_at="2026-08-30T00:02:00+00:00",
        )
        other.add_node(UnifiedNode(id="agent:other", entity_type=EntityType.AGENT, label="other"))
        graph_store.save_graph(conn, other)

        assert graph_store.latest_snapshot_id(conn, tenant_id="acme") == "scan-1"
        assert graph_store.latest_snapshot_id(conn, tenant_id="acme", snapshot_kind="scan") == "scan-1"
        assert graph_store.latest_snapshot_id(conn, tenant_id="acme", snapshot_kind="correlation") == "corr-1"
        assert graph_store.latest_snapshot_id(conn, tenant_id="other", snapshot_kind="correlation") == ""
        assert graph_store.previous_snapshot_id(conn, tenant_id="acme", before_scan_id="scan-1") == "scan-0"
        assert (
            graph_store.previous_snapshot_id(
                conn,
                tenant_id="acme",
                before_scan_id="corr-1",
                snapshot_kind="correlation",
            )
            == ""
        )

        with pytest.raises(ValueError, match="snapshot_kind"):
            graph_store.latest_snapshot_id(conn, tenant_id="acme", snapshot_kind="inventory")


def test_completed_correlation_snapshot_cannot_be_replaced_by_a_scan_retry(tmp_path) -> None:
    db = tmp_path / "graph.db"
    with graph_store.open_graph_db(db) as conn:
        correlated = UnifiedGraph(scan_id="corr-1", tenant_id="acme")
        correlated.add_node(UnifiedNode(id="agent:original", entity_type=EntityType.AGENT, label="original"))
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
        replacement = UnifiedGraph(scan_id="corr-1", tenant_id="acme")
        replacement.add_node(UnifiedNode(id="agent:replacement", entity_type=EntityType.AGENT, label="replacement"))

        with pytest.raises(ValueError, match="correlation snapshot is immutable"):
            graph_store.save_graph(conn, replacement)

        restored = graph_store.load_graph(conn, tenant_id="acme", scan_id="corr-1")
        metadata = graph_store.snapshots_by_ids(conn, tenant_id="acme", scan_ids={"corr-1"})[0]

    assert set(restored.nodes) == {"agent:original"}
    assert metadata["snapshot_kind"] == "correlation"
    assert metadata["evidence_manifest_sha256"] == "sha256:" + "b" * 64


def test_correlation_run_reserves_its_output_id_even_when_snapshot_is_missing(tmp_path) -> None:
    db = tmp_path / "graph.db"
    with graph_store.open_graph_db(db) as conn:
        graph_store.create_correlation_run(conn, _run())
        collision = UnifiedGraph(scan_id="corr-1", tenant_id="acme")
        collision.add_node(UnifiedNode(id="agent:collision", entity_type=EntityType.AGENT, label="collision"))

        with pytest.raises(ValueError, match="correlation output identifier is reserved"):
            graph_store.save_graph(conn, collision)

        assert graph_store.list_snapshots(conn, tenant_id="acme") == []


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


def test_evidence_manifest_digest_covers_attack_path_hop_receipts(tmp_path) -> None:
    db = tmp_path / "graph.db"
    graph = UnifiedGraph(scan_id="scan-proof", tenant_id="acme")
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a"))
    graph.add_node(UnifiedNode(id="tool:secret", entity_type=EntityType.TOOL, label="read_secret"))
    graph.attack_paths.append(
        AttackPath(
            source="agent:a",
            target="tool:secret",
            hops=["agent:a", "tool:secret"],
            edges=["reaches_tool"],
            composite_risk=9.0,
            hop_evidence=[{"source_snapshot_ids": ["runtime-a"], "freshness": "fresh"}],
            analysis={"status": "complete", "truncated": False},
        )
    )

    with graph_store.open_graph_db(db) as conn:
        graph_store.save_graph(conn, graph)
        first = graph_store.graph_evidence_manifest(conn, tenant_id="acme", scan_id="scan-proof")
        graph.attack_paths[0].hop_evidence[0]["freshness"] = "stale_allowed"
        graph_store.save_graph(conn, graph)
        second = graph_store.graph_evidence_manifest(conn, tenant_id="acme", scan_id="scan-proof")

    assert first["findings_digest"] != second["findings_digest"]


def test_snapshot_receipts_are_selected_by_exact_ids_without_history_paging(tmp_path) -> None:
    with graph_store.open_graph_db(tmp_path / "graph.db") as store:
        for scan_id in ("old-retained", "recent", "unselected"):
            graph = UnifiedGraph(scan_id=scan_id, tenant_id="acme")
            graph.add_node(UnifiedNode(id=f"agent:{scan_id}", entity_type=EntityType.AGENT, label=scan_id))
            graph_store.save_graph(store, graph)

        rows = graph_store.snapshots_by_ids(
            store,
            tenant_id="acme",
            scan_ids={"old-retained", "recent", "missing"},
        )

    assert {row["scan_id"] for row in rows} == {"old-retained", "recent"}
