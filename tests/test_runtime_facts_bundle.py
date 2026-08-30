"""Signed correlation runtime facts and last-valid cache behavior."""

from __future__ import annotations

import hmac
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.correlation import (
    CorrelationRunStatus,
    GraphCorrelationRun,
    correlation_graph_digest,
    correlation_manifest_digest,
)
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.runtime.correlation_facts import (
    RuntimeFactsBundleError,
    RuntimeFactsPoller,
    create_runtime_facts_bundle,
    create_runtime_facts_bundle_from_correlation,
    verify_runtime_facts_bundle,
)
from agent_bom.runtime.graph_reachability import AgentReachability, ReachabilityMap

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
KEY = b"runtime-facts-test-key-material-32-bytes"


def _resign(bundle: dict) -> None:
    signature_input = {
        "algorithm": bundle["signature"]["algorithm"],
        "key_id": bundle["signature"]["key_id"],
        "payload": bundle["payload"],
    }
    encoded = json.dumps(signature_input, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    bundle["signature"]["value"] = hmac.digest(KEY, encoded, "sha256").hex()


def _completed_run(
    graph: UnifiedGraph,
    *,
    freshness: str = "fresh",
    input_created_at: datetime | None = None,
    max_age_hours: int = 24,
) -> tuple[GraphCorrelationRun, dict[str, object]]:
    observed = input_created_at or (NOW - timedelta(hours=25 if freshness == "stale_allowed" else 1))
    inputs = [
        {"scan_id": "repo", "created_at": observed.isoformat(), "freshness": freshness},
        {"scan_id": "runtime", "created_at": observed.isoformat(), "freshness": freshness},
    ]
    graph_digest = correlation_graph_digest(graph)
    result_manifest = {
        "correlation_id": graph.scan_id,
        "freshness_policy": {
            "max_age_hours": max_age_hours,
            "allow_stale": freshness == "stale_allowed",
        },
        "input_snapshots": inputs,
        "output": {
            "scan_id": graph.scan_id,
            "node_count": len(graph.nodes),
            "edge_count": len(graph.edges),
            "graph_digest_sha256": graph_digest,
        },
    }
    manifest_sha256 = correlation_manifest_digest(result_manifest)
    run = GraphCorrelationRun(
        correlation_id=graph.scan_id,
        tenant_id=graph.tenant_id,
        idempotency_key=f"idem-{graph.scan_id}",
        name="runtime facts",
        status=CorrelationRunStatus.COMPLETE,
        max_age_hours=max_age_hours,
        allow_stale=freshness == "stale_allowed",
        input_manifest=inputs,
        result_manifest=result_manifest,
        manifest_sha256=manifest_sha256,
        output_scan_id=graph.scan_id,
        created_at=NOW.isoformat(),
        completed_at=NOW.isoformat(),
    )
    metadata: dict[str, object] = {
        "scan_id": graph.scan_id,
        "snapshot_kind": "correlation",
        "correlation_id": graph.scan_id,
        "evidence_manifest_sha256": manifest_sha256,
        "node_count": len(graph.nodes),
        "edge_count": len(graph.edges),
    }
    return run, metadata


def _runtime_graph(*, scan_id: str = "corr-1", hops: int = 1) -> UnifiedGraph:
    graph = UnifiedGraph(scan_id=scan_id, tenant_id="tenant-a", created_at=NOW.isoformat())
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a", attributes={"runtime_id": "agent-a"}))
    previous = "agent:a"
    for index in range(1, hops):
        node_id = f"module:{index}"
        graph.add_node(UnifiedNode(id=node_id, entity_type=EntityType.CODE_MODULE, label=node_id))
        graph.add_edge(
            UnifiedEdge(
                source=previous,
                target=node_id,
                relationship=RelationshipType.CALLED,
                source_scan_id=scan_id,
                provenance={"correlation": {"source_scan_ids": ["repo", "runtime"]}},
            )
        )
        previous = node_id
    graph.add_node(UnifiedNode(id="tool:secret", entity_type=EntityType.TOOL, label="read_secret"))
    graph.add_edge(
        UnifiedEdge(
            source=previous,
            target="tool:secret",
            relationship=RelationshipType.REACHES_TOOL,
            source_scan_id=scan_id,
            provenance={"correlation": {"source_scan_ids": ["repo", "runtime"], "freshness": "fresh"}},
        )
    )
    return graph


def _bundle(*, now: datetime = NOW, ttl_seconds: int = 300) -> dict:
    reachability = ReachabilityMap(
        by_agent={
            "agent-a": AgentReachability(
                agent_id="agent-a",
                node_ids=frozenset({"tool:read-secret"}),
                node_labels=frozenset({"read_secret"}),
            )
        }
    )
    return create_runtime_facts_bundle(
        correlation_id="corr-1",
        tenant_id="tenant-a",
        manifest_sha256="sha256:" + "a" * 64,
        reachability=reachability,
        signing_key=KEY,
        ttl_seconds=ttl_seconds,
        now=now,
        key_id="runtime-key-1",
    )


def test_bundle_is_signed_expiring_and_tenant_bound() -> None:
    bundle = _bundle()
    verified = verify_runtime_facts_bundle(bundle, signing_key=KEY, tenant_id="tenant-a", now=NOW)

    assert bundle["payload"]["schema_version"] == "agent-bom.runtime-facts/v2"
    assert verified.correlation_id == "corr-1"
    assert verified.manifest_sha256 == "sha256:" + "a" * 64
    assert verified.analysis_complete is True
    assert verified.analysis_bounds["status"] == "complete"
    assert verified.reachability.reaches_privileged("agent-a", "read_secret") is not None

    with pytest.raises(RuntimeFactsBundleError, match="tenant_mismatch"):
        verify_runtime_facts_bundle(_bundle(), signing_key=KEY, tenant_id="tenant-b", now=NOW)
    with pytest.raises(RuntimeFactsBundleError, match="bundle_expired"):
        verify_runtime_facts_bundle(_bundle(), signing_key=KEY, tenant_id="tenant-a", now=NOW + timedelta(minutes=6))


def test_tampered_bundle_is_rejected() -> None:
    bundle = _bundle()
    bundle["payload"]["facts"][0]["node_labels"] = ["run_shell"]

    with pytest.raises(RuntimeFactsBundleError, match="invalid_signature"):
        verify_runtime_facts_bundle(bundle, signing_key=KEY, tenant_id="tenant-a", now=NOW)


def test_tampered_key_id_is_rejected_as_unauthenticated_metadata() -> None:
    bundle = _bundle()
    bundle["signature"]["key_id"] = "attacker-controlled-label"

    with pytest.raises(RuntimeFactsBundleError, match="invalid_signature"):
        verify_runtime_facts_bundle(bundle, signing_key=KEY, tenant_id="tenant-a", now=NOW)


def test_manifest_hash_requires_a_canonical_sha256_digest() -> None:
    bundle = _bundle()
    bundle["payload"]["manifest_sha256"] = "sha256:" + "z" * 64

    with pytest.raises(RuntimeFactsBundleError, match="invalid_manifest_hash"):
        create_runtime_facts_bundle(
            correlation_id="corr-1",
            tenant_id="tenant-a",
            manifest_sha256=bundle["payload"]["manifest_sha256"],
            reachability=ReachabilityMap(),
            signing_key=KEY,
            ttl_seconds=300,
            now=NOW,
        )


def test_verifier_rejects_future_issued_and_overlong_signed_bundles() -> None:
    future = _bundle(now=NOW + timedelta(minutes=6))
    with pytest.raises(RuntimeFactsBundleError, match="bundle_not_yet_valid"):
        verify_runtime_facts_bundle(future, signing_key=KEY, tenant_id="tenant-a", now=NOW)

    overlong = _bundle()
    overlong["payload"]["expires_at"] = (NOW + timedelta(days=2)).isoformat()
    _resign(overlong)
    with pytest.raises(RuntimeFactsBundleError, match="invalid_expiry"):
        verify_runtime_facts_bundle(overlong, signing_key=KEY, tenant_id="tenant-a", now=NOW)


def test_verifier_rejects_signed_bundle_without_correlation_receipts() -> None:
    malformed = _bundle()
    malformed["payload"]["correlation_id"] = ""
    _resign(malformed)
    with pytest.raises(RuntimeFactsBundleError, match="invalid_identity"):
        verify_runtime_facts_bundle(malformed, signing_key=KEY, tenant_id="tenant-a", now=NOW)


def test_tampered_analysis_bounds_are_rejected_by_the_envelope_signature() -> None:
    bundle = _bundle()
    bundle["payload"]["analysis_bounds"]["complete"] = False

    with pytest.raises(RuntimeFactsBundleError, match="invalid_signature"):
        verify_runtime_facts_bundle(bundle, signing_key=KEY, tenant_id="tenant-a", now=NOW)


@pytest.mark.asyncio
async def test_poller_keeps_last_valid_bundle_during_outage_until_expiry() -> None:
    responses: list[object] = [_bundle(), RuntimeError("upstream secret must not leak")]

    async def fetch() -> dict:
        value = responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return value

    clock = [NOW]
    poller = RuntimeFactsPoller(
        fetch=fetch,
        signing_key=KEY,
        tenant_id="tenant-a",
        now=lambda: clock[0],
    )

    assert await poller.refresh() is True
    assert poller.current().reachability.reaches_privileged("agent-a", "read_secret") is not None
    assert await poller.refresh() is False
    assert poller.last_error == "bundle_fetch_failed"
    assert poller.current().correlation_id == "corr-1"

    clock[0] = NOW + timedelta(minutes=6)
    assert poller.current() is None


@pytest.mark.asyncio
async def test_poller_drops_cached_bundle_on_correlation_integrity_failure() -> None:
    responses: list[object] = [_bundle(), RuntimeFactsBundleError("correlation_output_unavailable")]

    async def fetch() -> dict:
        value = responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return value

    poller = RuntimeFactsPoller(fetch=fetch, signing_key=KEY, tenant_id="tenant-a", now=lambda: NOW)

    assert await poller.refresh() is True
    assert poller.current() is not None
    assert await poller.refresh() is False
    assert poller.last_error == "correlation_output_unavailable"
    assert poller.current() is None


def test_completed_correlation_produces_bundle_from_proven_graph_edges() -> None:
    graph = _runtime_graph()
    run, metadata = _completed_run(graph)

    bundle = create_runtime_facts_bundle_from_correlation(
        run,
        graph,
        snapshot_metadata=metadata,
        signing_key=KEY,
        ttl_seconds=300,
        now=NOW,
    )
    verified = verify_runtime_facts_bundle(bundle, signing_key=KEY, tenant_id="tenant-a", now=NOW)

    assert verified.reachability.reaches_privileged("agent-a", "read_secret") is not None
    assert verified.analysis_complete is True


def test_correlation_bundle_recomputes_immutable_input_age_at_each_issuance() -> None:
    graph = _runtime_graph(scan_id="corr-aging")
    run, metadata = _completed_run(
        graph,
        input_created_at=NOW - timedelta(hours=23),
        max_age_hours=24,
    )

    fresh = create_runtime_facts_bundle_from_correlation(
        run,
        graph,
        snapshot_metadata=metadata,
        signing_key=KEY,
        ttl_seconds=300,
        now=NOW,
    )

    assert fresh["payload"]["evidence_freshness"] == "fresh"
    assert fresh["payload"]["input_freshness"]["max_age_hours"] == 24
    assert fresh["payload"]["input_freshness"]["snapshots"] == [
        {"scan_id": "repo", "created_at": (NOW - timedelta(hours=23)).isoformat()},
        {"scan_id": "runtime", "created_at": (NOW - timedelta(hours=23)).isoformat()},
    ]

    with pytest.raises(RuntimeFactsBundleError, match="correlation_inputs_stale"):
        create_runtime_facts_bundle_from_correlation(
            run,
            graph,
            snapshot_metadata=metadata,
            signing_key=KEY,
            ttl_seconds=300,
            now=NOW + timedelta(hours=2),
        )


@pytest.mark.parametrize(
    ("metadata_update", "expected_code"),
    [
        ({"snapshot_kind": "scan"}, "correlation_output_replaced"),
        ({"correlation_id": "other"}, "correlation_output_replaced"),
        ({"evidence_manifest_sha256": "sha256:" + "b" * 64}, "correlation_manifest_mismatch"),
    ],
)
def test_runtime_facts_rejects_replaced_or_manifest_mismatched_output(metadata_update, expected_code) -> None:
    graph = _runtime_graph()
    run, metadata = _completed_run(graph)
    metadata.update(metadata_update)

    with pytest.raises(RuntimeFactsBundleError, match=expected_code):
        create_runtime_facts_bundle_from_correlation(
            run,
            graph,
            snapshot_metadata=metadata,
            signing_key=KEY,
            ttl_seconds=300,
            now=NOW,
        )


def test_runtime_facts_rejects_missing_or_content_changed_output() -> None:
    graph = _runtime_graph()
    run, metadata = _completed_run(graph)

    with pytest.raises(RuntimeFactsBundleError, match="correlation_output_unavailable"):
        create_runtime_facts_bundle_from_correlation(
            run,
            graph,
            snapshot_metadata=None,
            signing_key=KEY,
            ttl_seconds=300,
            now=NOW,
        )


def test_runtime_facts_rejects_a_result_manifest_changed_after_completion() -> None:
    graph = _runtime_graph()
    run, metadata = _completed_run(graph)
    tampered_run = replace(
        run,
        result_manifest={**run.result_manifest, "output": {**run.result_manifest["output"], "node_count": 999}},
    )

    with pytest.raises(RuntimeFactsBundleError, match="correlation_manifest_mismatch"):
        create_runtime_facts_bundle_from_correlation(
            tampered_run,
            graph,
            snapshot_metadata=metadata,
            signing_key=KEY,
            ttl_seconds=300,
            now=NOW,
        )

    graph.nodes["tool:secret"].label = "replacement_tool"
    with pytest.raises(RuntimeFactsBundleError, match="correlation_output_changed"):
        create_runtime_facts_bundle_from_correlation(
            run,
            graph,
            snapshot_metadata=metadata,
            signing_key=KEY,
            ttl_seconds=300,
            now=NOW,
        )


def test_runtime_facts_rejects_empty_facts_from_completed_output() -> None:
    graph = UnifiedGraph(scan_id="corr-empty", tenant_id="tenant-a", created_at=NOW.isoformat())
    graph.add_node(UnifiedNode(id="package:one", entity_type=EntityType.PACKAGE, label="one"))
    run, metadata = _completed_run(graph)

    with pytest.raises(RuntimeFactsBundleError, match="runtime_facts_empty"):
        create_runtime_facts_bundle_from_correlation(
            run,
            graph,
            snapshot_metadata=metadata,
            signing_key=KEY,
            ttl_seconds=300,
            now=NOW,
        )


def test_depth_seven_is_signed_as_limited_without_claiming_complete_reachability() -> None:
    graph = _runtime_graph(scan_id="corr-depth", hops=7)
    graph.add_node(UnifiedNode(id="tool:near", entity_type=EntityType.TOOL, label="list_files"))
    graph.add_edge(
        UnifiedEdge(
            source="agent:a",
            target="tool:near",
            relationship=RelationshipType.REACHES_TOOL,
            source_scan_id=graph.scan_id,
            provenance={"correlation": {"source_scan_ids": ["repo", "runtime"]}},
        )
    )
    run, metadata = _completed_run(graph)

    bundle = create_runtime_facts_bundle_from_correlation(
        run,
        graph,
        snapshot_metadata=metadata,
        signing_key=KEY,
        ttl_seconds=300,
        now=NOW,
    )
    verified = verify_runtime_facts_bundle(bundle, signing_key=KEY, tenant_id="tenant-a", now=NOW)

    assert verified.analysis_complete is False
    assert verified.analysis_bounds["status"] == "limited"
    assert verified.analysis_bounds["limit_reasons"] == ["depth_cap_reached"]
    assert verified.reachability.reaches_privileged("agent-a", "read_secret") is None
    assert verified.reachability.reaches_privileged("agent-a", "list_files") is not None


def test_visited_cap_is_signed_as_limited(monkeypatch) -> None:
    from agent_bom.runtime import correlation_facts

    monkeypatch.setattr(correlation_facts, "_VISITED_NODE_LIMIT", 3)
    graph = _runtime_graph(scan_id="corr-visited", hops=4)
    graph.add_node(UnifiedNode(id="tool:near", entity_type=EntityType.TOOL, label="list_files"))
    graph.add_edge(
        UnifiedEdge(
            source="agent:a",
            target="tool:near",
            relationship=RelationshipType.REACHES_TOOL,
            source_scan_id=graph.scan_id,
            provenance={"correlation": {"source_scan_ids": ["repo", "runtime"]}},
        )
    )
    run, metadata = _completed_run(graph)

    bundle = create_runtime_facts_bundle_from_correlation(
        run,
        graph,
        snapshot_metadata=metadata,
        signing_key=KEY,
        ttl_seconds=300,
        now=NOW,
    )
    verified = verify_runtime_facts_bundle(bundle, signing_key=KEY, tenant_id="tenant-a", now=NOW)

    assert verified.analysis_complete is False
    assert verified.analysis_bounds["limit_reasons"] == ["visited_node_cap_reached"]


def test_stale_allowed_correlation_bundle_is_never_presented_as_fresh() -> None:
    graph = _runtime_graph(scan_id="corr-stale")
    run, metadata = _completed_run(graph, freshness="stale_allowed")

    bundle = create_runtime_facts_bundle_from_correlation(
        run,
        graph,
        snapshot_metadata=metadata,
        signing_key=KEY,
        ttl_seconds=300,
        now=NOW,
    )
    verified = verify_runtime_facts_bundle(bundle, signing_key=KEY, tenant_id="tenant-a", now=NOW)

    assert bundle["payload"]["evidence_freshness"] == "stale_allowed"
    assert verified.evidence_freshness == "stale_allowed"
