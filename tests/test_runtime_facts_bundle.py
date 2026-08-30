"""Signed correlation runtime facts and last-valid cache behavior."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.correlation import CorrelationRunStatus, GraphCorrelationRun
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
    verified = verify_runtime_facts_bundle(_bundle(), signing_key=KEY, tenant_id="tenant-a", now=NOW)

    assert verified.correlation_id == "corr-1"
    assert verified.manifest_sha256 == "sha256:" + "a" * 64
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


def test_completed_correlation_produces_bundle_from_proven_graph_edges() -> None:
    graph = UnifiedGraph(scan_id="corr-1", tenant_id="tenant-a", created_at=NOW.isoformat())
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a", attributes={"runtime_id": "agent-a"}))
    graph.add_node(UnifiedNode(id="tool:secret", entity_type=EntityType.TOOL, label="read_secret"))
    graph.add_edge(
        UnifiedEdge(
            source="agent:a",
            target="tool:secret",
            relationship=RelationshipType.REACHES_TOOL,
            source_scan_id="corr-1",
            provenance={"correlation": {"source_scan_ids": ["repo", "runtime"], "freshness": "fresh"}},
        )
    )
    run = GraphCorrelationRun(
        correlation_id="corr-1",
        tenant_id="tenant-a",
        idempotency_key="idem-1",
        name="runtime facts",
        status=CorrelationRunStatus.COMPLETE,
        max_age_hours=24,
        allow_stale=False,
        input_manifest=[{"scan_id": "repo"}, {"scan_id": "runtime"}],
        result_manifest={"correlation_id": "corr-1"},
        manifest_sha256="sha256:" + "a" * 64,
        output_scan_id="corr-1",
        created_at=NOW.isoformat(),
        completed_at=NOW.isoformat(),
    )

    bundle = create_runtime_facts_bundle_from_correlation(
        run,
        graph,
        signing_key=KEY,
        ttl_seconds=300,
        now=NOW,
    )
    verified = verify_runtime_facts_bundle(bundle, signing_key=KEY, tenant_id="tenant-a", now=NOW)

    assert verified.reachability.reaches_privileged("agent-a", "read_secret") is not None


def test_stale_allowed_correlation_bundle_is_never_presented_as_fresh() -> None:
    graph = UnifiedGraph(scan_id="corr-stale", tenant_id="tenant-a", created_at=NOW.isoformat())
    run = GraphCorrelationRun(
        correlation_id="corr-stale",
        tenant_id="tenant-a",
        idempotency_key="idem-stale",
        name="stale runtime facts",
        status=CorrelationRunStatus.COMPLETE,
        max_age_hours=24,
        allow_stale=True,
        input_manifest=[
            {"scan_id": "repo", "freshness": "fresh"},
            {"scan_id": "runtime", "freshness": "stale_allowed"},
        ],
        result_manifest={"correlation_id": "corr-stale"},
        manifest_sha256="sha256:" + "b" * 64,
        output_scan_id="corr-stale",
        created_at=NOW.isoformat(),
        completed_at=NOW.isoformat(),
    )

    bundle = create_runtime_facts_bundle_from_correlation(
        run,
        graph,
        signing_key=KEY,
        ttl_seconds=300,
        now=NOW,
    )
    verified = verify_runtime_facts_bundle(bundle, signing_key=KEY, tenant_id="tenant-a", now=NOW)

    assert bundle["payload"]["evidence_freshness"] == "stale_allowed"
    assert verified.evidence_freshness == "stale_allowed"
