"""Contract tests for the CWPP runtime workload-evidence ingest door.

The store (:mod:`agent_bom.cloud.runtime_workload_evidence_store`) and the
``ingest_runtime_signals`` library existed with ZERO callers in the API/CLI/MCP
surface — a deployed product could never populate it. These tests pin the new
authenticated, tenant-scoped, read-only-posture ingest route end-to-end: it
authenticates a pre-registered source (HMAC secret), enforces tenant binding,
persists through the store's dedup contract, and the persisted evidence then
reaches the graph via ``enrich_graph_workload_runtime_evidence``.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

from starlette.testclient import TestClient

from agent_bom.api.server import app, configure_api
from agent_bom.cloud.runtime_workload_evidence import (
    RuntimeEvidenceSource,
    RuntimeSourceRegistry,
    RuntimeWorkloadEvidenceIndex,
    enrich_graph_workload_runtime_evidence,
    get_runtime_source_registry,
    set_runtime_source_registry,
)
from agent_bom.cloud.runtime_workload_evidence_store import (
    InMemoryRuntimeWorkloadEvidenceStore,
    set_runtime_workload_evidence_store,
)
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType

PROXY_SECRET = "test-proxy-secret-with-32-plus-bytes"
SOURCE_SECRET = "s3cr3t-token-value-1234"
TENANT = "tenant-alpha"


def _proxy_headers(role: str = "admin", tenant: str = TENANT) -> dict[str, str]:
    return {
        "X-Agent-Bom-Role": role,
        "X-Agent-Bom-Tenant-ID": tenant,
        "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
    }


def setup_module() -> None:
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH"] = "1"
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH_SECRET"] = PROXY_SECRET
    configure_api(api_key=None)


def teardown_module() -> None:
    os.environ.pop("AGENT_BOM_TRUST_PROXY_AUTH", None)
    os.environ.pop("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", None)
    set_runtime_source_registry(None)
    set_runtime_workload_evidence_store(None)


def _install_source(tenant: str = TENANT, account: str = "123456789012") -> None:
    registry = RuntimeSourceRegistry()
    registry.add(
        RuntimeEvidenceSource.register(
            source_id="edr-1",
            tenant_id=tenant,
            provider="aws",
            account_id=account,
            kind="edr",
            secret=SOURCE_SECRET,
        )
    )
    set_runtime_source_registry(registry)
    set_runtime_workload_evidence_store(InMemoryRuntimeWorkloadEvidenceStore())


def _signal(workload_ref: str = "i-0abc", dedup_key: str = "evt-1") -> dict:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "workload_ref": workload_ref,
        "signal_type": "ioc_detection",
        "severity": "high",
        "observed_at": now,
        "dedup_key": dedup_key,
        "title": "beacon",
    }


def test_ingest_persists_and_reaches_graph() -> None:
    _install_source()
    client = TestClient(app)
    resp = client.post(
        "/v1/cloud/runtime-evidence/ingest",
        headers=_proxy_headers(),
        json={"source_id": "edr-1", "secret": SOURCE_SECRET, "signals": [_signal()]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["accepted"] == 1
    assert body["persisted"] == 1
    assert body["tenant_id"] == TENANT

    # The persisted evidence must actually reach the graph enrichment path.
    from agent_bom.cloud.runtime_workload_evidence_store import get_runtime_workload_evidence_store

    index = RuntimeWorkloadEvidenceIndex.from_store(get_runtime_workload_evidence_store(), TENANT)
    assert not index.is_empty()
    graph = UnifiedGraph(tenant_id=TENANT)
    graph.add_node(
        UnifiedNode(
            id="cloud_resource:aws:i-0abc",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="i-0abc",
            attributes={
                "resource_type": "workload_disk",
                "cloud_provider": "aws",
                "account_id": "123456789012",
                "resource_id": "i-0abc",
            },
        )
    )
    annotated = enrich_graph_workload_runtime_evidence(graph, index)
    assert annotated == 1
    node = graph.nodes["cloud_resource:aws:i-0abc"]
    assert node.attributes["runtime_evidence"]["state"] == "runtime_ioc_observed"
    assert node.attributes["runtime_evidence"]["clean_workload_assertion"] is False


def test_ingest_dedups_on_retry() -> None:
    _install_source()
    client = TestClient(app)
    payload = {"source_id": "edr-1", "secret": SOURCE_SECRET, "signals": [_signal(dedup_key="evt-dup")]}
    first = client.post("/v1/cloud/runtime-evidence/ingest", headers=_proxy_headers(), json=payload)
    second = client.post("/v1/cloud/runtime-evidence/ingest", headers=_proxy_headers(), json=payload)
    assert first.json()["persisted"] == 1
    assert second.json()["persisted"] == 0
    assert second.json()["deduped"] == 1


def test_ingest_bad_secret_is_401() -> None:
    _install_source()
    client = TestClient(app)
    resp = client.post(
        "/v1/cloud/runtime-evidence/ingest",
        headers=_proxy_headers(),
        json={"source_id": "edr-1", "secret": "wrong-secret-value", "signals": [_signal()]},
    )
    assert resp.status_code == 401


def test_ingest_unknown_source_is_401_not_enumerable() -> None:
    _install_source()
    client = TestClient(app)
    resp = client.post(
        "/v1/cloud/runtime-evidence/ingest",
        headers=_proxy_headers(),
        json={"source_id": "does-not-exist", "secret": SOURCE_SECRET, "signals": [_signal()]},
    )
    assert resp.status_code == 401


def test_ingest_cross_tenant_source_rejected() -> None:
    # Source belongs to tenant-alpha; a request authenticated as another tenant
    # must not be able to ingest against it even with the right source secret.
    _install_source(tenant=TENANT)
    client = TestClient(app)
    resp = client.post(
        "/v1/cloud/runtime-evidence/ingest",
        headers=_proxy_headers(tenant="tenant-beta"),
        json={"source_id": "edr-1", "secret": SOURCE_SECRET, "signals": [_signal()]},
    )
    assert resp.status_code == 401


def test_ingest_requires_auth() -> None:
    _install_source()
    monkey = os.environ.pop("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", None)
    try:
        configure_api(api_key=None)
        client = TestClient(app)
        resp = client.post(
            "/v1/cloud/runtime-evidence/ingest",
            json={"source_id": "edr-1", "secret": SOURCE_SECRET, "signals": [_signal()]},
        )
        assert resp.status_code == 401
    finally:
        if monkey is not None:
            os.environ["AGENT_BOM_ALLOW_UNAUTHENTICATED_API"] = monkey
        configure_api(api_key=None)


def test_registry_bootstraps_from_env(monkeypatch) -> None:
    import json

    monkeypatch.setenv(
        "AGENT_BOM_RUNTIME_EVIDENCE_SOURCES",
        json.dumps(
            [
                {
                    "source_id": "env-edr",
                    "tenant_id": "tenant-x",
                    "provider": "gcp",
                    "account_id": "proj-1",
                    "kind": "edr",
                    "secret": "env-secret-value-12345",
                }
            ]
        ),
    )
    set_runtime_source_registry(None)
    registry = get_runtime_source_registry()
    src = registry.get("env-edr")
    assert src is not None
    assert src.tenant_id == "tenant-x"
    assert src.authenticate("env-secret-value-12345")
    set_runtime_source_registry(None)
