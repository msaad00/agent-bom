"""Cross-surface identity contracts for the final integrity series."""

from __future__ import annotations

from agent_bom.baseline import InMemoryTrendStore, SQLiteTrendStore, TrendPoint
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.models import Agent, AgentType, AIBOMReport, CredentialIdentityBinding, MCPServer
from agent_bom.output.json_fmt import to_json


def _finding(*, asset_id: str, cve_id: str = "CVE-2026-1000") -> Finding:
    return Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(
            name="requests",
            asset_type="package",
            identifier=asset_id,
        ),
        severity="high",
        cve_id=cve_id,
    )


def test_finding_group_identity_preserves_asset_occurrences() -> None:
    first = _finding(asset_id="pkg:pypi/requests@2.0.0?image=api")
    second = _finding(asset_id="pkg:pypi/requests@2.0.0?image=worker")

    assert first.occurrence_id != second.occurrence_id
    assert first.finding_group_id == second.finding_group_id
    assert first.to_dict()["finding_id"] == first.occurrence_id
    assert first.to_dict()["finding_group_id"] == first.finding_group_id


def test_finding_group_identity_separates_advisories() -> None:
    first = _finding(asset_id="pkg:pypi/requests@2.0.0", cve_id="CVE-2026-1000")
    second = _finding(asset_id="pkg:pypi/requests@2.0.0", cve_id="CVE-2026-2000")

    assert first.finding_group_id != second.finding_group_id


def test_trend_point_exposes_idempotent_scan_key() -> None:
    point = TrendPoint(
        scan_id="scan-123",
        timestamp="2026-08-20T12:00:00Z",
        total_vulns=4,
        critical=1,
        high=1,
        medium=1,
        low=1,
        posture_score=70.0,
        posture_grade="C",
        tenant_id="tenant-a",
    )

    assert point.idempotency_key == "tenant-a:scan-123"
    assert point.to_dict()["scan_id"] == "scan-123"


def _trend_point(*, score: float = 70.0) -> TrendPoint:
    return TrendPoint(
        scan_id="scan-123",
        timestamp="2026-08-20T12:00:00Z",
        total_vulns=4,
        critical=1,
        high=1,
        medium=1,
        low=1,
        posture_score=score,
        posture_grade="C",
        tenant_id="tenant-a",
    )


def test_inmemory_trend_store_upserts_scan_backed_points() -> None:
    store = InMemoryTrendStore()

    store.record(_trend_point(score=70.0))
    store.record(_trend_point(score=80.0))

    history = store.get_history(tenant_id="tenant-a")
    assert len(history) == 1
    assert history[0].scan_id == "scan-123"
    assert history[0].posture_score == 80.0


def test_sqlite_trend_store_upserts_and_round_trips_scan_id(tmp_path) -> None:
    store = SQLiteTrendStore(str(tmp_path / "trends.db"))

    store.record(_trend_point(score=70.0))
    store.record(_trend_point(score=80.0))

    history = store.get_history(tenant_id="tenant-a")
    assert len(history) == 1
    assert history[0].scan_id == "scan-123"
    assert history[0].posture_score == 80.0


def test_mcp_server_accepts_only_explicit_identity_bindings() -> None:
    binding = CredentialIdentityBinding(
        credential_ref="AWS_ROLE_ARN",
        identity_canonical_id="managed_identity:aws:role/deployer",
        evidence_source="mcp-config",
        provider="aws",
    )
    server = MCPServer(name="deploy", identity_bindings=[binding])

    assert server.identity_bindings == [binding]
    assert binding.to_dict() == {
        "credential_ref": "AWS_ROLE_ARN",
        "identity_canonical_id": "managed_identity:aws:role/deployer",
        "evidence_source": "mcp-config",
        "provider": "aws",
    }


def test_explicit_identity_bindings_survive_canonical_json_projection() -> None:
    binding = CredentialIdentityBinding(
        credential_ref="AWS_ROLE_ARN",
        identity_canonical_id="managed_identity:aws:role/deployer",
        evidence_source="mcp-config",
        provider="aws",
    )
    server = MCPServer(name="deploy", env={"AWS_ROLE_ARN": "***"}, identity_bindings=[binding])
    report = AIBOMReport(
        scan_id="scan-123",
        agents=[Agent(name="operator", agent_type=AgentType.CUSTOM, config_path="", mcp_servers=[server])],
    )

    payload = to_json(report)

    assert payload["agents"][0]["mcp_servers"][0]["identity_bindings"] == [binding.to_dict()]
