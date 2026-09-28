"""Agent detail returns one row per (finding, package) scoped to THAT agent.

A blast-radius row is estate-shaped: it lists every agent that reaches the
package and the union of their credentials. The same (advisory, package) pair
can also recur within one scan (one row per inventoried occurrence) and across
rescans. The per-agent detail must fold those into a single row carrying only
the selected agent's own reach evidence.
"""

from __future__ import annotations

import uuid

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

from fastapi.testclient import TestClient

import agent_bom.api.routes.discovery as discovery
from agent_bom.api.agent_findings import agent_scoped_blast_rows
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_job_store
from tests._clock_helpers import recent

TENANT = "default"


def _agent(name: str, canonical_id: str, credential: str, tool: str) -> dict:
    return {
        "name": name,
        "agent_type": "custom",
        "config_path": f"/work/{name}",
        "source": "project",
        "canonical_id": canonical_id,
        "stable_id": canonical_id,
        "mcp_servers": [
            {
                "name": f"{name}-server",
                "command": "npx",
                "surface": "mcp-server",
                "packages": [{"name": "requests", "version": "2.28.0", "ecosystem": "pypi"}],
                "tools": [{"name": tool}],
                "credential_env_vars": [credential],
            }
        ],
    }


def _row(vuln: str, severity: str, agents: list[tuple[str, str]], creds: list[str], tools: list[str], risk: float, **extra) -> dict:
    return {
        "vulnerability_id": vuln,
        "canonical_id": f"canon-{vuln}",
        "package": "requests@2.28.0",
        "package_name": "requests",
        "package_version": "2.28.0",
        "severity": severity,
        "risk_score": risk,
        "affected_agents": [name for name, _ in agents],
        "affected_agent_ids": [cid for _, cid in agents],
        "affected_servers": [f"{name}-server" for name, _ in agents],
        "exposed_credentials": list(creds),
        "all_server_credentials": list(creds),
        "exposed_tools": list(tools),
        "graph_reachable": extra.pop("graph_reachable", False),
        **extra,
    }


A = ("svc-a", "agent-a")
B = ("svc-b", "agent-b")


def _seed(store: InMemoryJobStore, day: int, blast: list[dict]) -> None:
    store.put(
        ScanJob(
            job_id=str(uuid.uuid4()),
            tenant_id=TENANT,
            status=JobStatus.DONE,
            created_at=recent(f"2026-07-{day:02d}T00:00:00Z"),
            completed_at=recent(f"2026-07-{day:02d}T00:01:00Z"),
            request=ScanRequest(offline=True),
            result={
                "agents": [
                    _agent("svc-a", "agent-a", "OPENAI_API_KEY", "run_chain"),
                    _agent("svc-b", "agent-b", "AWS_SECRET_ACCESS_KEY", "shell"),
                ],
                "blast_radius": blast,
            },
        )
    )


@pytest.fixture()
def shared_estate(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("AGENT_BOM_DEMO_ESTATE", raising=False)
    monkeypatch.delenv("AGENT_BOM_API_HOST_DISCOVERY_TENANT", raising=False)
    monkeypatch.delenv("AGENT_BOM_API_LOCAL_PATH_SCANS", raising=False)
    monkeypatch.delenv("AGENT_BOM_ENABLE_LOCAL_PATH_SCANS", raising=False)
    discovery._agents_response_cache.clear()
    store = InMemoryJobStore()
    set_job_store(store)
    shared = _row("CVE-2023-32681", "medium", [A, B], ["OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY"], ["run_chain", "shell"], 8.7)
    # The same exposure repeated once per inventoried occurrence of the package.
    occurrences = [_row("CVE-2023-32681", "medium", [A], [], [], 5.0) for _ in range(5)]
    critical = [_row("CVE-2023-36258", "critical", [A], [], [], 9.0, graph_reachable=True) for _ in range(4)]
    foreign_only = _row("CVE-2024-0001", "high", [B], ["AWS_SECRET_ACCESS_KEY"], ["shell"], 7.0)
    # An older rescan of the same scope must be superseded, not appended.
    _seed(store, 1, [shared, *occurrences, *critical])
    _seed(store, 2, [shared, *occurrences, *critical, foreign_only])
    yield store
    discovery._agents_response_cache.clear()


def test_agent_detail_has_one_row_per_finding_and_package(shared_estate) -> None:
    body = TestClient(app).get("/v1/agents/agent-a").json()

    rows = body["blast_radius"]
    keys = [(row["vulnerability_id"], row["package"]) for row in rows]
    assert sorted(keys) == [("CVE-2023-32681", "requests@2.28.0"), ("CVE-2023-36258", "requests@2.28.0")]
    assert body["summary"]["total_vulnerabilities"] == 2
    assert body["summary"]["severity_breakdown"] == {"critical": 1, "high": 0, "medium": 1, "low": 0, "unrated": 0}


def test_agent_detail_carries_only_the_agents_own_reach_evidence(shared_estate) -> None:
    body = TestClient(app).get("/v1/agents/agent-a").json()

    for row in body["blast_radius"]:
        assert "AWS_SECRET_ACCESS_KEY" not in row["exposed_credentials"]
        assert "AWS_SECRET_ACCESS_KEY" not in row["all_server_credentials"]
        assert "shell" not in row["exposed_tools"]
        assert "svc-b-server" not in row["affected_servers"]
    by_id = {row["vulnerability_id"]: row for row in body["blast_radius"]}
    shared = by_id["CVE-2023-32681"]
    assert shared["exposed_credentials"] == ["OPENAI_API_KEY"]
    assert shared["exposed_tools"] == ["run_chain"]
    assert shared["risk_score"] == 8.7
    assert shared["occurrence_count"] == 6
    assert by_id["CVE-2023-36258"]["graph_reachable"] is True
    assert by_id["CVE-2023-36258"]["occurrence_count"] == 4


def test_foreign_agent_detail_is_not_polluted_by_the_other_agent(shared_estate) -> None:
    body = TestClient(app).get("/v1/agents/agent-b").json()

    ids = sorted(row["vulnerability_id"] for row in body["blast_radius"])
    assert ids == ["CVE-2023-32681", "CVE-2024-0001"]
    for row in body["blast_radius"]:
        assert "OPENAI_API_KEY" not in row["exposed_credentials"]


def test_fold_is_deterministic_and_does_not_mutate_inputs() -> None:
    rows = [
        _row("CVE-1", "low", [A, B], ["OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY"], ["run_chain"], 3.0),
        _row("CVE-1", "high", [A], [], [], 6.0),
    ]
    snapshot = [dict(row) for row in rows]
    folded = agent_scoped_blast_rows(
        rows,
        agent_id="agent-a",
        credential_names={"OPENAI_API_KEY"},
        tool_names={"run_chain"},
        server_names={"svc-a-server"},
    )
    reversed_fold = agent_scoped_blast_rows(
        list(reversed(rows)),
        agent_id="agent-a",
        credential_names={"OPENAI_API_KEY"},
        tool_names={"run_chain"},
        server_names={"svc-a-server"},
    )
    assert rows == snapshot
    assert folded == reversed_fold
    assert len(folded) == 1
    assert folded[0]["severity"] == "high"
    assert folded[0]["risk_score"] == 6.0
