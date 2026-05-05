"""Tests for the deterministic effective-reach scoring (issue #2262)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_bom.context_graph import build_context_graph
from agent_bom.effective_reach import (
    ReachScore,
    annotate_graph,
    compute,
)

# ── Synthetic fixtures ────────────────────────────────────────────────────


def _low_reach_fixture() -> tuple[list[dict], list[dict]]:
    """A vulnerable package behind a read-only search tool with HOME-only env.

    Should land in the *green* band (≤30) per the moat sentence in #2262.
    """
    agents = [
        {
            "name": "claude-desktop",
            "type": "claude",
            "status": "configured",
            "mcp_servers": [
                {
                    "name": "search-server",
                    "command": "npx -y @example/search-mcp",
                    "transport": "stdio",
                    "env": {
                        "HOME": "/Users/alice",
                        "PATH": "/usr/local/bin",
                    },
                    "tools": [
                        {
                            "name": "search_documents",
                            "description": "Search and read indexed documents",
                            "capabilities": ["read"],
                        }
                    ],
                    "packages": [{"name": "left-pad", "version": "1.3.0"}],
                }
            ],
        }
    ]
    blast = [
        {
            "vulnerability_id": "CVE-2099-LOW",
            "package": "left-pad",
            "severity": "medium",
            "cvss_score": 6.5,
            "epss_score": 0.02,
            "is_kev": False,
            "affected_agents": ["claude-desktop"],
            "affected_servers": ["search-server"],
        }
    ]
    return agents, blast


def _high_reach_fixture() -> tuple[list[dict], list[dict]]:
    """Same package, but behind a run_shell tool with AWS_* env across two agents.

    Should land in the *red* / *pulsing-red* band (>80) per #2262.
    """
    agents = [
        {
            "name": "claude-desktop",
            "type": "claude",
            "status": "configured",
            "mcp_servers": [
                {
                    "name": "ops-runner",
                    "command": "node ops-mcp.js",
                    "transport": "stdio",
                    "env": {
                        "AWS_ACCESS_KEY_ID": "AKIA****",
                        "AWS_SECRET_ACCESS_KEY": "****",
                        "GITHUB_TOKEN": "ghp_****",
                    },
                    "tools": [
                        {
                            "name": "run_shell",
                            "description": "Execute arbitrary shell commands on the host",
                            "capabilities": ["execute"],
                        },
                        {
                            "name": "list_files",
                            "description": "List files in a directory",
                            "capabilities": ["read"],
                        },
                    ],
                    "packages": [{"name": "left-pad", "version": "1.3.0"}],
                }
            ],
        },
        {
            "name": "cursor",
            "type": "cursor",
            "status": "configured",
            "mcp_servers": [
                {
                    "name": "ops-runner",
                    "command": "node ops-mcp.js",
                    "transport": "stdio",
                    "env": {
                        "AWS_ACCESS_KEY_ID": "AKIA****",
                    },
                    "tools": [
                        {
                            "name": "run_shell",
                            "description": "Execute arbitrary shell commands on the host",
                            "capabilities": ["execute"],
                        }
                    ],
                    "packages": [{"name": "left-pad", "version": "1.3.0"}],
                }
            ],
        },
    ]
    blast = [
        {
            "vulnerability_id": "CVE-2099-HIGH",
            "package": "left-pad",
            "severity": "critical",
            "cvss_score": 9.8,
            "epss_score": 0.92,
            "is_kev": True,
            "affected_agents": ["claude-desktop", "cursor"],
            "affected_servers": ["ops-runner"],
        }
    ]
    return agents, blast


# ── Score band tests ──────────────────────────────────────────────────────


def test_low_reach_lands_in_green_band() -> None:
    agents, blast = _low_reach_fixture()
    graph = build_context_graph(agents, blast)
    annotate_graph(graph)
    node = graph.nodes["vuln:CVE-2099-LOW"]
    breakdown = node.metadata["effective_reach"]
    assert breakdown["composite"] < 30, breakdown
    assert breakdown["band"] == "green", breakdown
    assert breakdown["is_kev"] is False
    # Read-only tool → ~0.10 capability.
    assert breakdown["tool_capability"] <= 0.15
    # HOME-only env → ~0.10 visibility.
    assert breakdown["cred_visibility"] <= 0.15


def test_high_reach_lands_in_red_band() -> None:
    agents, blast = _high_reach_fixture()
    graph = build_context_graph(agents, blast)
    annotate_graph(graph)
    node = graph.nodes["vuln:CVE-2099-HIGH"]
    breakdown = node.metadata["effective_reach"]
    assert breakdown["composite"] > 80, breakdown
    assert breakdown["band"] in ("red", "pulsing-red"), breakdown
    assert breakdown["is_kev"] is True
    # run_shell → 1.0 capability.
    assert breakdown["tool_capability"] == 1.0
    # AWS_* → 1.0 visibility.
    assert breakdown["cred_visibility"] == 1.0
    # Two agents pivot through ops-runner via SHARES_SERVER.
    assert breakdown["agent_breadth"] >= 2


def test_agent_breadth_includes_shared_server_adjacency() -> None:
    """Breadth includes agents adjacent through SHARES_SERVER graph edges."""
    agents, blast = _high_reach_fixture()
    blast[0]["affected_agents"] = ["claude-desktop"]

    graph = build_context_graph(agents, blast)
    annotate_graph(graph)

    breakdown = graph.nodes["vuln:CVE-2099-HIGH"].metadata["effective_reach"]
    assert breakdown["agent_breadth"] == 2
    assert breakdown["reachable_agents"] == ["claude-desktop", "cursor"]


# ── Determinism (property test) ───────────────────────────────────────────


def test_determinism_high_reach_fixture() -> None:
    """Same fixture in → same composite out across many runs."""
    agents, blast = _high_reach_fixture()
    seen: set[float] = set()
    for _ in range(100):
        graph = build_context_graph(agents, blast)
        annotate_graph(graph)
        seen.add(graph.nodes["vuln:CVE-2099-HIGH"].metadata["effective_reach"]["composite"])
    assert len(seen) == 1, seen


def test_determinism_low_reach_fixture() -> None:
    agents, blast = _low_reach_fixture()
    seen: set[float] = set()
    for _ in range(100):
        graph = build_context_graph(agents, blast)
        annotate_graph(graph)
        seen.add(graph.nodes["vuln:CVE-2099-LOW"].metadata["effective_reach"]["composite"])
    assert len(seen) == 1, seen


# ── Snapshot test ─────────────────────────────────────────────────────────

_SNAPSHOT_PATH = Path(__file__).parent / "fixtures" / "effective_reach_snapshots.json"


def _current_snapshots() -> dict[str, dict]:
    snapshots: dict[str, dict] = {}
    for name, builder in (
        ("low_reach", _low_reach_fixture),
        ("high_reach", _high_reach_fixture),
    ):
        agents, blast = builder()
        graph = build_context_graph(agents, blast)
        annotate_graph(graph)
        # Only one vuln per fixture.
        for node in graph.nodes.values():
            if node.id.startswith("vuln:"):
                snapshots[name] = node.metadata["effective_reach"]
    return snapshots


def test_snapshot_matches() -> None:
    """The breakdown dict for each fixture is checked into the repo.

    To regenerate after a deliberate formula change:
        python -c "from tests.test_effective_reach import _current_snapshots; \
                   import json,pathlib; \
                   pathlib.Path('tests/fixtures/effective_reach_snapshots.json'\
                   ).write_text(json.dumps(_current_snapshots(), indent=2, sort_keys=True))"
    """
    if not _SNAPSHOT_PATH.exists():  # pragma: no cover - first run only
        _SNAPSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)
        _SNAPSHOT_PATH.write_text(json.dumps(_current_snapshots(), indent=2, sort_keys=True))
    expected = json.loads(_SNAPSHOT_PATH.read_text())
    actual = _current_snapshots()
    assert actual == expected, (
        f"Effective-reach breakdown drifted. If the change is intentional, regenerate {_SNAPSHOT_PATH.name} per the docstring."
    )


# ── Direct compute() unit tests ───────────────────────────────────────────


def test_compute_returns_reach_score_dataclass() -> None:
    agents, blast = _high_reach_fixture()
    graph = build_context_graph(agents, blast)
    node = graph.nodes["vuln:CVE-2099-HIGH"]
    score = compute(node, graph)
    assert isinstance(score, ReachScore)
    assert score.composite > 80
    assert score.band in ("red", "pulsing-red")


def test_band_thresholds_are_inclusive_of_acceptance() -> None:
    """Direct exercise of the band boundaries from the issue acceptance."""
    # green ≤ 30
    s = ReachScore(cvss=4.0, epss=0.05, is_kev=False, tool_capability=0.1, cred_visibility=0.1, agent_breadth=0)
    assert s.band == "green"
    # amber 30-70
    s = ReachScore(cvss=8.0, epss=0.3, is_kev=False, tool_capability=0.4, cred_visibility=0.4, agent_breadth=1)
    assert s.band == "amber"
    # red > 70
    s = ReachScore(cvss=9.0, epss=0.5, is_kev=True, tool_capability=0.5, cred_visibility=0.5, agent_breadth=2)
    assert s.band in ("red", "pulsing-red")
    # pulsing-red ≥ 90
    s = ReachScore(cvss=9.8, epss=0.9, is_kev=True, tool_capability=1.0, cred_visibility=1.0, agent_breadth=5)
    assert s.band == "pulsing-red"
    assert s.composite >= 90


def test_edge_inheritance_uses_higher_endpoint_score() -> None:
    """Edges adjacent to a scored vuln node carry the score for UI thickness."""
    agents, blast = _high_reach_fixture()
    graph = build_context_graph(agents, blast)
    annotate_graph(graph)
    expected = graph.nodes["vuln:CVE-2099-HIGH"].metadata["effective_reach"]["composite"]
    found = False
    for edge in graph.edges:
        if edge.target == "vuln:CVE-2099-HIGH" or edge.source == "vuln:CVE-2099-HIGH":
            assert edge.metadata.get("effective_reach_score") == pytest.approx(expected)
            found = True
    assert found, "expected at least one edge adjacent to the vuln node"
