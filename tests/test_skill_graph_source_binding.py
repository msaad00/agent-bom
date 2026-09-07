"""Skill findings must not invent agent ownership from ambiguous source labels."""

import pytest

from agent_bom.graph.builder import _resolve_skill_audit_target_ids, build_unified_graph_from_report


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("source_file, expected", [("/prod/SKILL.md", {"agent:prod"}), ("/unknown/SKILL.md", set())])
def test_explicit_skill_source_does_not_cross_bind_same_basename(reverse, source_file, expected):
    agents = [
        {"name": "prod", "type": "custom", "config_path": "/prod/SKILL.md", "mcp_servers": []},
        {"name": "dev", "type": "custom", "config_path": "/dev/SKILL.md", "mcp_servers": []},
    ]
    if reverse:
        agents.reverse()
    graph = build_unified_graph_from_report(
        {
            "scan_id": "skill-source-binding",
            "agents": agents,
            "skill_audit": {
                "findings": [{"source_file": source_file, "category": "shell_access", "title": "Skill shell access", "severity": "high"}]
            },
        }
    )
    finding_id = "misconfig:skill_audit:shell_access:1"
    assert finding_id in graph.nodes
    targets = {edge.target for edge in graph.edges if edge.source == finding_id and edge.target.startswith("agent:")}
    assert targets == expected
    assert graph.nodes[finding_id].attributes["source_file"] == source_file


@pytest.mark.parametrize(
    "source_file, paths, agent_ids, expected",
    [
        ("/unknown/SKILL.md", {"/prod/SKILL.md": "agent:prod"}, ["agent:prod"], []),
        ("nested/SKILL.md", {"/prod/SKILL.md": "agent:prod"}, ["agent:prod"], []),
        ("SKILL.md", {"/prod/SKILL.md": "agent:prod"}, ["agent:prod"], ["agent:prod"]),
        ("SKILL.md", {"/prod/SKILL.md": "agent:prod", "/dev/SKILL.md": "agent:dev"}, ["agent:prod", "agent:dev"], []),
        ("", {}, ["agent:prod"], ["agent:prod"]),
        ("", {}, ["agent:prod", "agent:dev"], []),
    ],
)
def test_legacy_skill_source_fallback_requires_one_unambiguous_owner(source_file, paths, agent_ids, expected):
    assert (
        _resolve_skill_audit_target_ids(
            {"source_file": source_file},
            package_name_to_ids={},
            server_name_to_ids={},
            agent_name_to_ids={"shared-name": agent_ids},
            agent_config_path_to_id=paths,
        )
        == expected
    )
