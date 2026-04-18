"""Tests for the bounded inter-procedural taint depth cap.

The taint analyzer follows tainted parameters through helper-call chains
with per-callsite parameter mapping. This is real inter-procedural
propagation, but without an explicit depth cap a long fan-out chain
can either explode the visit-set or surface noisy near-duplicate
findings the operator cannot act on.

These tests pin the depth-cap contract:

- ``AGENT_BOM_TAINT_MAX_DEPTH`` env caps the call_path length the
  analyzer commits to following
- the cap is clamped to the [2, 8] operational range
- a chain at the cap surfaces the finding; one step past it does not
- the cap applies uniformly across the two taint surfaces
  (``_build_taint_findings`` parameter recursion and ``_build_call_graph``
  BFS to dangerous sinks)
- malformed env values fall back to the documented default (4)
"""

from __future__ import annotations

import textwrap

import pytest

from agent_bom.ast_analyzer import _max_taint_depth, analyze_project


def _make_project(tmp_path, source: str) -> str:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "main.py").write_text(textwrap.dedent(source))
    return str(project)


# ─── Env parsing ──────────────────────────────────────────────────────────────


def test_default_depth_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_TAINT_MAX_DEPTH", raising=False)
    assert _max_taint_depth() == 4


def test_default_depth_when_blank(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_TAINT_MAX_DEPTH", "")
    assert _max_taint_depth() == 4


def test_default_depth_when_malformed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_TAINT_MAX_DEPTH", "not-a-number")
    assert _max_taint_depth() == 4


@pytest.mark.parametrize(
    "value,expected",
    [
        ("0", 2),  # clamped up to floor
        ("1", 2),  # clamped up to floor
        ("2", 2),
        ("3", 3),
        ("4", 4),
        ("5", 5),
        ("8", 8),
        ("12", 8),  # clamped down to ceiling
        ("9999", 8),  # clamped down to ceiling
    ],
)
def test_depth_clamped_to_operational_range(
    monkeypatch: pytest.MonkeyPatch, value: str, expected: int
) -> None:
    monkeypatch.setenv("AGENT_BOM_TAINT_MAX_DEPTH", value)
    assert _max_taint_depth() == expected


# ─── End-to-end: chain at cap fires, beyond cap does not ─────────────────────


def _chain_source(depth: int) -> str:
    """Build a tool that delegates through ``depth - 1`` helpers to os.system.

    With ``depth=2`` the structure is tool → helper1 → os.system.
    With ``depth=4`` it is tool → helper1 → helper2 → helper3 → os.system.
    """
    helper_definitions: list[str] = []
    for level in range(1, depth):
        next_call = f"helper{level + 1}(value)" if level + 1 < depth else "os.system(value)"
        helper_definitions.append(
            textwrap.dedent(
                f"""
                def helper{level}(value):
                    {next_call}
                """
            ).strip()
        )

    return (
        textwrap.dedent(
            """
            import os
            from mcp.server.fastmcp import FastMCP

            mcp = FastMCP("danger-server")
            """
        )
        + "\n\n"
        + "\n\n".join(helper_definitions)
        + textwrap.dedent(
            """

            @mcp.tool()
            def run(payload: str):
                helper1(payload)
            """
        )
    )


def _has_helper_chain_finding(result, sink: str = "os.system") -> bool:
    return any(
        finding.category in {"interprocedural_dangerous_flow", "interprocedural_tainted_sink", "tainted_dangerous_sink"}
        and sink in (finding.sink or "")
        for finding in result.flow_findings
    )


def test_chain_within_default_depth_fires(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Default cap is 4; a 3-hop chain (tool → h1 → h2 → sink) must surface."""
    monkeypatch.delenv("AGENT_BOM_TAINT_MAX_DEPTH", raising=False)
    project = _make_project(tmp_path, _chain_source(depth=3))
    result = analyze_project(project)
    assert _has_helper_chain_finding(result), (
        f"Expected an inter-procedural finding within the default depth (4); "
        f"got categories={[f.category for f in result.flow_findings]}"
    )


def test_chain_capped_does_not_fire(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Cap=2 stops at one helper hop — a 3-hop chain must NOT fire."""
    monkeypatch.setenv("AGENT_BOM_TAINT_MAX_DEPTH", "2")
    project = _make_project(tmp_path, _chain_source(depth=3))
    result = analyze_project(project)
    # The cap prevents the analyzer from reaching the sink past depth 2
    assert not _has_helper_chain_finding(result), (
        f"Expected no inter-procedural finding with cap=2; "
        f"got categories={[f.category for f in result.flow_findings]}"
    )


def test_raised_cap_extends_traversal(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Raising the cap to 6 lets a 4-hop chain through that the default would clip."""
    project = _make_project(tmp_path, _chain_source(depth=5))

    monkeypatch.setenv("AGENT_BOM_TAINT_MAX_DEPTH", "6")
    deep_result = analyze_project(project)
    assert _has_helper_chain_finding(deep_result)
