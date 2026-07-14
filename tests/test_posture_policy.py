"""Posture scorecard policy — defaults plus adopter overrides."""

from __future__ import annotations

import json

from agent_bom.models import (
    Agent,
    AgentType,
    AIBOMReport,
    BlastRadius,
    MCPServer,
    Package,
    Severity,
    Vulnerability,
)
from agent_bom.posture import (
    DEFAULT_DIMENSION_WEIGHTS,
    compute_posture_scorecard,
    load_posture_policy,
)


def test_no_artifact_scan_returns_na_not_passing_grade() -> None:
    """A scan that examined zero artifacts must not report a passing grade.

    Previously an empty report defaulted every dimension to 100/50 and produced
    a "B" (87.5) — an honest-looking pass for a scan that evaluated nothing.
    """
    scorecard = compute_posture_scorecard(AIBOMReport(agents=[], blast_radii=[]))
    assert scorecard.grade == "N/A"
    assert scorecard.score == 0
    assert scorecard.no_data is True
    # Policy plumbing is still preserved for downstream consumers.
    assert scorecard.policy_source == "default"
    d = scorecard.to_dict()
    assert d["grade"] == "N/A"
    assert d["no_data"] is True


def test_scan_with_real_artifacts_gets_a_real_grade() -> None:
    """A scan that actually examined a package still gets a real letter grade."""
    report = AIBOMReport(
        agents=[
            Agent(
                name="cursor",
                agent_type=AgentType.CUSTOM,
                config_path="/tmp/mcp.json",
                mcp_servers=[
                    MCPServer(
                        name="fs",
                        packages=[Package(name="requests", version="2.31.0", ecosystem="pypi")],
                    )
                ],
            )
        ],
        blast_radii=[],
    )
    scorecard = compute_posture_scorecard(report)
    assert scorecard.grade in {"A", "B", "C", "D", "F"}
    assert scorecard.no_data is False


def test_filesystem_scan_with_critical_findings_gets_real_grade_not_na() -> None:
    """A plain filesystem scan that surfaced critical findings must grade normally.

    The did-we-scan guard returns N/A only for scans that examined ZERO gradable
    artifacts. A findings-present scan — even one with no MCP servers, where the
    vulnerabilities live only in ``blast_radii`` — has examined real artifacts and
    must receive a real letter grade, never N/A.
    """
    pkg = Package(name="vulnerable-lib", version="1.0.0", ecosystem="pypi")
    vuln = Vulnerability(id="CVE-2026-9001", summary="critical RCE", severity=Severity.CRITICAL)
    report = AIBOMReport(
        agents=[],
        blast_radii=[
            BlastRadius(
                vulnerability=vuln,
                package=pkg,
                affected_servers=[],
                affected_agents=[],
                exposed_credentials=[],
                exposed_tools=[],
            )
        ],
    )
    scorecard = compute_posture_scorecard(report)
    assert scorecard.grade in {"A", "B", "C", "D", "F"}
    assert scorecard.grade != "N/A"
    assert scorecard.no_data is False


def test_default_policy_weights_sum_to_one() -> None:
    policy = load_posture_policy()
    assert policy.source == "default"
    assert abs(sum(policy.weights.values()) - 1.0) < 1e-6
    assert set(policy.weights) == set(DEFAULT_DIMENSION_WEIGHTS)


def test_env_policy_overrides_weights_and_thresholds(monkeypatch) -> None:
    monkeypatch.setenv(
        "AGENT_BOM_POSTURE_POLICY",
        json.dumps(
            {
                "weights": {
                    "vulnerability_posture": 0.5,
                    "credential_hygiene": 0.1,
                    "supply_chain_quality": 0.1,
                    "compliance_coverage": 0.1,
                    "active_exploitation": 0.1,
                    "configuration_quality": 0.1,
                },
                "grade_thresholds": {"A": 95, "B": 85, "C": 75, "D": 65},
            }
        ),
    )
    policy = load_posture_policy()
    assert policy.source.startswith("env:")
    assert abs(policy.weights["vulnerability_posture"] - 0.5) < 1e-6
    assert policy.grade_thresholds["A"] == 95.0

    scorecard = compute_posture_scorecard(AIBOMReport(agents=[], blast_radii=[]), policy=policy)
    assert scorecard.policy_source.startswith("env:")
    assert scorecard.dimensions["vulnerability_posture"].weight == policy.weights["vulnerability_posture"]


def test_partial_weight_override_keeps_other_defaults() -> None:
    """Adopters can tweak one dimension; remaining defaults stay and renormalize."""
    policy = load_posture_policy(weights={"vulnerability_posture": 0.6})
    assert policy.source == "explicit"
    assert policy.weights["vulnerability_posture"] > DEFAULT_DIMENSION_WEIGHTS["vulnerability_posture"]
    assert abs(sum(policy.weights.values()) - 1.0) < 1e-6

    scorecard = compute_posture_scorecard(
        AIBOMReport(agents=[], blast_radii=[]),
        weights={"vulnerability_posture": 0.6},
    )
    assert scorecard.policy_source == "explicit"
