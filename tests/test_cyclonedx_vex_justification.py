"""CycloneDX VEX ``analysis.justification`` must use the CDX enum (bug-fix).

A VEX-suppressed (``not_affected``) finding carries an OpenVEX-vocabulary
``vex_justification`` (e.g. ``vulnerable_code_not_present``). That vocabulary is
DISJOINT from CycloneDX's ``impactAnalysisJustification`` enum
(``code_not_present``, ``code_not_reachable``, ...). Emitting the raw OpenVEX
value produces a ``analysis`` object that a CDX 1.7 validator rejects
(``analysis`` is ``additionalProperties: false``). The exporter must translate to
the CDX enum via the inverse of ``vex._CDX_JUSTIFICATION_TO_VEX``, omitting the
justification when no valid mapping exists (keeping the ``state``).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agent_bom.models import (
    Agent,
    AgentType,
    AIBOMReport,
    BlastRadius,
    MCPServer,
    MCPTool,
    Package,
    Severity,
    Vulnerability,
)
from agent_bom.output.cyclonedx_fmt import to_cyclonedx
from agent_bom.vex import VexJustification

jsonschema = pytest.importorskip("jsonschema")
from jsonschema import Draft201909Validator  # noqa: E402
from referencing import Registry, Resource  # noqa: E402

_FIXTURES = Path(__file__).parent / "fixtures"

# The valid CycloneDX 1.7 impactAnalysisJustification enum == the forward-map keys.
_CDX_JUSTIFICATION_ENUM = {
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "protected_by_compiler",
    "protected_at_runtime",
    "protected_at_perimeter",
    "protected_by_mitigating_control",
}


def _cyclonedx_registry() -> Registry:
    resources = []
    for name in (
        "cyclonedx-1.7.schema.json",
        "spdx.schema.json",
        "jsf-0.82.schema.json",
        "cryptography-defs.schema.json",
    ):
        path = _FIXTURES / name
        if not path.exists():
            continue
        schema = json.loads(path.read_text())
        uri = schema.get("$id") or schema.get("id")
        if uri:
            resources.append((uri, Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def _report_with_vex(justification: str) -> AIBOMReport:
    vuln = Vulnerability(
        id="CVE-2026-0001",
        summary="RCE in flask",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        vex_status="not_affected",
        vex_justification=justification,
    )
    pkg = Package(
        name="flask",
        version="0.12.2",
        ecosystem="pypi",
        purl="pkg:pypi/flask@0.12.2",
        vulnerabilities=[vuln],
        is_direct=True,
    )
    server = MCPServer(name="db-server", packages=[pkg], tools=[MCPTool(name="query", description="sql")])
    agent = Agent(
        name="claude-desktop",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/cd.json",
        mcp_servers=[server],
        version="1.0",
    )
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=[],
        exposed_tools=[],
    )
    br.calculate_risk_score()
    return AIBOMReport(
        agents=[agent],
        blast_radii=[br],
        scan_sources=["agent_discovery"],
        scan_id="3c249b23-4088-4c46-911d-1d4daf950e47",
        tool_version="0.0.0-test",
        generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def _analysis_blocks(cdx: dict) -> list[dict]:
    return [v["analysis"] for v in cdx.get("vulnerabilities", []) if "analysis" in v]


@pytest.mark.parametrize("justification", [j.value for j in VexJustification])
def test_openvex_justification_maps_to_cdx_enum(justification: str) -> None:
    cdx = to_cyclonedx(_report_with_vex(justification))
    blocks = _analysis_blocks(cdx)
    assert blocks, "not_affected finding should emit an analysis block"
    for analysis in blocks:
        assert analysis["state"] == "not_affected"
        if "justification" in analysis:
            assert analysis["justification"] in _CDX_JUSTIFICATION_ENUM


def test_unknown_justification_is_omitted_not_passed_through() -> None:
    cdx = to_cyclonedx(_report_with_vex("some_bespoke_reason"))
    for analysis in _analysis_blocks(cdx):
        assert "justification" not in analysis
        assert analysis["state"] == "not_affected"


@pytest.mark.parametrize("justification", [j.value for j in VexJustification])
def test_cyclonedx_with_vex_validates_against_1_7_schema(justification: str) -> None:
    schema_path = _FIXTURES / "cyclonedx-1.7.schema.json"
    if not schema_path.exists():
        pytest.skip("vendored CDX 1.7 schema unavailable")
    schema = json.loads(schema_path.read_text())
    cdx = to_cyclonedx(_report_with_vex(justification))
    validator = Draft201909Validator(schema, registry=_cyclonedx_registry())
    errors = sorted(validator.iter_errors(cdx), key=lambda e: list(e.path))
    rendered = "\n".join(f"  - {'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors[:20])
    assert not errors, f"CDX with VEX justification={justification} not schema-valid:\n{rendered}"
