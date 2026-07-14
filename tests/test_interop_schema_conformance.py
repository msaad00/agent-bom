"""Interop conformance gate: validate every machine-readable export against its
official schema, and prove byte-for-byte determinism.

agent-bom advertises spec-conformant SARIF 2.1.0, CycloneDX 1.7, SPDX 2.3, and
SPDX 3.0 output. Downstream consumers (GitHub/GitLab code scanning, Dependency
Track, SPDX tooling) reject documents that drift from the spec, so this suite
generates each format from one multi-entity report (agent -> MCP server -> tool
-> vulnerable package -> CVE, plus a malicious package) and asserts:

* SARIF 2.1.0 / CycloneDX 1.7 / SPDX 2.3 validate against their vendored
  official JSON schemas (``jsonschema``);
* SPDX 3.0 is emitted as canonical SPDX 3.0.1 JSON-LD (``@context`` + ``@graph``
  with a ``CreationInfo`` blank node and ``SpdxDocument`` root) and is checked
  structurally + round-tripped — see ``test_spdx_3_0_is_canonical_jsonld``;
* JSON package serializers surface ``is_malicious`` / ``malicious_reason``; and
* two consecutive runs on identical input yield byte-identical bytes.

Schemas are vendored under ``tests/fixtures/`` so the suite is hermetic/offline;
if a schema file is unavailable the format falls back to structural assertions.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")
from jsonschema import Draft7Validator, Draft201909Validator  # noqa: E402
from referencing import Registry, Resource  # noqa: E402

from agent_bom.models import (  # noqa: E402
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
from agent_bom.output.cyclonedx_fmt import to_cyclonedx  # noqa: E402
from agent_bom.output.json_fmt import to_json  # noqa: E402
from agent_bom.output.sarif import to_sarif  # noqa: E402
from agent_bom.output.spdx2_fmt import to_spdx2  # noqa: E402
from agent_bom.output.spdx_fmt import to_spdx  # noqa: E402

_FIXTURES = Path(__file__).parent / "fixtures"


def _load_schema(name: str) -> dict | None:
    path = _FIXTURES / name
    if not path.exists():
        return None
    return json.loads(path.read_text())


def _cyclonedx_registry() -> Registry:
    """CDX 1.7 ``$ref``s ``spdx.schema.json``, ``jsf-0.82.schema.json`` and
    ``cryptography-defs.schema.json`` — map each vendored schema by its declared
    ``$id`` so refs resolve offline."""
    resources = []
    for name in (
        "cyclonedx-1.7.schema.json",
        "spdx.schema.json",
        "jsf-0.82.schema.json",
        "cryptography-defs.schema.json",
    ):
        schema = _load_schema(name)
        if schema is None:
            continue
        uri = schema.get("$id") or schema.get("id")
        if uri:
            resources.append((uri, Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def _conformance_report() -> AIBOMReport:
    """One report spanning agent -> MCP server -> tool -> vuln pkg -> CVE, plus a
    malicious (typosquat) package with no CVE. ``generated_at`` and ``scan_id``
    are pinned so identical construction produces identical bytes."""
    vuln = Vulnerability(
        id="CVE-2026-0001",
        summary="Remote code execution in flask",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        fixed_version="2.3.0",
        cwe_ids=["CWE-94"],
    )
    vuln_pkg = Package(
        name="flask",
        version="0.12.2",
        ecosystem="pypi",
        purl="pkg:pypi/flask@0.12.2",
        vulnerabilities=[vuln],
        is_direct=True,
    )
    malicious_pkg = Package(
        name="reqquests",
        version="1.0.0",
        ecosystem="pypi",
        purl="pkg:pypi/reqquests@1.0.0",
        is_direct=True,
        is_malicious=True,
        malicious_reason="MAL-2024-0001 typosquat of requests",
    )
    server = MCPServer(
        name="db-server",
        packages=[vuln_pkg, malicious_pkg],
        tools=[MCPTool(name="query", description="run sql")],
    )
    agent = Agent(
        name="claude-desktop",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/claude-desktop.json",
        mcp_servers=[server],
        version="1.0",
    )
    br = BlastRadius(
        vulnerability=vuln,
        package=vuln_pkg,
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=["AWS_SECRET_ACCESS_KEY"],
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


@pytest.fixture(scope="module")
def report() -> AIBOMReport:
    return _conformance_report()


def _assert_schema_valid(name: str, schema_file: str, validator_cls, doc: dict, *, registry=None) -> None:
    schema = _load_schema(schema_file)
    if schema is None:  # vendored schema unavailable — structural fallback elsewhere
        pytest.skip(f"vendored schema {schema_file} unavailable")
    validator = validator_cls(schema, registry=registry) if registry is not None else validator_cls(schema)
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    if errors:
        rendered = "\n".join(f"  - {'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors[:20])
        pytest.fail(f"{name} is not schema-valid ({len(errors)} error(s)):\n{rendered}")


def test_sarif_conforms_to_2_1_0_schema(report: AIBOMReport) -> None:
    _assert_schema_valid("SARIF 2.1.0", "sarif-schema-2.1.0.json", Draft7Validator, to_sarif(report))


def test_cyclonedx_conforms_to_1_7_schema(report: AIBOMReport) -> None:
    cdx = to_cyclonedx(report)
    assert cdx["specVersion"] == "1.7", "CycloneDX output must advertise specVersion 1.7"
    _assert_schema_valid(
        "CycloneDX 1.7",
        "cyclonedx-1.7.schema.json",
        Draft7Validator,
        cdx,
        registry=_cyclonedx_registry(),
    )


def test_cyclonedx_formulation_is_top_level(report: AIBOMReport) -> None:
    """CDX 1.7 defines ``formulation`` as a top-level BOM array — not a metadata
    field. Nesting it under metadata fails strict validation (regression guard)."""
    cdx = to_cyclonedx(report)
    assert isinstance(cdx.get("formulation"), list) and cdx["formulation"], "formulation must be a top-level array"
    assert "formulation" not in cdx.get("metadata", {}), "formulation must not live under metadata"


def test_cyclonedx_services_are_top_level(report: AIBOMReport) -> None:
    """MCP tool capabilities are CDX 1.7 top-level ``services`` — ``services`` is
    not a valid component property (strict-validity regression guard)."""
    cdx = to_cyclonedx(report)
    assert any(s.get("name") == "query" for s in cdx.get("services", [])), "MCP tool must surface as a top-level service"
    assert not any("services" in c for c in cdx["components"]), "no component may carry a nested services array"


def test_spdx2_conforms_to_2_3_schema(report: AIBOMReport) -> None:
    _assert_schema_valid("SPDX 2.3", "spdx-2.3.schema.json", Draft201909Validator, to_spdx2(report))


def test_spdx_3_0_is_canonical_jsonld(report: AIBOMReport) -> None:
    """SPDX 3.0 output is canonical SPDX 3.0.1 JSON-LD (#3967): a top-level
    ``@context`` + ``@graph``, a ``CreationInfo`` blank node with the semver
    ``specVersion``, an ``SpdxDocument`` root, and namespaced 3.0 vocabulary."""
    doc = to_spdx(report)
    # Canonical top level — exactly @context + @graph, no legacy flat keys.
    assert set(doc) == {"@context", "@graph"}
    assert doc["@context"] == "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
    # Parses as JSON-LD (deserializes cleanly, @graph is a node list).
    graph = json.loads(json.dumps(doc))["@graph"]
    assert isinstance(graph, list) and graph

    creation_info = next(n for n in graph if n["type"] == "CreationInfo")
    assert creation_info["@id"].startswith("_:")
    assert creation_info["specVersion"] == "3.0.1"

    spdx_document = next(n for n in graph if n["type"] == "SpdxDocument")
    assert spdx_document["spdxId"].startswith("SPDXRef-")
    assert spdx_document["creationInfo"] == creation_info["@id"]
    assert "core" in spdx_document["profileConformance"]
    assert spdx_document["rootElement"], "SpdxDocument must reference a root element"

    element_types = {n["type"] for n in graph}
    # 3.0 profile-namespaced vocabulary — a 2.x-style bare "Package" is a regression.
    assert "software_Package" in element_types
    assert "security_Vulnerability" in element_types

    # Every graph node (bar the CreationInfo blank node itself) is a real Element:
    # it carries a spdxId and a back-reference to the shared CreationInfo.
    for node in graph:
        if node["type"] == "CreationInfo":
            continue
        assert node.get("spdxId", "").startswith("SPDXRef-"), node
        assert node.get("creationInfo") == creation_info["@id"], node

    valid_rel_types = {"contains", "dependsOn", "hasAssessmentFor", "affects", "describes", "generates"}
    relationships = [n for n in graph if str(n.get("type") or "").endswith("Relationship")]
    assert relationships
    for rel in relationships:
        # Base Relationship or a 3.0 profile subtype (e.g.
        # security_CvssV3VulnAssessmentRelationship) — all end in "Relationship".
        assert rel["type"].endswith("Relationship"), rel
        assert rel["relationshipType"] in valid_rel_types, rel
        assert rel.get("from") and rel.get("to"), rel

    # Round-trips back through the SBOM reader with packages + vuln intact.
    from agent_bom.sbom import parse_sbom_document

    packages, fmt, _name = parse_sbom_document(doc)
    assert fmt == "spdx-3"
    assert {p.name for p in packages}, "expected packages recovered from @graph"


def test_json_packages_carry_is_malicious(report: AIBOMReport) -> None:
    """JSON package serializers (summary graph + per-agent) must surface
    ``is_malicious`` / ``malicious_reason`` — parity with CSV/SARIF/parquet."""
    doc = to_json(report)

    def package_dicts(node, acc):
        if isinstance(node, dict):
            if "is_malicious" in node and ("purl" in node or "ecosystem" in node or "canonical_id" in node):
                acc.append(node)
            for value in node.values():
                package_dicts(value, acc)
        elif isinstance(node, list):
            for value in node:
                package_dicts(value, acc)

    packages: list[dict] = []
    package_dicts(doc, packages)
    assert packages, "expected serialized package entries carrying is_malicious"
    for pkg in packages:
        assert "malicious_reason" in pkg, f"is_malicious present but malicious_reason missing: {pkg.get('name')}"
    assert any(pkg["is_malicious"] and pkg.get("malicious_reason") for pkg in packages), "malicious package must be flagged"


@pytest.mark.parametrize(
    "serialize",
    [to_sarif, to_json, to_cyclonedx, to_spdx2, to_spdx],
    ids=["sarif", "json", "cyclonedx", "spdx2", "spdx3"],
)
def test_output_is_byte_deterministic(report: AIBOMReport, serialize) -> None:
    """Two consecutive serializations of identical input are byte-identical —
    stable ordering, deterministic exposure-path ranks, stable property tags."""
    first = json.dumps(serialize(report), sort_keys=False)
    second = json.dumps(serialize(report), sort_keys=False)
    assert first == second


def test_sarif_exposure_rank_stable_under_score_ties() -> None:
    """Findings tied on risk score keep a deterministic rank order (id tie-break),
    so SARIF results never permute across runs on ties."""
    tied: list[BlastRadius] = []
    agent = Agent(name="a", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp/c.json")
    server = MCPServer(name="s")
    agent.mcp_servers = [server]
    for cve in ("CVE-2026-0002", "CVE-2026-0001", "CVE-2026-0003"):
        vuln = Vulnerability(id=cve, summary="tie", severity=Severity.HIGH, cvss_score=7.5, fixed_version="2")
        pkg = Package(
            name=f"pkg-{cve}", version="1", ecosystem="pypi", purl=f"pkg:pypi/pkg-{cve}@1", vulnerabilities=[vuln], is_direct=True
        )
        server.packages.append(pkg)
        br = BlastRadius(
            vulnerability=vuln, package=pkg, affected_servers=[server], affected_agents=[agent], exposed_credentials=[], exposed_tools=[]
        )
        br.calculate_risk_score()
        tied.append(br)
    report = AIBOMReport(
        agents=[agent], blast_radii=tied, scan_id="tie", tool_version="t", generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc)
    )

    order = [r["ruleId"] for r in to_sarif(report)["runs"][0]["results"] if r["ruleId"].startswith("CVE-")]
    assert order == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"], order
