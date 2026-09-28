"""Interop conformance gate: validate every machine-readable export against its
official schema, and prove byte-for-byte determinism.

agent-bom advertises spec-conformant SARIF 2.1.0, CycloneDX 1.7, SPDX 2.3, and
SPDX 3.0 output. Downstream consumers (GitHub/GitLab code scanning, Dependency
Track, SPDX tooling) reject documents that drift from the spec, so this suite
generates each format from one multi-entity report (agent -> MCP server -> tool
-> vulnerable package -> CVE, plus a malicious package) and asserts:

* SARIF 2.1.0 / CycloneDX 1.7 / SPDX 2.3 / SPDX 3.0.1 validate against their
  vendored official JSON schemas (``jsonschema``);
* SPDX 3.0 is emitted as canonical SPDX 3.0.1 JSON-LD (``@context`` + ``@graph``
  with a ``CreationInfo`` blank node and ``SpdxDocument`` root) and is also
  checked structurally + round-tripped — see ``test_spdx_3_0_is_canonical_jsonld``;
* JSON package serializers surface ``is_malicious`` / ``malicious_reason``; and
* two consecutive runs on identical input yield byte-identical bytes.

Schemas are vendored under ``tests/fixtures/`` so the suite is hermetic/offline;
if a schema file is unavailable the format falls back to structural assertions.

``tests/fixtures/spdx-3.0.1.schema.json`` is the unmodified "SPDX 3.0.1 JSON
Schema" published by the SPDX Project (Linux Foundation) at
https://spdx.org/schema/3.0.1/spdx-json-schema.json (sha256 582c64e8...49234b1),
used under the Community Specification License 1.0.
"""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")
from jsonschema import Draft7Validator, Draft201909Validator  # noqa: E402
from referencing import Registry, Resource  # noqa: E402

from agent_bom.evidence.scan_run import ScanIssue, ScanRun  # noqa: E402
from agent_bom.models import (  # noqa: E402
    Agent,
    AgentType,
    AIBOMReport,
    BlastRadius,
    MCPPrompt,
    MCPResource,
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


def test_cyclonedx_model_limitations_are_schema_valid_strings() -> None:
    report = AIBOMReport(
        model_provenance=[{"model": "org/model", "risk_flags": ["unsigned"], "is_safe_format": False}],
        model_files=[
            {
                "filename": "unsafe.pkl",
                "format": "pickle",
                "security_flags": [{"type": "MALICIOUS_PICKLE", "severity": "CRITICAL", "description": "Unsafe opcode"}],
            }
        ],
        training_pipelines={
            "runs": [
                {
                    "name": "train",
                    "security_flags": [{"type": "UNPINNED_INPUT", "description": "Input is not pinned"}],
                }
            ]
        },
    )
    cdx = to_cyclonedx(report)
    _assert_schema_valid(
        "CycloneDX 1.7 model limitations",
        "cyclonedx-1.7.schema.json",
        Draft7Validator,
        cdx,
        registry=_cyclonedx_registry(),
    )
    limitations = [
        item
        for component in cdx.get("components", [])
        for item in component.get("modelCard", {}).get("considerations", {}).get("technicalLimitations", [])
    ]
    assert limitations
    assert all(isinstance(item, str) for item in limitations)


def _shared_server_cyclonedx_report() -> AIBOMReport:
    """Demo-equivalent overlap: repeated agent/server discovery and a package
    without a package URL must still produce one strict-valid BOM graph."""
    shared_vuln = Vulnerability(id="CVE-2026-SHARED", summary="shared risk", severity=Severity.HIGH)
    late_vuln = Vulnerability(id="CVE-2026-LATE", summary="late enrichment", severity=Severity.CRITICAL)
    left_no_purl = Package(name="local-plugin", version="1.0", ecosystem="generic", purl=None)
    right_no_purl = Package(
        name="local-plugin",
        version="1.0",
        ecosystem="generic",
        purl=None,
        vulnerabilities=[late_vuln],
    )
    left_pkg = Package(
        name="left",
        version="1.0",
        ecosystem="npm",
        purl="pkg:npm/left@1.0",
        vulnerabilities=[shared_vuln],
    )
    right_pkg = Package(
        name="right",
        version="2.0",
        ecosystem="npm",
        purl="pkg:npm/right@2.0",
        vulnerabilities=[shared_vuln],
    )
    left_server = MCPServer(
        name="shared-server",
        command="npx",
        args=["shared-server"],
        packages=[left_no_purl, left_pkg],
        tools=[MCPTool(name="query", description="read data")],
    )
    right_server = MCPServer(
        name="shared-server",
        command="npx",
        args=["shared-server"],
        packages=[right_no_purl, right_pkg],
        tools=[
            MCPTool(name="query", description="read data"),
            MCPTool(name="admin", description="write data"),
        ],
        env={"API_KEY": "test-secret"},
    )
    first = Agent(
        name="first",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/first.json",
        mcp_servers=[left_server],
    )
    second = Agent(
        name="second",
        agent_type=AgentType.CURSOR,
        config_path="/tmp/second.json",
        mcp_servers=[right_server],
    )
    return AIBOMReport(
        agents=[first, second, first],
        scan_id="c95ee02e-5315-450e-a84d-6dbf17b26b68",
        tool_version="0.0.0-test",
        generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def test_cyclonedx_shared_discovery_is_globally_unique_and_schema_valid() -> None:
    cdx = to_cyclonedx(_shared_server_cyclonedx_report())
    _assert_schema_valid(
        "CycloneDX 1.7 shared discovery",
        "cyclonedx-1.7.schema.json",
        Draft7Validator,
        cdx,
        registry=_cyclonedx_registry(),
    )

    component_refs = [component["bom-ref"] for component in cdx["components"]]
    service_refs = [service["bom-ref"] for service in cdx.get("services", [])]
    dependency_refs = [dependency["ref"] for dependency in cdx["dependencies"]]
    assemblies = cdx["compositions"][0]["assemblies"]
    assert len(component_refs) == len(set(component_refs))
    assert len(service_refs) == len(set(service_refs))
    assert len(dependency_refs) == len(set(dependency_refs))
    assert len(assemblies) == len(set(assemblies))

    local_plugin = next(component for component in cdx["components"] if component["name"] == "local-plugin")
    assert "purl" not in local_plugin

    shared_server = next(component for component in cdx["components"] if component["name"] == "shared-server")
    properties = shared_server["properties"]
    assert {prop["value"] for prop in properties if prop["name"] == "agent-bom:has-credentials"} == {"true"}
    assert {prop["value"] for prop in properties if prop["name"] == "agent-bom:tool-count"} == {"2"}
    assert {prop["value"].split(":", 1)[0] for prop in properties if prop["name"] == "agent-bom:mcp-tool"} == {
        "admin",
        "query",
    }

    vulnerabilities = {vulnerability["id"]: vulnerability for vulnerability in cdx["vulnerabilities"]}
    assert set(vulnerabilities) == {"CVE-2026-LATE", "CVE-2026-SHARED"}
    component_name_by_ref = {component["bom-ref"]: component["name"] for component in cdx["components"]}
    assert {component_name_by_ref[item["ref"]] for item in vulnerabilities["CVE-2026-LATE"]["affects"]} == {"local-plugin"}
    assert {component_name_by_ref[item["ref"]] for item in vulnerabilities["CVE-2026-SHARED"]["affects"]} == {
        "left",
        "right",
    }


def test_cyclonedx_merges_repeated_dependency_edges_deterministically() -> None:
    report = _shared_server_cyclonedx_report()
    first = to_cyclonedx(report)
    second = to_cyclonedx(report)
    assert first["dependencies"] == second["dependencies"]
    assert first["dependencies"] == sorted(first["dependencies"], key=lambda dependency: dependency["ref"])
    for dependency in first["dependencies"]:
        assert dependency["dependsOn"] == sorted(set(dependency["dependsOn"]))

    shared = next(dependency for dependency in first["dependencies"] if dependency["ref"].startswith("mcp-server-"))
    package_names_by_ref = {component["bom-ref"]: component["name"] for component in first["components"] if component["type"] == "library"}
    assert {package_names_by_ref[ref] for ref in shared["dependsOn"]} == {"local-plugin", "left", "right"}


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


def test_cyclonedx_exports_prompt_and_resource_evidence_as_native_data_components() -> None:
    server = MCPServer(
        name="context-server",
        prompts=[MCPPrompt(name="summarize", description="Summarize a document")],
        resources=[MCPResource(uri="file:///docs/runbook.md", name="runbook", mime_type="text/markdown")],
    )
    report = AIBOMReport(
        agents=[Agent(name="agent", agent_type=AgentType.CUSTOM, config_path="/tmp/agent.json", mcp_servers=[server])],
        scan_id="3c249b23-4088-4c46-911d-1d4daf950e47",
        generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    cdx = to_cyclonedx(report)

    _assert_schema_valid(
        "CycloneDX 1.7",
        "cyclonedx-1.7.schema.json",
        Draft7Validator,
        cdx,
        registry=_cyclonedx_registry(),
    )
    data_components = {component["name"]: component for component in cdx["components"] if component["type"] == "data"}
    assert data_components["summarize"]["data"][0]["type"] == "definition"
    assert data_components["runbook"]["data"][0]["type"] == "other"
    resource_properties = {prop["name"]: prop["value"] for prop in data_components["runbook"]["properties"]}
    assert resource_properties["agent-bom:uri"] == "file:///docs/runbook.md"
    server_dependency = next(dependency for dependency in cdx["dependencies"] if dependency["ref"].startswith("mcp-server-"))
    assert data_components["summarize"]["bom-ref"] in server_dependency["dependsOn"]
    assert data_components["runbook"]["bom-ref"] in server_dependency["dependsOn"]


def test_cyclonedx_composition_and_metadata_reflect_partial_scan_run(report: AIBOMReport) -> None:
    partial_report = deepcopy(report)
    partial_report.scan_run = ScanRun(
        issues=[
            ScanIssue(
                code="scanner_coverage_gap",
                stage="scanning",
                source="osv",
                message="Advisory source unavailable",
            )
        ]
    )

    cdx = to_cyclonedx(partial_report)

    assert cdx["compositions"][0]["aggregate"] == "incomplete"
    metadata_properties = {prop["name"]: prop["value"] for prop in cdx["metadata"]["properties"]}
    assert metadata_properties["agent-bom:scan-outcome"] == "partial"
    assert metadata_properties["agent-bom:scan-issue-count"] == "1"


def test_spdx2_conforms_to_2_3_schema(report: AIBOMReport) -> None:
    _assert_schema_valid("SPDX 2.3", "spdx-2.3.schema.json", Draft201909Validator, to_spdx2(report))


def _spdx3_rich_report() -> AIBOMReport:
    """Exercise every optional SPDX 3 branch: MCP version, supplier, homepage,
    download location, copyright, license, checksums, integrity verdict, a
    malicious package, a CVSS v3 + a CVSS v4 + a vector-less + a GHSA finding,
    KEV/EPSS enrichment, and an agent with discovery-source provenance."""
    cvss3 = Vulnerability(
        id="CVE-2026-0001",
        summary="Remote code execution in flask",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        fixed_version="2.3.0",
        cwe_ids=["CWE-94"],
        is_kev=True,
        kev_date_added="2026-01-02",
        epss_score=0.91,
        epss_percentile=0.99,
        severity_source="cvss",
    )
    cvss4 = Vulnerability(
        id="CVE-2026-0002",
        summary="Path traversal",
        severity=Severity.HIGH,
        cvss_score=8.7,
        cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    )
    no_vector = Vulnerability(id="CVE-2026-0003", summary="", severity=Severity.MEDIUM, cvss_score=5.0)
    ghsa = Vulnerability(id="GHSA-xxxx-yyyy-zzzz", summary="No fix yet", severity=Severity.LOW)
    rich_pkg = Package(
        name="flask",
        version="0.12.2",
        ecosystem="pypi",
        purl="pkg:pypi/flask@0.12.2",
        vulnerabilities=[cvss3, cvss4, no_vector, ghsa],
        is_direct=True,
        license_expression="BSD-3-Clause",
        supplier="Pallets",
        homepage="https://palletsprojects.com/p/flask/",
        download_url="https://files.pythonhosted.org/packages/flask-0.12.2.tar.gz",
        copyright_text="Copyright 2010 Pallets",
        description="A micro web framework",
        checksums={"SHA-256": "a" * 64},
        integrity_verified=True,
        provenance_attested=False,
    )
    malicious_pkg = Package(
        name="reqquests",
        version="1.0.0",
        ecosystem="pypi",
        is_direct=True,
        is_malicious=True,
        malicious_reason="MAL-2024-0001 typosquat of requests",
        supplier="Pallets",
    )
    server = MCPServer(
        name="db-server",
        packages=[rich_pkg, malicious_pkg],
        tools=[MCPTool(name="query", description="run sql")],
        mcp_version="2025-06-18",
    )
    agent = Agent(
        name="claude-desktop",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/claude-desktop.json",
        mcp_servers=[server],
        source="project",
    )
    return AIBOMReport(
        agents=[agent],
        scan_id="5d6a8a52-0e7f-4c1c-9d9c-2f0b1c1b7f10",
        tool_version="0.0.0-test",
        generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def _spdx3_validator():
    from jsonschema import Draft202012Validator

    schema = _load_schema("spdx-3.0.1.schema.json")
    assert schema is not None, "official SPDX 3.0.1 JSON schema must be vendored under tests/fixtures/"
    return Draft202012Validator(schema)


@pytest.mark.parametrize("builder", [_conformance_report, _spdx3_rich_report], ids=["baseline", "rich"])
def test_spdx3_conforms_to_official_3_0_1_schema(builder) -> None:
    """The default ``-f spdx`` output must validate against the official SPDX
    3.0.1 JSON schema (no ad-hoc ``annotation``/``versionInfo`` properties,
    spec-shaped CVSS + VEX assessment relationships)."""
    doc = to_spdx(builder())
    errors = list(_spdx3_validator().iter_errors(doc))
    if errors:
        rendered = "\n".join(f"  - {e.json_path}: {e.message[:200]}" for e in errors[:20])
        pytest.fail(f"SPDX 3.0.1 output is not schema-valid ({len(errors)} error(s)):\n{rendered}")


def test_spdx3_schema_rejects_legacy_inline_shape() -> None:
    """Guard the guard: the vendored schema must actually reject the pre-fix
    inline ``versionInfo`` shape, so a permissive schema can't mask a regression."""
    doc = deepcopy(to_spdx(_conformance_report()))
    pkg = next(n for n in doc["@graph"] if n.get("type") == "software_Package")
    pkg["versionInfo"] = "1.0"
    assert list(_spdx3_validator().iter_errors(doc)), "schema accepted a non-SPDX-3 property"


def test_spdx3_rich_output_uses_spec_model() -> None:
    """Spec-model shapes: package version/URLs are ``software_*`` properties,
    annotations are standalone ``Annotation`` elements keyed by ``subject``,
    CVSS assessments carry the vector, license and supplier are elements."""
    graph = to_spdx(_spdx3_rich_report())["@graph"]
    by_id = {n["spdxId"]: n for n in graph if "spdxId" in n}
    flask = next(n for n in graph if n.get("type") == "software_Package" and n.get("name") == "flask")
    assert flask["software_packageVersion"] == "0.12.2"
    assert flask["software_packageUrl"] == "pkg:pypi/flask@0.12.2"
    assert flask["software_homePage"] == "https://palletsprojects.com/p/flask/"
    assert flask["software_downloadLocation"].endswith("flask-0.12.2.tar.gz")
    assert flask["software_copyrightText"] == "Copyright 2010 Pallets"
    assert "annotation" not in flask and "versionInfo" not in flask

    statements = {n["statement"] for n in graph if n.get("type") == "Annotation" and n["subject"] == flask["spdxId"]}
    assert "agent-bom:ecosystem=pypi" in statements

    supplier = by_id[flask["suppliedBy"]]
    assert supplier["type"] == "Organization" and supplier["name"] == "Pallets"
    malicious = next(n for n in graph if n.get("type") == "software_Package" and n.get("name") == "reqquests")
    assert malicious["suppliedBy"] == flask["suppliedBy"], "one Organization element per distinct supplier"

    license_rel = next(n for n in graph if n.get("relationshipType") == "hasDeclaredLicense" and n["from"] == flask["spdxId"])
    assert by_id[license_rel["to"][0]]["simplelicensing_licenseExpression"] == "BSD-3-Clause"

    cvss = {n["type"]: n for n in graph if "Cvss" in str(n.get("type"))}
    assert cvss["security_CvssV3VulnAssessmentRelationship"]["security_vectorString"].startswith("CVSS:3.1/")
    assert cvss["security_CvssV3VulnAssessmentRelationship"]["security_severity"] == "critical"
    assert cvss["security_CvssV4VulnAssessmentRelationship"]["security_vectorString"].startswith("CVSS:4.0/")
    # A score without a vector can't form a spec-valid CVSS assessment; it is
    # preserved as an annotation on the vulnerability instead of being dropped.
    vuln3 = next(n for n in graph if n.get("type") == "security_Vulnerability" and n.get("name") == "CVE-2026-0003")
    vuln3_statements = {n["statement"] for n in graph if n.get("type") == "Annotation" and n["subject"] == vuln3["spdxId"]}
    assert "agent-bom:cvss-score=5.0" in vuln3_statements

    affects = [n for n in graph if n.get("type") == "security_VexAffectedVulnAssessmentRelationship"]
    assert len(affects) == 4
    assert all(a["security_actionStatement"] for a in affects)
    assert all(a.get("security_assessedElement") is None or a["security_assessedElement"] in by_id for a in affects)


def test_spdx3_rich_output_round_trips_through_reader() -> None:
    """Moving to the spec model must not lose data on re-ingest."""
    from agent_bom.sbom import parse_sbom_document

    packages, fmt, _name = parse_sbom_document(to_spdx(_spdx3_rich_report()))
    assert fmt == "spdx-3"
    flask = next(p for p in packages if p.name == "flask")
    assert flask.version == "0.12.2"
    assert flask.license == "BSD-3-Clause"
    assert flask.supplier == "Pallets"
    assert flask.homepage == "https://palletsprojects.com/p/flask/"
    assert flask.download_url and flask.download_url.endswith("flask-0.12.2.tar.gz")
    assert flask.copyright_text == "Copyright 2010 Pallets"
    vulns = {v.id: v for v in flask.vulnerabilities}
    assert set(vulns) == {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "GHSA-xxxx-yyyy-zzzz"}
    assert vulns["CVE-2026-0001"].cvss_score == 9.8
    assert vulns["CVE-2026-0001"].fixed_version == "2.3.0"
    assert vulns["CVE-2026-0001"].is_kev is True
    assert vulns["CVE-2026-0001"].epss_score == pytest.approx(0.91)
    assert vulns["CVE-2026-0002"].cvss_score == 8.7
    assert vulns["CVE-2026-0003"].cvss_score == 5.0
    assert vulns["CVE-2026-0003"].severity == Severity.MEDIUM
    assert vulns["GHSA-xxxx-yyyy-zzzz"].severity == Severity.LOW


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
    assert ":" in spdx_document["spdxId"] and not spdx_document["spdxId"].startswith("_:")
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
        assert ":" in node.get("spdxId", "") and not node.get("spdxId", "").startswith("_:"), node
        assert node.get("creationInfo") == creation_info["@id"], node

    # SPDX 3 Element identifiers and originatedBy references are IRIs. A raw
    # discovery-source label such as "project" must never be projected as an
    # identity reference.
    element_ids = {node["spdxId"] for node in graph if node.get("spdxId")}
    for node in graph:
        originated_by = node.get("originatedBy", [])
        if isinstance(originated_by, str):
            originated_by = [originated_by]
        assert all(originator in element_ids for originator in originated_by), node

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
