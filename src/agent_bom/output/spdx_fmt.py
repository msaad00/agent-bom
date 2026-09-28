"""SPDX 3.0 (JSON-LD) output format."""

from __future__ import annotations

import json
import re
from datetime import timezone
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from agent_bom.asset_provenance import package_discovery_provenance, package_version_provenance
from agent_bom.checksums import integrity_verdict, integrity_verdict_statements, spdx3_verified_using
from agent_bom.compliance_utils import framework_qualified_finding_tags
from agent_bom.models import AIBOMReport
from agent_bom.output.finding_views import cve_findings, package_ecosystem, package_name, package_version
from agent_bom.package_utils import synthesize_purl

# Canonical SPDX 3.0.1 JSON-LD context (media type application/spdx+json-ld,
# ``.spdx.json`` / ``.jsonld`` extension). Every SPDX 3.0.1 document references
# this global context at the top level.
SPDX_3_CONTEXT = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
# Core/CreationInfo/specVersion is a SemVer token in 3.0 (the ``SPDX-<x.y>``
# form was dropped after 2.x); ``3.0.1`` is the current canonical value.
SPDX_3_SPEC_VERSION = "3.0.1"
# Blank-node id shared by every element's ``creationInfo`` back-reference.
_CREATION_INFO_ID = "_:creationinfo"
# Profiles this document draws vocabulary from (namespaced ``software_``/
# ``security_``/``ai_`` terms below).
SPDX_3_PROFILE_CONFORMANCE = ("core", "software", "security", "simpleLicensing", "ai")
# SpdxDocument/dataLicense is an AnyLicenseInfo reference; SPDX listed licenses
# are addressed by their canonical license-list IRI.
SPDX_3_DATA_LICENSE = "https://spdx.org/licenses/CC0-1.0"
# Action statement is mandatory on a VEX "affected" assessment. When no fixed
# version is known the honest statement is that no upgrade path exists yet.
_NO_FIX_ACTION = "No fixed version is known; mitigate exposure or remove the affected package."


def to_spdx(report: AIBOMReport) -> dict:
    """Build a canonical SPDX 3.0.1 JSON-LD dict from report.

    Emits the canonical ``{"@context": ..., "@graph": [...]}`` serialization:
    a ``CreationInfo`` blank node, a ``SpdxDocument`` root, and every element and
    relationship as a flat node in ``@graph`` (each carrying a ``creationInfo``
    back-reference). Follows the SPDX 3.0 AI BOM profile where applicable:
    - Each agent / MCP server becomes a ``software_Package`` element
    - Each dependency becomes a ``software_Package`` element
    - Vulnerabilities become ``security_Vulnerability`` elements with
      ``security_*VulnAssessmentRelationship`` edges
    - Dependency edges become ``dependsOn`` relationships
    """
    spdx_id_counter = [0]
    # SPDX 3 ``spdxId`` is an IRI, not the local ``SPDXRef-*`` token used by
    # SPDX 2.x. Keep the namespace deterministic so repeated exports of the
    # same scan remain byte-identical.
    namespace_seed = report.scan_id or report.generated_at.isoformat()
    document_namespace = f"https://agent-bom.dev/spdx/{uuid5(NAMESPACE_URL, namespace_seed)}"

    def _next_id(prefix: str = "SPDXRef") -> str:
        spdx_id_counter[0] += 1
        return f"{document_namespace}/{prefix}-{spdx_id_counter[0]}"

    elements: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    # SPDX 3 has no inline ``annotation`` property: an Annotation is its own
    # Element pointing at the annotated Element through ``subject``.
    annotations: list[dict[str, Any]] = []

    def _annotate(subject: str, statement: str) -> None:
        annotations.append(
            {
                "type": "Annotation",
                "spdxId": _next_id("SPDXRef-Annotation"),
                "annotationType": "other",
                "subject": subject,
                "statement": statement,
            }
        )

    supplier_ids: dict[str, str] = {}
    license_ids: dict[str, str] = {}

    def _supplier_ref(name: str) -> str:
        if name not in supplier_ids:
            supplier_ids[name] = _next_id("SPDXRef-Supplier")
            elements.append({"type": "Organization", "spdxId": supplier_ids[name], "name": name})
        return supplier_ids[name]

    def _license_ref(expression: str) -> str:
        if expression not in license_ids:
            license_ids[expression] = _next_id("SPDXRef-License")
            elements.append(
                {
                    "type": "simplelicensing_LicenseExpression",
                    "spdxId": license_ids[expression],
                    "simplelicensing_licenseExpression": expression,
                }
            )
        return license_ids[expression]

    root_element_ids: list[str] = []
    document_id = _next_id("SPDXRef-DOCUMENT")
    tool_id = f"{document_namespace}/SPDXRef-Tool-agent-bom"

    created = (
        report.generated_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if report.generated_at.tzinfo
        else report.generated_at.strftime("%Y-%m-%dT%H:%M:%SZ") + "Z"
    )
    creation_info = {
        "@id": _CREATION_INFO_ID,
        "type": "CreationInfo",
        "specVersion": SPDX_3_SPEC_VERSION,
        "created": created,
        "createdBy": [tool_id],
    }
    tool_element: dict[str, Any] = {
        "type": "Tool",
        "spdxId": tool_id,
        "creationInfo": _CREATION_INFO_ID,
        "name": f"agent-bom {report.tool_version}",
        "externalIdentifier": [
            {
                "type": "ExternalIdentifier",
                "externalIdentifierType": "packageUrl",
                "identifier": f"pkg:pypi/agent-bom@{report.tool_version}",
            }
        ],
    }
    elements.append(tool_element)

    pkg_ref_map: dict[str, str] = {}
    vuln_compliance_tags = _finding_compliance_tags(report)
    vuln_workflow = _finding_workflow_metadata(report)

    for agent in report.agents:
        agent_id = _next_id("SPDXRef-Agent")
        root_element_ids.append(agent_id)

        agent_element: dict[str, Any] = {
            "type": "software_Package",
            "spdxId": agent_id,
            "name": agent.name,
            "software_primaryPurpose": "application",
            "description": f"AI Agent ({agent.agent_type.value})",
        }
        _annotate(agent_id, f"agent-bom:ai-agent-type={agent.agent_type.value}")
        if agent.config_path:
            agent_element["comment"] = f"config_path: {agent.config_path}, status: {agent.status.value}"
        if agent.source:
            # ``Agent.source`` is discovery provenance (for example
            # ``project`` or ``snowflake``), not an SPDX Agent identity. Keep
            # it as an annotation instead of emitting an invalid originatedBy
            # reference to a non-existent Element.
            _annotate(agent_id, f"agent-bom:discovery-source={agent.source}")
        elements.append(agent_element)

        for server in agent.mcp_servers:
            server_id = _next_id("SPDXRef-MCPServer")

            server_desc = f"MCP Server ({server.transport.value})"
            if server.tools:
                server_desc += f" — {len(server.tools)} tool(s): {', '.join(t.name for t in server.tools[:10])}"
                if len(server.tools) > 10:
                    server_desc += f" (+{len(server.tools) - 10} more)"
            server_element: dict[str, Any] = {
                "type": "software_Package",
                "spdxId": server_id,
                "name": server.name,
                "software_primaryPurpose": "application",
                "description": server_desc,
            }
            if server.mcp_version:
                server_element["software_packageVersion"] = server.mcp_version
            elements.append(server_element)
            for tool in server.tools:
                _annotate(server_id, f"agent-bom:mcp-tool={tool.name}" + (f": {tool.description[:120]}" if tool.description else ""))

            relationships.append(
                {
                    "type": "Relationship",
                    "spdxId": _next_id("SPDXRef-Rel"),
                    "relationshipType": "contains",
                    "from": agent_id,
                    "to": [server_id],
                }
            )

            for pkg in server.packages:
                pkg_key = f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"
                if pkg_key not in pkg_ref_map:
                    pkg_id = _next_id("SPDXRef-Pkg")
                    pkg_ref_map[pkg_key] = pkg_id

                    pkg_element: dict[str, object] = {
                        "type": "software_Package",
                        "spdxId": pkg_id,
                        "name": pkg.name,
                        "software_packageVersion": pkg.version,
                        "software_primaryPurpose": "library",
                    }
                    for statement in _package_statements(pkg):
                        _annotate(pkg_id, statement)
                    pkg_element.update(_package_optional_fields(pkg, _supplier_ref))
                    elements.append(pkg_element)
                    declared_license = pkg.license_expression or pkg.license
                    if declared_license:
                        # Licensing is a hasDeclaredLicense edge to a
                        # LicenseExpression element, not a package property.
                        relationships.append(
                            {
                                "type": "Relationship",
                                "spdxId": _next_id("SPDXRef-Rel"),
                                "relationshipType": "hasDeclaredLicense",
                                "from": pkg_id,
                                "to": [_license_ref(declared_license)],
                            }
                        )

                pkg_id = pkg_ref_map[pkg_key]
                relationships.append(
                    {
                        "type": "Relationship",
                        "spdxId": _next_id("SPDXRef-Rel"),
                        "relationshipType": "dependsOn",
                        "from": server_id,
                        "to": [pkg_id],
                    }
                )

                for vuln in pkg.vulnerabilities:
                    vuln_element_id = _next_id("SPDXRef-Vuln")
                    vuln_element: dict[str, object] = {
                        "type": "security_Vulnerability",
                        "spdxId": vuln_element_id,
                        "name": vuln.id,
                        "description": vuln.summary or "",
                        "externalIdentifier": (
                            [{"type": "ExternalIdentifier", "externalIdentifierType": "cve", "identifier": vuln.id}]
                            if vuln.id.startswith("CVE-")
                            else []
                        ),
                    }
                    elements.append(vuln_element)
                    cvss_type = _cvss_assessment_type(vuln.cvss_vector) if vuln.cvss_score is not None else None
                    for statement in _vulnerability_statements(
                        vuln,
                        compliance_tags=vuln_compliance_tags.get(_vulnerability_key(pkg, vuln), []),
                        observed_at=report.generated_at.isoformat(),
                        workflow=vuln_workflow.get(_vulnerability_key(pkg, vuln)),
                        cvss_in_assessment=cvss_type is not None,
                    ):
                        _annotate(vuln_element_id, statement)

                    # CVSS is a security-profile assessment relationship in
                    # SPDX 3.0, not an ad-hoc score object on the vulnerability.
                    # The class follows the vector's CVSS version and the vector
                    # is mandatory; without one the score rides on an annotation.
                    if cvss_type is not None and vuln.cvss_score is not None:
                        relationships.append(
                            {
                                "type": cvss_type,
                                "spdxId": _next_id("SPDXRef-Cvss"),
                                "relationshipType": "hasAssessmentFor",
                                "from": vuln_element_id,
                                "to": [pkg_id],
                                "security_score": vuln.cvss_score,
                                "security_severity": _cvss_qualitative_severity(vuln.cvss_score),
                                "security_vectorString": vuln.cvss_vector,
                            }
                        )

                    assessment_id = _next_id("SPDXRef-VulnAssessment")
                    assessment: dict[str, object] = {
                        "type": "security_VexAffectedVulnAssessmentRelationship",
                        "spdxId": assessment_id,
                        "relationshipType": "affects",
                        "from": vuln_element_id,
                        "to": [pkg_id],
                        "security_actionStatement": (f"Upgrade to {vuln.fixed_version}" if vuln.fixed_version else _NO_FIX_ACTION),
                    }
                    if vuln.is_kev:
                        assessment["comment"] = "CISA KEV: actively exploited in the wild"
                    relationships.append(assessment)

    # Stamp the shared CreationInfo back-reference on every element / relationship
    # node (Relationships are Elements in SPDX 3.0 and require creationInfo too).
    for node in (*elements, *relationships, *annotations):
        node.setdefault("creationInfo", _CREATION_INFO_ID)

    spdx_document: dict[str, Any] = {
        "type": "SpdxDocument",
        "spdxId": document_id,
        "creationInfo": _CREATION_INFO_ID,
        "name": f"agent-bom-{report.generated_at.strftime('%Y%m%d-%H%M%S')}",
        "dataLicense": SPDX_3_DATA_LICENSE,
        "profileConformance": list(SPDX_3_PROFILE_CONFORMANCE),
        "rootElement": root_element_ids,
        "comment": (
            f"Security scan generated by agent-bom {report.tool_version}. "
            f"Covers {report.total_agents} agent(s), {report.total_servers} MCP server(s), "
            f"{report.total_packages} package(s), {report.total_vulnerabilities} vulnerability/ies."
        ),
    }

    # Canonical JSON-LD: a single flat @graph holding the CreationInfo blank node,
    # the SpdxDocument root, and every element + relationship.
    graph: list[dict[str, Any]] = [creation_info, spdx_document, *elements, *relationships, *annotations]
    document = {
        "@context": SPDX_3_CONTEXT,
        "@graph": graph,
    }
    from agent_bom.output.interop_security import sanitize_linked_document

    # Element IDs are minted here from the uuid5 namespace plus a fixed prefix
    # and counter, so they carry no input text; skip re-redacting each one.
    minted_ids = re.compile(re.escape(document_namespace) + r"/SPDXRef-[A-Za-z]+(?:-[A-Za-z]+)*(?:-\d+)?")
    return sanitize_linked_document(document, trusted_ids=minted_ids)


def _package_statements(pkg: Any) -> list[str]:
    """Package enrichments with no modelled SPDX 3 slot, as annotation statements."""
    version_provenance = package_version_provenance(pkg)
    statements = [
        f"agent-bom:ecosystem={pkg.ecosystem}",
        f"agent-bom:version-provenance-source={version_provenance.get('version_source', 'unknown')}",
        f"agent-bom:version-provenance-confidence={version_provenance.get('confidence', 'unknown')}",
    ]
    discovery_provenance = package_discovery_provenance(pkg) or {}
    for field_name in ("source_type", "collector", "resource_type", "location"):
        value = discovery_provenance.get(field_name)
        if value:
            statements.append(f"agent-bom:discovery-provenance-{field_name.replace('_', '-')}={value}")
    if pkg.is_malicious:
        # Surface the malicious flag so a MAL- package is distinguishable from
        # an ordinary library in the SBOM.
        statements.append(f"agent-bom:malicious=true reason={pkg.malicious_reason or 'flagged malicious'}")
    # SPDX 3.0.1 has no modelled slot for a verification verdict; an ``other``
    # Annotation is the core-profile mechanism for it. ``verifiedUsing`` carries
    # the digest; this carries whether it was checked, and what came back.
    statements.extend(integrity_verdict_statements(integrity_verdict(pkg)))
    return statements


def _package_optional_fields(pkg: Any, supplier_ref: Any) -> dict[str, object]:
    """Spec-model ``software_Package`` properties that are only set when known."""
    fields: dict[str, object] = {}
    verified_using = spdx3_verified_using(pkg.checksums)
    if verified_using:
        fields["verifiedUsing"] = verified_using
    purl = pkg.purl or synthesize_purl(pkg.name, pkg.version, pkg.ecosystem)
    if purl:
        fields["software_packageUrl"] = purl
        fields["externalIdentifier"] = [{"type": "ExternalIdentifier", "externalIdentifierType": "packageUrl", "identifier": purl}]
    if pkg.supplier:
        fields["suppliedBy"] = supplier_ref(pkg.supplier)
    optional = {
        "description": pkg.description[:300] if pkg.description else None,
        "software_homePage": pkg.homepage,
        "software_downloadLocation": pkg.download_url,
        "software_copyrightText": pkg.copyright_text,
    }
    fields.update({key: value for key, value in optional.items() if value})
    return fields


def export_spdx(report: AIBOMReport, output_path: str) -> None:
    """Export report as a canonical SPDX 3.0.1 JSON-LD file."""
    data = to_spdx(report)
    Path(output_path).write_text(json.dumps(data, indent=2))


def _cvss_assessment_type(vector: str | None) -> str | None:
    """SPDX 3 CVSS assessment class for a vector, or ``None`` when the vector is
    absent or not a CVSS v3/v4 vector (both classes require ``vectorString``)."""
    if not vector:
        return None
    if vector.startswith("CVSS:3."):
        return "security_CvssV3VulnAssessmentRelationship"
    if vector.startswith("CVSS:4."):
        return "security_CvssV4VulnAssessmentRelationship"
    return None


def _cvss_qualitative_severity(score: float) -> str:
    """CVSS v3/v4 qualitative severity rating for a base score."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


def _vulnerability_statements(
    vuln: Any,
    *,
    compliance_tags: list[str] | None = None,
    observed_at: str | None = None,
    workflow: dict[str, str] | None = None,
    cvss_in_assessment: bool = False,
) -> list[str]:
    """Encode non-core vulnerability enrichments as SPDX annotation statements.

    ``observed_at`` anchors the severity-derived remediation SLA
    (``agent-bom:sla-due-at``, KEV override); omitted when no deadline is
    derivable so a missing statement never reads as "no SLA".
    """
    statements: list[str] = []
    severity_value = vuln.severity.value if hasattr(vuln.severity, "value") else str(vuln.severity)
    # agent-bom's severity may come from a non-CVSS source, so it is carried
    # verbatim rather than re-derived from the CVSS assessment's rating.
    statements.append(f"agent-bom:severity={severity_value}")
    if vuln.cvss_score is not None and not cvss_in_assessment:
        statements.append(f"agent-bom:cvss-score={vuln.cvss_score}")
        if vuln.cvss_vector:
            statements.append(f"agent-bom:cvss-vector={vuln.cvss_vector}")
    if vuln.severity_source:
        statements.append(f"agent-bom:severity-source={vuln.severity_source}")
    if vuln.epss_score is not None:
        statements.append(f"agent-bom:epss-score={vuln.epss_score:.4f}")
    if vuln.epss_percentile is not None:
        statements.append(f"agent-bom:epss-percentile={vuln.epss_percentile:.4f}")
    statements.append(f"agent-bom:kev={'true' if vuln.is_kev else 'false'}")
    if vuln.kev_date_added:
        statements.append(f"agent-bom:kev-date-added={vuln.kev_date_added}")
    if vuln.kev_due_date:
        statements.append(f"agent-bom:kev-due-date={vuln.kev_due_date}")
    from agent_bom.graph.sla import sla_due_at as _compute_sla_due_at

    workflow_data = workflow or {}
    explicit_sla = workflow_data.get("sla_due_at")
    sla_due = explicit_sla or _compute_sla_due_at(severity_value, observed_at, kev_due_date=vuln.kev_due_date)
    if sla_due is not None:
        statements.append(f"agent-bom:sla-due-at={sla_due}")
        source = workflow_data.get("sla_due_at_source", "unknown") if explicit_sla else "severity-kev/v1"
        statements.append(f"agent-bom:sla-due-at-source={source}")
    if workflow_data.get("owner"):
        statements.append(f"agent-bom:owner={workflow_data['owner']}")
    if workflow_data.get("workflow_status"):
        statements.append(f"agent-bom:workflow-status={workflow_data['workflow_status']}")
    for cwe_id in vuln.cwe_ids:
        statements.append(f"agent-bom:cwe={cwe_id}")
    compliance_statements = [*list(compliance_tags or []), *_vulnerability_compliance_tags(vuln)]
    for tag in compliance_statements:
        statements.append(f"agent-bom:compliance-tag={tag}")
    if compliance_statements:
        # Honesty: these finding→control tags are agent-bom's own asserted
        # mapping judgment, not an authority-published crosswalk. Label the
        # provenance so SPDX consumers never read them as official.
        statements.append("agent-bom:compliance-tag-provenance=vendor-asserted")

    return statements


def _vulnerability_compliance_tags(vuln: Any) -> list[str]:
    """Return framework-qualified vulnerability compliance tags."""
    raw_tags = getattr(vuln, "compliance_tags", None) or {}
    if isinstance(raw_tags, dict):
        tags: list[str] = []
        for framework, controls in sorted(raw_tags.items()):
            if isinstance(controls, str):
                controls = [controls]
            for control in controls or []:
                tags.append(f"{framework}:{control}")
        return tags
    if isinstance(raw_tags, list | tuple | set):
        return [str(tag) for tag in raw_tags if tag]
    return []


def _finding_compliance_tags(report: AIBOMReport) -> dict[tuple[str, str, str | None, str], list[str]]:
    """Return framework-qualified Finding tags keyed by package vulnerability."""
    by_vuln: dict[tuple[str, str, str | None, str], list[str]] = {}
    for finding in cve_findings(report):
        vuln_id = finding.cve_id or finding.id
        tags = framework_qualified_finding_tags(finding)
        if tags:
            by_vuln[(package_ecosystem(finding), package_name(finding), package_version(finding), vuln_id)] = tags
    return by_vuln


def _finding_workflow_metadata(report: AIBOMReport) -> dict[tuple[str, str, str | None, str], dict[str, str]]:
    """Return persisted owner/SLA/state keyed by package vulnerability."""
    from agent_bom.output.finding_views import workflow_status

    by_vuln: dict[tuple[str, str, str | None, str], dict[str, str]] = {}
    for finding in cve_findings(report):
        metadata: dict[str, str] = {}
        if finding.owner:
            metadata["owner"] = finding.owner
        sla_due = finding.to_dict().get("sla_due_at")
        if sla_due:
            metadata["sla_due_at"] = str(sla_due)
            metadata["sla_due_at_source"] = str(finding.to_dict()["sla_due_at_source"])
        status = workflow_status(finding)
        if status:
            metadata["workflow_status"] = status
        if metadata:
            by_vuln[(package_ecosystem(finding), package_name(finding), package_version(finding), finding.cve_id or finding.id)] = metadata
    return by_vuln


def _vulnerability_key(pkg: Any, vuln: Any) -> tuple[str, str, str | None, str]:
    return (pkg.ecosystem, pkg.name, pkg.version, vuln.id)
