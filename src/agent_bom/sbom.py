"""SBOM ingestion — parse Syft/Grype CycloneDX and SPDX output into Package objects.

Allows agent-bom to accept an existing SBOM (from Syft, Grype, Trivy, etc.) as
input instead of scanning lock files, enabling integration into existing pipelines:

    syft image myapp:latest -o cyclonedx-json > sbom.json
    agent-bom scan --sbom sbom.json --inventory agents.json

Supported formats:
- CycloneDX 1.x JSON (Syft, Grype, Trivy, cdxgen)
- SPDX 2.x / 3.0 JSON (Syft, ort, spdx-tools)
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_bom.models import Package, Severity, Vulnerability
from agent_bom.sbom_formats.cyclonedx import (
    is_context_component,
    restore_dependency_hierarchy,
    restore_package_metadata,
    restore_vulnerability_enrichment,
    software_components,
)
from agent_bom.sbom_formats.spdx3 import (
    _spdx3_annotation_kv,
    _spdx3_cvss,
    _spdx3_fold_annotations,
    _spdx3_graph,
    _spdx3_package_metadata,
    _spdx3_purl,
    _spdx3_references,
    _spdx3_version,
    upstream_enrichment_fields,
)
from agent_bom.sbom_formats.spdx_hierarchy import context_role, restore_spdx_hierarchy


def _ecosystem_from_purl(purl: str) -> str:
    """Extract ecosystem from a Package URL string.

    Examples:
      pkg:npm/%40scope/name@1.0.0  → npm
      pkg:pypi/requests@2.28.0     → pypi
      pkg:golang/github.com/x/y@v1 → go
      pkg:cargo/serde@1.0.0        → cargo
      pkg:maven/org.foo/bar@1.0    → maven
      pkg:nuget/Newtonsoft.Json@13  → nuget
    """
    if not purl or not purl.startswith("pkg:"):
        return "unknown"
    parts = purl[4:].split("/", 1)
    eco = parts[0].lower()
    # Normalize Package URL ecosystem aliases to the scanner-facing ecosystem
    # keys. SBOM imports must resolve against the same advisory databases as
    # lockfile/image scans; language names like "ruby" or "php" are too broad.
    return {
        "gem": "rubygems",
        "golang": "go",
        "rubygems": "rubygems",
    }.get(eco, eco)


def _ecosystem_from_type(component_type: str) -> str:
    """Map CycloneDX component type to ecosystem name."""
    return {
        "npm": "npm",
        "pypi": "pypi",
        "golang": "go",
        "cargo": "cargo",
        "maven": "maven",
        "nuget": "nuget",
        "gem": "rubygems",
        "rubygems": "rubygems",
        "composer": "composer",
        "hex": "hex",
        "pub": "pub",
    }.get(component_type.lower(), component_type.lower())


# ─── CycloneDX ────────────────────────────────────────────────────────────────


def parse_cyclonedx(data: dict) -> list[Package]:
    """Parse a CycloneDX 1.x JSON document into Package objects.

    Works with output from Syft, Grype, Trivy, cdxgen, and agent-bom itself.
    Dependency edges establish directness; scope describes inclusion, not depth.
    Imported assertions do not establish runtime reachability.
    """
    packages: list[Package] = []
    bom_ref_to_pkg: dict[str, Package] = {}
    components = software_components(data)

    for comp in components:
        if not isinstance(comp, dict) or is_context_component(comp):
            continue

        name = comp.get("name", "")
        version = comp.get("version", "unknown")
        purl = comp.get("purl", "")

        if not name:
            continue

        # Determine ecosystem: prefer purl, then component type
        ecosystem = _ecosystem_from_purl(purl) if purl else _ecosystem_from_type(comp.get("type", "library"))
        if ecosystem in ("library", "framework", "container", "device", "unknown"):
            ecosystem = "unknown"

        # Extract supply chain metadata from CycloneDX fields
        supplier_name = None
        supplier_data = comp.get("supplier") or comp.get("manufacturer")
        if isinstance(supplier_data, dict):
            supplier_name = supplier_data.get("name")
        elif isinstance(supplier_data, str):
            supplier_name = supplier_data

        author_val = comp.get("author") or None

        description_val = comp.get("description") or None
        if description_val:
            description_val = description_val[:300]

        # Extract license from CycloneDX licenses array
        lic_id = None
        lic_expr = None
        cdx_licenses = comp.get("licenses", [])
        if cdx_licenses:
            ids = []
            for lic_entry in cdx_licenses:
                if isinstance(lic_entry, dict):
                    lic_obj = lic_entry.get("license", {})
                    if isinstance(lic_obj, dict):
                        lid = lic_obj.get("id") or lic_obj.get("name")
                        if lid:
                            ids.append(lid)
                    expr = lic_entry.get("expression")
                    if expr:
                        lic_expr = expr
            if ids:
                lic_id = ids[0]
                if not lic_expr:
                    lic_expr = " AND ".join(ids) if len(ids) > 1 else ids[0]

        # Extract external references (homepage, repo, download)
        homepage_val = None
        repo_val = None
        download_val = None
        for ref in comp.get("externalReferences", []):
            ref_type = (ref.get("type") or "").lower()
            ref_url = ref.get("url") or ""
            if not ref_url:
                continue
            if ref_type == "website" and not homepage_val:
                homepage_val = ref_url
            elif ref_type == "vcs" and not repo_val:
                repo_val = ref_url
            elif ref_type == "distribution" and not download_val:
                download_val = ref_url

        copyright_val = comp.get("copyright") or None

        bom_ref = comp.get("bom-ref", "")
        package = Package(
            name=name,
            version=version,
            ecosystem=ecosystem,
            purl=purl or None,
            is_direct=False,
            resolved_from_registry=False,
            license=lic_id,
            license_expression=lic_expr,
            supplier=supplier_name,
            author=author_val,
            description=description_val,
            homepage=homepage_val,
            repository_url=repo_val,
            download_url=download_val,
            copyright_text=copyright_val,
        )
        restore_package_metadata(package, comp)
        packages.append(package)
        if bom_ref:
            bom_ref_to_pkg[bom_ref] = package

    restore_dependency_hierarchy(data, bom_ref_to_pkg)

    # Ingest CycloneDX vulnerabilities[] array if present
    for vuln_data in data.get("vulnerabilities", []):
        if not isinstance(vuln_data, dict):
            continue
        vuln_id = vuln_data.get("id", "")
        if not vuln_id:
            continue
        summary = vuln_data.get("description") or vuln_data.get("detail") or ""

        # Determine severity from ratings
        severity = Severity.UNKNOWN
        cvss_score: float | None = None
        cvss_vector: str | None = None
        for rating in vuln_data.get("ratings", []):
            if not isinstance(rating, dict):
                continue
            sev_str = (rating.get("severity") or "").lower()
            if sev_str in ("critical", "high", "medium", "low", "none"):
                severity = Severity(sev_str)
            vector = rating.get("vector")
            cvss_vector = vector if isinstance(vector, str) else None
            score = rating.get("score")
            if score is not None:
                try:
                    cvss_score = float(score)
                except (TypeError, ValueError):
                    pass
            break  # use first rating

        recommendation = vuln_data.get("recommendation", "")
        fixed = (
            recommendation.removeprefix("Upgrade to ")
            if isinstance(recommendation, str) and recommendation.startswith("Upgrade to ")
            else None
        )
        source = vuln_data.get("source", {})
        references = [source["url"]] if isinstance(source, dict) and isinstance(source.get("url"), str) else []
        vuln = Vulnerability(
            id=vuln_id,
            summary=summary,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            fixed_version=fixed,
            severity_source="sbom",
            references=references,
        )

        restore_vulnerability_enrichment(vuln, vuln_data)

        # Map vulnerability to affected packages via affects[] array
        for affect in vuln_data.get("affects", []):
            if not isinstance(affect, dict):
                continue
            affected_ref = affect.get("ref", "")
            affected_pkg = bom_ref_to_pkg.get(affected_ref)
            if affected_pkg is not None and vuln not in affected_pkg.vulnerabilities:
                affected_pkg.vulnerabilities.append(vuln)

    return packages


# ─── SPDX ────────────────────────────────────────────────────────────────────


def _spdx3_vulnerabilities(data: dict, pkg_by_id: dict[str, Package]) -> None:
    """Attach SPDX 3.0 vulnerability assessments (AFFECTS) to packages in place.

    agent-bom emits each vulnerability as a ``security_Vulnerability`` element and
    links it to the affected package via a ``security_VexAffectedVulnAssessmentRelationship``
    (``relationshipType: affects``) in the top-level ``relationships`` array, with
    the CVSS score carried on a sibling ``security_CvssV3VulnAssessmentRelationship``
    (``relationshipType: hasAssessmentFor``). The severity/fix/KEV/EPSS/CWE
    enrichments ride on those relationships and on the vulnerability element's
    annotations. Legacy documents that inline a ``score`` object and use the
    upper-cased ``AFFECTS``/``remediation`` shape are still accepted.
    """
    elements = data.get("elements", [])
    vuln_elems: dict[str, dict] = {}
    for elem in elements:
        if isinstance(elem, dict) and str(elem.get("type") or "").lower().endswith("vulnerability"):
            spdx_id = elem.get("spdxId") or elem.get("SPDXID")
            if spdx_id:
                vuln_elems[spdx_id] = elem

    # AFFECTS relationships can live in the top-level array or among elements.
    relationships = list(data.get("relationships", []))
    relationships += [e for e in elements if isinstance(e, dict) and "Relationship" in str(e.get("type") or "")]

    # Index CVSS assessment relationships by the vulnerability they assess so the
    # (score-less) affects relationship can recover severity/score.
    cvss_by_vuln: dict[str, dict] = {}
    for rel in relationships:
        if not isinstance(rel, dict):
            continue
        if "cvss" in str(rel.get("type") or "").lower() or rel.get("security_score") is not None:
            frm = rel.get("from", "")
            if frm:
                cvss_by_vuln[frm] = rel

    for rel in relationships:
        if not isinstance(rel, dict) or str(rel.get("relationshipType") or "").lower() != "affects":
            continue
        vuln_elem = vuln_elems.get(rel.get("from", ""))
        if vuln_elem is None:
            continue
        targets = rel.get("to", [])
        if isinstance(targets, str):
            targets = [targets]

        cvss_rel = cvss_by_vuln.get(rel.get("from", ""), {})
        vuln_id = vuln_elem.get("name") or ""
        raw_score = vuln_elem.get("score")
        score_obj: dict = raw_score if isinstance(raw_score, dict) else {}
        ann = _spdx3_annotation_kv(vuln_elem)
        sev_str = ann.get("severity") or rel.get("severity") or cvss_rel.get("security_severity") or score_obj.get("severity") or "unknown"
        try:
            severity = Severity(str(sev_str).lower())
        except ValueError:
            severity = Severity.UNKNOWN
        cvss_score, cvss_vector = _spdx3_cvss(cvss_rel, score_obj, ann)

        fixed_version = None
        remediation = rel.get("security_actionStatement") or rel.get("remediation") or ""
        if remediation.startswith("Upgrade to "):
            fixed_version = remediation[len("Upgrade to ") :].strip() or None

        cwe_ids = [v for k, v in ann.items() if k == "cwe"]

        def _as_float(value: str | None) -> float | None:
            try:
                return float(value) if value is not None else None
            except (TypeError, ValueError):
                return None

        for pkg_id in targets:
            pkg = pkg_by_id.get(pkg_id)
            if pkg is None or not vuln_id:
                continue
            if any(existing.id == vuln_id for existing in pkg.vulnerabilities):
                continue
            pkg.vulnerabilities.append(
                Vulnerability(
                    id=vuln_id,
                    summary=vuln_elem.get("description") or "",
                    severity=severity,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    fixed_version=fixed_version,
                    severity_source=ann.get("severity-source"),
                    epss_score=_as_float(ann.get("epss-score")),
                    epss_percentile=_as_float(ann.get("epss-percentile")),
                    is_kev=ann.get("kev") == "true",
                    kev_date_added=ann.get("kev-date-added"),
                    **upstream_enrichment_fields(ann),
                    cwe_ids=cwe_ids,
                )
            )


def _normalize_spdx3_graph(data: dict) -> dict:
    """Project a canonical ``@graph`` SPDX 3.0.1 document onto the flat
    ``elements``/``relationships``/``spdxVersion`` shape the parser consumes.

    Legacy flat SPDX 3.0 documents and non-SPDX-3 documents pass through
    unchanged, so both serializations round-trip through the same reader.
    """
    graph = _spdx3_graph(data)
    if graph is None:
        return data
    spec = ""
    doc_id = ""
    doc_name = ""
    for node in graph:
        if not isinstance(node, dict):
            continue
        ntype = node.get("type")
        if ntype == "CreationInfo" and not spec:
            spec = str(node.get("specVersion") or "")
        elif ntype == "SpdxDocument":
            doc_id = node.get("spdxId") or node.get("SPDXID") or doc_id
            doc_name = node.get("name") or doc_name
    graph = _spdx3_fold_annotations(graph)
    relationships = [n for n in graph if isinstance(n, dict) and str(n.get("type") or "").endswith("Relationship")]
    projected = dict(data)
    projected["spdxVersion"] = f"SPDX-{spec}" if spec else "SPDX-3.0"
    projected["elements"] = graph
    projected["relationships"] = relationships
    if doc_id:
        projected["SPDXID"] = doc_id
    if doc_name and not projected.get("name"):
        projected["name"] = doc_name
    return projected


def parse_spdx(data: dict) -> list[Package]:
    """Parse an SPDX 2.x or 3.0 JSON document into Package objects.

    Handles both:
    - SPDX 2.x: top-level "packages" array with "name", "versionInfo", "externalRefs"
    - SPDX 3.0: canonical ``@graph`` JSON-LD or a flat "elements" array
    """
    data = _normalize_spdx3_graph(data)
    packages: list[Package] = []

    # SPDX 3.0 format
    if "spdxVersion" in data and data.get("spdxVersion", "").startswith("SPDX-3"):
        pkg_by_id: dict[str, Package] = {}
        references = _spdx3_references(data)
        for elem in data.get("elements", []):
            if not isinstance(elem, dict):
                continue
            if elem.get("type") not in ("software/Package", "SOFTWARE_PACKAGE", "software_Package"):
                continue
            # Explicit agent/server containers are topology, but APPLICATION
            # alone is a valid purpose for real, scannable software packages.
            if context_role(elem) and not _spdx3_purl(elem):
                continue
            name = elem.get("name", "")
            if not name:
                continue
            version = _spdx3_version(elem)
            purl = _spdx3_purl(elem)
            ecosystem = _ecosystem_from_purl(purl) if purl else "unknown"

            elem_spdxid = str(elem.get("spdxId") or elem.get("SPDXID") or "")

            pkg = Package(
                name=name,
                version=version,
                ecosystem=ecosystem,
                purl=purl or None,
                is_direct=None,
                reachability_evidence="declaration_only",
                dependency_scope="unknown",
                version_source="sbom_ingest",
                **_spdx3_package_metadata(elem, references),
            )
            packages.append(pkg)
            if elem_spdxid:
                pkg_by_id[elem_spdxid] = pkg

        restore_spdx_hierarchy(data, pkg_by_id)
        _spdx3_vulnerabilities(data, pkg_by_id)
        return packages

    # SPDX 2.x format
    pkg_by_id = {}
    for pkg in data.get("packages", []):
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name", "")
        version = pkg.get("versionInfo", "unknown")
        if not name or name == "NOASSERTION":
            continue

        purl = ""
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator", "")
                break

        ecosystem = _ecosystem_from_purl(purl) if purl else "unknown"

        if context_role(pkg) and not purl:
            continue

        # SPDX 2.x supply chain metadata
        lic_declared = pkg.get("licenseDeclared") or None
        if lic_declared and lic_declared.upper() in ("NOASSERTION", "NONE"):
            lic_declared = None
        supplier_2x = pkg.get("supplier") or None
        if isinstance(supplier_2x, str) and supplier_2x.upper() == "NOASSERTION":
            supplier_2x = None
        download_loc = pkg.get("downloadLocation") or None
        if download_loc and download_loc.upper() == "NOASSERTION":
            download_loc = None
        homepage_2x = pkg.get("homepage") or None
        if homepage_2x and homepage_2x.upper() == "NOASSERTION":
            homepage_2x = None
        desc_2x = pkg.get("description") or None
        copyright_2x = pkg.get("copyrightText") or None
        if copyright_2x and copyright_2x.upper() == "NOASSERTION":
            copyright_2x = None

        pkg_spdxid = pkg.get("SPDXID", "")

        packages.append(
            Package(
                name=name,
                version=version,
                ecosystem=ecosystem,
                purl=purl or None,
                is_direct=None,
                reachability_evidence="declaration_only",
                dependency_scope="unknown",
                version_source="sbom_ingest",
                license=lic_declared,
                supplier=supplier_2x,
                description=desc_2x[:300] if desc_2x else None,
                homepage=homepage_2x,
                download_url=download_loc,
                copyright_text=copyright_2x,
            )
        )

        if pkg_spdxid:
            pkg_by_id[pkg_spdxid] = packages[-1]

    restore_spdx_hierarchy(data, pkg_by_id)
    return packages


# ─── Auto-detect + load ──────────────────────────────────────────────────────


def detect_sbom_resource_name(data: dict) -> str | None:
    """Try to extract a human-readable resource name from SBOM metadata.

    Checks (in order):
    - CycloneDX: ``metadata.component.name``
    - SPDX 2.x: ``name`` (document name, often the target)
    - SPDX 3.0: first element ``name`` where type is ``software/Package``

    Returns None if no meaningful name is found.
    """
    data = _normalize_spdx3_graph(data)
    # CycloneDX
    if data.get("bomFormat") == "CycloneDX":
        comp = data.get("metadata", {}).get("component", {})
        name = comp.get("name", "")
        if name:
            return name

    # SPDX 2.x
    if data.get("spdxVersion", "").startswith("SPDX-2"):
        doc_name = data.get("name", "")
        if doc_name and doc_name not in ("NOASSERTION", "NONE"):
            # SPDX doc names are often "DOCUMENT-<target>" — strip prefix
            return doc_name.removeprefix("DOCUMENT-").strip() or None

    # SPDX 3.0
    if data.get("spdxVersion", "").startswith("SPDX-3"):
        for elem in data.get("elements", []):
            if isinstance(elem, dict) and elem.get("type") in ("software/Package", "SOFTWARE_PACKAGE", "software_Package"):
                return elem.get("name") or None

    return None


def parse_sbom_document(data: dict, source_name: str = "<memory>") -> tuple[list[Package], str, str | None]:
    """Parse an in-memory SBOM document.

    Returns ``(packages, format_name, resource_name)`` where ``resource_name``
    is auto-detected from SBOM metadata when available.
    """
    data = _normalize_spdx3_graph(data)
    resource_name = detect_sbom_resource_name(data)

    if "bomFormat" in data and data["bomFormat"] == "CycloneDX":
        return parse_cyclonedx(data), "cyclonedx", resource_name

    if data.get("spdxVersion", "").startswith("SPDX-3"):
        return parse_spdx(data), "spdx-3", resource_name

    if data.get("spdxVersion", "").startswith("SPDX-2"):
        return parse_spdx(data), "spdx-2", resource_name

    if "ai_bom_version" in data or "blast_radius" in data:
        raise ValueError("That looks like an agent-bom report, not an SBOM. Use 'agent-bom diff' for report comparison.")

    raise ValueError(f"Unrecognised SBOM format in {source_name}. Expected CycloneDX JSON (bomFormat=CycloneDX) or SPDX 2.x/3.0 JSON.")


def load_sbom(path: str) -> tuple[list[Package], str, str | None]:
    """Load an SBOM file and return ``(packages, format_name, resource_name)``.

    ``resource_name`` is the auto-detected target name from SBOM metadata
    (e.g. ``nginx:1.25``, ``prod-api-01``).  It is ``None`` when the SBOM
    does not carry a meaningful component name.

    Auto-detects CycloneDX vs SPDX from file content.
    Raises ValueError if the format is not recognised.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"SBOM file not found: {path}")

    text = p.read_text()
    if text.lstrip().startswith("SPDXVersion:"):
        raise ValueError("SPDX tag-value input is not supported; supply SPDX JSON instead.")
    data = json.loads(text)

    return parse_sbom_document(data, source_name=path)
