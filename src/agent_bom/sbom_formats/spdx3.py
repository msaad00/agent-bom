"""SPDX 3.0 element readers shared by the SBOM ingester.

Pure helpers over one SPDX 3 element or the projected ``elements`` /
``relationships`` view: version/PURL/purpose lookup across emitter dialects,
``agent-bom:`` annotation statements, and the spec-model references (standalone
``Annotation`` elements, ``suppliedBy`` agents, ``hasDeclaredLicense`` license
expressions, CVSS assessment relationships) that agent-bom's exporter emits.
"""

from __future__ import annotations

from typing import Any, TypedDict

from agent_bom.advisory_ids import upstream_advisory_ids


class Spdx3PackageMetadata(TypedDict):
    license: str | None
    supplier: str | None
    description: str | None
    homepage: str | None
    download_url: str | None
    copyright_text: str | None


# Element-level keys that may carry a package version across SPDX 3.0 emitters.
# agent-bom emits ``versionInfo``; third-party tools emit the expanded
# ``software/packageVersion`` / ``software_packageVersion`` / ``packageVersion``.
_SPDX3_VERSION_KEYS = ("versionInfo", "software/packageVersion", "software_packageVersion", "packageVersion")


# Element-level keys that may carry a flat PackageURL string.
_SPDX3_PURL_KEYS = ("software/packageUrl", "software_packageUrl", "packageUrl")


def _spdx3_version(elem: dict) -> str:
    """Return the package version from an SPDX 3.0 element, or ``"unknown"``."""
    for key in _SPDX3_VERSION_KEYS:
        value = elem.get(key)
        if value:
            return str(value)
    return "unknown"


def _spdx3_purl(elem: dict) -> str:
    """Return the PackageURL for an SPDX 3.0 element.

    Handles every shape agent-bom and third-party tools produce:
    - a flat ``software/packageUrl`` (or aliases) string, or
    - an ``externalIdentifier`` that is either a single object or a list of
      objects, each ``{"type": "PackageURL", "identifier": "pkg:..."}``.
    """
    for key in _SPDX3_PURL_KEYS:
        value = elem.get(key)
        if isinstance(value, str) and value:
            return value

    ext = elem.get("externalIdentifier")
    candidates = ext if isinstance(ext, list) else [ext] if isinstance(ext, dict) else []
    fallback = ""
    for entry in candidates:
        if not isinstance(entry, dict):
            continue
        identifier = entry.get("identifier") or ""
        if not identifier:
            continue
        id_type = str(entry.get("type") or "").lower()
        ext_id_type = str(entry.get("externalIdentifierType") or "").lower()
        if id_type in ("packageurl", "purl") or ext_id_type in ("packageurl", "purl") or identifier.startswith("pkg:"):
            return identifier
        if not fallback:
            fallback = identifier
    return fallback


def _spdx3_primary_purpose(elem: dict) -> str:
    """Return the (upper-cased) primaryPurpose for an SPDX 3.0 element."""
    for key in ("primaryPurpose", "software/primaryPurpose", "software_primaryPurpose"):
        value = elem.get(key)
        if isinstance(value, str) and value:
            return value.upper()
    return ""


def _spdx3_annotation_kv(elem: dict) -> dict[str, str]:
    """Parse ``agent-bom:key=value`` annotation statements into a dict."""
    kv: dict[str, str] = {}
    annotations = elem.get("annotation")
    if isinstance(annotations, dict):
        annotations = [annotations]
    for ann in annotations or []:
        if not isinstance(ann, dict):
            continue
        statement = ann.get("statement") or ""
        if statement.startswith("agent-bom:") and "=" in statement:
            key, _, value = statement[len("agent-bom:") :].partition("=")
            kv[key] = value
    return kv


def _spdx3_graph(data: dict) -> list | None:
    """Return the JSON-LD ``@graph`` node list if ``data`` is a canonical
    SPDX 3.0 document, else ``None``."""
    graph = data.get("@graph")
    if not isinstance(graph, list):
        return None
    ctx = data.get("@context")
    if isinstance(ctx, str) and "spdx.org/rdf/3." in ctx:
        return graph
    if isinstance(ctx, list) and any(isinstance(c, str) and "spdx.org/rdf/3." in c for c in ctx):
        return graph
    for node in graph:
        if isinstance(node, dict) and node.get("type") == "CreationInfo" and str(node.get("specVersion") or "").startswith("3."):
            return graph
    return None


def _spdx3_fold_annotations(graph: list) -> list:
    """Fold standalone ``Annotation`` elements onto their ``subject`` so readers
    see one shape for both this and the legacy inline ``annotation`` list."""
    by_subject: dict[str, list[dict]] = {}
    for node in graph:
        if isinstance(node, dict) and node.get("type") == "Annotation" and isinstance(node.get("subject"), str):
            by_subject.setdefault(node["subject"], []).append(node)
    if not by_subject:
        return graph
    folded: list = []
    for node in graph:
        node_id = node.get("spdxId") if isinstance(node, dict) else None
        if isinstance(node_id, str) and node_id in by_subject:
            inline = node.get("annotation")
            existing = inline if isinstance(inline, list) else [inline] if isinstance(inline, dict) else []
            node = {**node, "annotation": [*existing, *by_subject[node_id]]}
        folded.append(node)
    return folded


def _spdx3_references(data: dict) -> tuple[dict[str, dict], dict[str, str]]:
    """Index elements by id and resolve ``hasDeclaredLicense`` to expressions."""
    elem_by_id = {e["spdxId"]: e for e in data.get("elements", []) if isinstance(e, dict) and isinstance(e.get("spdxId"), str)}
    licenses: dict[str, str] = {}
    for rel in data.get("relationships", []):
        if not isinstance(rel, dict) or rel.get("relationshipType") != "hasDeclaredLicense" or not isinstance(rel.get("from"), str):
            continue
        targets = rel.get("to", [])
        for target in targets if isinstance(targets, list) else [targets]:
            expression = (elem_by_id.get(target) or {}).get("simplelicensing_licenseExpression")
            if isinstance(expression, str) and expression:
                licenses.setdefault(rel["from"], expression)
    return elem_by_id, licenses


def _spdx3_supplier(elem: dict, elem_by_id: dict[str, dict]) -> str | None:
    supplier = elem.get("suppliedBy") or elem.get("supplier") or elem.get("originatedBy") or None
    if isinstance(supplier, list):
        supplier = supplier[0] if supplier else None
    if isinstance(supplier, str) and supplier in elem_by_id:
        supplier = elem_by_id[supplier].get("name")
    if isinstance(supplier, dict):
        supplier = supplier.get("name")
    return supplier if isinstance(supplier, str) else None


def _first_str(elem: dict, *keys: str) -> str | None:
    for key in keys:
        value = elem.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _spdx3_package_metadata(elem: dict, references: tuple[dict[str, dict], dict[str, str]]) -> Spdx3PackageMetadata:
    """Package metadata from spec-model properties, falling back to legacy keys."""
    elem_by_id, licenses = references
    spdx_id = str(elem.get("spdxId") or elem.get("SPDXID") or "")
    description = _first_str(elem, "description", "software/description")
    return {
        "license": licenses.get(spdx_id) or _first_str(elem, "declaredLicense", "software/declaredLicense"),
        "supplier": _spdx3_supplier(elem, elem_by_id),
        "description": description[:300] if description else None,
        "homepage": _first_str(elem, "software_homePage", "homepage"),
        "download_url": _first_str(elem, "software_downloadLocation", "downloadLocation"),
        "copyright_text": _first_str(elem, "software_copyrightText", "copyrightText"),
    }


def _spdx3_cvss(cvss_rel: dict, score_obj: dict, ann: dict[str, str]) -> tuple[float | None, str | None]:
    """CVSS score/vector from an assessment relationship, a legacy inline score,
    or (for vector-less scores) the ``agent-bom:cvss-*`` annotations."""
    raw: Any = cvss_rel.get("security_score")
    if raw is None:
        raw = score_obj.get("score")
    if raw is None:
        raw = ann.get("cvss-score")
    try:
        score = float(raw) if raw is not None else None
    except (TypeError, ValueError):
        score = None
    vector = cvss_rel.get("security_vectorString") or ann.get("cvss-vector")
    return score, vector if isinstance(vector, str) and vector else None


def upstream_enrichment_fields(annotations: dict) -> dict:
    """Portable upstream relations remain distinct from vulnerability identity."""
    return {
        "upstream_ids": upstream_advisory_ids(annotations.get("upstream-ids", "").split(",")),
        "epss_cve_id": annotations.get("epss-cve-id"),
        "kev_cve_id": annotations.get("kev-cve-id"),
        "kev_due_date": annotations.get("kev-due-date"),
    }


def upstream_enrichment_statements(vuln) -> list[str]:
    """Encode relationships and selected CVEs as SPDX annotations."""
    statements: list[str] = []
    if vuln.upstream_ids:
        statements.append(f"agent-bom:upstream-ids={','.join(vuln.upstream_ids)}")
    for key in ("epss_cve_id", "kev_cve_id"):
        value = getattr(vuln, key)
        if value:
            statements.append(f"agent-bom:{key.replace('_', '-')}={value}")
    return statements
