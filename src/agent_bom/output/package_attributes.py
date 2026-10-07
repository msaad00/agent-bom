"""Canonical package attributes for standalone graph projections."""

from typing import Any

from agent_bom.package_utils import canonical_package_key


def _package_node_attributes(pkg: dict[str, Any]) -> dict[str, Any]:
    raw_version_provenance = pkg.get("version_provenance")
    version_provenance: dict[str, Any]
    if isinstance(raw_version_provenance, dict):
        version_provenance = raw_version_provenance
    else:
        discovery = pkg.get("discovery_provenance")
        if isinstance(discovery, dict) and isinstance(discovery.get("version_provenance"), dict):
            version_provenance = discovery["version_provenance"]
        else:
            version_provenance = {}
    version_source = version_provenance.get("version_source") or pkg.get("version_source")
    version_confidence = version_provenance.get("confidence") or pkg.get("version_confidence")
    attributes = {
        "canonical_node_id": "pkg:"
        + canonical_package_key(
            str(pkg.get("name") or ""), str(pkg.get("version") or ""), str(pkg.get("ecosystem") or ""), pkg.get("purl")
        ),
        "name": pkg.get("name"),
        "version": pkg.get("version"),
        "ecosystem": pkg.get("ecosystem"),
        "purl": pkg.get("purl"),
        "version_source": version_source,
        "version_confidence": version_confidence,
        "version_provenance": version_provenance,
    }
    return {key: value for key, value in attributes.items() if value not in (None, "", [], {})}
