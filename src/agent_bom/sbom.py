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

from agent_bom.models import Package


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
    # Normalise aliases
    return {
        "golang": "go",
        "rubygems": "ruby",
        "hex": "erlang",
        "composer": "php",
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
        "gem": "ruby",
        "composer": "php",
    }.get(component_type.lower(), component_type.lower())


# ─── CycloneDX ────────────────────────────────────────────────────────────────


def parse_cyclonedx(data: dict) -> list[Package]:
    """Parse a CycloneDX 1.x JSON document into Package objects.

    Works with output from Syft, Grype, Trivy, cdxgen, and agent-bom itself.
    """
    packages: list[Package] = []
    components = data.get("components", [])

    for comp in components:
        if not isinstance(comp, dict):
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

        packages.append(
            Package(
                name=name,
                version=version,
                ecosystem=ecosystem,
                purl=purl or None,
                is_direct=True,
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
        )

    return packages


# ─── SPDX ────────────────────────────────────────────────────────────────────


def parse_spdx(data: dict) -> list[Package]:
    """Parse an SPDX 2.x or 3.0 JSON document into Package objects.

    Handles both:
    - SPDX 2.x: top-level "packages" array with "name", "versionInfo", "externalRefs"
    - SPDX 3.0: "elements" array with type "software/Package"
    """
    packages: list[Package] = []

    # SPDX 3.0 format
    if "spdxVersion" in data and data.get("spdxVersion", "").startswith("SPDX-3"):
        for elem in data.get("elements", []):
            if not isinstance(elem, dict):
                continue
            if elem.get("type") not in ("software/Package", "SOFTWARE_PACKAGE"):
                continue
            name = elem.get("name", "")
            version = elem.get("software/packageVersion", elem.get("packageVersion", "unknown"))
            purl = elem.get("software/packageUrl", elem.get("externalIdentifier", {}).get("identifier", ""))
            if not name:
                continue
            ecosystem = _ecosystem_from_purl(purl) if purl else "unknown"

            # Extract SPDX 3.0 metadata
            lic_3 = elem.get("declaredLicense") or elem.get("software/declaredLicense") or None
            supplier_3 = elem.get("supplier") or elem.get("originatedBy") or None
            if isinstance(supplier_3, dict):
                supplier_3 = supplier_3.get("name")
            desc_3 = elem.get("description") or elem.get("software/description") or None
            copyright_3 = elem.get("copyrightText") or None

            packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem=ecosystem,
                    purl=purl or None,
                    is_direct=True,
                    license=lic_3 if isinstance(lic_3, str) else None,
                    supplier=supplier_3 if isinstance(supplier_3, str) else None,
                    description=desc_3[:300] if desc_3 else None,
                    copyright_text=copyright_3 if isinstance(copyright_3, str) else None,
                )
            )
        return packages

    # SPDX 2.x format
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

        packages.append(
            Package(
                name=name,
                version=version,
                ecosystem=ecosystem,
                purl=purl or None,
                is_direct=True,
                license=lic_declared,
                supplier=supplier_2x,
                description=desc_2x[:300] if desc_2x else None,
                homepage=homepage_2x,
                download_url=download_loc,
                copyright_text=copyright_2x,
            )
        )

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
            if isinstance(elem, dict) and elem.get("type") in ("software/Package", "SOFTWARE_PACKAGE"):
                return elem.get("name") or None

    return None


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

    data = json.loads(p.read_text())

    resource_name = detect_sbom_resource_name(data)

    # CycloneDX: has "bomFormat" key
    if "bomFormat" in data and data["bomFormat"] == "CycloneDX":
        return parse_cyclonedx(data), "cyclonedx", resource_name

    # SPDX 3.0: has "spdxVersion" starting with "SPDX-3"
    if data.get("spdxVersion", "").startswith("SPDX-3"):
        return parse_spdx(data), "spdx-3", resource_name

    # SPDX 2.x: has "spdxVersion" starting with "SPDX-2"
    if data.get("spdxVersion", "").startswith("SPDX-2"):
        return parse_spdx(data), "spdx-2", resource_name

    # agent-bom JSON report: has "ai_bom_version"
    if "ai_bom_version" in data or "blast_radius" in data:
        raise ValueError("That looks like an agent-bom report, not an SBOM. Use 'agent-bom diff' for report comparison.")

    raise ValueError(f"Unrecognised SBOM format in {path}. Expected CycloneDX JSON (bomFormat=CycloneDX) or SPDX 2.x/3.0 JSON.")
