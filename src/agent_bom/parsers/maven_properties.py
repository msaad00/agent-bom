"""Bounded local Maven parent/property evidence; never retrieves remote POMs."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import fromstring

from agent_bom.coverage import record_manifest_parse_warning
from agent_bom.parsers.file_limits import read_text_limited

_PROPERTY = re.compile(r"\$\{([^}]+)\}")


def read_pom(path: Path) -> ET.Element:
    return fromstring(read_text_limited(path))


def local_properties(path: Path, root: ET.Element, scan_root: Path, seen: frozenset[Path] = frozenset(), hops: int = 0) -> dict[str, str]:
    """Merge at most eight local parents, with child values taking precedence."""
    properties: dict[str, str] = {}
    ns = root.tag.partition("}")[0] + "}" if root.tag.startswith("{") else ""
    parent = root.find(f"{ns}parent")
    if parent is not None and hops < 8:
        rel = parent.find(f"{ns}relativePath")
        relative = "../pom.xml" if rel is None else (rel.text or "").strip()
        if relative:
            candidate = (path.parent / relative).resolve()
            if candidate.is_dir():
                candidate /= "pom.xml"
            if candidate.is_relative_to(scan_root) and candidate not in seen | {path.resolve()}:
                try:
                    parent_root = read_pom(candidate)
                    # A relative path is only applicable when supplied parent coordinates agree.
                    matches = all(
                        not (expected := parent.findtext(f"{ns}{key}"))
                        or expected.strip() == (parent_root.findtext(f"{ns}{key}") or "").strip()
                        for key in ("groupId", "artifactId", "version")
                    )
                    if matches:
                        properties.update(local_properties(candidate, parent_root, scan_root, seen | {path.resolve()}, hops + 1))
                except (OSError, ValueError, ET.ParseError, DefusedXmlException):
                    pass  # Unresolved dependency values below produce the coverage warning.
    own = root.find(f"{ns}properties")
    if own is not None:
        properties.update({child.tag.rsplit("}", 1)[-1]: (child.text or "").strip() for child in own})
    for key in ("groupId", "artifactId", "version"):
        value = root.findtext(f"{ns}{key}")
        if value:
            properties[f"project.{key}"] = value.strip()
            properties[f"pom.{key}"] = value.strip()
    return properties


def resolve_property(value: str, properties: dict[str, str], path: Path) -> str | None:
    """Resolve nested substitutions with an explicit cycle/expansion bound."""
    seen: set[str] = set()
    for _ in range(32):
        if "${" not in value:
            return value
        if value in seen:
            break
        seen.add(value)
        value = _PROPERTY.sub(lambda match: properties.get(match[1], match[0]), value)
        if len(value) > 16_384:
            break
    record_manifest_parse_warning(
        ecosystem="maven",
        path=str(path),
        detail="pom.xml contains unresolved dependency properties; Maven dependency coverage is partial",
    )
    return None


def dependency_coordinates(group: str, artifact: str, version: str, properties: dict[str, str], path: Path) -> tuple[str, str, str] | None:
    if not version:
        record_manifest_parse_warning(
            ecosystem="maven", path=str(path), detail="pom.xml dependency version is unresolved; Maven dependency coverage is partial"
        )
        return None
    values = [resolve_property(value, properties, path) for value in (group, artifact, version)]
    if any(not value for value in values):
        return None
    return str(values[0]), str(values[1]), str(values[2])
