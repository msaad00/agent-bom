#!/usr/bin/env python3
"""Render the README hero as a single GitHub-portable SVG."""

from __future__ import annotations

import copy
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs" / "images" / "social-preview.source.svg"
OUTPUT = ROOT / "docs" / "images" / "social-preview.svg"
SVG_NS = "http://www.w3.org/2000/svg"
SVG = f"{{{SVG_NS}}}"
ICON_COLORS = {
    "amazonwebservices": "#ff9900",
    "claude": "#d97757",
    "clickhouse": "#ffcc00",
    "cursor": "#f8fafc",
    "databricks": "#ff3621",
    "githubcopilot": "#f8fafc",
    "googlecloud": "#4285f4",
    "kubernetes": "#326ce5",
    "microsoftazure": "#0078d4",
    "okta": "#007dc1",
    "snowflake": "#29b5e8",
    "windsurf": "#f8fafc",
}

ET.register_namespace("", SVG_NS)


def _asset_path(source: Path, href: str) -> Path:
    if ":" in href or href.startswith(("/", "\\")):
        raise ValueError(f"social preview asset must be relative: {href}")
    asset = (source.parent / href).resolve()
    try:
        asset.relative_to(source.parent.resolve())
    except ValueError as exc:
        raise ValueError(f"social preview asset escapes its directory: {href}") from exc
    if not asset.is_file():
        raise FileNotFoundError(asset)
    return asset


def render(source: Path = SOURCE) -> str:
    """Inline referenced vectors as symbols and return deterministic SVG text."""
    tree = ET.parse(source)
    root = tree.getroot()
    defs = root.find(f"{SVG}defs")
    if defs is None:
        raise ValueError("social preview must contain a defs element")

    symbols: dict[Path, str] = {}
    images = list(root.iter(f"{SVG}image"))
    parents = {child: parent for parent in root.iter() for child in parent}
    for image in images:
        href = image.attrib.get("href", "")
        asset = _asset_path(source, href)
        symbol_id = symbols.get(asset)
        if symbol_id is None:
            symbol_id = f"embedded-{asset.stem}"
            symbols[asset] = symbol_id
            asset_root = ET.parse(asset).getroot()
            symbol = ET.Element(
                f"{SVG}symbol",
                {"id": symbol_id, "viewBox": asset_root.attrib.get("viewBox", "0 0 24 24")},
            )
            for name in ("fill", "stroke", "color"):
                if name in asset_root.attrib:
                    symbol.set(name, asset_root.attrib[name])
            for child in asset_root:
                symbol.append(copy.deepcopy(child))
            if color := ICON_COLORS.get(asset.stem):
                symbol.set("fill", color)
                for element in symbol.iter():
                    if "fill" in element.attrib:
                        element.set("fill", color)
            defs.append(symbol)

        use = ET.Element(
            f"{SVG}use",
            {key: value for key, value in image.attrib.items() if key not in {"href", "filter"}},
        )
        use.set("href", f"#{symbol_id}")
        use.tail = image.tail
        parent = parents[image]
        parent.insert(list(parent).index(image), use)
        parent.remove(image)

    if not images:
        raise ValueError("social preview source must reference at least one vector asset")
    for element in list(defs):
        if element.tag == f"{SVG}filter" and element.attrib.get("id", "").startswith("tint-"):
            defs.remove(element)
    ET.indent(tree, space="  ")
    return ET.tostring(root, encoding="unicode") + "\n"


def main() -> int:
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else OUTPUT
    output.write_text(render(), encoding="utf-8")
    print(f"Rendered portable social preview: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
