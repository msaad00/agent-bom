#!/usr/bin/env python3
"""Generate CSP hashes for inline blocks in the bundled dashboard export."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from html.parser import HTMLParser
from pathlib import Path


class _InlineBlockParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self._capture: str | None = None
        self._parts: list[str] = []
        self.scripts: list[str] = []
        self.styles: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_by_name = {name.lower(): value for name, value in attrs}
        if tag.lower() == "script" and "src" not in attrs_by_name:
            self._capture = "script"
            self._parts = []
        elif tag.lower() == "style":
            self._capture = "style"
            self._parts = []

    def handle_data(self, data: str) -> None:
        if self._capture:
            self._parts.append(data)

    def handle_entityref(self, name: str) -> None:
        if self._capture:
            self._parts.append(f"&{name};")

    def handle_charref(self, name: str) -> None:
        if self._capture:
            self._parts.append(f"&#{name};")

    def handle_endtag(self, tag: str) -> None:
        capture = self._capture
        if capture and tag.lower() == capture:
            value = "".join(self._parts)
            if value.strip():
                if capture == "script":
                    self.scripts.append(value)
                else:
                    self.styles.append(value)
            self._capture = None
            self._parts = []


def _hash_block(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    return "sha256-" + base64.b64encode(digest).decode("ascii")


def generate_hash_manifest(ui_dist: Path) -> dict[str, object]:
    script_hashes: set[str] = set()
    style_hashes: set[str] = set()
    html_files = sorted(ui_dist.rglob("*.html"))
    for html_file in html_files:
        parser = _InlineBlockParser()
        parser.feed(html_file.read_text(encoding="utf-8"))
        script_hashes.update(_hash_block(value) for value in parser.scripts)
        style_hashes.update(_hash_block(value) for value in parser.styles)
    return {
        "version": 1,
        "html_file_count": len(html_files),
        "script_hashes": sorted(script_hashes),
        "style_hashes": sorted(style_hashes),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ui_dist", type=Path, help="Path to src/agent_bom/ui_dist")
    args = parser.parse_args()
    ui_dist = args.ui_dist
    if not ui_dist.is_dir():
        raise SystemExit(f"UI dist directory not found: {ui_dist}")
    manifest = generate_hash_manifest(ui_dist)
    output = ui_dist / "csp-hashes.json"
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {output} ({len(manifest['script_hashes'])} script hashes, {len(manifest['style_hashes'])} style hashes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
