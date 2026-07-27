#!/usr/bin/env python3
"""Reject release wheels that omit required schemas or dashboard assets."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from zipfile import BadZipFile, ZipFile

REQUIRED_FILES = (
    "agent_bom/data/inventory.schema.json",
    "agent_bom/data/mcp-intelligence.schema.json",
    "agent_bom/ui_dist/index.html",
    "agent_bom/ui_dist/csp-hashes.json",
)
CSP_MANIFEST = "agent_bom/ui_dist/csp-hashes.json"


def verify_wheel(wheel_path: Path) -> None:
    """Raise ``ValueError`` when a wheel lacks required release evidence."""
    try:
        with ZipFile(wheel_path) as archive:
            members = set(archive.namelist())
            missing = [path for path in REQUIRED_FILES if path not in members]
            if missing:
                raise ValueError(f"missing required file(s): {', '.join(missing)}")
            manifest = json.loads(archive.read(CSP_MANIFEST))
    except (BadZipFile, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid release wheel: {exc}") from exc

    if not isinstance(manifest, dict) or not isinstance(manifest.get("script_hashes"), list) or not manifest["script_hashes"]:
        raise ValueError(f"{CSP_MANIFEST} must contain a non-empty script_hashes list")


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    dist_dir = Path(args[0]) if args else Path("dist")
    wheels = sorted(dist_dir.glob("*.whl"))
    if not wheels:
        print(f"ERROR: no wheel found in {dist_dir}", file=sys.stderr)
        return 1

    for wheel in wheels:
        try:
            verify_wheel(wheel)
        except (OSError, ValueError) as exc:
            print(f"ERROR: {wheel.name}: {exc}", file=sys.stderr)
            return 1
        print(f"{wheel.name}: dashboard and CSP manifest verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
