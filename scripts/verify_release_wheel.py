#!/usr/bin/env python3
"""Reject release wheels that omit required schemas or dashboard assets."""

from __future__ import annotations

import json
import re
import sys
from email.parser import Parser
from pathlib import Path
from zipfile import BadZipFile, ZipFile

REQUIRED_FILES = (
    "agent_bom/cloud/benchmark_inventory.json",
    "agent_bom/data/inventory.schema.json",
    "agent_bom/data/mcp-intelligence.schema.json",
    "agent_bom/ui_dist/index.html",
    "agent_bom/ui_dist/csp-hashes.json",
)
CSP_MANIFEST = "agent_bom/ui_dist/csp-hashes.json"
INSTALL_PIN = re.compile(r"(?:agentbom/agent-bom(?:-api)?:v?|msaad00/agent-bom@v)([0-9]+\.[0-9]+\.[0-9]+)")


def verify_dashboard_install_pins(archive: ZipFile) -> None:
    """Compare compiled first-run commands with the wheel's own version."""
    metadata = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
    if len(metadata) != 1:
        raise ValueError("release wheel must contain exactly one package METADATA")
    version = Parser().parsestr(archive.read(metadata[0]).decode("utf-8")).get("Version")
    if not version:
        raise ValueError("release wheel METADATA must declare Version")
    for name in archive.namelist():
        if name.startswith("agent_bom/ui_dist/") and name.endswith((".js", ".html")):
            for pin in INSTALL_PIN.findall(archive.read(name).decode("utf-8")):
                if pin != version:
                    raise ValueError(f"dashboard install pin {pin} differs from wheel {version}: {name}")


def verify_wheel(wheel_path: Path) -> None:
    """Raise ``ValueError`` when a wheel lacks required release evidence."""
    try:
        with ZipFile(wheel_path) as archive:
            members = set(archive.namelist())
            missing = [path for path in REQUIRED_FILES if path not in members]
            if missing:
                raise ValueError(f"missing required file(s): {', '.join(missing)}")
            manifest = json.loads(archive.read(CSP_MANIFEST))
            verify_dashboard_install_pins(archive)
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
