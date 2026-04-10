#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

_DRIVE_RE = re.compile(r"^[A-Za-z]:[/\\]")


def _bad_package_key(key: str) -> bool:
    if key == "":
        return False
    if key.startswith("node_modules/"):
        return False
    if key.startswith(("/", "\\")):
        return True
    if key.startswith("../") or "/../" in key or "\\..\\" in key:
        return True
    if _DRIVE_RE.match(key):
        return True
    return True


def validate_lockfile(path: Path) -> list[str]:
    data = json.loads(path.read_text())
    packages = data.get("packages", {})
    errors: list[str] = []
    if not isinstance(packages, dict):
        return [f"{path}: expected top-level 'packages' object"]
    for key in packages:
        if not isinstance(key, str):
            errors.append(f"{path}: non-string package key: {key!r}")
            continue
        if _bad_package_key(key):
            errors.append(f"{path}: non-portable package key: {key}")
    return errors


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: check_npm_lockfile.py <package-lock.json> [...]", file=sys.stderr)
        return 2

    errors: list[str] = []
    for raw in argv[1:]:
        path = Path(raw)
        errors.extend(validate_lockfile(path))

    if errors:
        print("npm lockfile validation failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print("npm lockfile validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
