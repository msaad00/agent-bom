#!/usr/bin/env python3
"""Fail closed when a required release surface loses its proof contract."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "docs" / "release" / "release-evidence-matrix.json"
REQUIRED_SURFACES = {
    "python",
    "dashboard",
    "docker_api",
    "docker_ui",
    "docker_collector",
    "helm_oci",
    "github_action",
    "mcp_metadata",
    "registries",
    "sbom",
    "signatures",
    "provenance",
    "live_demo",
}
VALID_PHASES = {"pre_publish", "post_publish", "pre_publish_and_post_publish"}
REQUIRED_MARKERS = {
    ".github/workflows/release.yml": (
        "name: Publish to PyPI",
        "name: Publish to Docker Hub",
        "name: Publish cloud-SDK collector image",
        "name: Publish UI image",
        "name: Publish Helm chart to OCI",
        "name: Generate CycloneDX SBOM",
        "name: Sign distribution with Sigstore",
        "name: Generate SLSA provenance",
        "name: Create GitHub Release",
    ),
    ".github/workflows/ci.yml": ("name: Dogfood GitHub Action",),
    ".github/workflows/demo-deploy-cloudrun.yml": ("name: Deploy hosted demo to Cloud Run",),
    "scripts/check_surface_freshness.py": ('"surface": "Glama"', '"surface": "Smithery"'),
}


def check() -> list[str]:
    errors: list[str] = []
    try:
        payload = json.loads(MATRIX.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"release evidence matrix is unavailable or invalid: {type(exc).__name__}"]
    if payload.get("schema_version") != "release-evidence-matrix.v1":
        errors.append("release evidence matrix schema_version must be release-evidence-matrix.v1")
    rows = payload.get("surfaces")
    if not isinstance(rows, list):
        return errors + ["release evidence matrix surfaces must be a list"]
    names = {row.get("surface") for row in rows if isinstance(row, dict)}
    if names != REQUIRED_SURFACES:
        missing = sorted(REQUIRED_SURFACES - names)
        extra = sorted(names - REQUIRED_SURFACES)
        errors.append(f"release evidence surfaces drifted: missing={missing} extra={extra}")
    for row in rows:
        if not isinstance(row, dict):
            errors.append("release evidence surface entries must be objects")
            continue
        surface = row.get("surface", "unknown")
        if row.get("phase") not in VALID_PHASES:
            errors.append(f"{surface}: invalid verification phase")
        if not str(row.get("verification", "")).strip():
            errors.append(f"{surface}: verification command or action is missing")
        paths = row.get("evidence_paths")
        if not isinstance(paths, list) or not paths:
            errors.append(f"{surface}: evidence_paths must be non-empty")
            continue
        for relative in paths:
            if not isinstance(relative, str) or not (ROOT / relative).is_file():
                errors.append(f"{surface}: missing evidence path {relative!r}")
    for relative, markers in REQUIRED_MARKERS.items():
        text = (ROOT / relative).read_text(encoding="utf-8")
        for marker in markers:
            if marker not in text:
                errors.append(f"{relative}: required release proof marker is missing: {marker}")
    return errors


def main() -> int:
    errors = check()
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("release evidence matrix: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
