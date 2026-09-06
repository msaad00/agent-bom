#!/usr/bin/env python3
"""Replay a real advisory's package-version boundary without installing packages."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agent_bom.parsers import scan_project_directory  # noqa: E402
from agent_bom.scanners.package_scan import default_scan_options, scan_packages  # noqa: E402

ADVISORY = "CVE-2023-4863"


async def _scan_manifest(version: str) -> dict[str, Any]:
    manifest = f"Pillow=={version}\n"
    with tempfile.TemporaryDirectory(prefix="agent-bom-package-replay-") as directory:
        project = Path(directory)
        (project / "requirements.txt").write_text(manifest, encoding="utf-8")
        discovered = scan_project_directory(project, max_depth=1)
        packages = [package for path in sorted(discovered, key=str) for package in discovered[path]]
        if len(packages) != 1 or packages[0].name.lower() != "pillow" or packages[0].version != version:
            raise RuntimeError("Package replay parser did not recover the exact input version")
        await scan_packages(
            packages,
            options=default_scan_options(offline=True, demo_advisories=True, project_dir=str(project)),
        )
    findings = sorted(vulnerability.id for vulnerability in packages[0].vulnerabilities)
    return {
        "package": f"pkg:pypi/pillow@{version}",
        "manifest_sha256": f"sha256:{hashlib.sha256(manifest.encode('utf-8')).hexdigest()}",
        "matched": ADVISORY in findings,
        "advisory_ids": findings,
    }


async def replay() -> dict[str, Any]:
    before = await _scan_manifest("9.0.0")
    after = await _scan_manifest("10.0.1")
    if not before["matched"] or after["matched"]:
        raise RuntimeError("Package replay did not reproduce the expected advisory boundary")
    return {
        "schema_version": "agent-bom.package-remediation-replay/v1",
        "advisory": ADVISORY,
        "upstream_reference": "https://pillow.readthedocs.io/en/stable/releasenotes/10.0.1.html",
        "coverage": "bundled_pinned_advisories_only",
        "parser": "agent_bom.parsers.scan_project_directory",
        "scanner": "agent_bom.scanners.package_scan.scan_packages",
        "before": before,
        "after": after,
        "package_installation": "not_performed",
        "exploit_execution": "not_performed",
        "deployed_remediation": "not_tested",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Write the JSON receipt to this file instead of stdout.")
    args = parser.parse_args()
    rendered = json.dumps(asyncio.run(replay()), indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
        print(f"Wrote package replay receipt: {args.output}")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
