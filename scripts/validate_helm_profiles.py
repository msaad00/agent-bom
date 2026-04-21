#!/usr/bin/env python3
"""Render the shipped Helm example profiles to catch deployment drift early."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_profile_helpers():
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from agent_bom.deploy_profiles import helm_chart_dir, helm_validation_profiles

    return helm_chart_dir, helm_validation_profiles


def _run(cmd: list[str]) -> None:
    print("+", " ".join(cmd))
    subprocess.run(cmd, check=True)


def main() -> int:
    helm_chart_dir, helm_validation_profiles = _load_profile_helpers()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile",
        action="append",
        dest="profiles",
        help="Only validate the named profile. Repeat to run multiple profiles.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List the available validation profiles and exit.",
    )
    args = parser.parse_args()

    profiles = helm_validation_profiles(REPO_ROOT)
    if args.list:
        for profile in profiles:
            print(f"{profile.name}: {profile.description}")
        return 0

    if shutil.which("helm") is None:
        print("error: helm is required to validate chart profiles", file=sys.stderr)
        return 1

    selected = profiles
    if args.profiles:
        requested = set(args.profiles)
        selected = [profile for profile in profiles if profile.name in requested]
        missing = sorted(requested - {profile.name for profile in selected})
        if missing:
            parser.error(f"unknown profile(s): {', '.join(missing)}")

    chart_dir = helm_chart_dir(REPO_ROOT)
    _run(["helm", "lint", str(chart_dir)])
    for profile in selected:
        cmd = ["helm", "template", f"agent-bom-{profile.name}", str(chart_dir)]
        for values_file in profile.values_files:
            cmd.extend(["-f", str(values_file)])
        for set_argument in profile.set_arguments:
            cmd.extend(["--set", set_argument])
        for key, path in profile.set_file_arguments:
            cmd.extend(["--set-file", f"{key}={path}"])
        _run(cmd)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
