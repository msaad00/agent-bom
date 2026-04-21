#!/usr/bin/env python3
"""Install or print a shipped Helm deployment profile."""

from __future__ import annotations

import argparse
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_profile_helpers():
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from agent_bom.deploy_profiles import build_helm_profile_command, helm_validation_profiles

    return build_helm_profile_command, helm_validation_profiles


def _run(cmd: list[str]) -> None:
    print("+", shlex.join(cmd))
    subprocess.run(cmd, check=True)


def main() -> int:
    build_helm_profile_command, helm_validation_profiles = _load_profile_helpers()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", nargs="?", help="Shipped profile name to install.")
    parser.add_argument("--list", action="store_true", help="List the available shipped profiles and exit.")
    parser.add_argument("--release", default="agent-bom", help="Helm release name (default: agent-bom).")
    parser.add_argument("--namespace", default="agent-bom", help="Kubernetes namespace (default: agent-bom).")
    parser.add_argument(
        "--set",
        dest="set_arguments",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Additional Helm --set argument. Repeat as needed.",
    )
    parser.add_argument(
        "--values",
        dest="values_files",
        action="append",
        default=[],
        metavar="PATH",
        help="Additional values file to append after the shipped profile values.",
    )
    parser.add_argument(
        "--set-file",
        dest="set_file_arguments",
        action="append",
        default=[],
        metavar="KEY=PATH",
        help="Additional Helm --set-file argument. Repeat as needed.",
    )
    parser.add_argument(
        "--no-create-namespace",
        action="store_true",
        help="Skip --create-namespace in the generated Helm command.",
    )
    parser.add_argument(
        "--print-command",
        action="store_true",
        help="Print the resolved Helm command and exit without running it.",
    )
    args = parser.parse_args()

    profiles = helm_validation_profiles(REPO_ROOT)
    if args.list:
        for profile in profiles:
            print(f"{profile.name}: {profile.description}")
        return 0

    if not args.profile:
        parser.error("a profile name is required unless --list is used")

    extra_values_files = tuple(Path(path).resolve() for path in args.values_files)
    extra_set_file_arguments: list[tuple[str, Path]] = []
    for raw in args.set_file_arguments:
        key, sep, value = raw.partition("=")
        if not sep or not key or not value:
            parser.error(f"invalid --set-file value '{raw}', expected KEY=PATH")
        extra_set_file_arguments.append((key, Path(value).resolve()))

    try:
        cmd = build_helm_profile_command(
            REPO_ROOT,
            args.profile,
            release_name=args.release,
            namespace=args.namespace,
            create_namespace=not args.no_create_namespace,
            extra_values_files=extra_values_files,
            extra_set_arguments=tuple(args.set_arguments),
            extra_set_file_arguments=tuple(extra_set_file_arguments),
        )
    except KeyError as exc:
        parser.error(str(exc))

    if args.print_command:
        print(shlex.join(cmd))
        return 0

    if shutil.which("helm") is None:
        print("error: helm is required to install shipped profiles", file=sys.stderr)
        return 1
    _run(cmd)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
