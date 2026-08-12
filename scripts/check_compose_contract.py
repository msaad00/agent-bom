#!/usr/bin/env python3
"""Validate every shipped Docker Compose file — and what it renders to.

Nothing in CI has ever run ``docker compose config`` against these files. The
only caller in the tree is ``scripts/deploy/hosted_poc_preflight.py``, and the
one automated invocation of that (``make secrets``) passes ``--skip-compose``,
so the parse path never executes. Meanwhile ``docs/DEPLOY_PLATFORM.md`` tells
operators the stack "passes ``docker compose config``" — a claim no automation
backed.

Two things are checked, deliberately in this order:

1. ``docker compose config`` parses each standalone file, and each documented
   overlay merged onto its base. Overlays are shipped as fragments and fail
   standalone by design, so validating them alone would be meaningless.

2. Assertions on the RENDERED output. "It exited 0" is not a test — this repo
   already learned that when ``helm template`` rendered an ingress with empty
   ``paths`` across five profiles and CI called it green. So the rendered model
   is inspected: every service resolves to an image or a build context, every
   ``depends_on`` names a real service, and every read-only bind mount points at
   a path that exists. A ``:ro`` mount of a missing directory does not fail
   ``config`` or even ``up`` — Docker silently creates an empty directory and
   the container gets nothing.

Environment interpolation is derived from the files themselves: a variable
written ``${VAR:?message}`` is required by design, so the gate supplies a
placeholder rather than pretending the file is broken.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent

# Discovered structurally, so a newly added profile is covered on arrival.
COMPOSE_GLOBS = (
    "deploy/docker-compose*.yml",
    "deploy/**/docker-compose*.yml",
    "examples/docker-compose*.yml",
    "compose.yml",
    "compose.yaml",
)

# Overlays carry no image or build of their own and cannot declare their base,
# so the pairing has to live here. Any overlay NOT listed fails the gate rather
# than being skipped.
OVERLAY_BASES: dict[str, tuple[str, ...]] = {
    "deploy/docker-compose.hosted-poc.yml": ("deploy/docker-compose.platform.yml",),
    "deploy/docker-compose.product.yml": ("deploy/docker-compose.platform.yml",),
    "deploy/docker-compose.demo-override.yml": ("deploy/docker-compose.platform.yml",),
}

# Bind-mount sources that are generated rather than committed. `make secrets`
# writes these; `deploy/secrets/.gitignore` keeps them out of the tree.
GENERATED_MOUNT_PREFIXES = ("secrets/",)

_REQUIRED_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\s*:\?")
_PLACEHOLDER = "ci-compose-contract-placeholder"


@dataclass
class Target:
    """One `docker compose` invocation: a base file plus any overlays."""

    files: list[Path]
    label: str
    problems: list[str] = field(default_factory=list)


def discover() -> tuple[list[Path], list[Path]]:
    """Return ``(standalone files, overlay files)``."""
    seen: dict[Path, None] = {}
    for glob in COMPOSE_GLOBS:
        for path in sorted(ROOT.glob(glob)):
            if path.is_file():
                seen[path] = None
    standalone: list[Path] = []
    overlays: list[Path] = []
    for path in seen:
        (overlays if _is_overlay(path) else standalone).append(path)
    return standalone, overlays


def _is_overlay(path: Path) -> bool:
    """An overlay patches services it does not define — no image, no build."""
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    services = document.get("services") or {}
    if not services:
        return False
    return all(not (service or {}).get("image") and not (service or {}).get("build") for service in services.values())


def _env_for(files: list[Path]) -> dict[str, str]:
    env = dict(os.environ)
    for path in files:
        for name in _REQUIRED_VAR.findall(path.read_text(encoding="utf-8")):
            env.setdefault(name, _PLACEHOLDER)
    return env


def _render(target: Target) -> dict | None:
    command = ["docker", "compose"]
    for path in target.files:
        command += ["-f", str(path)]
    command += ["config", "--format", "json"]
    result = subprocess.run(
        command,
        cwd=target.files[0].parent,
        env=_env_for(target.files),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        target.problems.append(f"docker compose config failed:\n      {(result.stderr or result.stdout).strip()}")
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        target.problems.append(f"docker compose config emitted invalid JSON: {exc}")
        return None


def _assert_rendered(target: Target, rendered: dict) -> None:
    services = rendered.get("services") or {}
    if not services:
        target.problems.append("renders no services")
        return
    for name, service in services.items():
        if not service.get("image") and not service.get("build"):
            target.problems.append(f"service {name!r} resolves to neither an image nor a build context")
        for dependency in service.get("depends_on") or {}:
            if dependency not in services:
                target.problems.append(f"service {name!r} depends_on {dependency!r}, which no service defines")
        for volume in service.get("volumes") or []:
            _assert_readonly_mount(target, name, volume)


def _assert_readonly_mount(target: Target, service: str, volume: dict) -> None:
    """A `:ro` bind mount of a missing path yields an empty directory, silently."""
    if volume.get("type") != "bind" or not volume.get("read_only"):
        return
    source = str(volume.get("source") or "")
    if not source.startswith("/"):
        return
    try:
        relative = Path(source).relative_to(ROOT).as_posix()
    except ValueError:
        return  # outside the repo (a host home directory) — not ours to assert
    if relative.startswith(GENERATED_MOUNT_PREFIXES) or any(part in relative for part in GENERATED_MOUNT_PREFIXES):
        return
    if not Path(source).exists():
        target.problems.append(f"service {service!r} read-only bind mount points at a missing path: {relative}")


def build_targets() -> list[Target]:
    standalone, overlays = discover()
    targets = [Target(files=[path], label=path.relative_to(ROOT).as_posix()) for path in standalone]
    for overlay in overlays:
        relative = overlay.relative_to(ROOT).as_posix()
        bases = OVERLAY_BASES.get(relative)
        if not bases:
            target = Target(files=[overlay], label=relative)
            target.problems.append("overlay has no declared base in OVERLAY_BASES — it can never be validated")
            targets.append(target)
            continue
        files = [ROOT / base for base in bases] + [overlay]
        targets.append(Target(files=files, label=" + ".join([*bases, relative])))
    return targets


def run() -> list[Target]:
    targets = build_targets()
    for target in targets:
        if target.problems:
            continue
        rendered = _render(target)
        if rendered is not None:
            _assert_rendered(target, rendered)
    return targets


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="List the compose invocations this gate validates.")
    args = parser.parse_args(argv)

    if args.list:
        for target in build_targets():
            print(target.label)
        return 0

    targets = run()
    failed = [target for target in targets if target.problems]
    if failed:
        print(f"ERROR: {len(failed)} compose target(s) failed the contract:\n", file=sys.stderr)
        for target in failed:
            for problem in target.problems:
                print(f"  - {target.label}: {problem}", file=sys.stderr)
        return 1

    print(f"Compose contract passed — {len(targets)} target(s) parse and render a valid service graph")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
