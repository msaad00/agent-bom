"""Mode-specific scan command setup."""

from __future__ import annotations

import importlib.metadata
import json
import os
import sys
import tempfile
from typing import Optional

import click

from agent_bom.cli.agents._self_scan import _build_self_scan_inventory


def apply_self_scan_mode(*, self_scan: bool, inventory: Optional[str], enrich: bool) -> tuple[Optional[str], bool]:
    """Materialize a self-scan inventory file when requested."""
    if not self_scan:
        return inventory, enrich

    try:
        self_inventory = _build_self_scan_inventory()
    except importlib.metadata.PackageNotFoundError:
        click.echo("Error: agent-bom package not found. Install it first.", err=True)
        sys.exit(2)

    fd, path = tempfile.mkstemp(suffix=".json", prefix="agent-bom-self-scan-")
    with os.fdopen(fd, "w") as out:
        json.dump(self_inventory, out)
    return path, True


def apply_demo_mode(
    *,
    demo: bool,
    project: Optional[str],
    inventory: Optional[str],
    enrich: bool,
    compliance: bool,
    iac_paths: tuple,
) -> tuple[Optional[str], Optional[str], bool, bool, tuple]:
    """Materialize the curated demo inventory and skip ambient discovery."""
    if not demo:
        return project, inventory, enrich, compliance, iac_paths

    from agent_bom.demo import DEMO_INVENTORY

    fd, path = tempfile.mkstemp(suffix=".json", prefix="agent-bom-demo-")
    with os.fdopen(fd, "w") as out:
        json.dump(DEMO_INVENTORY, out)

    inventory = path
    enrich = True
    compliance = True
    if not project:
        project = tempfile.mkdtemp(prefix="agent-bom-demo-dir-")
    for agent_data in DEMO_INVENTORY.get("agents", []):
        agent_data.setdefault("config_path", f"~/.config/{agent_data.get('agent_type', 'agent')}/config.json")

    # Disable IaC auto-detection: point iac_paths at the empty demo project so
    # the later "if not iac_paths" detection branch does not run.
    iac_paths = (project,)
    return project, inventory, enrich, compliance, iac_paths


def validate_skill_mode(*, no_skill: bool, skill_only: bool) -> None:
    """Reject mutually exclusive skill discovery flags."""
    if no_skill and skill_only:
        click.echo("Error: --no-skill and --skill-only are mutually exclusive.", err=True)
        sys.exit(2)
