"""The Docker MCP submission pin is owned by the release run, not by memory.

`integrations/docker-mcp-registry/server.yaml` builds the published server from
`source.commit`. That value is the commit a release tag points at, so it cannot
be written alongside the version bump, and it was carried for several releases
as a line in SUBMISSION.md asking a human to remember.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import yaml

ROOT = Path(__file__).resolve().parents[1]
SERVER_YAML = ROOT / "integrations" / "docker-mcp-registry" / "server.yaml"
SUBMISSION = ROOT / "integrations" / "docker-mcp-registry" / "SUBMISSION.md"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


def _load_script(name: str) -> ModuleType:
    path = ROOT / "scripts" / name
    mod_name = name.removesuffix(".py")
    spec = importlib.util.spec_from_file_location(mod_name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)
    return module


def test_shipped_pin_is_a_full_sha_reachable_in_this_repository() -> None:
    pin = _load_script("sync_docker_mcp_pin.py")
    current = pin.read_pin(SERVER_YAML.read_text(encoding="utf-8"))
    assert current is not None, "server.yaml lost its source.commit pin"
    assert re.fullmatch(r"[0-9a-f]{40}", current), f"source.commit must be a full SHA, not a prefix or a branch: {current!r}"
    # ``-c safe.directory=*`` so these read-only queries work when the repo is
    # checked out under a different UID than the process (git's dubious-ownership
    # guard otherwise makes cat-file exit 128 — indistinguishable from a missing
    # object — and blanks the is-shallow-repository probe below so its skip never
    # fires). This surfaced on the musl CI container's newer git. Reachability is
    # still enforced: a genuinely absent commit exits 1 and fails the assert.
    resolved = subprocess.run(
        ["git", "-c", "safe.directory=*", "cat-file", "-e", f"{current}^{{commit}}"],
        cwd=ROOT,
        capture_output=True,
    )
    shallow = subprocess.run(
        ["git", "-c", "safe.directory=*", "rev-parse", "--is-shallow-repository"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if shallow != "true":
        assert resolved.returncode == 0, f"source.commit {current} is not a commit in this repository"


def test_only_the_pin_under_source_is_rewritten() -> None:
    """A `commit:` key in another block must survive a pin write untouched."""
    pin = _load_script("sync_docker_mcp_pin.py")
    document = (
        "name: agent-bom\n"
        "provenance:\n"
        "  commit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "source:\n"
        "  project: https://example.invalid\n"
        "  commit: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "run:\n"
        "  commit: cccccccccccccccccccccccccccccccccccccccc\n"
    )
    assert pin.read_pin(document) == "b" * 40
    rewritten = pin.write_pin(document, "d" * 40)
    assert "  commit: " + "a" * 40 in rewritten
    assert "  commit: " + "c" * 40 in rewritten
    assert "  commit: " + "d" * 40 in rewritten
    assert "b" * 40 not in rewritten


def test_set_refuses_anything_short_of_a_full_sha() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "sync_docker_mcp_pin.py"), "--set", "cc4640f"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "full 40-character SHA" in result.stderr
    assert SERVER_YAML.read_text(encoding="utf-8").count("commit:") == 1


def test_the_release_run_owns_the_pin() -> None:
    """The job is what replaces the manual step; SUBMISSION.md must not re-add it."""
    workflow = yaml.safe_load(RELEASE_WORKFLOW.read_text(encoding="utf-8"))
    job = workflow["jobs"].get("docker-mcp-pin")
    assert job is not None, "the release run no longer syncs the pin — SUBMISSION.md promises it does"
    run_steps = "\n".join(step.get("run", "") for step in job["steps"])
    assert 'sync_docker_mcp_pin.py --set "${{ github.sha }}"' in run_steps, "the pin job no longer writes the tagged commit"
    assert job.get("continue-on-error") is True, "the pin job must not be able to fail a release whose artifacts are already published"

    submission = SUBMISSION.read_text(encoding="utf-8")
    update_section = submission.split("## Update process", 1)[1]
    first_step = update_section.split("2.", 1)[0]
    assert "updated for you" in first_step, "the update process reverted to asking a human to edit source.commit"
