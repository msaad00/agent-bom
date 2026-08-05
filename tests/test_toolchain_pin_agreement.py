"""Every gate that runs ruff must run the same ruff.

Three sources pinned it independently — ``uv.lock`` (what CI resolves),
``.pre-commit-config.yaml`` (what a contributor's commit hook runs), and the
``pyproject.toml`` dev extra floor. They disagreed: 0.16.1, 0.9.7, and
``>=0.4``. The lint *rules* happened to agree across that range, so nothing
went red; the *formatter* style did not, which meant the committed tree was
formatted to 0.9.7 while CI resolved a version that would reformat ~240 files.
Nothing compared the two, so the divergence was invisible.
"""

from __future__ import annotations

import re
import subprocess
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _locked_ruff_version() -> str:
    lock = (ROOT / "uv.lock").read_text(encoding="utf-8")
    match = re.search(r'\[\[package\]\]\nname = "ruff"\nversion = "([^"]+)"', lock)
    assert match, "uv.lock does not pin ruff"
    return match.group(1)


def _pre_commit_ruff_revision() -> str:
    config = yaml.safe_load((ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8"))
    repos = [repo for repo in config["repos"] if "ruff-pre-commit" in repo["repo"]]
    assert len(repos) == 1, "expected exactly one ruff-pre-commit hook repo"
    return str(repos[0]["rev"])


def _dev_extra_ruff_specifier() -> str:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dev = pyproject["project"]["optional-dependencies"]["dev"]
    requirement = next(item for item in dev if item.split(">")[0].split("=")[0].strip() == "ruff")
    return requirement


def test_pre_commit_hook_runs_the_locked_ruff() -> None:
    """A commit hook formatting to a different target than CI is worse than none."""
    assert _pre_commit_ruff_revision() == f"v{_locked_ruff_version()}"


def test_dev_extra_floor_cannot_resolve_behind_the_lock() -> None:
    """``ruff>=0.4`` let a contributor install a formatter generations behind."""
    locked = _locked_ruff_version()
    assert _dev_extra_ruff_specifier() == f"ruff>={locked}"


def test_ci_checks_formatting_from_the_shared_path_list() -> None:
    """Without a format gate the pins can drift again and nothing notices."""
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "format-check:" in makefile
    assert "ruff format --check $(LINT_PATHS)" in makefile

    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["lint"]["steps"]
    step = next(candidate for candidate in steps if candidate.get("name") == "Ruff format")
    assert "make format-check" in step["run"]


def test_blame_ignore_list_holds_only_resolvable_full_shas() -> None:
    """A bogus entry here is silent — git skips nothing and says nothing.

    The list is allowed to be empty: this repository squash-merges, so a
    reformat's final SHA does not exist until its pull request lands, and an
    entry written before the squash names a commit that is already gone. What
    must never happen is an abbreviation (git errors out) or a SHA that does not
    resolve (git skips nothing, silently).
    """
    revs = ROOT / ".git-blame-ignore-revs"
    assert revs.is_file(), "a tree-wide reformat needs a blame-ignore list"
    shas = [line.split("#", 1)[0].strip() for line in revs.read_text(encoding="utf-8").splitlines() if line.split("#", 1)[0].strip()]
    for sha in shas:
        assert re.fullmatch(r"[0-9a-f]{40}", sha), f"not a full SHA: {sha!r}"
        resolved = subprocess.run(
            ["git", "cat-file", "-t", sha],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        assert resolved.stdout.strip() == "commit", f"{sha} does not resolve to a commit in this repository"
