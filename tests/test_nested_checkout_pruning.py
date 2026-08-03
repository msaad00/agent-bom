"""No project scanner may descend into a nested checkout.

A ``git worktree add`` checkout (as Cursor/Claude/Codex agent tooling creates)
is a full second copy of the repository living inside it. Any scanner that
walks into one re-reports the whole project a second time, so counts inflate
and the duplicate findings look like real ones.

``traversal.is_nested_worktree_root`` identifies these by the ``.git`` pointer
*file* a linked worktree carries, which a primary checkout never has. Every
entry point below walks a user-supplied project root and must honour it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

BAIT = "nested-worktree-bait"


def _project_with_nested_checkout(tmp_path: Path, nest: str) -> Path:
    """A project whose real content is duplicated inside a nested worktree."""
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / ".git").mkdir()
    _populate(root / "src", "primary")

    worktree = root / nest
    worktree.mkdir(parents=True)
    (worktree / ".git").write_text("gitdir: /somewhere/.git/worktrees/wt\n")
    (worktree / "src").mkdir()
    _populate(worktree / "src", BAIT)
    return root


def _populate(directory: Path, marker: str) -> None:
    (directory / "requirements.txt").write_text("requests==2.20.0\n")
    (directory / "package.json").write_text(json.dumps({"name": marker, "version": "1.0.0", "dependencies": {"lodash": "4.17.11"}}))
    (directory / "main.tf").write_text('resource "aws_s3_bucket" "b" {\n  bucket = "x"\n  acl    = "public-read"\n}\n')
    (directory / "crypto_util.py").write_text("import hashlib\n\ndef h(v):\n    return hashlib.md5(v).hexdigest()\n")
    (directory / "LICENSE").write_text("MIT License\n")


@pytest.fixture(params=[".cursor/worktrees/wt", "vendored/checkout"])
def project(request: pytest.FixtureRequest, tmp_path: Path) -> Path:
    """Nested checkouts, hidden and plainly named — neither may be walked."""
    return _project_with_nested_checkout(tmp_path, request.param)


def test_manifest_discovery_skips_nested_checkout(project: Path) -> None:
    from agent_bom.parsers import scan_project_directory

    found = scan_project_directory(project)

    walked = {str(directory) for directory in found}
    assert not any(BAIT in str(p) or "worktrees" in p or "checkout" in p for p in walked), walked
    assert len(found) == 1, f"the project's manifests were counted more than once: {walked}"


def test_weak_crypto_scan_skips_nested_checkout(project: Path) -> None:
    from agent_bom.api.repo_tree_scan import _scan_weak_crypto

    result = _scan_weak_crypto(project)

    assert result.total == 1, f"md5 use counted once per checkout: {result.to_dict()}"


def test_iac_scan_skips_nested_checkout(project: Path) -> None:
    from agent_bom.iac import scan_iac_directory

    findings = scan_iac_directory(project)

    paths = {str(getattr(f, "file_path", "")) for f in findings}
    assert not any("worktrees" in p or "checkout" in p for p in paths), paths


def test_license_scan_skips_nested_checkout(project: Path) -> None:
    from agent_bom.license_file_scanner import scan_directory

    result = scan_directory(project)

    blob = json.dumps(result, default=str)
    assert "worktrees" not in blob and "checkout" not in blob


def test_ai_component_scan_skips_nested_checkout(project: Path) -> None:
    from agent_bom.ai_components.scanner import scan_source

    report = scan_source(project)

    blob = json.dumps(report, default=str)
    assert "worktrees" not in blob and "checkout" not in blob
