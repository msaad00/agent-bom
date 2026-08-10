"""The release pre-flight must refuse a version that has already shipped.

`scripts/preflight_release.sh 0.99.0` printed **"Pre-flight OK — safe to tag"**
on 2026-08-10, when `v0.99.0` had been tagged on 2026-08-05 and was already
live on PyPI, Docker Hub and Glama, with 24 further commits on `main`.

Every gate it runs was green and every one of them answers a different
question: *are the managed files consistent with the version string I was
handed?* Nothing asked the only question that distinguishes a release from a
re-release — *does this tag already exist?* The script's own header comment
records the previous instance of this class (a missing VERSION used to skip the
bump check and still print a green verdict), which is why the check belongs in
the script positioned as the go/no-go rather than in a reviewer's memory.

The CHANGELOG assertion is here for the same reason: `release.yml`'s
version-guard requires a `## [<version>]` heading, so a tag pushed without one
fails *in CI, after the tag exists* — the expensive place to find out.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_release_tag_is_new.py"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A throwaway repo with one commit and a CHANGELOG."""
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "Test")
    (tmp_path / "CHANGELOG.md").write_text("# Changelog\n\n## [Unreleased]\n\n## [0.99.0] - 2026-08-05\n\nShipped.\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "initial")
    return tmp_path


def run(repo: Path, version: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), version],
        cwd=repo,
        capture_output=True,
        text=True,
    )


def test_an_already_tagged_version_is_refused(repo: Path) -> None:
    """The defect: 0.99.0 was tagged, published, and still called safe to tag."""
    _git(repo, "tag", "-a", "v0.99.0", "-m", "release")
    result = run(repo, "0.99.0")
    assert result.returncode != 0, result.stdout
    assert "already" in (result.stdout + result.stderr).lower()


def test_a_new_version_is_allowed(repo: Path) -> None:
    (repo / "CHANGELOG.md").write_text("# Changelog\n\n## [0.99.1] - 2026-08-10\n\nFixes.\n\n## [0.99.0] - 2026-08-05\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "changelog")
    _git(repo, "tag", "-a", "v0.99.0", "-m", "release")
    result = run(repo, "0.99.1")
    assert result.returncode == 0, result.stdout + result.stderr


def test_a_version_with_no_changelog_entry_is_refused(repo: Path) -> None:
    """`release.yml`'s version-guard requires the heading; fail before the tag."""
    _git(repo, "tag", "-a", "v0.99.0", "-m", "release")
    result = run(repo, "0.99.1")
    assert result.returncode != 0, result.stdout
    assert "changelog" in (result.stdout + result.stderr).lower()


def test_the_lightweight_tag_form_is_caught_too(repo: Path) -> None:
    """A tag is a tag; the annotated/lightweight distinction must not matter."""
    _git(repo, "tag", "v0.99.0")
    result = run(repo, "0.99.0")
    assert result.returncode != 0, result.stdout


def test_a_v_prefixed_argument_is_accepted(repo: Path) -> None:
    """`0.99.0` and `v0.99.0` name the same release; both must be refused."""
    _git(repo, "tag", "-a", "v0.99.0", "-m", "release")
    result = run(repo, "v0.99.0")
    assert result.returncode != 0, result.stdout


def test_it_reports_how_far_main_has_moved_past_the_last_tag(repo: Path) -> None:
    """A reviewer needs the drift, not just a verdict: 24 commits was the signal."""
    _git(repo, "tag", "-a", "v0.99.0", "-m", "release")
    (repo / "CHANGELOG.md").write_text("# Changelog\n\n## [0.99.1] - 2026-08-10\n\nFixes.\n\n## [0.99.0] - 2026-08-05\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "later work")
    result = run(repo, "0.99.1")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 commit" in result.stdout, result.stdout


def test_the_real_repo_refuses_the_version_that_already_shipped() -> None:
    """The regression itself, against this repository rather than a fixture."""
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([sys.executable, str(SCRIPT), "0.99.0"], cwd=root, capture_output=True, text=True)
    assert result.returncode != 0, result.stdout
