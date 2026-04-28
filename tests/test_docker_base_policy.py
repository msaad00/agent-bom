"""Unit tests for scripts/check_docker_base_policy.py.

The script is the CI gate for issue #1961 — it asserts that every Dockerfile
in the repo references the base image and tag the policy table allows, and
that the FROM line is digest-pinned (or carries the temporary
``# pending-digest`` marker dependabot will resolve within a day).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_docker_base_policy.py"


def _load_script():
    name = "check_docker_base_policy"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_repo_state_passes_policy() -> None:
    # The committed repo must satisfy the policy on every push so the
    # error path of the script never lands silently.
    script = _load_script()
    assert script.main() == 0


def test_split_image_extracts_repo_tag_digest() -> None:
    script = _load_script()
    repo, tag, digest = script._split_image("python:3.14.3-alpine3.23@sha256:" + "a" * 64)
    assert repo == "python"
    assert tag == "3.14.3-alpine3.23"
    assert digest == "sha256:" + "a" * 64


def test_split_image_handles_registry_path_no_tag() -> None:
    script = _load_script()
    repo, tag, digest = script._split_image("gcr.io/oss-fuzz-base/base-builder-python@sha256:" + "b" * 64)
    assert repo == "gcr.io/oss-fuzz-base/base-builder-python"
    assert tag is None
    assert digest == "sha256:" + "b" * 64


def test_pending_digest_marker_is_recognized(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Synthesize a tiny repo where one Dockerfile uses the marker and one
    # does not, then run the script with ROOT pointed at the synthetic tree.
    script = _load_script()

    repo = tmp_path
    (repo / "scripts").mkdir()
    (repo / "Dockerfile").write_text(
        "# pending-digest\nFROM python:3.14.3-alpine3.23\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(script, "ROOT", repo)
    monkeypatch.setattr(
        script,
        "POLICY",
        {
            "Dockerfile": script.BasePolicy(
                image="python",
                expected_tags=("3.14.3-alpine3.23",),
                rationale="synthetic test fixture",
            )
        },
    )

    assert script.main() == 0


def test_pending_digest_in_shallow_checkout_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Regression: when the file IS git-tracked but `git blame` returns no
    timestamp (shallow checkout drops history), the gate must fail closed.

    Before this regression test, the gate skipped the age check entirely
    in that case — which let stale `# pending-digest` markers pass CI
    silently while a deeper checkout running the test locally caught the
    real violation. See `.github/workflows/ci.yml` (Lint and Type Check
    job sets `fetch-depth: 0` on the checkout step that runs this script).
    """
    script = _load_script()

    repo = tmp_path
    (repo / "scripts").mkdir()
    (repo / "Dockerfile").write_text(
        "# pending-digest\nFROM python:3.14.3-alpine3.23\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(script, "ROOT", repo)
    monkeypatch.setattr(
        script,
        "POLICY",
        {
            "Dockerfile": script.BasePolicy(
                image="python",
                expected_tags=("3.14.3-alpine3.23",),
                rationale="synthetic test fixture",
            )
        },
    )
    # Force the "tracked but blame returns nothing" condition.
    monkeypatch.setattr(script, "_is_git_tracked_in_repo", lambda _: True)
    monkeypatch.setattr(script, "_git_blame_commit_timestamp", lambda *_: None)

    assert script.main() == 1
    err = capsys.readouterr().err
    assert "fetch-depth: 0" in err
    assert "shallow checkout" in err


def test_missing_digest_without_marker_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    script = _load_script()
    repo = tmp_path
    (repo / "scripts").mkdir()
    (repo / "Dockerfile").write_text("FROM python:3.14.3-alpine3.23\n", encoding="utf-8")

    monkeypatch.setattr(script, "ROOT", repo)
    monkeypatch.setattr(
        script,
        "POLICY",
        {
            "Dockerfile": script.BasePolicy(
                image="python",
                expected_tags=("3.14.3-alpine3.23",),
                rationale="synthetic test fixture",
            )
        },
    )

    assert script.main() == 1
    captured = capsys.readouterr()
    assert "not digest-pinned" in captured.err


def test_unknown_dockerfile_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    script = _load_script()
    repo = tmp_path
    (repo / "scripts").mkdir()
    (repo / "Dockerfile.surprise").write_text(
        "FROM python:3.14.3-alpine3.23@sha256:" + "c" * 64 + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(script, "ROOT", repo)
    monkeypatch.setattr(script, "POLICY", {})

    assert script.main() == 1
    captured = capsys.readouterr()
    assert "no entry in scripts/check_docker_base_policy.py POLICY" in captured.err
