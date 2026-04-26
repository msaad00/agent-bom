from __future__ import annotations

from pathlib import Path

from scripts.check_duplicate_artifacts import find_duplicate_artifacts, main


def test_duplicate_artifact_guard_detects_finder_copies() -> None:
    paths = [
        "src/agent_bom/model_advisories.py",
        "src/agent_bom/model_advisories 2.py",
        "contracts/v1/scan.schema.json",
        "contracts/v1 2/scan.schema.json",
        "tests/test_cloud_resilience 3.py",
    ]

    assert find_duplicate_artifacts(paths) == [
        "contracts/v1 2/scan.schema.json",
        "src/agent_bom/model_advisories 2.py",
        "tests/test_cloud_resilience 3.py",
    ]


def test_duplicate_artifact_guard_ignores_untracked_noise_prefixes() -> None:
    paths = [
        "ui/node_modules/package 2/index.js",
        "ui/out/graph 2/index.html",
        "site/deployment/docker 2/index.html",
        ".venv/lib/python/site-packages/pkg 2.py",
        "src/agent_bom/model_advisories.py",
    ]

    assert find_duplicate_artifacts(paths) == []


def test_duplicate_artifact_guard_cli_returns_failure_for_duplicates(tmp_path: Path, capsys) -> None:
    paths = tmp_path / "paths.txt"
    paths.write_text("src/agent_bom/model_advisories 2.py\nsrc/agent_bom/model_advisories.py\n", encoding="utf-8")

    assert main(["--paths-file", str(paths)]) == 1
    captured = capsys.readouterr()
    assert "model_advisories 2.py" in captured.err
