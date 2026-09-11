"""Directory exclusions must remain visible in secret-scan coverage."""

import pytest

from agent_bom.secret_scanner import scan_secrets
from agent_bom.traversal import iter_discovery_files


@pytest.mark.parametrize(
    "name", ["env", "test", "testing", "build", "dist", "fixtures", "fuzz", "site-packages", ".tox", ".eggs", ".mypy_cache"]
)
def test_directory_policy_exclusion_cannot_report_complete(tmp_path, name):
    skipped = tmp_path / "app" / name
    skipped.mkdir(parents=True)
    (skipped / "credentials.env").write_text("AWS_ACCESS_KEY_ID=" + "AKIA" + "IOSFODNN7EXAMPLE\n")
    result = scan_secrets(tmp_path)
    assert result.files_scanned == 0
    assert result.to_dict()["complete"] is False
    assert result.to_dict()["pruned_directories"] == 1
    assert any("directory" in warning.lower() for warning in result.warnings)


def test_explicit_skipped_directory_root_can_be_scanned(tmp_path):
    root = tmp_path / "env"
    root.mkdir()
    (root / "credentials.env").write_text("AWS_ACCESS_KEY_ID=" + "AKIA" + "IOSFODNN7EXAMPLE\n")
    result = scan_secrets(root)
    assert result.files_scanned == 1
    assert result.total >= 1
    assert result.to_dict()["complete"] is True


def test_prune_callback_counts_ancestors_without_descending(tmp_path):
    root = tmp_path / "node_modules"
    nested = root / "build"
    nested.mkdir(parents=True)
    (nested / "leak.env").write_text("placeholder")
    seen = []
    assert list(iter_discovery_files(tmp_path, on_prune=lambda path, reason: seen.append((path, reason)))) == []
    assert seen == [(root, "directory_policy")]


def test_nested_worktree_exclusion_has_a_distinct_reason(tmp_path):
    root = tmp_path / "linked"
    root.mkdir()
    (root / ".git").write_text("gitdir: ../.git/worktrees/linked")
    seen = []
    assert list(iter_discovery_files(tmp_path, on_prune=lambda path, reason: seen.append((path, reason)))) == []
    assert seen == [(root, "nested_worktree")]


def test_traversal_budget_is_reported(tmp_path):
    (tmp_path / "a.env").write_text("placeholder")
    (tmp_path / "b.env").write_text("placeholder")
    limits = []
    assert len(list(iter_discovery_files(tmp_path, max_files=1, on_limit=limits.append))) == 1
    assert limits == [1]


def test_secret_file_budget_does_not_materialize_the_whole_walk(monkeypatch, tmp_path):
    from agent_bom import secret_scanner

    (tmp_path / "a.env").write_text("placeholder")
    (tmp_path / "b.env").write_text("placeholder")

    def files(*args, **kwargs):
        yield tmp_path / "a.env"
        yield tmp_path / "b.env"
        raise AssertionError("walk continued beyond the scanner budget")

    monkeypatch.setattr(secret_scanner, "iter_discovery_files", files)
    monkeypatch.setattr(secret_scanner, "_MAX_FILES", 1)
    result = scan_secrets(tmp_path)
    assert result.files_scanned == 1
    assert result.to_dict()["complete"] is False


@pytest.mark.parametrize("format", ["console", "json"])
def test_focused_cli_cannot_exit_clean_for_uninspected_subtrees(tmp_path, format):
    from click.testing import CliRunner

    from agent_bom.cli import main

    root = tmp_path / "env"
    root.mkdir()
    (root / "prod.env").write_text("placeholder")
    result = CliRunner().invoke(main, ["secrets", str(tmp_path), "--format", format])
    assert result.exit_code == 2
    assert "No secrets or PII found." not in result.output
    assert "directory" in result.output
