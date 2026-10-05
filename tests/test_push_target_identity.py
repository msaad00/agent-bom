"""Push scope is deterministic and independent of display/redaction choices."""

from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from agent_bom.api.models import PushPayload
from agent_bom.evidence.push_scope import cli_target_scope
from agent_bom.models import AIBOMReport
from agent_bom.output import to_json
from agent_bom.push import sanitize_results


def test_roots_are_normalized_but_distinct_projects_never_share_scope(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    first = cli_target_scope(SimpleNamespace(project="one"))
    assert first == cli_target_scope(SimpleNamespace(project=str(tmp_path / "one" / ".." / "one")))
    assert first != cli_target_scope(SimpleNamespace(project="two"))
    assert first == cli_target_scope(SimpleNamespace(project="one", output="different.json", push_api_key="secret", quiet=True))
    assert str(tmp_path) not in first


def test_remote_repo_scope_ignores_temporary_checkout_and_credentials():
    first = cli_target_scope(SimpleNamespace(repo_url="https://user:secret@example.org/org/repo", project="/tmp/one"))
    second = cli_target_scope(SimpleNamespace(repo_url="https://example.org/org/repo/", project="/tmp/two"))
    assert first == second


def test_multiple_targets_are_order_independent_and_restricted_collection_is_distinct(tmp_path):
    first = cli_target_scope(SimpleNamespace(filesystem_paths=[str(tmp_path / "a"), str(tmp_path / "b")]))
    assert first == cli_target_scope(SimpleNamespace(filesystem_paths=[str(tmp_path / "b"), str(tmp_path / "a")]))
    assert first != cli_target_scope(SimpleNamespace(filesystem_paths=[str(tmp_path / "a")]))
    assert cli_target_scope(SimpleNamespace(project=".", deps_dev=True)) != cli_target_scope(SimpleNamespace(project=".", deps_dev=False))


def test_implicit_accounts_and_targetless_scans_remain_unscoped():
    assert cli_target_scope(SimpleNamespace()) is None
    assert cli_target_scope(SimpleNamespace(project=".", aws=True)) is None


def test_scope_survives_report_projection_and_push_redaction():
    scope = cli_target_scope(SimpleNamespace(project="private-project"))
    report = {**to_json(AIBOMReport()), "target_scope": scope}
    assert sanitize_results(report)["target_scope"] == scope
    assert PushPayload.model_validate(sanitize_results(report)).target_scope == scope


@pytest.mark.parametrize("scope", ["", "repo-a", "v2:" + "a" * 64, "v1:" + "z" * 64, "v1:" + "a" * 65])
def test_push_rejects_malformed_scope_identifiers(scope):
    with pytest.raises(ValidationError):
        PushPayload(source_id="host", target_scope=scope)


def test_real_cli_push_carries_stable_project_scope(tmp_path, monkeypatch):
    from click.testing import CliRunner

    from agent_bom.cli import main

    captured = []
    monkeypatch.setattr("agent_bom.push.push_results", lambda url, results, **kwargs: captured.append(results) or True)
    for name in ("one", "two", "one"):
        root = tmp_path / name
        root.mkdir(exist_ok=True)
        (root / "requirements.txt").write_text("requests==2.19.0\n")
        result = CliRunner().invoke(main, ["scan", str(root), "--no-scan", "--no-discover", "--quiet", "--push-url", "https://example.org"])
        assert result.exit_code in (0, 1), result.output
    assert len(captured) == 3
    assert captured[0]["target_scope"] == captured[2]["target_scope"]
    assert captured[0]["target_scope"] != captured[1]["target_scope"]
