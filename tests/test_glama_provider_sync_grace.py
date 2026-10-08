"""Glama freshness separates bounded provider sync lag from a real regression."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "publish-registries.yml"
NOW = datetime(2026, 10, 8, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def checker(monkeypatch):
    spec = importlib.util.spec_from_file_location("glama_sync_grace_check", ROOT / "scripts/check_glama_listing.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.delenv("GLAMA_API_KEY", raising=False)
    monkeypatch.delenv("GLAMA_DIAGNOSTICS_DIR", raising=False)
    monkeypatch.setattr(module, "_utcnow", lambda: NOW)
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)
    return module


def _stale_listing(checker, monkeypatch) -> None:
    """Glama serves an older build: listing reachable, inventory empty."""

    def fetch(url: str, timeout: float) -> str:
        if url.endswith("/schema"):
            raise urllib.error.URLError("schema not indexed")
        return "<html><body>agent-bom v0.107.2 exposes 8 MCP tools</body></html>"

    monkeypatch.setattr(checker, "_fetch", fetch)
    monkeypatch.setattr(checker, "_fetch_json", lambda url, timeout: {"tools": []})


def _run(checker, *extra: str) -> int:
    return checker.main(["--expected", "0.108.1", "--expected-tool-count", "8", "--retries", "1", "--delay-seconds", "0", *extra])


def _published(hours_ago: float) -> str:
    return (NOW - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_stale_listing_within_grace_is_provider_sync_pending(checker, monkeypatch, capsys):
    _stale_listing(checker, monkeypatch)

    code = _run(checker, "--release-published-at", _published(30), "--provider-sync-grace-hours", "72")

    assert code == checker.EXIT_PROVIDER_SYNC_PENDING == 3
    err = capsys.readouterr().err
    assert "pending provider sync" in err
    assert "30.0h" in err and "72h" in err
    assert "Glama public API exposes 0 tools; expected 8" in err
    assert "Sync Server" in err


def test_stale_listing_after_grace_fails(checker, monkeypatch, capsys):
    _stale_listing(checker, monkeypatch)

    code = _run(checker, "--release-published-at", _published(73), "--provider-sync-grace-hours", "72")

    assert code == 1
    assert "stale or unreachable" in capsys.readouterr().err


def test_without_release_timestamp_staleness_still_fails(checker, monkeypatch):
    _stale_listing(checker, monkeypatch)

    assert _run(checker, "--provider-sync-grace-hours", "72") == 1
    assert _run(checker, "--release-published-at", _published(1)) == 1


def test_unreachable_listing_within_grace_is_provider_sync_pending(checker, monkeypatch):
    def fetch(url: str, timeout: float) -> str:
        raise urllib.error.URLError("provider outage")

    monkeypatch.setattr(checker, "_fetch", fetch)

    code = _run(checker, "--release-published-at", _published(2), "--provider-sync-grace-hours", "72")

    assert code == checker.EXIT_PROVIDER_SYNC_PENDING


@pytest.mark.parametrize("published_at", ["not-a-date", "2026-10-07", _published(-1)])
def test_unusable_or_future_release_timestamp_fails_closed(checker, monkeypatch, published_at):
    _stale_listing(checker, monkeypatch)

    with pytest.raises(SystemExit):
        _run(checker, "--release-published-at", published_at, "--provider-sync-grace-hours", "72")


def test_negative_grace_is_rejected(checker, monkeypatch):
    _stale_listing(checker, monkeypatch)

    with pytest.raises(SystemExit):
        _run(checker, "--release-published-at", _published(1), "--provider-sync-grace-hours", "-1")


def test_json_reports_pending_provider_sync_status(checker, monkeypatch, capsys):
    _stale_listing(checker, monkeypatch)

    code = _run(checker, "--json", "--release-published-at", _published(30), "--provider-sync-grace-hours", "72")

    assert code == checker.EXIT_PROVIDER_SYNC_PENDING
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert payload["status"] == "pending_provider_sync"
    assert payload["provider_sync_grace_hours"] == 72
    assert payload["hours_since_release"] == 30.0
    assert payload["tool_count"] == 0


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_release_job_exports_validated_publish_time() -> None:
    release = _workflow()["jobs"]["release"]
    assert release["outputs"]["published_at"] == "${{ steps.release.outputs.published_at }}"
    script = next(step["run"] for step in release["steps"] if step.get("id") == "release")
    assert "releases/tags/${RELEASE_TAG}" in script
    assert "published_at=$PUBLISHED_AT" in script
    assert "Published release has no valid publish time" in script


def test_glama_step_maps_only_pending_sync_to_a_warning() -> None:
    steps = _workflow()["jobs"]["glama"]["steps"]
    step = next(step for step in steps if step.get("name") == "Verify Glama listing freshness")
    env = step["env"]
    script = step["run"]

    assert env["RELEASE_PUBLISHED_AT"] == "${{ needs.release.outputs.published_at }}"
    assert int(env["GLAMA_SYNC_GRACE_HOURS"]) == 72
    assert '--release-published-at "$RELEASE_PUBLISHED_AT"' in script
    assert '--provider-sync-grace-hours "$GLAMA_SYNC_GRACE_HOURS"' in script
    pending, _, failure = script.partition('if [ "$STATUS" -eq 3 ]; then')[2].partition("fi\n")
    assert "::warning::" in pending and "Sync Server" in pending and "exit 0" in pending
    assert "::error::" in failure and failure.rstrip().endswith("exit 1")
    assert "continue-on-error" not in _workflow()["jobs"]["glama"]


@pytest.mark.parametrize(
    "checker_status,step_status,annotation",
    [(0, 0, None), (3, 0, "::warning::"), (1, 1, "::error::"), (2, 1, "::error::")],
)
def test_glama_step_executes_exit_code_mapping(tmp_path, checker_status, step_status, annotation) -> None:
    steps = _workflow()["jobs"]["glama"]["steps"]
    script = next(step for step in steps if step.get("name") == "Verify Glama listing freshness")["run"]
    stub = 'python() { echo "$@" > "$ARGS_FILE"; return "$CHECKER_STATUS"; }\n'
    args_file = tmp_path / "args"
    result = subprocess.run(
        ["bash", "-c", stub + script],
        env={
            **os.environ,
            "ARGS_FILE": str(args_file),
            "CHECKER_STATUS": str(checker_status),
            "EXPECTED_VERSION": "0.108.1",
            "EXPECTED_TOOL_COUNT": "8",
            "RELEASE_PUBLISHED_AT": "2026-10-06T17:40:00Z",
            "GLAMA_SYNC_GRACE_HOURS": "72",
        },
        text=True,
        capture_output=True,
        timeout=20,
    )
    assert result.returncode == step_status, result.stdout + result.stderr
    if annotation is None:
        assert "::" not in result.stdout
    else:
        assert annotation in result.stdout
        assert "Sync Server" in result.stdout
    assert "--release-published-at 2026-10-06T17:40:00Z --provider-sync-grace-hours 72" in args_file.read_text()
