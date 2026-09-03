"""Glama publication must use provider-supported automatic synchronization."""

from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "publish-registries.yml"


def _glama_job_text() -> str:
    """Return the Glama job without unrelated registry implementation text."""
    text = WORKFLOW.read_text(encoding="utf-8")
    return text.split("  glama:\n", 1)[1].split("  clawhub:\n", 1)[0]


def _workflow() -> dict:
    # `on` parses as the boolean True in YAML 1.1, which is why this reads it back
    # by key rather than by name.
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_dispatch_does_not_expose_an_unsupported_glama_trigger() -> None:
    triggers = _workflow()[True]
    inputs = (triggers["workflow_dispatch"] or {}).get("inputs", {})

    assert "glama_repair" not in inputs


def test_registry_reconciliation_retries_automatically_without_republishing_clawhub() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    triggers = _workflow()[True]

    assert triggers["schedule"] == [{"cron": "17 */6 * * *"}]
    assert text.count("github.event_name == 'schedule'") == 3
    clawhub = text.split("  clawhub:\n", 1)[1]
    assert "github.event_name == 'schedule'" not in clawhub


def test_glama_job_verifies_provider_managed_sync_without_inventing_an_api() -> None:
    job = _glama_job_text()

    assert "GLAMA_WEBHOOK_URL" not in job
    assert "Trigger Glama rebuild" not in job
    assert "-X POST" not in job
    assert "--verify-manifest --git-ref" in job
    assert '--expected "$EXPECTED_VERSION"' in job
    assert '--expected-tool-count "$EXPECTED_TOOL_COUNT"' in job


def test_stale_glama_directory_fails_with_supported_recovery_guidance() -> None:
    """A stale provider directory stays visible without a fictitious trigger claim."""
    job = _glama_job_text()

    assert "Glama syncs linked GitHub repositories automatically at least daily" in job
    assert "Sync Server" in job
    assert "exit 1" in job
