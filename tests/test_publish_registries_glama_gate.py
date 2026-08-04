"""An unconfigured optional integration must not fail the whole publish.

`Publish to Registries` pushes PyPI, Docker, Smithery and Glama. The Glama step
failed the entire workflow when `GLAMA_WEBHOOK_URL` was unset, on the reasoning
that a *manual repair* which cannot do what was asked should fail loudly. That
intent is right, but `workflow_dispatch` carried no inputs, so an ordinary
re-run of the publish was indistinguishable from an explicit Glama repair — and
a third-party webhook nobody had configured became a release blocker (#4651).

The operator now says which one they meant.
"""

from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "publish-registries.yml"


def _glama_step_text() -> str:
    """Just the Glama step. The release job legitimately branches on event_name."""
    text = WORKFLOW.read_text(encoding="utf-8")
    start = text.index("Trigger Glama rebuild")
    return text[start:]


def _workflow() -> dict:
    # `on` parses as the boolean True in YAML 1.1, which is why this reads it back
    # by key rather than by name.
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_dispatch_exposes_an_explicit_glama_repair_input() -> None:
    triggers = _workflow()[True]
    inputs = triggers["workflow_dispatch"]["inputs"]

    assert "glama_repair" in inputs, "an operator cannot signal a Glama repair without an input"
    assert inputs["glama_repair"]["type"] == "boolean"
    assert inputs["glama_repair"]["default"] is False, "repair must be opt-in, never the default for a re-run"


def test_a_missing_webhook_only_fails_an_explicit_repair() -> None:
    """The gate must read the intent input, not merely that the run was dispatched."""
    step = _glama_step_text()

    assert "GLAMA_REPAIR: ${{ inputs.glama_repair }}" in step
    assert '[ "$EVENT_NAME" = "workflow_dispatch" ]' not in step, "gating on event_name treats every manual re-run as a repair request"
    assert '[ "$GLAMA_REPAIR" = "true" ]' in step


def test_the_unconfigured_path_still_reports_and_leaves_the_issue_open() -> None:
    """Warning quietly is how a stale listing survives for months — say it out loud."""
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "rebuild_triggered=false" in text
    assert "the freshness issue will remain open" in text
