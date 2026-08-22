"""Registry repair must evaluate Smithery auth from the published release."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "publish-registries.yml"


def test_smithery_publish_waits_for_oauth_capable_forward_release() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "smithery_oauth_ready: ${{ steps.release.outputs.smithery_oauth_ready }}" in workflow
    assert 'git show "${RELEASE_SHA}:src/agent_bom/mcp_server_metadata.py"' in workflow
    assert "SMITHERY_OAUTH_READY: ${{ needs.release.outputs.smithery_oauth_ready }}" in workflow
    assert 'if [ "$SMITHERY_OAUTH_READY" != "true" ]; then' in workflow
    assert "publish the next forward release" in workflow
    assert '(.authentication.schemes | index("oauth2") != null)' in workflow


def test_automatic_forward_release_cannot_report_success_when_smithery_is_skipped() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert "REGISTRY_PUBLISH_REQUIRED: ${{ github.event_name == 'workflow_run' }}" in workflow
    assert "Smithery publication is required for an automatic forward release" in workflow


def test_surface_freshness_rechecks_immediately_after_registry_publication() -> None:
    workflow = (ROOT / ".github/workflows/surface-freshness.yml").read_text(encoding="utf-8")
    assert 'workflows: ["Publish to Registries"]' in workflow
    assert "github.event.workflow_run.conclusion == 'success'" in workflow
