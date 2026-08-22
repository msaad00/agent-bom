"""Registry repair must evaluate Smithery auth from the published release."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_smithery_publish_waits_for_oauth_capable_forward_release() -> None:
    workflow = (ROOT / ".github" / "workflows" / "publish-registries.yml").read_text(encoding="utf-8")

    assert "smithery_oauth_ready: ${{ steps.release.outputs.smithery_oauth_ready }}" in workflow
    assert 'git show "${RELEASE_SHA}:src/agent_bom/mcp_server_metadata.py"' in workflow
    assert "SMITHERY_OAUTH_READY: ${{ needs.release.outputs.smithery_oauth_ready }}" in workflow
    assert 'if [ "$SMITHERY_OAUTH_READY" != "true" ]; then' in workflow
    assert "skipping Smithery until the next forward release" in workflow
    assert '(.authentication.schemes | index("oauth2") != null)' in workflow
