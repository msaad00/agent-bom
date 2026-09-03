"""Registry repair must evaluate Smithery auth from the published release."""

import json
import subprocess
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


def test_smithery_publication_is_idempotent_and_bounds_authorization_recovery() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "Check Smithery catalog parity" in workflow
    assert "Extract immutable Smithery release tool contract" in workflow
    assert "--write-tool-names /tmp/smithery-expected-tool-names.json" in workflow
    assert "smithery-actual-server-card-tool-names.json" in workflow
    assert "cmp -s /tmp/smithery-expected-tool-names.json /tmp/smithery-actual-server-card-tool-names.json" in workflow
    assert "LATEST_SUCCESS_UPSTREAM" in workflow
    assert 'select(.type == "external_shttp" and .status == "SUCCESS")' in workflow
    assert '"$LATEST_SUCCESS_UPSTREAM" = "$SMITHERY_MCP_URL"' in workflow
    assert "tool catalog matches but the successful release upstream differs" in workflow
    assert "smithery_catalog.outputs.fresh != 'true'" in workflow
    assert "smithery-expected-tool-names.json" in workflow
    assert "skipping a duplicate deployment" in workflow
    assert "Smithery catalog is unavailable; refusing to create a potentially duplicate release" in workflow
    assert "for ATTEMPT in $(seq 1 90)" in workflow
    assert "AUTH_REQUIRED)" in workflow
    assert "bounded recovery attempt" in workflow
    assert "within 15 minutes" in workflow


def test_smithery_publication_reuses_matching_pending_release() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "List resumable Smithery releases" in workflow
    assert 'GET "https://api.smithery.ai/servers/${QUALIFIED_NAME}/releases?page=${PAGE}&pageSize=100"' in workflow
    assert ".releases[]" in workflow
    assert ".pagination.currentPage" in workflow
    assert ".pagination.totalPages" in workflow
    assert "MAX_RELEASE_PAGES=20" in workflow
    assert 'select(.type == "external_shttp" and .upstreamUrl == $upstream)' in workflow
    assert 'select(.status == "AUTH_REQUIRED" or .status == "QUEUED" or .status == "WORKING")' in workflow
    assert 'POST "https://api.smithery.ai/servers/${QUALIFIED_NAME}/releases/${RELEASE_ID}/resume"' in workflow
    assert "Reusing matching Smithery release" in workflow


def test_smithery_release_selector_accepts_documented_envelope_shape() -> None:
    payload = {
        "releases": [
            {"id": "other", "type": "external_shttp", "upstreamUrl": "https://other.example/mcp", "status": "WORKING"},
            {"id": "wanted", "type": "external_shttp", "upstreamUrl": "https://mcp.example.test/mcp", "status": "AUTH_REQUIRED"},
        ],
        "pagination": {"currentPage": 1, "pageSize": 100, "totalCount": 2, "totalPages": 1},
    }
    selector = (
        '[.releases[] | select(.type == "external_shttp" and .upstreamUrl == $upstream) '
        '| select(.status == "AUTH_REQUIRED" or .status == "QUEUED" or .status == "WORKING")] '
        "| first // empty"
    )

    result = subprocess.run(
        ["jq", "-c", "--arg", "upstream", "https://mcp.example.test/mcp", selector],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=True,
    )

    assert json.loads(result.stdout) == payload["releases"][1]


def test_registry_publication_runs_are_serialized() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "concurrency:\n  group: publish-registries\n  cancel-in-progress: false" in workflow


def test_delayed_release_event_cannot_republish_an_older_version_as_latest() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "publish_current: ${{ steps.release.outputs.publish_current }}" in workflow
    assert 'LATEST_RELEASE_TAG=$(gh api "repos/${GITHUB_REPOSITORY}/releases/latest" --jq .tag_name)' in workflow
    assert 'if [ "$LATEST_RELEASE_TAG" != "$RELEASE_TAG" ]; then' in workflow
    assert "publish_current=false" in workflow
    assert workflow.count("needs.release.outputs.publish_current == 'true'") == 3


def test_new_smithery_release_completes_machine_authorization_before_resume() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "authorize_smithery_release.py" in workflow
    assert "Complete Smithery scan authorization" in workflow
    assert "AUTHORIZATION_ATTEMPTED" in workflow
    assert "Smithery authorization remained required after the bounded recovery attempt" in workflow


def test_surface_freshness_rechecks_immediately_after_registry_publication() -> None:
    workflow = (ROOT / ".github/workflows/surface-freshness.yml").read_text(encoding="utf-8")
    assert 'workflows: ["Publish to Registries"]' in workflow
    assert "github.event.workflow_run.conclusion == 'success'" in workflow
