"""Contract for the official MCP Registry publish workflow."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "publish-mcp-registry.yml"


def test_oidc_token_audience_is_the_registry_origin() -> None:
    """The registry binds GitHub OIDC exchange to its own origin (registry #1229).

    A token minted for the old ``mcp-registry`` audience is rejected with 401.
    """
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "audience=https%3A%2F%2Fregistry.modelcontextprotocol.io" in workflow
    assert "audience=mcp-registry" not in workflow


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq is required")
def test_auth_failure_reports_the_registry_reason() -> None:
    """The registry returns problem+json; its reason lives in detail/errors, not error/message."""
    workflow = WORKFLOW.read_text(encoding="utf-8")
    line = next(line for line in workflow.splitlines() if "ERROR=$(jq -r" in line and "auth-response.json" in line)
    program = line.split("jq -r '", 1)[1].split("' /tmp/auth-response.json", 1)[0]
    body = {
        "title": "Unauthorized",
        "status": 401,
        "detail": "Token exchange failed",
        "errors": [{"message": "failed to validate OIDC token: invalid audience"}],
    }

    result = subprocess.run(["jq", "-r", program], input=json.dumps(body), capture_output=True, text=True, check=True)

    assert result.stdout.strip() == "Token exchange failed: failed to validate OIDC token: invalid audience"
