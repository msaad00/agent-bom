"""Production documentation opt-out removes handlers, independently of auth."""

from __future__ import annotations

import os
import subprocess
import sys

import pytest


@pytest.mark.parametrize("disabled,expected", [("0", 200), ("1", 404)])
def test_docs_gate_is_enforced_at_asgi_bootstrap(disabled: str, expected: int) -> None:
    # A fresh interpreter reflects the production import-time environment and
    # avoids mutating the shared application used by other test modules.
    script = """
from starlette.testclient import TestClient
from agent_bom.api.server import app, configure_api
paths = ("/docs", "/redoc", "/openapi.json")
configure_api(allow_unauthenticated=True)
client = TestClient(app)
assert [client.get(path).status_code for path in paths] == [EXPECTED] * 3
configure_api(api_key="isolated-docs-gate-key", allow_unauthenticated=False)
client = TestClient(app)
assert [client.get(path, headers={"X-API-Key": "isolated-docs-gate-key"}).status_code for path in paths] == [EXPECTED] * 3
if EXPECTED == 404:
    assert not set(paths) & {getattr(route, "path", "") for route in app.routes}
""".replace("EXPECTED", str(expected))
    result = subprocess.run(
        [sys.executable, "-c", script],
        env={**os.environ, "AGENT_BOM_DISABLE_DOCS": disabled, "AGENT_BOM_ALLOW_UNAUTHENTICATED_API": "0"},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
