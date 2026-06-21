"""Route parity checks for the Python control-plane client."""

from __future__ import annotations

import ast
from pathlib import Path

from agent_bom.api.server import app


def test_python_control_plane_client_paths_exist_in_api() -> None:
    source = Path("src/agent_bom/client.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    client_paths = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and (node.value == "/health" or node.value.startswith("/v1/"))
        and "{" not in node.value
        and not node.value.endswith("/")
    }
    # FastAPI >=0.137 includes sub-routers lazily as ``_IncludedRouter`` wrappers
    # in ``app.routes`` that do not expose their child ``.path`` values, so the
    # generated OpenAPI document is the version-stable source of registered paths.
    registered_paths = set(app.openapi().get("paths", {}))

    assert client_paths
    assert client_paths <= registered_paths
