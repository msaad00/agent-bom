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
    registered_paths = {getattr(route, "path", "") for route in app.routes}

    assert client_paths
    assert client_paths <= registered_paths
