"""Route parity checks for the TypeScript control-plane client."""

from __future__ import annotations

import re
from pathlib import Path

from agent_bom.api.server import app


def test_typescript_control_plane_client_paths_exist_in_api() -> None:
    source = Path("sdks/typescript-client/src/index.ts").read_text(encoding="utf-8")
    client_paths = {
        match for match in re.findall(r"[\"`](/(?:health|v1/[^\"`?$]+))", source) if "{" not in match and not match.endswith("/")
    }
    registered_paths = {getattr(route, "path", "") for route in app.routes}

    assert client_paths
    assert client_paths <= registered_paths
