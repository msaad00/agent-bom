"""Route parity checks for the Go control-plane client."""

from __future__ import annotations

import re
from pathlib import Path

from agent_bom.api.server import app


def test_go_control_plane_client_paths_exist_in_api() -> None:
    source = Path("sdks/go/client.go").read_text(encoding="utf-8")
    client_paths = {
        match
        for match in re.findall(r'"(/(?:health|v1/[^"?]+))"', source)
        if "{" not in match and not match.endswith("/") and "+" not in match
    }
    # FastAPI >=0.137 includes sub-routers lazily as ``_IncludedRouter`` wrappers
    # in ``app.routes`` that do not expose their child ``.path`` values, so the
    # generated OpenAPI document is the version-stable source of registered paths.
    registered_paths = set(app.openapi().get("paths", {}))

    assert client_paths
    assert client_paths <= registered_paths
