"""Guard soft-deprecated orphan API routes (#3666 Phase 2).

Confirmed product orphans are marked ``deprecated=True`` in FastAPI / OpenAPI
but remain callable. This test prevents UI / CLI / MCP surfaces from adopting
those paths as string literals, and pins the OpenAPI deprecation flags.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Keep in sync with docs/design/API_ORPHAN_ROUTES.md soft-deprecate rows.
SOFT_DEPRECATED_ORPHAN_PATHS: tuple[str, ...] = (
    "/v1/agents/mesh",
    "/v1/graph/legend",
    "/v1/cortex/telemetry",
    "/v1/posture/backpressure",
    "/v1/estate/correlations",
    "/v1/cis/trends",
    "/v1/credentials/posture",
)

# Must stay active (auth protocol) — never soft-deprecated in this phase.
KEEP_ACTIVE_PATHS: tuple[str, ...] = ("/v1/auth/saml/relay-state",)

# Held for an explicit product call post-#3664 — not soft-deprecated yet.
HOLD_PATHS: tuple[str, ...] = (
    "/v1/graph/presets",
    "/v1/graph/presets/{name}",
    "/v1/graph/nhi/governance",
)

_CONSUMER_ROOTS: tuple[Path, ...] = (
    ROOT / "ui",
    ROOT / "src" / "agent_bom" / "cli",
    ROOT / "src" / "agent_bom" / "mcp_tools",
)
_CONSUMER_FILES: tuple[Path, ...] = (ROOT / "src" / "agent_bom" / "mcp_server.py",)
_CODE_SUFFIXES = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
_SKIP_DIR_NAMES = {
    "node_modules",
    ".next",
    "dist",
    "build",
    "coverage",
    "__pycache__",
    ".turbo",
}


def _iter_consumer_files() -> list[Path]:
    files: list[Path] = []
    for root in _CONSUMER_ROOTS:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in _SKIP_DIR_NAMES for part in path.parts):
                continue
            if path.suffix.lower() in _CODE_SUFFIXES:
                files.append(path)
    for path in _CONSUMER_FILES:
        if path.is_file():
            files.append(path)
    return files


def test_soft_deprecated_orphans_have_no_ui_cli_mcp_literals() -> None:
    hits: list[str] = []
    for path in _iter_consumer_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for route in SOFT_DEPRECATED_ORPHAN_PATHS:
            if route in text:
                hits.append(f"{path.relative_to(ROOT)}:{route}")
    assert not hits, (
        "Soft-deprecated orphan routes must not gain UI/CLI/MCP callers; "
        f"found: {hits}. See docs/design/API_ORPHAN_ROUTES.md."
    )


def test_openapi_marks_soft_deprecated_orphans() -> None:
    schema = json.loads((ROOT / "docs/openapi/v1.json").read_text(encoding="utf-8"))
    paths = schema["paths"]

    for route in SOFT_DEPRECATED_ORPHAN_PATHS:
        assert route in paths, f"missing OpenAPI path {route}"
        operations = [op for op in paths[route].values() if isinstance(op, dict)]
        assert operations, f"no operations documented for {route}"
        assert all(op.get("deprecated") is True for op in operations), (
            f"{route} must be marked deprecated:true in OpenAPI"
        )

    for route in KEEP_ACTIVE_PATHS:
        assert route in paths, f"missing OpenAPI path {route}"
        operations = [op for op in paths[route].values() if isinstance(op, dict)]
        assert operations and all(op.get("deprecated") is not True for op in operations), (
            f"{route} must remain active (not soft-deprecated)"
        )

    for route in HOLD_PATHS:
        assert route in paths, f"missing OpenAPI path {route}"
        operations = [op for op in paths[route].values() if isinstance(op, dict)]
        assert operations and all(op.get("deprecated") is not True for op in operations), (
            f"{route} is held for a product call — do not soft-deprecate yet"
        )
