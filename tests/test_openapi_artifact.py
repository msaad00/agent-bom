from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_committed_openapi_artifact_matches_fastapi_app() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/export_openapi.py", "--check"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_openapi_artifact_documents_agent_native_routes() -> None:
    schema = json.loads((ROOT / "docs/openapi/v1.json").read_text(encoding="utf-8"))
    paths = schema["paths"]

    assert "/v1/findings/bulk" in paths
    assert "/v1/datasets/{dataset_id}/versions" in paths
    assert "/v1/graph/exposure-paths" in paths
    assert "/v1/graph/should-i-deploy" in paths
