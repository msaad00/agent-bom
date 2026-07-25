"""Contract lock for UI API methods changed by the product-correctness pass."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _query_parameters(spec: dict, path: str) -> set[str]:
    return {
        str(parameter["name"])
        for parameter in spec["paths"][path]["get"].get("parameters", [])
        if parameter.get("in") == "query"
    }


def test_ui_jobs_and_compliance_clients_match_checked_in_openapi() -> None:
    spec = json.loads((ROOT / "docs/openapi/v1.json").read_text(encoding="utf-8"))
    client = (ROOT / "ui/lib/api.ts").read_text(encoding="utf-8")

    assert {"include_details", "limit", "offset", "q", "status"} <= _query_parameters(spec, "/v1/jobs")
    assert {"scan_id"} <= _query_parameters(spec, "/v1/compliance")
    assert "`/v1/jobs${qs ? `?${qs}` : \"\"}`" in client
    assert "`/v1/compliance${query ? `?${query}` : \"\"}`" in client
