"""Read-only comparison of Glama's two documented server lookup routes."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

from check_glama_listing import _api_inventory_result, _fetch_json, _load_expected_tool_contract


def main() -> int:
    if not os.environ.get("GLAMA_API_KEY"):
        raise SystemExit("Authenticated diagnostic requires the configured Actions secret")
    expected = _load_expected_tool_contract(Path(sys.argv[1]))
    namespace = _fetch_json("https://glama.ai/api/mcp/v1/servers/msaad00/agent-bom", 20)
    server_id = namespace.get("id")
    if not isinstance(server_id, str) or not re.fullmatch(r"[a-z0-9]{10}", server_id):
        raise SystemExit("Documented server identifier is missing or malformed")
    by_id = _fetch_json(f"https://glama.ai/api/mcp/v1/servers/{server_id}", 20)
    results = []
    for route, payload in (("namespace_slug", namespace), ("server_id", by_id)):
        count, failures, exact_names, exact_schemas = _api_inventory_result(
            payload.get("tools"),
            tool_count=len(expected),
            expected_tool_names=[str(tool["name"]) for tool in expected],
            expected_tool_contract=expected,
        )
        results.append(
            {
                "route": route,
                "identity_matches": payload.get("namespace") == "msaad00" and payload.get("slug") == "agent-bom",
                "same_server_id": payload.get("id") == server_id,
                "tool_count": count,
                "expected_tool_count": len(expected),
                "exact_names": exact_names,
                "exact_schemas": exact_schemas,
                "contract_matches": not failures,
            }
        )
    print(json.dumps(results, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        raise SystemExit(f"Directory diagnostic failed ({type(exc).__name__}); response and credentials omitted") from None
