"""Tiny stdio MCP fixture used by release/runtime smoke tests.

This is not a production MCP server. It exists so Docker/runtime evidence can
exercise the proxy command path without depending on npm, network access, or a
third-party package inside the runtime image.
"""

from __future__ import annotations

import json
import os
import sys


def main() -> int:
    oneshot = os.environ.get("AGENT_BOM_RUNTIME_SMOKE_ONESHOT", "").strip().lower() in {"1", "true", "yes"}
    for raw_line in sys.stdin:
        try:
            message = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        response = _response_for(message)
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()
        if oneshot and message.get("method") == "tools/list":
            break
    return 0


def _response_for(message: dict) -> dict:
    if message.get("method") == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {
                "tools": [
                    {
                        "name": "allowed_tool",
                        "inputSchema": {"type": "object"},
                    }
                ]
            },
        }
    if message.get("method") == "tools/call":
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"ok": True},
        }
    return {
        "jsonrpc": "2.0",
        "id": message.get("id"),
        "error": {"code": -32601, "message": "method not found"},
    }


if __name__ == "__main__":
    raise SystemExit(main())
