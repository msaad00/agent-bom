#!/usr/bin/env python3
"""Minimal FastAPI echo MCP upstream for gateway relay benchmarks.

Listens on ``--port`` (default 8100). ``POST /mcp`` returns a JSON-RPC result
echoing the request id and tool name. Intended only for local perf harnesses.
"""

from __future__ import annotations

import argparse
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


def create_app() -> FastAPI:
    app = FastAPI(title="mock-mcp-upstream", docs_url=None, redoc_url=None)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/mcp")
    async def mcp(request: Request) -> JSONResponse:
        try:
            body: Any = await request.json()
        except Exception:
            return JSONResponse(
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}},
                status_code=200,
            )
        if not isinstance(body, dict):
            return JSONResponse(
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}},
                status_code=200,
            )
        req_id = body.get("id")
        method = str(body.get("method") or "")
        params = body.get("params") if isinstance(body.get("params"), dict) else {}
        tool_name = str(params.get("name") or "")
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"echo method={method} tool={tool_name}"}],
                    "isError": False,
                },
            }
        )

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8100, help="Listen port (default 8100)")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default 127.0.0.1)")
    args = parser.parse_args()

    import uvicorn

    uvicorn.run(create_app(), host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
