"""Runtime protection server — stdin or HTTP listener for ProtectionEngine.

Provides two input modes for feeding tool call data to the ProtectionEngine:

1. **stdin mode** (default): Reads line-delimited JSON from stdin.
   Each line is a JSON object with one of:
     - ``{"tool_name": "...", "arguments": {...}}`` → process_tool_call
     - ``{"type": "response", "tool_name": "...", "text": "..."}`` → process_tool_response
     - ``{"type": "drift", "tools": [...]}`` → check_tool_drift

2. **http mode**: Starts a lightweight HTTP server with endpoints:
     - ``POST /tool-call``     — process_tool_call
     - ``POST /tool-response`` — process_tool_response
     - ``POST /drift-check``   — check_tool_drift
     - ``GET  /status``        — engine status JSON
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_bom.runtime.protection import ProtectionEngine

logger = logging.getLogger(__name__)


# ─── stdin mode ──────────────────────────────────────────────────────────────


async def run_stdin_mode(engine: ProtectionEngine) -> None:
    """Read line-delimited JSON from stdin, dispatch to engine, write alerts to stdout."""
    engine.start()
    logger.info("Protection engine running in stdin mode (Ctrl+C to stop)")

    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)

    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            text = line.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                sys.stdout.write(json.dumps({"error": "invalid JSON"}) + "\n")
                sys.stdout.flush()
                continue

            alerts = await _dispatch(engine, data)
            if alerts:
                for alert in alerts:
                    sys.stdout.write(json.dumps(alert) + "\n")
                sys.stdout.flush()
    except asyncio.CancelledError:
        pass
    finally:
        engine.stop()


async def _dispatch(engine: ProtectionEngine, data: dict) -> list[dict]:
    """Route a parsed JSON object to the appropriate engine method."""
    msg_type = data.get("type", "tool_call")

    if msg_type == "response":
        tool_name = data.get("tool_name", "unknown")
        text = data.get("text", "")
        return await engine.process_tool_response(tool_name, text)

    if msg_type == "drift":
        tools = data.get("tools", [])
        return await engine.check_tool_drift(tools)

    # Default: tool call
    tool_name = data.get("tool_name", "unknown")
    arguments = data.get("arguments", {})
    return await engine.process_tool_call(tool_name, arguments)


# ─── HTTP mode ───────────────────────────────────────────────────────────────


async def run_http_mode(engine: ProtectionEngine, host: str, port: int) -> None:
    """Start an asyncio HTTP server that accepts tool call JSON via POST."""
    engine.start()

    async def handle_request(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            # Read HTTP request line + headers
            request_line = await asyncio.wait_for(reader.readline(), timeout=30)
            if not request_line:
                writer.close()
                return

            request_str = request_line.decode("utf-8", errors="replace").strip()
            parts = request_str.split(" ")
            method = parts[0] if parts else "GET"
            path = parts[1] if len(parts) > 1 else "/"

            # Read headers
            content_length = 0
            while True:
                header_line = await asyncio.wait_for(reader.readline(), timeout=10)
                header_str = header_line.decode("utf-8", errors="replace").strip()
                if not header_str:
                    break
                if header_str.lower().startswith("content-length:"):
                    content_length = int(header_str.split(":", 1)[1].strip())

            # Read body
            body = b""
            if content_length > 0:
                body = await asyncio.wait_for(reader.readexactly(content_length), timeout=30)

            # Route
            status, response_body = await _route_http(engine, method, path, body)
            response_json = json.dumps(response_body)
            http_response = (
                f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {len(response_json)}\r\n\r\n{response_json}"
            )
            writer.write(http_response.encode("utf-8"))
            await writer.drain()
        except (asyncio.TimeoutError, ConnectionResetError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handle_request, host, port)
    logger.info("Protection engine HTTP server listening on %s:%d", host, port)

    try:
        await server.serve_forever()
    except asyncio.CancelledError:
        pass
    finally:
        server.close()
        engine.stop()


async def _route_http(engine: ProtectionEngine, method: str, path: str, body: bytes) -> tuple[str, dict]:
    """Route an HTTP request to the appropriate engine method."""
    if method == "GET" and path == "/status":
        return "200 OK", engine.status()

    if method != "POST":
        return "405 Method Not Allowed", {"error": "use POST"}

    try:
        data = json.loads(body) if body else {}
    except json.JSONDecodeError:
        return "400 Bad Request", {"error": "invalid JSON"}

    if path == "/tool-call":
        tool_name = data.get("tool_name", "unknown")
        arguments = data.get("arguments", {})
        alerts = await engine.process_tool_call(tool_name, arguments)
        return "200 OK", {"alerts": alerts}

    if path == "/tool-response":
        tool_name = data.get("tool_name", "unknown")
        text = data.get("text", "")
        alerts = await engine.process_tool_response(tool_name, text)
        return "200 OK", {"alerts": alerts}

    if path == "/drift-check":
        tools = data.get("tools", [])
        alerts = await engine.check_tool_drift(tools)
        return "200 OK", {"alerts": alerts}

    return "404 Not Found", {"error": f"unknown path: {path}"}
