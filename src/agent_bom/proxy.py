"""MCP runtime proxy — intercept JSON-RPC between client and server.

A stdio proxy that sits between an MCP client (Claude Desktop, Cursor, etc.)
and an MCP server. It intercepts all JSON-RPC messages, logs tool call
invocations, compares actual usage against declared capabilities, and
optionally enforces security policy in real-time.

Usage:
    agent-bom proxy [--policy policy.json] [--log audit.jsonl] -- npx @mcp/server-filesystem /tmp
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ─── JSON-RPC parsing ────────────────────────────────────────────────────────


def parse_jsonrpc(line: str) -> Optional[dict]:
    """Parse a JSON-RPC message from a single line.

    Returns the parsed dict or None if the line is not valid JSON-RPC.
    """
    line = line.strip()
    if not line:
        return None
    try:
        msg = json.loads(line)
        if isinstance(msg, dict) and ("jsonrpc" in msg or "method" in msg or "result" in msg):
            return msg
        return None
    except (json.JSONDecodeError, TypeError):
        return None


def is_tools_call(msg: dict) -> bool:
    """Check if a JSON-RPC message is a tools/call request."""
    return msg.get("method") == "tools/call"


def is_tools_list_response(msg: dict, request_id: Optional[int | str] = None) -> bool:
    """Check if a JSON-RPC message is a tools/list response."""
    if "result" not in msg:
        return False
    result = msg.get("result", {})
    if isinstance(result, dict) and "tools" in result:
        return True
    return False


def extract_tool_name(msg: dict) -> Optional[str]:
    """Extract the tool name from a tools/call request."""
    params = msg.get("params", {})
    return params.get("name")


def extract_tool_arguments(msg: dict) -> dict:
    """Extract tool arguments from a tools/call request."""
    params = msg.get("params", {})
    return params.get("arguments", {})


def extract_declared_tools(msg: dict) -> list[str]:
    """Extract declared tool names from a tools/list response."""
    result = msg.get("result", {})
    tools = result.get("tools", [])
    return [t.get("name", "") for t in tools if isinstance(t, dict)]


def make_error_response(request_id: int | str | None, code: int, message: str) -> dict:
    """Create a JSON-RPC error response."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": code,
            "message": message,
        },
    }


# ─── Audit logging ───────────────────────────────────────────────────────────


def log_tool_call(
    log_file: object,
    tool_name: str,
    arguments: dict,
    policy_result: str = "allowed",
    reason: str = "",
) -> None:
    """Append a tool call record to the audit JSONL log.

    Args:
        log_file: File-like object opened for writing/appending.
        tool_name: Name of the tool being called.
        arguments: Tool call arguments.
        policy_result: "allowed" or "blocked".
        reason: Reason for blocking (if blocked).
    """
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "type": "tools/call",
        "tool": tool_name,
        "args": _truncate_args(arguments),
        "policy": policy_result,
    }
    if reason:
        record["reason"] = reason

    log_file.write(json.dumps(record) + "\n")  # type: ignore[union-attr]
    log_file.flush()  # type: ignore[union-attr]


def _truncate_args(args: dict, max_value_len: int = 200) -> dict:
    """Truncate long argument values for logging."""
    result = {}
    for k, v in args.items():
        if isinstance(v, str) and len(v) > max_value_len:
            result[k] = v[:max_value_len] + "...<truncated>"
        else:
            result[k] = v
    return result


# ─── Policy checking ─────────────────────────────────────────────────────────


def check_policy(
    policy: dict,
    tool_name: str,
    arguments: dict,
) -> tuple[bool, str]:
    """Evaluate runtime policy against a tools/call request.

    Args:
        policy: Policy dict with runtime rules.
        tool_name: Name of the tool being called.
        arguments: Tool call arguments.

    Returns:
        (allowed, reason) tuple. If blocked, reason explains why.
    """
    rules = policy.get("rules", [])
    for rule in rules:
        action = rule.get("action", "warn")
        if action not in ("fail", "block"):
            continue  # Only enforce blocking rules at runtime

        # block_tools: list of tool names to block entirely
        blocked = rule.get("block_tools", [])
        if blocked and tool_name in blocked:
            return False, f"Tool '{tool_name}' is blocked by rule '{rule.get('id', '?')}'"

        # tool_name match (exact)
        rule_tool = rule.get("tool_name")
        if rule_tool and rule_tool == tool_name:
            return False, f"Tool '{tool_name}' blocked by rule '{rule.get('id', '?')}'"

        # tool_name_pattern match (regex)
        pattern = rule.get("tool_name_pattern")
        if pattern:
            try:
                if re.match(pattern, tool_name):
                    return False, f"Tool '{tool_name}' matches blocked pattern '{pattern}'"
            except re.error:
                pass

        # arg_pattern: {arg_name: regex_pattern}
        arg_patterns = rule.get("arg_pattern", {})
        for arg_name, arg_regex in arg_patterns.items():
            arg_value = str(arguments.get(arg_name, ""))
            try:
                if re.search(arg_regex, arg_value):
                    return False, f"Argument '{arg_name}' matches blocked pattern '{arg_regex}'"
            except re.error:
                pass

    return True, ""


# ─── Proxy core ──────────────────────────────────────────────────────────────


async def run_proxy(
    server_cmd: list[str],
    policy_path: Optional[str] = None,
    log_path: Optional[str] = None,
    block_undeclared: bool = False,
) -> int:
    """Main proxy loop. Spawns server subprocess, relays JSON-RPC.

    Returns the server process exit code.
    """
    # Load policy if provided
    policy: dict = {}
    if policy_path:
        policy = json.loads(Path(policy_path).read_text())

    # Open audit log
    log_file = None
    if log_path:
        log_file = open(log_path, "a")  # noqa: SIM115

    # Track declared tools from tools/list responses
    declared_tools: set[str] = set()
    tools_list_request_ids: set[int | str] = set()

    # Spawn the actual MCP server
    process = await asyncio.create_subprocess_exec(
        *server_cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    async def relay_client_to_server():
        """Read from our stdin, forward to server stdin."""
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin.buffer)

        while True:
            line = await reader.readline()
            if not line:
                break

            line_str = line.decode("utf-8", errors="replace")
            msg = parse_jsonrpc(line_str)

            if msg:
                # Track tools/list requests so we can identify responses
                if msg.get("method") == "tools/list" and "id" in msg:
                    tools_list_request_ids.add(msg["id"])

                # Intercept tools/call requests
                if is_tools_call(msg):
                    tool_name = extract_tool_name(msg) or "unknown"
                    arguments = extract_tool_arguments(msg)

                    # Check if tool is declared
                    if block_undeclared and declared_tools and tool_name not in declared_tools:
                        reason = f"Tool '{tool_name}' not in declared tools/list"
                        if log_file:
                            log_tool_call(log_file, tool_name, arguments, "blocked", reason)
                        # Send error back to client
                        error_resp = make_error_response(msg.get("id"), -32600, reason)
                        sys.stdout.buffer.write((json.dumps(error_resp) + "\n").encode())
                        sys.stdout.buffer.flush()
                        continue

                    # Check policy
                    if policy:
                        allowed, reason = check_policy(policy, tool_name, arguments)
                        if not allowed:
                            if log_file:
                                log_tool_call(log_file, tool_name, arguments, "blocked", reason)
                            error_resp = make_error_response(msg.get("id"), -32600, reason)
                            sys.stdout.buffer.write((json.dumps(error_resp) + "\n").encode())
                            sys.stdout.buffer.flush()
                            continue

                    # Log allowed call
                    if log_file:
                        log_tool_call(log_file, tool_name, arguments, "allowed")

            # Forward to server
            if process.stdin:
                process.stdin.write(line)
                await process.stdin.drain()

    async def relay_server_to_client():
        """Read from server stdout, forward to our stdout."""
        while True:
            if not process.stdout:
                break
            line = await process.stdout.readline()
            if not line:
                break

            line_str = line.decode("utf-8", errors="replace")
            msg = parse_jsonrpc(line_str)

            # Capture tools/list responses to track declared tools
            if msg and is_tools_list_response(msg):
                new_tools = extract_declared_tools(msg)
                declared_tools.update(new_tools)
                logger.debug("Declared tools updated: %s", declared_tools)

            # Forward to client
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()

    async def forward_stderr():
        """Forward server stderr to our stderr."""
        while True:
            if not process.stderr:
                break
            line = await process.stderr.readline()
            if not line:
                break
            sys.stderr.buffer.write(line)
            sys.stderr.buffer.flush()

    try:
        await asyncio.gather(
            relay_client_to_server(),
            relay_server_to_client(),
            forward_stderr(),
            return_exceptions=True,
        )
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        if log_file:
            log_file.close()
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                process.kill()

    return process.returncode or 0
