"""Strict-args contract for MCP tools (#2197 audit fix).

The audit caught a P1 silent-arg-drop defect: passing `{"package": "flask",
"version": "2.0.0"}` to `check` returned CLEAN because the unknown `version`
arg was silently dropped (FastMCP defaults to allowing extra properties),
so `check` resolved `flask` -> latest -> 0 vulns. AI agents passing typo
args (`Version` capital, `frob`, etc.) get false-clean verdicts on every
pre-install gate.

Fix: walk every registered FastMCP tool after registration and:

1. Set `additionalProperties: false` on the JSON Schema served via
   `tools/list` so MCP clients can validate locally before calling.
2. Wrap each tool's runner so unknown argument keys raise a clear
   `ToolError` ("Unknown argument 'Version' for tool 'check' -- accepted
   keys: ...") instead of being silently dropped.

Pydantic `model_config['extra'] = 'forbid'` cannot be retrofitted after
model creation (Pydantic only reads it at class-build time), so the
runtime check lives in a wrapper instead of being baked into the model.
"""

from __future__ import annotations

from typing import Any


def harden_tool_arguments(mcp: Any) -> int:
    """Mutate every registered FastMCP tool to reject unknown arguments.

    Two hardenings applied:

    1. **Public schema** -- `additionalProperties: false` on every tool's
       parameters dict so MCP clients can validate locally before sending.
    2. **Runtime guard** -- the tool manager's `call_tool` is wrapped so
       any call carrying an unknown argument key raises a clear `ToolError`
       *before* FastMCP's Pydantic-backed validation silently drops it.

    Pydantic `model_config['extra'] = 'forbid'` cannot be retrofitted after
    model creation, so the guard lives at the manager call boundary
    instead of inside the tool model.

    Returns the number of tools whose schema was hardened. Idempotent.
    """

    tools = list(mcp._tool_manager._tools.values())
    hardened = 0
    for tool in tools:
        params = getattr(tool, "parameters", None)
        if isinstance(params, dict) and params.get("additionalProperties") is not False:
            params["additionalProperties"] = False
            hardened += 1

    manager = mcp._tool_manager
    original_call = manager.call_tool
    if getattr(original_call, "_agent_bom_strict", False):
        return hardened

    async def _strict_call_tool(name: str, arguments: dict[str, Any], *args: Any, **kwargs: Any) -> Any:
        tool = manager.get_tool(name)
        if tool is not None and isinstance(arguments, dict):
            accepted = _accepted_keys_for_tool(tool)
            unknown = sorted(set(arguments) - accepted)
            if unknown:
                from mcp.server.fastmcp.exceptions import ToolError

                raise ToolError(
                    f"Unknown argument(s) for tool '{name}': {unknown}. "
                    f"Accepted: {sorted(accepted)}. "
                    "(These previously were silently dropped, which let AI agents "
                    "get false-clean verdicts on typo args -- now they fail loudly.)"
                )
        return await original_call(name, arguments, *args, **kwargs)

    _strict_call_tool._agent_bom_strict = True  # type: ignore[attr-defined]
    manager.call_tool = _strict_call_tool  # type: ignore[method-assign]
    return hardened


def _accepted_keys_for_tool(tool: Any) -> frozenset[str]:
    """Return the set of argument names the tool's signature actually accepts."""
    params = getattr(tool, "parameters", None) or {}
    properties = params.get("properties", {})
    if isinstance(properties, dict):
        return frozenset(str(k) for k in properties.keys())
    return frozenset()


__all__ = ["harden_tool_arguments"]
