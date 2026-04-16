"""Shared runtime helpers for the MCP server.

This module intentionally contains implementation details behind the stable
``agent_bom.mcp_server`` wrapper functions so the public import surface can stay
unchanged while the monolith is decomposed.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import AbstractSet, Any, Awaitable, Callable, TypeVar

_ToolReturn = TypeVar("_ToolReturn")


def validate_ecosystem(ecosystem: str, valid_ecosystems: AbstractSet[str]) -> str:
    cleaned = ecosystem.lower().strip()
    if cleaned not in valid_ecosystems:
        raise ValueError(f"Invalid ecosystem: {ecosystem!r}. Valid: {', '.join(sorted(valid_ecosystems))}")
    return cleaned


def validate_cve_id(cve_id: str, cve_re, ghsa_re) -> str:  # noqa: ANN001
    cleaned = cve_id.strip()
    if not cleaned:
        raise ValueError("CVE ID cannot be empty")
    if not (cve_re.match(cleaned) or ghsa_re.match(cleaned)):
        raise ValueError(f"Invalid CVE ID format: {cleaned!r}. Expected CVE-YYYY-NNNNN or GHSA-xxxx-xxxx-xxxx")
    return cleaned


def truncate_response(response_str: str, max_response_chars: int) -> str:
    if len(response_str) <= max_response_chars:
        return response_str
    return (
        response_str[:max_response_chars] + '\n\n{"_truncated": true, "message": '
        '"Response truncated at 500,000 characters. '
        'Use more specific parameters to reduce output size."}'
    )


def safe_path(path_str: str) -> Path:
    from agent_bom.security import SecurityError, validate_path

    try:
        return validate_path(path_str, restrict_to_home=True)
    except SecurityError as exc:
        raise ValueError(str(exc)) from exc


def get_tool_semaphore(
    loop_tool_semaphores,
    *,
    max_cached_tool_loops: int,
    max_concurrent_tools: int,
) -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    loop_id = id(loop)
    semaphore = loop_tool_semaphores.get(loop_id)
    if semaphore is None:
        if len(loop_tool_semaphores) >= max_cached_tool_loops:
            loop_tool_semaphores.popitem(last=False)
        semaphore = asyncio.Semaphore(max_concurrent_tools)
        loop_tool_semaphores[loop_id] = semaphore
    else:
        loop_tool_semaphores.move_to_end(loop_id)
    return semaphore


def record_tool_metric(
    tool_metrics,
    *,
    max_tool_metrics: int,
    tool_name: str,
    elapsed_ms: int,
    success: bool,
    timed_out: bool = False,
    error: str | None = None,
) -> None:
    metrics = tool_metrics.get(tool_name)
    if metrics is None:
        if len(tool_metrics) >= max_tool_metrics:
            tool_metrics.popitem(last=False)
        metrics = {
            "tool": tool_name,
            "calls": 0,
            "failures": 0,
            "timeouts": 0,
            "last_status": "unknown",
            "last_error": None,
            "last_elapsed_ms": 0,
            "max_elapsed_ms": 0,
            "total_elapsed_ms": 0,
        }
        tool_metrics[tool_name] = metrics
    else:
        tool_metrics.move_to_end(tool_name)

    metrics["calls"] += 1
    metrics["last_status"] = "ok" if success else ("timeout" if timed_out else "error")
    metrics["last_error"] = None if success else error
    metrics["last_elapsed_ms"] = elapsed_ms
    metrics["max_elapsed_ms"] = max(metrics["max_elapsed_ms"], elapsed_ms)
    metrics["total_elapsed_ms"] += elapsed_ms
    if not success:
        metrics["failures"] += 1
    if timed_out:
        metrics["timeouts"] += 1


def tool_metrics_snapshot(
    tool_metrics,
    *,
    caller_rate_windows,
    recent_tool_requests,
    max_concurrent_tools: int,
    tool_timeout_seconds: float,
    caller_rate_limit: int,
    caller_window_seconds: float,
) -> dict[str, Any]:
    tool_stats = []
    total_calls = 0
    total_failures = 0
    total_timeouts = 0
    for name, metrics in tool_metrics.items():
        calls = int(metrics["calls"])
        total_calls += calls
        total_failures += int(metrics["failures"])
        total_timeouts += int(metrics["timeouts"])
        tool_stats.append(
            {
                "tool": name,
                "calls": calls,
                "failures": int(metrics["failures"]),
                "timeouts": int(metrics["timeouts"]),
                "last_status": metrics["last_status"],
                "last_error": metrics["last_error"],
                "last_elapsed_ms": int(metrics["last_elapsed_ms"]),
                "max_elapsed_ms": int(metrics["max_elapsed_ms"]),
                "avg_elapsed_ms": round(int(metrics["total_elapsed_ms"]) / calls, 2) if calls else 0.0,
            }
        )
    return {
        "summary": {
            "tool_count": len(tool_stats),
            "total_calls": total_calls,
            "total_failures": total_failures,
            "total_timeouts": total_timeouts,
            "max_concurrent_tools": max_concurrent_tools,
            "default_timeout_seconds": tool_timeout_seconds,
            "caller_rate_limit_per_window": caller_rate_limit,
            "caller_rate_limit_window_seconds": caller_window_seconds,
            "tracked_callers": len(caller_rate_windows),
            "recent_request_count": len(recent_tool_requests),
        },
        "tools": tool_stats,
        "recent_requests": list(recent_tool_requests),
    }


def current_tool_request(request_ctx_getter: Callable[[], Any]) -> dict[str, str | None]:
    try:
        current_request = request_ctx_getter()
    except LookupError:
        return {"caller": "local", "client_id": None, "request_id": None}

    meta = getattr(current_request, "meta", None)
    client_id = getattr(meta, "client_id", None) if meta else None
    session = getattr(current_request, "session", None)
    session_label = f"session-{id(session) % 1_000_000}" if session is not None else "local"
    return {
        "caller": client_id or session_label,
        "client_id": client_id,
        "request_id": str(getattr(current_request, "request_id", "")) or None,
    }


def check_caller_rate_limit(
    caller_rate_windows,
    caller: str,
    *,
    caller_rate_limit: int,
    caller_window_seconds: float,
    max_caller_states: int,
    monotonic_now: float,
) -> float | None:
    if caller_rate_limit <= 0:
        return None

    window = caller_rate_windows.get(caller)
    if window is None:
        if len(caller_rate_windows) >= max_caller_states:
            caller_rate_windows.popitem(last=False)
        from collections import deque

        window = deque()
        caller_rate_windows[caller] = window
    else:
        caller_rate_windows.move_to_end(caller)

    cutoff = monotonic_now - caller_window_seconds
    while window and window[0] <= cutoff:
        window.popleft()

    if len(window) >= caller_rate_limit:
        return round(max(0.0, caller_window_seconds - (monotonic_now - window[0])), 3)

    window.append(monotonic_now)
    return None


def record_tool_request(
    recent_tool_requests,
    tool_name: str,
    *,
    caller: str | None,
    client_id: str | None,
    request_id: str | None,
    status: str,
    elapsed_ms: int,
    error: str | None = None,
) -> None:
    recent_tool_requests.append(
        {
            "tool": tool_name,
            "caller": caller or "local",
            "client_id": client_id,
            "request_id": request_id,
            "status": status,
            "elapsed_ms": elapsed_ms,
            "error": error,
            "ts": int(time.time()),
        }
    )


async def execute_tool_async(
    tool_name: str,
    handler: Callable[..., Awaitable[_ToolReturn]],
    /,
    *args,
    timeout_seconds: float,
    request_meta_factory: Callable[[], dict[str, str | None]],
    check_caller_rate_limit_fn: Callable[[str], float | None],
    record_tool_metric_fn: Callable[..., None],
    record_tool_request_fn: Callable[..., None],
    truncate_response_fn: Callable[[str], str],
    get_tool_semaphore_fn: Callable[[], asyncio.Semaphore],
    sanitize_error_fn: Callable[[Exception], str],
    logger,
    **kwargs,
) -> _ToolReturn | str:
    request_meta = request_meta_factory()
    retry_after = check_caller_rate_limit_fn(request_meta["caller"] or "local")
    if retry_after is not None:
        record_tool_metric_fn(tool_name, elapsed_ms=0, success=False, error="rate limited")
        record_tool_request_fn(
            tool_name,
            caller=request_meta["caller"],
            client_id=request_meta["client_id"],
            request_id=request_meta["request_id"],
            status="rate_limited",
            elapsed_ms=0,
            error="rate limited",
        )
        logger.warning("mcp tool rate limited: %s caller=%s retry_after=%.3fs", tool_name, request_meta["caller"], retry_after)
        return truncate_response_fn(
            json.dumps(
                {
                    "error": f"Tool '{tool_name}' exceeded the caller rate limit",
                    "tool": tool_name,
                    "rate_limited": True,
                    "retry_after_seconds": retry_after,
                }
            )
        )
    start = time.perf_counter()
    logger.info("mcp tool start: %s caller=%s request_id=%s", tool_name, request_meta["caller"], request_meta["request_id"])
    try:
        async with get_tool_semaphore_fn():
            result = await asyncio.wait_for(handler(*args, **kwargs), timeout=timeout_seconds)
    except TimeoutError:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        record_tool_metric_fn(
            tool_name,
            elapsed_ms=elapsed_ms,
            success=False,
            timed_out=True,
            error=f"timed out after {timeout_seconds:.1f}s",
        )
        record_tool_request_fn(
            tool_name,
            caller=request_meta["caller"],
            client_id=request_meta["client_id"],
            request_id=request_meta["request_id"],
            status="timeout",
            elapsed_ms=elapsed_ms,
            error=f"timed out after {timeout_seconds:.1f}s",
        )
        logger.warning("mcp tool timed out: %s caller=%s after %.1fs", tool_name, request_meta["caller"], timeout_seconds)
        return truncate_response_fn(
            json.dumps(
                {
                    "error": f"Tool '{tool_name}' timed out after {timeout_seconds:.1f}s",
                    "tool": tool_name,
                    "timed_out": True,
                }
            )
        )
    except Exception as exc:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        sanitized = sanitize_error_fn(exc)
        record_tool_metric_fn(tool_name, elapsed_ms=elapsed_ms, success=False, error=sanitized)
        record_tool_request_fn(
            tool_name,
            caller=request_meta["caller"],
            client_id=request_meta["client_id"],
            request_id=request_meta["request_id"],
            status="error",
            elapsed_ms=elapsed_ms,
            error=sanitized,
        )
        logger.warning("mcp tool failed: %s caller=%s (%s)", tool_name, request_meta["caller"], sanitized)
        raise
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    record_tool_metric_fn(tool_name, elapsed_ms=elapsed_ms, success=True)
    record_tool_request_fn(
        tool_name,
        caller=request_meta["caller"],
        client_id=request_meta["client_id"],
        request_id=request_meta["request_id"],
        status="ok",
        elapsed_ms=elapsed_ms,
    )
    logger.info("mcp tool ok: %s caller=%s (%dms)", tool_name, request_meta["caller"], elapsed_ms)
    return result


async def execute_tool_sync_async(
    tool_name: str,
    handler: Callable[..., _ToolReturn],
    /,
    *args,
    timeout_seconds: float,
    request_meta_factory: Callable[[], dict[str, str | None]],
    check_caller_rate_limit_fn: Callable[[str], float | None],
    record_tool_metric_fn: Callable[..., None],
    record_tool_request_fn: Callable[..., None],
    truncate_response_fn: Callable[[str], str],
    get_tool_semaphore_fn: Callable[[], asyncio.Semaphore],
    sanitize_error_fn: Callable[[Exception], str],
    logger,
    **kwargs,
) -> _ToolReturn | str:
    request_meta = request_meta_factory()
    retry_after = check_caller_rate_limit_fn(request_meta["caller"] or "local")
    if retry_after is not None:
        record_tool_metric_fn(tool_name, elapsed_ms=0, success=False, error="rate limited")
        record_tool_request_fn(
            tool_name,
            caller=request_meta["caller"],
            client_id=request_meta["client_id"],
            request_id=request_meta["request_id"],
            status="rate_limited",
            elapsed_ms=0,
            error="rate limited",
        )
        logger.warning("mcp tool rate limited: %s caller=%s retry_after=%.3fs", tool_name, request_meta["caller"], retry_after)
        return truncate_response_fn(
            json.dumps(
                {
                    "error": f"Tool '{tool_name}' exceeded the caller rate limit",
                    "tool": tool_name,
                    "rate_limited": True,
                    "retry_after_seconds": retry_after,
                }
            )
        )
    async with get_tool_semaphore_fn():
        start = time.perf_counter()
        logger.info("mcp tool start: %s caller=%s request_id=%s", tool_name, request_meta["caller"], request_meta["request_id"])
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(handler, *args, **kwargs),
                timeout=timeout_seconds,
            )
        except asyncio.TimeoutError:
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            record_tool_metric_fn(
                tool_name,
                elapsed_ms=elapsed_ms,
                success=False,
                timed_out=True,
                error=f"timed out after {timeout_seconds:.1f}s",
            )
            record_tool_request_fn(
                tool_name,
                caller=request_meta["caller"],
                client_id=request_meta["client_id"],
                request_id=request_meta["request_id"],
                status="timeout",
                elapsed_ms=elapsed_ms,
                error=f"timed out after {timeout_seconds:.1f}s",
            )
            logger.warning("mcp tool timed out: %s caller=%s after %.1fs", tool_name, request_meta["caller"], timeout_seconds)
            return truncate_response_fn(
                json.dumps(
                    {
                        "error": f"Tool '{tool_name}' timed out after {timeout_seconds:.1f}s",
                        "tool": tool_name,
                        "timed_out": True,
                    }
                )
            )
        except Exception as exc:
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            sanitized = sanitize_error_fn(exc)
            record_tool_metric_fn(tool_name, elapsed_ms=elapsed_ms, success=False, error=sanitized)
            record_tool_request_fn(
                tool_name,
                caller=request_meta["caller"],
                client_id=request_meta["client_id"],
                request_id=request_meta["request_id"],
                status="error",
                elapsed_ms=elapsed_ms,
                error=sanitized,
            )
            logger.warning("mcp tool failed: %s caller=%s (%s)", tool_name, request_meta["caller"], sanitized)
            raise
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        record_tool_metric_fn(tool_name, elapsed_ms=elapsed_ms, success=True)
        record_tool_request_fn(
            tool_name,
            caller=request_meta["caller"],
            client_id=request_meta["client_id"],
            request_id=request_meta["request_id"],
            status="ok",
            elapsed_ms=elapsed_ms,
        )
        logger.info("mcp tool ok: %s caller=%s (%dms)", tool_name, request_meta["caller"], elapsed_ms)
        return result


def get_registry_data(registry_cache: dict | None, registry_path: Path) -> dict:
    if registry_cache is None:
        return json.loads(registry_path.read_text())
    return registry_cache


def get_registry_data_raw(registry_raw_cache: str | None, registry_path: Path) -> str:
    if registry_raw_cache is None:
        return registry_path.read_text()
    return registry_raw_cache


def check_mcp_sdk() -> None:
    try:
        import mcp  # noqa: F401
    except ImportError:
        raise ImportError("mcp SDK is required for the MCP server. Install with: pip install 'agent-bom[mcp-server]'") from None
