"""Shared runtime helpers for the MCP server.

This module intentionally contains implementation details behind the stable
``agent_bom.mcp_server`` wrapper functions so the public import surface can stay
unchanged while the monolith is decomposed.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from pathlib import Path
from typing import AbstractSet, Any, Awaitable, Callable, TypeVar

from agent_bom.security import sanitize_log_label

_ToolReturn = TypeVar("_ToolReturn")

try:
    from mcp.server.fastmcp.exceptions import ToolError as _FastMCPToolError
except ModuleNotFoundError:  # pragma: no cover - base CLI installs do not include MCP extras
    _TOOL_ERROR_TYPES: tuple[type[BaseException], ...] = ()
else:
    _TOOL_ERROR_TYPES = (_FastMCPToolError,)


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


def _log_value(value: object, *, max_len: int = 160) -> str:
    return sanitize_log_label(value, max_len=max_len) or "-"


def _error_payload(tool_name: str, error: str) -> str:
    return json.dumps({"error": error, "tool": tool_name, "status": "error"})


def _is_tool_error(exc: Exception) -> bool:
    return bool(_TOOL_ERROR_TYPES) and isinstance(exc, _TOOL_ERROR_TYPES)


def _raise_sanitized_tool_error(exc: Exception, sanitized: str) -> None:
    raise type(exc)(sanitized) from None


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


def _verified_token_caller(current_request: Any) -> str | None:
    """Return a stable caller key bound to the verified access token, if any.

    Keying the rate-limit window on the authenticated identity (the token's
    ``client_id`` or, failing that, a hash of the token material) means a caller
    cannot reset its window simply by opening a fresh connection. Returns None
    when no verified token is attached so unauthenticated/local callers fall
    back to the per-connection label.
    """
    holders: list[Any] = []
    for holder_name in ("access_token", "auth", "token"):
        holder = getattr(current_request, holder_name, None)
        if holder is not None:
            holders.append(holder)
    experimental = getattr(current_request, "experimental", None)
    if experimental is not None:
        for holder_name in ("access_token", "auth", "token"):
            holder = getattr(experimental, holder_name, None)
            if holder is not None:
                holders.append(holder)
    for holder in holders:
        client_id = getattr(holder, "client_id", None)
        if client_id and str(client_id).strip():
            return f"token-client:{str(client_id).strip()}"
        for token_attr in ("token", "access_token", "jti"):
            raw = getattr(holder, token_attr, None)
            if isinstance(raw, str) and raw.strip():
                return f"token-hash:{hashlib.sha256(raw.strip().encode()).hexdigest()[:32]}"
    return None


def current_tool_request(request_ctx_getter: Callable[[], Any]) -> dict[str, str | None]:
    try:
        current_request = request_ctx_getter()
    except LookupError:
        return {"caller": "local", "client_id": None, "request_id": None, "auth_scopes": ""}

    meta = getattr(current_request, "meta", None)
    client_id = getattr(meta, "client_id", None) if meta else None
    session = getattr(current_request, "session", None)
    session_label = f"session-{id(session) % 1_000_000}" if session is not None else "local"
    auth_scopes: set[str] = set()
    for holder_name in ("access_token", "auth", "token"):
        holder = getattr(current_request, holder_name, None)
        scopes = getattr(holder, "scopes", None)
        if isinstance(scopes, list | tuple | set):
            auth_scopes.update(str(scope).strip().lower() for scope in scopes if str(scope).strip())
    experimental = getattr(current_request, "experimental", None)
    for holder_name in ("access_token", "auth", "token"):
        holder = getattr(experimental, holder_name, None) if experimental is not None else None
        scopes = getattr(holder, "scopes", None)
        if isinstance(scopes, list | tuple | set):
            auth_scopes.update(str(scope).strip().lower() for scope in scopes if str(scope).strip())
    # Prefer the verified access-token identity so a hostile caller cannot reset
    # its rate-limit window by reconnecting (which mints a fresh per-connection
    # session object id). The client-declared meta.client_id is only a fallback
    # for unauthenticated/local transports.
    verified_caller = _verified_token_caller(current_request)
    return {
        "caller": verified_caller or client_id or session_label,
        "client_id": client_id,
        "request_id": str(getattr(current_request, "request_id", "")) or None,
        "auth_scopes": ",".join(sorted(auth_scopes)),
    }


_GLOBAL_CALLER_KEY = "__mcp_global__"


def _hit_rate_window(
    caller_rate_windows,
    key: str,
    *,
    limit: int,
    window_seconds: float,
    max_caller_states: int,
    monotonic_now: float,
) -> float | None:
    """Slide one bounded window. Returns retry-after seconds when over budget."""
    window = caller_rate_windows.get(key)
    if window is None:
        if len(caller_rate_windows) >= max_caller_states:
            # Never evict the reserved global backstop bucket.
            oldest = next(iter(caller_rate_windows))
            if oldest == _GLOBAL_CALLER_KEY and len(caller_rate_windows) > 1:
                caller_rate_windows.move_to_end(_GLOBAL_CALLER_KEY)
            caller_rate_windows.popitem(last=False)
        from collections import deque

        window = deque()
        caller_rate_windows[key] = window
    else:
        caller_rate_windows.move_to_end(key)

    cutoff = monotonic_now - window_seconds
    while window and window[0] <= cutoff:
        window.popleft()

    if len(window) >= limit:
        return round(max(0.0, window_seconds - (monotonic_now - window[0])), 3)

    window.append(monotonic_now)
    return None


def check_caller_rate_limit(
    caller_rate_windows,
    caller: str,
    *,
    caller_rate_limit: int,
    caller_window_seconds: float,
    max_caller_states: int,
    monotonic_now: float,
    global_rate_limit: int = 0,
    global_window_seconds: float | None = None,
) -> float | None:
    if caller_rate_limit > 0:
        retry_after = _hit_rate_window(
            caller_rate_windows,
            caller,
            limit=caller_rate_limit,
            window_seconds=caller_window_seconds,
            max_caller_states=max_caller_states,
            monotonic_now=monotonic_now,
        )
        if retry_after is not None:
            return retry_after

    # Process-wide backstop: a flood spread across many distinct (or
    # per-connection) caller identities is still capped in aggregate.
    if global_rate_limit > 0:
        return _hit_rate_window(
            caller_rate_windows,
            _GLOBAL_CALLER_KEY,
            limit=global_rate_limit,
            window_seconds=global_window_seconds or caller_window_seconds,
            max_caller_states=max_caller_states,
            monotonic_now=monotonic_now,
        )
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


# Write / destructive MCP tools (``destructiveHint: true`` / ``readOnlyHint:
# false``) accept ``operator_role`` + ``operator_scopes`` as audit/request
# context, but dispatch authorization is bound to the authenticated MCP request
# scopes. A tool argument can no longer self-assert admin authority.
_WRITE_SCOPE_WILDCARDS = ("*", "admin:*", "write", "*:write")


def _scope_set(operator_scopes: str) -> set[str]:
    return {part.strip().lower() for part in (operator_scopes or "").split(",") if part.strip()}


def authorize_destructive_tool(
    tool_name: str,
    *,
    operator_role: str,
    operator_scopes: str,
    auth_scopes: str = "",
    required_scope: str | None = None,
) -> dict[str, Any] | None:
    """Authorize a destructive MCP tool. Return an error payload, or None if allowed.

    Fails closed: a destructive tool requires an authenticated admin/operator
    token. ``operator_role`` and ``operator_scopes`` are retained for audit
    context and handler compatibility, but cannot authorize a write by
    themselves. When ``required_scope`` is supplied, the authenticated scopes
    must include it (or a recognized wildcard).
    """
    normalized_role = (operator_role or "").strip().lower()
    trusted_scopes = _scope_set(auth_scopes)
    has_authenticated_admin = bool(trusted_scopes & {"admin", "operator", "admin:*", "*"})
    if not has_authenticated_admin:
        return {
            "error": f"tool '{tool_name}' is a write action and requires an authenticated operator token",
            "tool": tool_name,
            "status": "blocked",
            "required_role": "admin",
            "provided_role": normalized_role or "unset",
        }
    if required_scope:
        wanted = required_scope.strip().lower()
        family = wanted.split(":", 1)[0]
        allowed = trusted_scopes & ({wanted, f"{family}:*", *(_WRITE_SCOPE_WILDCARDS)})
        if not allowed:
            return {
                "error": f"tool '{tool_name}' requires the '{wanted}' scope",
                "tool": tool_name,
                "status": "blocked",
                "required_role": "admin",
                "required_scope": wanted,
            }
    return None


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
    destructive: bool = False,
    required_scope: str | None = None,
    **kwargs,
) -> _ToolReturn | str:
    request_meta = request_meta_factory()
    if destructive:
        authenticated_actor = request_meta.get("client_id") or request_meta.get("caller") or "mcp-operator"
        kwargs.setdefault("_authenticated_actor", authenticated_actor)
        auth_scopes = str(request_meta.get("auth_scopes", "") or "")
        denial = authorize_destructive_tool(
            tool_name,
            operator_role=str(kwargs.get("operator_role", "") or ""),
            operator_scopes=str(kwargs.get("operator_scopes", "") or ""),
            auth_scopes=auth_scopes,
            required_scope=required_scope,
        )
        if denial is not None:
            log_caller = _log_value(request_meta["caller"])
            log_actor = _log_value(str(authenticated_actor or "unset"))
            record_tool_metric_fn(tool_name, elapsed_ms=0, success=False, error="forbidden")
            record_tool_request_fn(
                tool_name,
                caller=request_meta["caller"],
                client_id=request_meta["client_id"],
                request_id=request_meta["request_id"],
                status="forbidden",
                elapsed_ms=0,
                error="forbidden",
            )
            logger.warning(
                "mcp tool forbidden: %s caller=%s actor=%r",
                tool_name,
                log_caller,
                log_actor,
            )
            return truncate_response_fn(json.dumps(denial))
        if _scope_set(auth_scopes) & {"admin", "operator", "admin:*", "*"}:
            kwargs["operator_role"] = "admin"
    log_caller = _log_value(request_meta["caller"])
    log_request_id = _log_value(request_meta["request_id"])
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
        logger.warning("mcp tool rate limited: %s caller=%s retry_after=%.3fs", tool_name, log_caller, retry_after)
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
    logger.info("mcp tool start: %s caller=%s request_id=%s", tool_name, log_caller, log_request_id)
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
        logger.warning("mcp tool timed out: %s caller=%s after %.1fs", tool_name, log_caller, timeout_seconds)
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
        sanitized = _log_value(sanitize_error_fn(exc), max_len=200)
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
        logger.warning("mcp tool failed: %s caller=%s (%s)", tool_name, log_caller, sanitized)
        if _is_tool_error(exc):
            _raise_sanitized_tool_error(exc, sanitized)
        return truncate_response_fn(_error_payload(tool_name, sanitized))
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
    logger.info("mcp tool ok: %s caller=%s (%dms)", tool_name, log_caller, elapsed_ms)
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
    log_caller = _log_value(request_meta["caller"])
    log_request_id = _log_value(request_meta["request_id"])
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
        logger.warning("mcp tool rate limited: %s caller=%s retry_after=%.3fs", tool_name, log_caller, retry_after)
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
        logger.info("mcp tool start: %s caller=%s request_id=%s", tool_name, log_caller, log_request_id)
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
            logger.warning("mcp tool timed out: %s caller=%s after %.1fs", tool_name, log_caller, timeout_seconds)
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
            sanitized = _log_value(sanitize_error_fn(exc), max_len=200)
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
            logger.warning("mcp tool failed: %s caller=%s (%s)", tool_name, log_caller, sanitized)
            if _is_tool_error(exc):
                _raise_sanitized_tool_error(exc, sanitized)
            return truncate_response_fn(_error_payload(tool_name, sanitized))
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
        logger.info("mcp tool ok: %s caller=%s (%dms)", tool_name, log_caller, elapsed_ms)
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
