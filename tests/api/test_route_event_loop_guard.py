"""Event-loop guard: async route handlers must not run blocking work directly.

A single sync network call or heavy store scan inside an ``async def`` handler
freezes ``/health`` and every unrelated request for its full duration (measured
10.18s from one black-holed SIEM/connector probe). The fix idiom is the
``anyio.to_thread.run_sync`` / ``asyncio.to_thread`` offload used across the
API (``hub_store_call``, the cloud route offloads, ``_store_call`` in fleet).

The AST guard below keeps the class closed: it walks every async route handler
in ``agent_bom.api.routes`` and fails on any *direct* call to a denylisted
known-blocking callable — sync HTTP clients, ``time.sleep``, connector
``health_check``, and the heavy store methods that were caught running on-loop
(#4277). Calls inside nested ``def`` bodies are exempt: those are the sync
bodies handed to ``to_thread``, which run in a worker thread.

The behavioral test proves the offload for one representative handler: with the
blocking internal replaced by ``time.sleep``, a concurrent trivial coroutine
must still complete promptly while the handler is in flight.
"""

from __future__ import annotations

import ast
import asyncio
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import agent_bom.api.routes as routes_pkg

ROUTES_DIR = Path(routes_pkg.__file__).resolve().parent

HTTP_VERBS = {"get", "post", "put", "delete", "patch", "head", "options", "websocket", "api_route"}

# Module roots whose direct calls are sync network/IO on the loop.
BLOCKING_MODULE_ROOTS = {"requests", "urllib", "socket", "httpx"}

# Exact dotted callables that block.
BLOCKING_DOTTED = {"time.sleep"}

# Any ``<obj>.health_check()`` is a sync connector probe (SIEM, ticketing, …).
BLOCKING_ATTR_CALLS = {"health_check"}

# ``<getter>().<method>(...)`` chains that hit a store synchronously with
# unbounded / per-tenant-scan work. A bare getter call is fine (cheap handle);
# invoking these methods on the loop is not.
BLOCKING_STORE_GETTERS = {"get_ticketing_store", "get_compliance_hub_store"}
BLOCKING_STORE_METHODS = {
    ("_get_store", "list_all"),
    ("_get_store", "put"),
    ("_get_analytics_store", "record_events"),
    ("get_campaign_store", "list_verification_queue"),
}


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _callable_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


class _BlockingCallFinder(ast.NodeVisitor):
    def __init__(self) -> None:
        self.violations: list[tuple[int, str]] = []

    # Nested sync defs are the offload bodies handed to to_thread — worker-thread code.
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        dotted = _dotted(func)
        root = dotted.split(".", 1)[0]
        if root in BLOCKING_MODULE_ROOTS:
            self.violations.append((node.lineno, dotted))
        if dotted in BLOCKING_DOTTED:
            self.violations.append((node.lineno, dotted))
        if isinstance(func, ast.Attribute):
            if func.attr in BLOCKING_ATTR_CALLS:
                self.violations.append((node.lineno, f"{dotted}()"))
            if isinstance(func.value, ast.Call):
                getter = _callable_name(func.value.func)
                if getter in BLOCKING_STORE_GETTERS or (getter, func.attr) in BLOCKING_STORE_METHODS:
                    self.violations.append((node.lineno, f"{getter}().{func.attr}"))
        self.generic_visit(node)


def _iter_route_handlers(tree: ast.Module):
    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncFunctionDef):
            continue
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr in HTTP_VERBS:
                yield node
                break


def test_async_route_handlers_never_call_blocking_work_on_the_loop():
    violations: list[str] = []
    for path in sorted(ROUTES_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for handler in _iter_route_handlers(tree):
            finder = _BlockingCallFinder()
            for stmt in handler.body:
                finder.visit(stmt)
            violations.extend(f"{path.name}:{lineno} {handler.name}: {what}" for lineno, what in finder.violations)
    assert violations == [], (
        "Blocking call(s) running directly on the event loop in async route handlers "
        "(offload via anyio.to_thread.run_sync / asyncio.to_thread):\n" + "\n".join(violations)
    )


async def _trivial() -> str:
    return "responsive"


@pytest.mark.asyncio
async def test_slow_siem_health_check_keeps_event_loop_responsive(monkeypatch):
    """A hung SIEM probe must not pin the loop — the offload proves it."""
    import agent_bom.siem as siem_mod
    from agent_bom.api import audit_log
    from agent_bom.api.routes import enterprise

    monkeypatch.setattr(enterprise, "require_request_tenant_id", lambda request: "t-siem")
    monkeypatch.setattr(audit_log, "log_action", lambda *args, **kwargs: None)

    block_seconds = 0.5

    class _SlowConnector:
        def health_check(self) -> bool:
            time.sleep(block_seconds)
            return True

    monkeypatch.setattr(siem_mod, "create_connector", lambda *args, **kwargs: _SlowConnector())

    request = SimpleNamespace(state=SimpleNamespace(api_key_name="tester"))
    loop = asyncio.get_running_loop()
    task = asyncio.create_task(enterprise.test_siem_connection(request=request, siem_type="splunk", url="", token=""))
    await asyncio.sleep(0.05)
    assert not task.done(), "probe should still be in flight"

    started = loop.time()
    assert await asyncio.wait_for(_trivial(), timeout=0.15) == "responsive"
    assert loop.time() - started < block_seconds / 2, "event loop was blocked during the SIEM probe — offload ineffective"

    result = await task
    assert result == {"siem_type": "splunk", "healthy": True}
