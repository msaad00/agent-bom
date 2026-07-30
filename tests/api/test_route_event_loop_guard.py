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

# Imported functions whose implementation is known to perform blocking IO.
BLOCKING_IMPORTED_CALLS = {"agent_bom.intel_lookup.list_intel_sources"}

# Heavy sync helpers defined in the route module itself.
BLOCKING_LOCAL_CALLS = {"_build_agents_response"}

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


def _import_aliases(tree: ast.Module) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if alias.name != "*":
                    aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        elif isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".", 1)[0]] = alias.name
    return aliases


def _resolve_dotted(dotted: str, aliases: dict[str, str]) -> str:
    root, separator, remainder = dotted.partition(".")
    resolved_root = aliases.get(root, root)
    return f"{resolved_root}.{remainder}" if separator else resolved_root


class _BlockingCallFinder(ast.NodeVisitor):
    def __init__(self, aliases: dict[str, str]) -> None:
        self.violations: list[tuple[int, str]] = []
        self.aliases = aliases

    # Nested sync defs are the offload bodies handed to to_thread — worker-thread code.
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        dotted = _dotted(func)
        resolved = _resolve_dotted(dotted, self.aliases)
        root = resolved.split(".", 1)[0]
        if root in BLOCKING_MODULE_ROOTS:
            self.violations.append((node.lineno, resolved))
        if resolved in BLOCKING_DOTTED or resolved in BLOCKING_IMPORTED_CALLS:
            self.violations.append((node.lineno, resolved))
        if isinstance(func, ast.Name) and func.id in BLOCKING_LOCAL_CALLS:
            self.violations.append((node.lineno, func.id))
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
        aliases = _import_aliases(tree)
        for handler in _iter_route_handlers(tree):
            finder = _BlockingCallFinder(aliases)
            for stmt in handler.body:
                finder.visit(stmt)
            violations.extend(f"{path.name}:{lineno} {handler.name}: {what}" for lineno, what in finder.violations)
    assert violations == [], (
        "Blocking call(s) running directly on the event loop in async route handlers "
        "(offload via anyio.to_thread.run_sync / asyncio.to_thread):\n" + "\n".join(violations)
    )


def test_imported_blocking_callable_alias_is_detected() -> None:
    tree = ast.parse(
        """
from agent_bom.intel_lookup import list_intel_sources as sources

async def handler():
    return sources()
"""
    )
    handler = next(node for node in tree.body if isinstance(node, ast.AsyncFunctionDef))
    finder = _BlockingCallFinder(_import_aliases(tree))
    for statement in handler.body:
        finder.visit(statement)
    assert finder.violations == [(5, "agent_bom.intel_lookup.list_intel_sources")]


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


@pytest.mark.asyncio
async def test_slow_intel_source_listing_keeps_event_loop_responsive(monkeypatch):
    from agent_bom.api.routes import intel

    block_seconds = 0.5

    def _slow_sources() -> dict[str, object]:
        time.sleep(block_seconds)
        return {"sources": []}

    monkeypatch.setattr(intel, "list_intel_sources", _slow_sources)
    task = asyncio.create_task(intel.get_intel_sources())
    await asyncio.sleep(0.05)
    assert not task.done(), "source listing should still be in flight"

    started = asyncio.get_running_loop().time()
    assert await asyncio.wait_for(_trivial(), timeout=0.15) == "responsive"
    assert asyncio.get_running_loop().time() - started < block_seconds / 2
    assert await task == {"sources": []}


@pytest.mark.asyncio
async def test_slow_agent_discovery_keeps_event_loop_responsive(monkeypatch):
    from agent_bom.api.routes import discovery

    block_seconds = 0.5

    def _slow_agents(_tenant_id: str) -> dict[str, object]:
        time.sleep(block_seconds)
        return {"agents": [], "count": 0}

    discovery._clear_agents_response_cache_for_tests()
    monkeypatch.setattr(discovery, "_tenant_id", lambda _request: "tenant-agents")
    monkeypatch.setattr(discovery, "_build_agents_response", _slow_agents)
    task = asyncio.create_task(discovery.list_agents(SimpleNamespace(), refresh=True))
    await asyncio.sleep(0.05)
    assert not task.done(), "agent discovery should still be in flight"

    started = asyncio.get_running_loop().time()
    assert await asyncio.wait_for(_trivial(), timeout=0.15) == "responsive"
    assert asyncio.get_running_loop().time() - started < block_seconds / 2
    assert await task == {"agents": [], "count": 0}
