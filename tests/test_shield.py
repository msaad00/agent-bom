from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor

from agent_bom.shield import Shield


def test_shield_check_tool_call_uses_async_bridge_in_running_loop(monkeypatch):
    shield = Shield()

    async def fake_process_tool_call(tool_name: str, arguments: dict) -> list[dict]:
        return [{"tool": tool_name, "arguments": arguments}]

    class _Future:
        def __init__(self, value):
            self._value = value

        def result(self):
            return self._value

    submitted = {}

    class _Executor:
        def submit(self, fn, coro):
            submitted["fn"] = fn
            submitted["coro"] = coro
            with ThreadPoolExecutor(max_workers=1) as pool:
                return _Future(pool.submit(fn, coro).result())

    monkeypatch.setattr(shield._engine, "process_tool_call", fake_process_tool_call)
    monkeypatch.setattr("agent_bom.shield._SHIELD_ASYNC_BRIDGE", _Executor())

    async def _run():
        return shield.check_tool_call("read_file", {"path": "/tmp/demo"})

    result = asyncio.run(_run())

    assert submitted["fn"] is asyncio.run
    assert result == [{"tool": "read_file", "arguments": {"path": "/tmp/demo"}}]


def test_shield_check_response_runs_without_async_loop(monkeypatch):
    shield = Shield()

    async def fake_process_tool_response(tool_name: str, response_text: str) -> list[dict]:
        return [{"tool": tool_name, "response": response_text}]

    monkeypatch.setattr(shield._engine, "process_tool_response", fake_process_tool_response)

    result = shield.check_response("read_file", "ok")

    assert result == [{"tool": "read_file", "response": "ok"}]
