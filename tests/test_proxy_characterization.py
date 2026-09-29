"""Golden characterization of the stdio proxy relay (``run_proxy``).

Each scenario drives a scripted JSON-RPC session through ``run_proxy`` against a
deterministic fake MCP server and compares, byte-for-byte after normalising
timestamps and random identifiers:

* the frames forwarded to the server,
* the frames written to the client,
* the audit JSONL records,
* the batches pushed to the control plane (when enabled),
* the return code.

The scripted client waits for each expected response before sending the next
frame, so the interleaving of client- and server-originated output is fixed.

Regenerate with ``AGENT_BOM_UPDATE_PROXY_GOLDENS=1``.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from agent_bom import proxy as proxy_mod

FIXTURES = Path(__file__).parent / "fixtures" / "proxy_characterization"
FAKE_SERVER = FIXTURES / "fake_server.py"
UPDATE = os.environ.get("AGENT_BOM_UPDATE_PROXY_GOLDENS") == "1"

_VOLATILE_KEYS = {
    "ts",
    "timestamp",
    "session_id",
    "source_id",
    "uptime_seconds",
    "started_at",
    "ended_at",
    "latency_p50_ms",
    "latency_p95_ms",
    "latency_p99_ms",
    "latency_avg_ms",
    "latency_max_ms",
    "latency_min_ms",
    "avg_latency_ms",
    "p50_latency_ms",
    "p95_latency_ms",
    "p99_latency_ms",
    "latency_ms",
    "record_hash",
    "prev_hash",
    "p50_ms",
    "p95_ms",
    "p99_ms",
    "min_ms",
    "max_ms",
    "avg_ms",
    "latest_runtime_alert_at",
}


def _call(msg_id: int, name: str, arguments: dict | None = None) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "method": "tools/call", "params": {"name": name, "arguments": arguments or {}}}


def _list(msg_id: int) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "method": "tools/list"}


_EXIT = ({"jsonrpc": "2.0", "method": "test/exit"}, False)
_SECRET_ARG = "sk-proj-" + "a" * 25


def _scenarios() -> dict[str, dict[str, Any]]:
    oversize = b'{"jsonrpc":"2.0","id":99,"method":"ping","pad":"' + b"x" * (proxy_mod._MAX_MESSAGE_BYTES + 1) + b'"}'
    return {
        "allowed_malformed_oversize_replay": {
            "kwargs": {},
            "script": [
                (_list(1), True),
                (_call(2, "echo", {"text": "hi"}), True),
                ({"jsonrpc": "2.0", "method": "notifications/initialized"}, False),
                (b"{not json", False),
                (oversize, False),
                (_call(3, "read_file", {"path": "../../../../etc/passwd"}), True),
                (_call(3, "read_file", {"path": "../../../../etc/passwd"}), True),
                ({"jsonrpc": "2.0", "id": 4, "method": "resources/read", "params": {"uri": "file:///tmp/x"}}, True),
                _EXIT,
            ],
        },
        "policy_block_tools": {
            "kwargs": {"policy": {"rules": [{"id": "no-delete", "action": "block", "block_tools": ["delete_file"]}]}},
            "script": [
                (_list(1), True),
                (_call(2, "delete_file", {"path": "/tmp/a"}), True),
                (_call(3, "echo", {"text": "fine"}), True),
                _EXIT,
            ],
        },
        "block_undeclared": {
            "kwargs": {"block_undeclared": True},
            "script": [
                (_call(1, "echo", {"text": "early"}), True),
                (_list(2), True),
                (_call(3, "mystery", {}), True),
                (_call(4, "echo", {"text": "late"}), True),
                _EXIT,
            ],
        },
        "rate_limit": {
            "kwargs": {"rate_limit_threshold": 2},
            "script": [
                (_call(1, "echo", {"n": 1}), True),
                (_call(2, "echo", {"n": 2}), True),
                (_call(3, "echo", {"n": 3}), True),
                (_call(4, "echo", {"n": 4}), True),
                _EXIT,
            ],
        },
        "log_only_rate_limit_and_replay": {
            "kwargs": {"rate_limit_threshold": 1, "log_only": True},
            "script": [
                (_call(1, "echo", {"n": 1}), True),
                (_call(1, "echo", {"n": 1}), True),
                (_call(2, "echo", {"n": 2}), True),
                _EXIT,
            ],
        },
        "credential_redaction": {
            "kwargs": {"detect_credentials": True},
            "script": [
                (_call(1, "leak", {}), True),
                (_call(2, "fail", {}), True),
                _EXIT,
            ],
        },
        "credential_log_only": {
            "kwargs": {"detect_credentials": True, "log_only": True},
            "script": [(_call(1, "leak", {}), True), _EXIT],
        },
        "inline_scanner_enforce": {
            "kwargs": {"policy": {"inline_scanning": {"enabled": True, "mode": "enforce", "pii_action": "redact"}}},
            "script": [
                (_call(1, "echo", {"token": _SECRET_ARG}), True),
                (_call(2, "leak", {}), True),
                (_call(3, "echo", {"text": "clean"}), True),
                _EXIT,
            ],
        },
        "response_signing": {
            "kwargs": {"response_signing_key": "char-key"},
            "script": [(_call(1, "echo", {"text": "sign me"}), True), _EXIT],
        },
        "upstream_crash": {
            "kwargs": {},
            "script": [(_call(1, "echo", {}), True), (_call(2, "crash", {}), False)],
        },
        "stdin_eof_clean_shutdown": {
            "kwargs": {},
            "script": [(_list(1), True), _EXIT],
        },
        "control_plane_gateway_policy": {
            "kwargs": {"control_plane_url": "https://control.example.test", "control_plane_token": "tok"},
            "script": [
                (_call(1, "read_file", {"path": "/etc/hosts"}), True),
                (_call(2, "echo", {"text": "ok"}), True),
                (_call(3, "echo", {"path": "../../../../etc/shadow"}), True),
                _EXIT,
            ],
        },
    }


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("<volatile>" if k in _VOLATILE_KEYS else _normalize(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    return value


def _frames(raw: bytes) -> list[Any]:
    frames: list[Any] = []
    for line in raw.decode("utf-8", errors="replace").splitlines():
        if len(line) > 4096:
            frames.append({"<oversize-line-bytes>": len(line)})
            continue
        try:
            frames.append(json.loads(line))
        except ValueError:
            frames.append({"<raw>": line})
    return frames


def _encode(item: dict | bytes) -> bytes:
    if isinstance(item, bytes):
        return item + b"\n"
    return (json.dumps(item) + "\n").encode()


def _scripted_reader(script: list[tuple[dict | bytes, bool]], stdout: SimpleNamespace):
    state = {"index": 0, "expected": 0}

    async def read_line(_reader: object) -> bytes:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 10
        while stdout.buffer.getvalue().count(b"\n") < state["expected"]:
            if loop.time() > deadline:
                raise AssertionError(f"timed out waiting for response #{state['expected']}")
            await asyncio.sleep(0.002)
        if state["index"] >= len(script):
            return b""
        item, expects_response = script[state["index"]]
        state["index"] += 1
        state["expected"] += int(expects_response)
        return _encode(item)

    return read_line


def _run_scenario(name: str, spec: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    from agent_bom.api.policy_store import GatewayPolicy

    for var in list(os.environ):
        if var.startswith("AGENT_BOM_PROXY_") or var == "AGENT_BOM_TENANT_ID":
            monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("AGENT_BOM_PROXY_POLICY_CACHE_PATH", str(tmp_path / "policy-cache.json"))

    stdout = SimpleNamespace(buffer=io.BytesIO())
    monkeypatch.setattr(proxy_mod.sys, "stdout", stdout)
    monkeypatch.setattr(proxy_mod, "create_async_stdin_reader", AsyncMock(return_value=object()))
    monkeypatch.setattr(proxy_mod, "read_async_stdin_line", _scripted_reader(spec["script"], stdout))

    pushed: list[dict[str, Any]] = []

    async def fake_push(base_url, token, source_id, session_id, alerts, summary):  # noqa: ANN001
        pushed.append({"base_url": base_url, "token": token, "alerts": alerts, "summary": summary})

    policies = [
        GatewayPolicy(
            policy_id="p-block-read",
            name="block-read-file",
            enabled=True,
            mode="enforce",
            bound_agents=[],
            rules=[{"id": "r1", "action": "block", "block_tools": ["read_file"]}],
        )
    ]
    monkeypatch.setattr(proxy_mod, "_fetch_enabled_gateway_policies", AsyncMock(return_value=(policies, "etag-1")))
    monkeypatch.setattr(proxy_mod, "_push_proxy_audit_batch", fake_push)

    kwargs = dict(spec["kwargs"])
    policy = kwargs.pop("policy", None)
    if policy is not None:
        policy_path = tmp_path / "policy.json"
        policy_path.write_text(json.dumps(policy), encoding="utf-8")
        kwargs["policy_path"] = str(policy_path)
    record = tmp_path / "server-frames.jsonl"
    audit = tmp_path / "audit.jsonl"
    exit_code = asyncio.run(
        proxy_mod.run_proxy(
            ["python3", str(FAKE_SERVER), str(record)],
            log_path=str(audit),
            metrics_port=0,
            **kwargs,
        )
    )
    audit_records = [json.loads(line) for line in audit.read_text().splitlines()] if audit.exists() else []
    return _normalize(
        {
            "exit_code": exit_code,
            "server_frames": _frames(record.read_bytes()) if record.exists() else [],
            "client_frames": _frames(stdout.buffer.getvalue()),
            "audit": audit_records,
            "control_plane_pushes": pushed,
        }
    )


@pytest.mark.parametrize("name", sorted(_scenarios()))
def test_run_proxy_characterization(name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    observed = _run_scenario(name, _scenarios()[name], tmp_path, monkeypatch)
    golden_path = FIXTURES / f"{name}.json"
    rendered = json.dumps(observed, indent=2, sort_keys=True) + "\n"
    if UPDATE:
        golden_path.write_text(rendered, encoding="utf-8")
    assert golden_path.exists(), f"missing golden {golden_path.name}; run with AGENT_BOM_UPDATE_PROXY_GOLDENS=1"
    assert json.loads(rendered) == json.loads(golden_path.read_text(encoding="utf-8"))
