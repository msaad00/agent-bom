"""Inline response DLP must enforce the same policy on both proxy transports."""

import asyncio
import io
import json
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from agent_bom import proxy
from agent_bom.proxy_scanner import ScanConfig, scan_jsonrpc_response


def _policy(tmp_path, mode="enforce", enabled=True, pii_action="redact"):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"inline_scanning": {"enabled": enabled, "mode": mode, "pii_action": pii_action}}))
    return str(path)


def _response(text):
    return {"jsonrpc": "2.0", "id": 7, "result": {"content": [{"type": "text", "text": text}], "isError": False}}


@pytest.mark.parametrize("method", ["tools/call", "resources/read", "tools/list"])
@pytest.mark.parametrize(
    "mode,enabled,pii_action,text,expected",
    [
        ("enforce", True, "redact", "key: sk-proj-" + "a" * 25, "block"),
        ("enforce", True, "block", "Contact alice@example.com", "block"),
        ("enforce", True, "redact", "Contact alice@example.com", "redact"),
        ("enforce", True, "redact", "No sensitive content", "unchanged"),
        ("audit", True, "block", "key: sk-proj-" + "a" * 25, "unchanged"),
        ("enforce", False, "block", "key: sk-proj-" + "a" * 25, "unchanged"),
    ],
)
def test_sse_response_policy_before_stdout(tmp_path, monkeypatch, method, mode, enabled, pii_action, text, expected):
    original = _response(text)
    tools = MagicMock()
    tools.json.return_value = {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}
    response = MagicMock()
    response.json.return_value = original
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.post.side_effect = [tools, response]
    monkeypatch.setattr("httpx.AsyncClient", lambda **kwargs: client)
    request = {"jsonrpc": "2.0", "id": 7, "method": method, "params": {"name": "read", "arguments": {}}}
    monkeypatch.setattr(proxy, "create_async_stdin_reader", AsyncMock(return_value=object()))
    monkeypatch.setattr(proxy, "read_async_stdin_line", AsyncMock(side_effect=[json.dumps(request).encode(), b""]))
    stdout = SimpleNamespace(buffer=io.BytesIO())
    monkeypatch.setattr(proxy.sys, "stdout", stdout)
    audit = tmp_path / "audit.jsonl"

    assert (
        asyncio.run(
            proxy._proxy_sse_server(
                "https://upstream.example.test", policy_path=_policy(tmp_path, mode, enabled, pii_action), log_path=str(audit)
            )
        )
        == 0
    )

    written = json.loads(stdout.buffer.getvalue())
    assert written["id"] == 7
    assert written["jsonrpc"] == "2.0"
    if expected == "block":
        assert "result" not in written
        assert written["error"]["code"] == -32600
        assert text not in stdout.buffer.getvalue().decode()
    elif expected == "redact":
        assert written["result"]["content"][0]["text"] == "Contact [REDACTED:email]"
        assert written["result"]["isError"] is False
    else:
        assert written == original
    if (enabled and expected != "unchanged") or mode == "audit":
        records = [json.loads(line) for line in audit.read_text().splitlines()]
        assert any(str(record.get("detector", "")).startswith("scanner:") for record in records)
    assert "alice@example.com" not in audit.read_text()
    assert "sk-proj-" + "a" * 25 not in audit.read_text()


@pytest.mark.parametrize("shape", ["string", "array", "object"])
def test_redaction_preserves_json_result_shape(shape):
    content = "alice@example.com"
    value = {"string": content, "array": [content, 123], "object": {"nested": [content], "flag": True}}[shape]
    message = {"jsonrpc": "2.0", "id": "request-1", "result": value, "_meta": {"trace": "retained"}}
    safe, findings = scan_jsonrpc_response(message, ScanConfig(enabled=True, scanners=["pii"]))
    assert type(safe["result"]) is type(value)
    assert "alice@example.com" not in json.dumps(safe)
    assert safe["_meta"] == message["_meta"]
    assert message["result"] == value  # upstream evidence is not mutated
    assert findings


def test_redaction_failure_blocks_instead_of_forwarding_original(monkeypatch):
    monkeypatch.setattr("agent_bom.proxy_scanner.redact_pii", lambda text: "invalid JSON")
    safe, _ = scan_jsonrpc_response(_response("alice@example.com"), ScanConfig(enabled=True))
    assert "result" not in safe
    assert safe["error"]["code"] == -32600


def test_adjacent_email_matches_are_both_redacted():
    safe, _ = scan_jsonrpc_response(_response("alice@example.com_bob@example.net"), ScanConfig(enabled=True))
    assert safe["result"]["content"][0]["text"] == "[REDACTED:email][REDACTED:email]"


def test_normalized_pii_that_literal_redaction_misses_fails_closed():
    safe, _ = scan_jsonrpc_response(_response("ａｌｉｃｅ＠ｅｘａｍｐｌｅ．ｃｏｍ"), ScanConfig(enabled=True))
    assert "result" not in safe
    assert safe["error"]["code"] == -32600


def test_long_ordinary_response_does_not_backtrack_quadratically():
    # Use a child process so a regression terminates instead of hanging the
    # suite. The old unanchored email pattern exceeds this generous deadline.
    subprocess.run(
        [
            sys.executable,
            "-c",
            "from agent_bom.proxy_scanner import ScanConfig, scan_jsonrpc_response; "
            "message = {'jsonrpc': '2.0', 'id': 1, 'result': 'a' * 200_000}; "
            "safe, findings = scan_jsonrpc_response(message, ScanConfig(enabled=True)); "
            "assert safe == message and findings == []; "
            "message['result'] = 'alice@example.com ' + message['result']; "
            "safe, findings = scan_jsonrpc_response(message, ScanConfig(enabled=True)); "
            "assert safe['result'] == '[REDACTED:email] ' + 'a' * 200_000 and findings",
        ],
        check=True,
        timeout=10,
        capture_output=True,
    )


def test_sse_upstream_error_does_not_echo_connection_secrets(monkeypatch):
    response = MagicMock()
    response.json.return_value = {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.post.side_effect = [response, RuntimeError("https://private-user:private-password@upstream.example.test")]
    monkeypatch.setattr("httpx.AsyncClient", lambda **kwargs: client)
    request = {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "read", "arguments": {}}}
    monkeypatch.setattr(proxy, "create_async_stdin_reader", AsyncMock(return_value=object()))
    monkeypatch.setattr(proxy, "read_async_stdin_line", AsyncMock(side_effect=[json.dumps(request).encode(), b""]))
    stdout = SimpleNamespace(buffer=io.BytesIO())
    monkeypatch.setattr(proxy.sys, "stdout", stdout)
    assert asyncio.run(proxy._proxy_sse_server("https://upstream.example.test")) == 0
    written = json.loads(stdout.buffer.getvalue())
    assert written["id"] == 7
    assert written["error"] == {"code": -32603, "message": "Upstream connection error"}


@pytest.mark.parametrize("text,expected", [("key: sk-proj-" + "a" * 25, "block"), ("alice@example.com", "redact")])
def test_stdio_response_policy_uses_shared_enforcement(tmp_path, monkeypatch, text, expected):
    monkeypatch.setattr(proxy, "create_async_stdin_reader", AsyncMock(return_value=object()))
    monkeypatch.setattr(proxy, "read_async_stdin_line", AsyncMock(return_value=b""))
    stdout = SimpleNamespace(buffer=io.BytesIO())
    monkeypatch.setattr(proxy.sys, "stdout", stdout)
    command = ["python3", "-c", f"print({json.dumps(_response(text))!r})"]
    assert asyncio.run(proxy.run_proxy(command, policy_path=_policy(tmp_path), metrics_port=0)) == 0
    written = json.loads(stdout.buffer.getvalue())
    if expected == "block":
        assert "result" not in written
        assert written["error"]["code"] == -32600
    else:
        assert written["result"]["content"][0]["text"] == "[REDACTED:email]"
