"""Durable MCP results must preserve caller and tenant boundaries across workers."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from agent_bom.mcp_tools.result_store import DurableScanResultStore, scan_result_owner


def store(path, tenant="tenant-a", **kwargs):
    return DurableScanResultStore(path=path, tenant_id=tenant, max_entries=2, ttl_seconds=60, **kwargs)


def test_reopened_store_preserves_result_and_rejects_other_scopes(tmp_path):
    path = tmp_path / "results.db"
    rid = store(path).put("caller-a", {"report": {"findings": [{"id": "one"}]}})
    assert store(path).get("caller-a", rid)["report"]["findings"] == [{"id": "one"}]
    assert store(path).get("caller-b", rid) is None
    assert store(path, "tenant-b").get("caller-a", rid) is None
    assert path.stat().st_mode & 0o777 == 0o600


def test_expiry_and_eviction_are_durable_and_tenant_scoped(tmp_path):
    now = [100.0]
    path = tmp_path / "results.db"
    first = store(path, clock=lambda: now[0])
    other = store(path, "tenant-b", clock=lambda: now[0])
    foreign = other.put("caller", {"v": "foreign"})
    ids = []
    for i in range(3):
        now[0] += 1
        ids.append(first.put("caller", {"v": i}))
    assert first.get("caller", ids[0]) is None
    assert first.get("caller", ids[-1]) == {"v": 2}
    assert other.get("caller", foreign) == {"v": "foreign"}
    now[0] += 60
    assert store(path, clock=lambda: now[0]).get("caller", ids[-1]) is None


def test_concurrent_writers_preserve_bound_without_lost_updates(tmp_path):
    path = tmp_path / "results.db"
    with ThreadPoolExecutor(max_workers=4) as executor:
        ids = list(executor.map(lambda i: store(path).put("caller", {"v": i}), range(12)))
    assert sum(store(path).get("caller", rid) is not None for rid in ids) == 2


def test_collision_never_overwrites_prior_result(tmp_path, monkeypatch):
    monkeypatch.setattr("agent_bom.mcp_tools.result_store.secrets.token_urlsafe", lambda _: "same-id")
    cache = store(tmp_path / "results.db")
    rid = cache.put("first", {"v": 1})
    with pytest.raises(Exception):
        cache.put("second", {"v": 2})
    assert cache.get("first", rid) == {"v": 1}
    assert cache.get("second", rid) is None


def test_oversize_and_storage_errors_fail_closed(tmp_path):
    cache = store(tmp_path / "results.db", max_result_bytes=10)
    with pytest.raises(ValueError, match="size limit"):
        cache.put("caller", {"long": "x" * 20})
    path = tmp_path / "directory"
    path.mkdir()
    with pytest.raises(OSError):
        store(path).get("caller", "id")


def test_verified_token_binds_owner_not_self_declared_client_id():
    from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
    from mcp.server.auth.provider import AccessToken
    from starlette.requests import Request

    token = AccessToken(token="token-a", client_id="shared-client", scopes=["read"])
    context = SimpleNamespace(
        request=Request({"type": "http", "user": AuthenticatedUser(token)}), meta=SimpleNamespace(client_id="spoofed")
    )
    first = scan_result_owner(lambda: context)
    context.meta.client_id = "changed"
    assert scan_result_owner(lambda: context) == first
    token.token = "token-b"
    assert scan_result_owner(lambda: context) != first
    assert "token-a" not in first


def test_http_without_verified_token_rejected_and_stdio_stable(monkeypatch):
    monkeypatch.setattr("mcp.server.auth.middleware.auth_context.get_access_token", lambda: None)
    with pytest.raises(ValueError, match="authenticated"):
        scan_result_owner(lambda: SimpleNamespace(request=object(), meta=SimpleNamespace(client_id="local")))
    assert scan_result_owner(lambda: SimpleNamespace(request=None)) == "local"


def test_restart_in_separate_process_preserves_result(tmp_path):
    import json
    import os
    import subprocess
    import sys

    path = tmp_path / "results.db"
    rid = store(path).put("caller", {"v": "restart"})
    code = (
        "import json, sys; from pathlib import Path; "
        "from agent_bom.mcp_tools.result_store import DurableScanResultStore; "
        "s=DurableScanResultStore(path=Path(sys.argv[1]),tenant_id='tenant-a',max_entries=2,ttl_seconds=60); "
        "print(json.dumps(s.get('caller',sys.argv[2])))"
    )
    output = subprocess.check_output([sys.executable, "-c", code, str(path), rid], env=os.environ.copy(), text=True)
    assert json.loads(output) == {"v": "restart"}


def test_failed_insert_rolls_back_eviction(tmp_path, monkeypatch):
    import sqlite3

    now = [100.0]
    path = tmp_path / "results.db"
    cache = store(path, clock=lambda: now[0])
    old = cache.put("caller", {"v": 1})
    now[0] += 61
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TRIGGER reject_result BEFORE INSERT ON mcp_scan_results BEGIN SELECT RAISE(ABORT, 'unavailable'); END")
    with pytest.raises(sqlite3.IntegrityError):
        cache.put("caller", {"v": 2})
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT result_id FROM mcp_scan_results").fetchall() == [(old,)]


@pytest.mark.parametrize("ttl", [0, -1, float("nan"), float("inf")])
def test_invalid_retention_limits_fail_closed(tmp_path, ttl):
    with pytest.raises(ValueError, match="positive and finite"):
        DurableScanResultStore(path=tmp_path / "results.db", max_entries=2, ttl_seconds=ttl)


def test_result_retrieval_storage_error_is_generic():
    import asyncio

    from mcp.server.fastmcp.exceptions import ToolError

    from agent_bom.mcp_tools.scanning import scan_impl

    class BrokenStore:
        def get(self, owner, result_id):
            raise RuntimeError("postgresql://user:secret@host/db")

    with pytest.raises(ToolError, match="MCP result storage unavailable") as error:
        asyncio.run(scan_impl(result_id="known", _result_store=BrokenStore(), _run_scan_pipeline=None, _truncate_response=str))
    assert "secret" not in str(error.value)


def test_authenticated_http_workers_share_results_and_reject_rotated_tokens(tmp_path, monkeypatch):
    import hashlib
    import json
    from datetime import datetime, timedelta, timezone

    from starlette.testclient import TestClient

    from agent_bom.mcp_server import create_mcp_server
    from tests.test_mcp_private_auth import _event

    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "worker-tenant")
    monkeypatch.setenv("AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT", (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat())
    original = "original-read-credential"
    owner = "token:" + hashlib.sha256(original.encode()).hexdigest()
    rid = DurableScanResultStore(max_entries=4, ttl_seconds=60).put(owner, {"report": {"findings": [{"id": "preserved"}]}})

    def page(configured_token, supplied_token):
        server = create_mcp_server(host="127.0.0.1", port=8000, bearer_token=configured_token, profile="scan")
        with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
            headers = {"Accept": "application/json, text/event-stream", "Authorization": "Bearer " + supplied_token}
            response = client.post(
                "/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "same-client", "version": "1"}},
                },
            )
            if response.status_code != 200:
                return response.status_code, None
            headers.update({"mcp-session-id": response.headers["mcp-session-id"], "mcp-protocol-version": "2025-11-25"})
            client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "method": "notifications/initialized"})
            response = client.post(
                "/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "scan", "arguments": {"result_id": rid, "section": "findings"}},
                },
            )
            return response.status_code, _event(response)["result"]

    for _ in range(2):
        status, result = page(original, original)
        assert status == 200 and not result.get("isError")
        assert json.loads(result["content"][0]["text"])["items"] == [{"id": "preserved"}]
    assert page("rotated-credential", original)[0] == 401
    status, result = page("rotated-credential", "rotated-credential")
    assert status == 200 and result["isError"]
    assert "Unknown or expired result_id" in result["content"][0]["text"]
