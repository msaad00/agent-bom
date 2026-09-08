"""Profile client wire contracts and no-gap CLI checkpoint behavior."""

import json

import httpx
import pytest
from click.testing import CliRunner

from agent_bom.cli._runtime_profiles import runtime_feed, runtime_profiles
from agent_bom.client import AgentBomApiError, AgentBomClient
from agent_bom.runtime.activity_stream import decode_activity_stream


def wire(cursor="cursor-1", events=None):
    data = {"schema_version": "gateway.activity.stream.v1", "next_cursor": cursor, "events": events or []}
    return f"event: activity\r\nid: {cursor}\r\ndata: {json.dumps(data)}\r\n\r\n".encode()


def test_python_profile_methods_use_tenant_auth_and_encoded_ids():
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(200, json={"profile_allowed": True})

    with AgentBomClient(
        base_url="https://api.example", bearer_token="secret", tenant_id="a", transport=httpx.MockTransport(respond)
    ) as client:
        client.runtime_profiles()
        client.create_runtime_profile({"identity_id": "id", "environment": "prod"})
        client.get_runtime_profile("a/b")
        client.update_runtime_profile("id", {"expected_revision": 2})
        client.revoke_runtime_profile("id")
        client.validate_runtime_profile("id", issuer="agent-bom", environment="prod", granted_scopes=["tools:read"])
        client.test_runtime_profile("id", issuer="agent-bom", environment="prod", upstream="fs", tool="read")
        with pytest.raises(ValueError):
            client.create_runtime_profile({"environment": "prod"})
    assert len(requests) == 7
    assert all(r.headers["authorization"] == "Bearer secret" and r.headers["x-agent-bom-tenant-id"] == "a" for r in requests)
    assert requests[2].url.raw_path.endswith(b"a%2Fb")
    assert json.loads(requests[-1].content)["tool"] == "read"
    assert json.loads(requests[-2].content)["config_id"] == "id"


def test_fragmented_sse_discards_partial_frame_and_preserves_checkpoint():
    stream = b": ping\r\n\r\n" + wire(events=[{"name": "caf\u00e9"}]) + b"event: activity\nid: incomplete\ndata: {"
    frames = list(decode_activity_stream(bytes([byte]) for byte in stream))
    assert len(frames) == 1
    assert frames[0]["id"] == "cursor-1"
    assert frames[0]["data"]["events"] == [{"name": "caf\u00e9"}]


@pytest.mark.parametrize(
    "data", [b"event: bad\ndata: {}\n\n", b"event: activity\nid: a\ndata: {}\n\n", b"data: [1]\n\n", b"data: invalid\n\n"]
)
def test_invalid_frames_fail_closed(data):
    with pytest.raises(ValueError):
        list(decode_activity_stream([data]))


def test_frame_size_limit(monkeypatch):
    monkeypatch.setattr("agent_bom.runtime.activity_stream.MAX_FRAME_BYTES", 10)
    with pytest.raises(ValueError, match="exceeds"):
        list(decode_activity_stream([b"data: " + b"a" * 20]))


def test_sdk_resume_header_and_terminal_gap():
    def respond(request):
        assert request.headers["Last-Event-ID"] == "previous"
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=wire() + b'event: gap\ndata: {"reason":"cursor_expired"}\n\n' + wire("must-not-read"),
        )

    with AgentBomClient(base_url="https://api.example", transport=httpx.MockTransport(respond)) as client:
        frames = list(client.gateway_activity(cursor="previous"))
    assert [f["event"] for f in frames] == ["activity", "gap"]


def test_sdk_expired_cursor_does_not_expose_response():
    with AgentBomClient(
        base_url="https://api.example", transport=httpx.MockTransport(lambda _: httpx.Response(410, text="secret"))
    ) as client:
        with pytest.raises(AgentBomApiError) as error:
            list(client.gateway_activity(cursor="expired"))
    assert error.value.status_code == 410
    assert error.value.body == ""


def test_cli_reconnects_from_complete_batch_and_retains_gap_checkpoint(tmp_path, monkeypatch):
    checkpoint = tmp_path / "cursor.json"
    calls = []

    def respond(request):
        calls.append(request.headers.get("Last-Event-ID"))
        body = wire(events=[{"event_id": "e1"}]) if len(calls) == 1 else b'event: gap\ndata: {"reason":"cursor_expired"}\n\n'
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=body)

    client = AgentBomClient(base_url="https://api.example", tenant_id="a", transport=httpx.MockTransport(respond))
    monkeypatch.setattr("agent_bom.cli._runtime_profiles._make_client", lambda **_: client)
    monkeypatch.setattr("agent_bom.cli._runtime_profiles.time.sleep", lambda _: None)
    result = CliRunner().invoke(runtime_feed, ["--cursor-file", str(checkpoint), "--follow"])
    assert result.exit_code == 1
    assert "gap detected" in result.output
    assert calls == [None, "cursor-1"]
    assert json.loads(checkpoint.read_text())["cursor"] == "cursor-1"
    assert checkpoint.stat().st_mode & 0o777 == 0o600


def test_cli_rejects_checkpoint_from_another_tenant(tmp_path, monkeypatch):
    checkpoint = tmp_path / "cursor.json"
    checkpoint.write_text(json.dumps({"api_url": "https://api.example", "tenant_id": "other", "cursor": "old"}))
    client = AgentBomClient(base_url="https://api.example", tenant_id="a")
    monkeypatch.setattr("agent_bom.cli._runtime_profiles._make_client", lambda **_: client)
    result = CliRunner().invoke(runtime_feed, ["--cursor-file", str(checkpoint)])
    assert result.exit_code == 1
    assert "does not match" in result.output


def test_cli_profile_test_denial_is_nonzero_and_labels_simulation(monkeypatch):
    client = AgentBomClient(
        base_url="https://api.example",
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, json={"profile_allowed": False, "executed": False, "scope": "profile_contract_only"})
        ),
    )
    monkeypatch.setattr("agent_bom.cli._runtime_profiles._make_client", lambda **_: client)
    result = CliRunner().invoke(runtime_profiles, ["test", "id", "--environment", "prod", "--upstream", "fs", "--tool", "delete"])
    assert result.exit_code == 1
    assert '"executed": false' in result.output


def test_checkpoint_failure_does_not_advance_previous_cursor(tmp_path, monkeypatch):
    checkpoint = tmp_path / "cursor.json"
    saved = {"api_url": "https://api.example", "tenant_id": "a", "cursor": "old"}
    checkpoint.write_text(json.dumps(saved))
    client = AgentBomClient(
        base_url="https://api.example",
        tenant_id="a",
        transport=httpx.MockTransport(lambda _: httpx.Response(200, headers={"content-type": "text/event-stream"}, content=wire())),
    )
    monkeypatch.setattr("agent_bom.cli._runtime_profiles._make_client", lambda **_: client)

    def fail(*args):
        raise OSError("secret disk path")

    monkeypatch.setattr("agent_bom.cli._runtime_profiles.os.replace", fail)
    result = CliRunner().invoke(runtime_feed, ["--cursor-file", str(checkpoint)])
    assert result.exit_code == 1
    assert "secret disk path" not in result.output
    assert json.loads(checkpoint.read_text()) == saved
    assert not list(tmp_path.glob(".activity-cursor-*"))


def test_cli_create_and_list_managed_profiles(tmp_path, monkeypatch):
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(200, json={"assignment": {"config_id": "managed-1", "revision": 1}})

    monkeypatch.setattr(
        "agent_bom.cli._runtime_profiles._make_client",
        lambda **_: AgentBomClient(base_url="https://api.example", transport=httpx.MockTransport(respond)),
    )
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"identity_id": "identity-a", "environment": "prod"}))
    runner = CliRunner()
    assert runner.invoke(runtime_profiles, ["create", "--file", str(profile)]).exit_code == 0
    assert runner.invoke(runtime_profiles, ["list"]).exit_code == 0
    assert [r.method for r in requests] == ["POST", "GET"]
    profile.write_text("[]")
    assert runner.invoke(runtime_profiles, ["create", "--file", str(profile)]).exit_code == 1
