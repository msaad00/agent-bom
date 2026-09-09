"""In-cluster probe used by check_runtime_reconnect.py; never log credentials."""

from __future__ import annotations

import json

import httpx


def run(config: dict) -> dict:
    from agent_bom.api.browser_session import SESSION_COOKIE_NAME, create_browser_session_token

    mode = config["mode"]
    if mode == "source":
        import hashlib
        from pathlib import Path

        import agent_bom

        root = Path(agent_bom.__file__).parent
        return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in config["files"]}
    if mode == "seed":
        from agent_bom.api.agent_identity_store import get_agent_identity_store, issue_identity
        from agent_bom.api.mcp_config_store import McpClientConfigAssignment, get_mcp_config_store

        identity, token = issue_identity(
            get_agent_identity_store(),
            agent_id="acceptance-agent",
            tenant_id="default",
            blueprint_id="finance",
            allowed_tools=["read_file"],
        )
        get_mcp_config_store().put(
            McpClientConfigAssignment(
                config_id="acceptance-profile",
                name="Acceptance",
                tenant_id="default",
                profile_id="finance",
                identity_id=identity.identity_id,
                connector_ids=["filesystem"],
                allowed_tools=["read_file"],
                issuer="agent-bom",
                environment="prod",
                revision=1,
            )
        )
        return {"identity_token": token}
    if mode == "call":
        with httpx.Client(timeout=30, trust_env=False) as client:
            for i in range(config["count"]):
                response = client.post(
                    "http://agent-bom-gateway:8090/mcp/filesystem",
                    headers={"Authorization": "Bearer " + config["transport_token"]},
                    json={
                        "jsonrpc": "2.0",
                        "id": i,
                        "method": "tools/call",
                        "params": {"name": "read_file", "arguments": {}, "_meta": {"agent_identity": config["identity_token"]}},
                    },
                )
                assert response.status_code == 200 and "result" in response.json(), "Gateway scoped allow failed"
        return {"calls": config["count"]}
    cookie, _ = create_browser_session_token(
        subject="acceptance-operator",
        tenant_id=config.get("tenant", "default"),
        role=config.get("role", "viewer"),
        auth_method="browser_session",
        max_age_seconds=300,
    )
    if mode == "cookie":
        return {"name": SESSION_COOKIE_NAME, "value": cookie}
    headers = {"Last-Event-ID": config["cursor"]} if config.get("cursor") else {}
    with httpx.Client(timeout=30, trust_env=False, cookies={SESSION_COOKIE_NAME: cookie}) as client:
        url = f"http://{config['host']}:8422/v1/gateway/feed/stream?limit=50"
        with client.stream("GET", url, headers=headers) as response:
            if "expected_status" in config:
                assert response.status_code == config["expected_status"]
                return {"status": response.status_code}
            assert response.status_code == 200, "Authenticated stream failed"
            events, frame = [], {}
            for line in response.iter_lines():
                if line.startswith(("event: ", "id: ", "data: ")):
                    key, value = line.split(": ", 1)
                    frame[key] = value
                elif not line and "data" in frame:
                    assert frame["event"] in {"activity", "checkpoint"}, "Unexpected stream discontinuity"
                    page = json.loads(frame["data"])
                    events.extend(page["events"])
                    if not page["has_more"]:
                        assert all(event["tenant_id"] == config.get("tenant", "default") for event in events)
                        return {"events": events, "cursor": frame["id"]}
                    frame = {}
    raise AssertionError("Stream closed before a complete page")
