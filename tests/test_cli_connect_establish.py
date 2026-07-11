"""`agent-bom connect <provider>` establish + verify behavior.

Covers the four behaviors the connect-polish work guarantees:

* the informational default (no connection flags) is unchanged / back-compatible;
* local verify succeeds and fails cleanly with a mocked boto3/STS;
* the server-register path sends the *same* ``CloudConnectionCreate`` schema the
  API expects, via the API client;
* the connection secret (external_id / client secret / key) is never printed.
"""

from __future__ import annotations

import json
import sys
import types

import httpx
import pytest
from click.testing import CliRunner

SECRET = "super-secret-external-id"


# ── Fake boto3 so local verify runs the real broker without a real AWS call ────


def _make_fake_boto3(*, assume_fails: bool = False) -> types.ModuleType:
    class FakeStsClient:
        def assume_role(self, **kwargs: object) -> dict[str, object]:
            # The broker must present the decrypted ExternalId, never anything else.
            assert kwargs["ExternalId"] == SECRET
            if assume_fails:
                raise RuntimeError("AccessDenied assuming role")
            return {"Credentials": {"AccessKeyId": "AKIA", "SecretAccessKey": "sk", "SessionToken": "tok"}}

        def get_caller_identity(self) -> dict[str, str]:
            return {"Account": "123456789012", "Arn": "arn:aws:sts::123456789012:assumed-role/ro/x"}

    class FakeSession:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def client(self, _service: str) -> FakeStsClient:
            return FakeStsClient()

    module = types.ModuleType("boto3")
    module.client = lambda *_a, **_k: FakeStsClient()  # type: ignore[attr-defined]
    module.Session = FakeSession  # type: ignore[attr-defined]
    return module


@pytest.fixture
def fake_boto3(monkeypatch: pytest.MonkeyPatch):
    def _install(*, assume_fails: bool = False) -> None:
        monkeypatch.setitem(sys.modules, "boto3", _make_fake_boto3(assume_fails=assume_fails))

    return _install


def _main():
    from agent_bom.cli import main

    return main


# ── (a) informational default unchanged ───────────────────────────────────────


class TestInformationalDefault:
    @pytest.mark.parametrize("provider", ["aws", "azure", "gcp", "snowflake"])
    def test_no_flags_prints_readonly_guidance(self, provider: str) -> None:
        r = CliRunner().invoke(_main(), ["connect", provider])
        assert r.exit_code == 0
        assert "Provision the read-only grant" in r.output
        # The establish path must not run without connection flags.
        assert "Verifying a read-only" not in r.output
        assert "Registered" not in r.output

    def test_help_documents_establish_and_verify(self) -> None:
        r = CliRunner().invoke(_main(), ["connect", "--help"])
        assert r.exit_code == 0
        assert "establish" in r.output.lower()

    def test_aws_help_exposes_schema_flags(self) -> None:
        r = CliRunner().invoke(_main(), ["connect", "aws", "--help"])
        assert r.exit_code == 0
        for flag in ("--role-arn", "--external-id", "--region", "--server", "--api-key", "--scan"):
            assert flag in r.output


# ── (b) local verify success + failure ────────────────────────────────────────


class TestLocalVerify:
    def test_success_probes_readonly_and_hides_secret(self, fake_boto3) -> None:
        fake_boto3()
        r = CliRunner().invoke(
            _main(),
            ["connect", "aws", "--role-arn", "arn:aws:iam::123456789012:role/ro", "--external-id", SECRET, "--region", "us-east-1"],
        )
        assert r.exit_code == 0
        assert "Verified" in r.output
        assert "123456789012" in r.output  # non-secret probe result
        assert SECRET not in r.output

    def test_failure_is_clean_and_hides_secret(self, fake_boto3) -> None:
        fake_boto3(assume_fails=True)
        r = CliRunner().invoke(
            _main(),
            ["connect", "aws", "--role-arn", "arn:aws:iam::1:role/ro", "--external-id", SECRET],
        )
        assert r.exit_code == 0
        assert "Verification failed" in r.output
        assert SECRET not in r.output

    def test_scan_flag_prints_local_scan_guidance(self, fake_boto3) -> None:
        fake_boto3()
        r = CliRunner().invoke(
            _main(),
            ["connect", "aws", "--role-arn", "arn:aws:iam::1:role/ro", "--external-id", SECRET, "--scan"],
        )
        assert r.exit_code == 0
        assert "agent-bom scan --aws" in r.output

    def test_missing_secret_is_rejected(self) -> None:
        r = CliRunner().invoke(_main(), ["connect", "aws", "--role-arn", "arn:aws:iam::1:role/ro"])
        assert r.exit_code != 0
        assert "--external-id" in r.output

    def test_missing_sdk_degrades_with_install_hint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from agent_bom.cloud.base import CloudDiscoveryError

        def _raise(*_a: object, **_k: object) -> None:
            raise CloudDiscoveryError("boto3 is required to broker AWS connections. Install with: pip install 'agent-bom[aws]'")

        monkeypatch.setattr("agent_bom.cloud.connection_broker.broker_session", _raise)
        r = CliRunner().invoke(
            _main(),
            ["connect", "aws", "--role-arn", "arn:aws:iam::1:role/ro", "--external-id", SECRET],
        )
        assert r.exit_code == 0
        assert "Cannot verify locally" in r.output
        assert "agent-bom[aws]" in r.output
        assert SECRET not in r.output


# ── (c) API-register path uses the SAME CloudConnectionCreate schema ───────────


class _FakeClient:
    instances: list[_FakeClient] = []

    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs
        self.create_kwargs: dict[str, object] | None = None
        self.tested: list[str] = []
        self.scanned: list[str] = []
        self.closed = False
        _FakeClient.instances.append(self)

    def create_cloud_connection(self, **kwargs: object) -> dict[str, object]:
        self.create_kwargs = kwargs
        return {"id": "conn-9", "provider": kwargs.get("provider")}

    def test_cloud_connection(self, connection_id: str) -> dict[str, object]:
        self.tested.append(connection_id)
        return {"status": "ok"}

    def scan_cloud_connection(self, connection_id: str) -> dict[str, object]:
        self.scanned.append(connection_id)
        return {"scan_id": "scan-1"}

    def close(self) -> None:
        self.closed = True


class TestServerRegister:
    def test_register_and_test_send_schema_fields(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _FakeClient.instances = []
        monkeypatch.setattr("agent_bom.client.AgentBomClient", _FakeClient)
        r = CliRunner().invoke(
            _main(),
            [
                "connect", "aws",
                "--role-arn", "arn:aws:iam::123456789012:role/ro",
                "--external-id", SECRET,
                "--region", "us-east-1",
                "--server", "https://cp.example.com",
                "--api-key", "k-123",
                "--tenant", "tenant-a",
            ],
        )
        assert r.exit_code == 0, r.output
        assert "Registered" in r.output
        assert "conn-9" in r.output
        assert SECRET not in r.output

        client = _FakeClient.instances[-1]
        assert client.kwargs["base_url"] == "https://cp.example.com"
        assert client.kwargs["api_key"] == "k-123"
        assert client.kwargs["tenant_id"] == "tenant-a"
        assert client.create_kwargs == {
            "provider": "aws",
            "display_name": "Amazon Web Services (read-only)",
            "role_ref": "arn:aws:iam::123456789012:role/ro",
            "external_id": SECRET,
            "regions": ["us-east-1"],
            "auth_params": {},
        }
        assert client.tested == ["conn-9"]
        assert client.scanned == []
        assert client.closed is True

    def test_scan_flag_triggers_server_scan(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _FakeClient.instances = []
        monkeypatch.setattr("agent_bom.client.AgentBomClient", _FakeClient)
        r = CliRunner().invoke(
            _main(),
            [
                "connect", "aws",
                "--role-arn", "arn:aws:iam::1:role/ro",
                "--external-id", SECRET,
                "--server", "https://cp.example.com",
                "--api-key", "k",
                "--scan",
            ],
        )
        assert r.exit_code == 0, r.output
        assert _FakeClient.instances[-1].scanned == ["conn-9"]
        assert "Scan:" in r.output

    def test_server_without_api_key_is_rejected(self) -> None:
        r = CliRunner().invoke(
            _main(),
            ["connect", "aws", "--role-arn", "arn:aws:iam::1:role/ro", "--external-id", SECRET, "--server", "https://cp"],
        )
        assert r.exit_code != 0
        assert "--server and --api-key are both required" in r.output


# ── Schema/client consistency: CLI body == CloudConnectionCreate ───────────────


class TestSchemaConsistency:
    def test_builder_body_matches_create_schema(self) -> None:
        from agent_bom.api.routes.cloud_connections import CloudConnectionCreate
        from agent_bom.cloud.connection_request import build_connection_create_body

        body = build_connection_create_body(
            provider="aws",
            display_name="d",
            role_ref="r",
            external_id="s",
            regions=["us-east-1"],
            auth_params={"k": "v"},
            scan_interval_minutes=60,
        )
        assert set(body) <= set(CloudConnectionCreate.model_fields)
        # The body must validate against the API's own request model.
        CloudConnectionCreate(**body)

    def test_client_posts_create_body_to_v1_route(self) -> None:
        from agent_bom.api.routes.cloud_connections import CloudConnectionCreate
        from agent_bom.client import AgentBomClient

        captured: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            captured["method"] = request.method
            captured["json"] = json.loads(request.content)
            return httpx.Response(201, json={"id": "conn-1", "provider": "aws"})

        client = AgentBomClient(
            base_url="http://cp",
            api_key="k",
            tenant_id="t",
            transport=httpx.MockTransport(handler),
        )
        try:
            client.create_cloud_connection(
                provider="aws",
                display_name="d",
                role_ref="r",
                external_id=SECRET,
                regions=["us-east-1"],
            )
        finally:
            client.close()

        assert captured["method"] == "POST"
        assert str(captured["url"]).endswith("/v1/cloud/connections")
        body = captured["json"]
        assert body["external_id"] == SECRET
        CloudConnectionCreate(**body)  # type: ignore[arg-type]
