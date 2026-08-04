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
        # A failed verify must not look like success to `connect && promote`.
        assert r.exit_code == 1
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
        # Degrading gracefully still means the connection was never verified —
        # exit 1 ("dependency not present") per site-docs/reference/exit-codes.md.
        assert r.exit_code == 1
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
                "connect",
                "aws",
                "--role-arn",
                "arn:aws:iam::123456789012:role/ro",
                "--external-id",
                SECRET,
                "--region",
                "us-east-1",
                "--server",
                "https://cp.example.com",
                "--api-key",
                "k-123",
                "--tenant",
                "tenant-a",
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
            "inventory_scope": None,
            "scan_mode": None,
            "auto_scan_on_create": None,
        }
        assert client.tested == ["conn-9"]
        assert client.scanned == []
        assert client.closed is True

    def test_register_passes_scope_mode_and_auto_scan_flags(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _FakeClient.instances = []
        monkeypatch.setattr("agent_bom.client.AgentBomClient", _FakeClient)
        r = CliRunner().invoke(
            _main(),
            [
                "connect",
                "aws",
                "--role-arn",
                "arn:aws:iam::123456789012:role/ro",
                "--external-id",
                SECRET,
                "--server",
                "https://cp.example.com",
                "--api-key",
                "k-123",
                "--inventory-scope",
                "organization",
                "--scan-mode",
                "continuous",
                "--no-auto-scan-on-create",
            ],
        )
        assert r.exit_code == 0, r.output
        client = _FakeClient.instances[-1]
        assert client.create_kwargs == {
            "provider": "aws",
            "display_name": "Amazon Web Services (read-only)",
            "role_ref": "arn:aws:iam::123456789012:role/ro",
            "external_id": SECRET,
            "regions": [],
            "auth_params": {},
            "inventory_scope": "organization",
            "scan_mode": "continuous",
            "auto_scan_on_create": False,
        }

    def test_scan_flag_triggers_server_scan(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _FakeClient.instances = []
        monkeypatch.setattr("agent_bom.client.AgentBomClient", _FakeClient)
        r = CliRunner().invoke(
            _main(),
            [
                "connect",
                "aws",
                "--role-arn",
                "arn:aws:iam::1:role/ro",
                "--external-id",
                SECRET,
                "--server",
                "https://cp.example.com",
                "--api-key",
                "k",
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


# ── Failure exit codes + actionable reasons ───────────────────────────────────


def _fake_control_plane(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    """Point the CLI at an in-process fake control plane.

    Builds a *real* ``AgentBomClient`` over an httpx ``MockTransport`` so the
    test exercises the genuine ``AgentBomApiError`` (status_code + body) the CLI
    has to interpret. No network, no cloud credentials.
    """
    from agent_bom.client import AgentBomClient

    def _factory(**kwargs: object) -> AgentBomClient:
        return AgentBomClient(**kwargs, transport=httpx.MockTransport(handler))  # type: ignore[arg-type]

    monkeypatch.setattr("agent_bom.client.AgentBomClient", _factory)


# The remediation the AWS broker curates for a bad role/trust policy. The API
# echoes it as the ``detail`` of its 502; the operator needs to see exactly this.
ASSUME_ROLE_REMEDIATION = (
    "AssumeRole failed. Verify the role ARN, its trust policy, and that the "
    "ExternalId matches the one embedded in the grant script. The control plane's "
    "caller identity also needs sts:AssumeRole permission on that role."
)


FAKE_ROLE_ARN = "arn:aws:iam::123456789012:role/totally-fake"


def _connect_aws(*extra: str) -> list[str]:
    """Minimal AWS connect argv (a role that cannot exist), plus extra flags."""
    return ["connect", "aws", "--role-arn", FAKE_ROLE_ARN, "--external-id", SECRET, *extra]


class TestServerFailureExitCode:
    """`connect --server` must fail loudly, with the control plane's own reason."""

    def test_failed_test_exits_one_and_surfaces_control_plane_detail(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/test"):
                return httpx.Response(502, json={"detail": ASSUME_ROLE_REMEDIATION})
            return httpx.Response(201, json={"id": "conn-9", "provider": "aws"})

        _fake_control_plane(monkeypatch, handler)
        r = CliRunner().invoke(_main(), _connect_aws("--server", "http://cp", "--api-key", "k"))

        assert r.exit_code == 1, r.output
        assert "Verify the role ARN" in r.output
        assert "sts:AssumeRole" in r.output
        assert "See server logs" not in r.output
        assert SECRET not in r.output

    def test_failed_create_exits_one_and_surfaces_detail(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503, json={"detail": "Connection secret encryption is not configured."})

        _fake_control_plane(monkeypatch, handler)
        r = CliRunner().invoke(_main(), _connect_aws("--server", "http://cp", "--api-key", "k"))

        assert r.exit_code == 1, r.output
        assert "Connection secret encryption is not configured." in r.output
        assert "Registered" not in r.output

    def test_caller_input_rejected_exits_two(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A 400/422 is the caller's mistake — same exit code as local input validation."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(400, json={"detail": "Invalid region format: us-east-1a"})

        _fake_control_plane(monkeypatch, handler)
        r = CliRunner().invoke(_main(), _connect_aws("--server", "http://cp", "--api-key", "k"))

        assert r.exit_code == 2, r.output
        assert "Invalid region format" in r.output

    def test_failed_scan_exits_one(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/scan"):
                return httpx.Response(503, json={"detail": "Cloud connection scan could not be queued."})
            if request.url.path.endswith("/test"):
                return httpx.Response(200, json={"status": "ok"})
            return httpx.Response(201, json={"id": "conn-9", "provider": "aws"})

        _fake_control_plane(monkeypatch, handler)
        r = CliRunner().invoke(_main(), _connect_aws("--server", "http://cp", "--api-key", "k", "--scan"))

        assert r.exit_code == 1, r.output
        assert "could not be queued" in r.output

    def test_non_json_error_body_still_fails_without_dumping_html(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A proxy's HTML error page is not an operator message — do not print it."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(504, text="<html><body>gateway timeout</body></html>")

        _fake_control_plane(monkeypatch, handler)
        r = CliRunner().invoke(_main(), _connect_aws("--server", "http://cp", "--api-key", "k"))

        assert r.exit_code == 1, r.output
        assert "<html>" not in r.output
        assert "504" in r.output

    def test_unreachable_control_plane_fails_gracefully(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("[Errno 61] Connection refused", request=request)

        _fake_control_plane(monkeypatch, handler)
        r = CliRunner().invoke(_main(), _connect_aws("--server", "http://cp", "--api-key", "k"))

        assert r.exit_code == 1, r.output
        assert "Could not reach" in r.output
        assert "Traceback" not in r.output
        assert SECRET not in r.output


class TestLocalFailureReason:
    """Local verify must give the operator the broker's curated remediation."""

    def test_broker_remediation_reaches_the_operator(self, fake_boto3) -> None:
        fake_boto3(assume_fails=True)
        r = CliRunner().invoke(_main(), _connect_aws())

        assert r.exit_code == 1, r.output
        assert "Verify the role ARN" in r.output
        assert "An internal error occurred" not in r.output
        assert SECRET not in r.output

    def test_unexpected_exception_stays_redacted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Only curated remediation passes through; a stray exception is generic."""

        def _raise(*_a: object, **_k: object) -> None:
            raise RuntimeError(f"boom while reading /etc/agent-bom/creds with secret={SECRET}")

        monkeypatch.setattr("agent_bom.cloud.connection_broker.broker_session", _raise)
        r = CliRunner().invoke(_main(), _connect_aws())

        assert r.exit_code == 1, r.output
        assert "An internal error occurred" in r.output
        assert SECRET not in r.output
        assert "/etc/agent-bom" not in r.output

    def test_broker_error_without_remediation_stays_redacted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from agent_bom.cloud.connection_broker import ConnectionBrokerError

        def _raise(*_a: object, **_k: object) -> None:
            raise ConnectionBrokerError(f"free-form message carrying {SECRET}")

        monkeypatch.setattr("agent_bom.cloud.connection_broker.broker_session", _raise)
        r = CliRunner().invoke(_main(), _connect_aws())

        assert r.exit_code == 1, r.output
        assert "An internal error occurred" in r.output
        assert SECRET not in r.output


class TestOperatorDetailBoundary:
    """The CLI and the API must share ONE definition of an operator-safe detail."""

    def test_api_route_delegates_to_the_shared_helper(self) -> None:
        from agent_bom.api.routes.cloud_connections import _safe_connection_detail
        from agent_bom.cloud.base import CloudDiscoveryError
        from agent_bom.cloud.connection_broker import ConnectionBrokerError, operator_facing_detail

        curated = ConnectionBrokerError("free-form", remediation=ASSUME_ROLE_REMEDIATION)
        missing_sdk = CloudDiscoveryError("boto3 is required. Install with: pip install 'agent-bom[aws]'")
        unexpected = RuntimeError("stray")

        for exc in (curated, missing_sdk, unexpected):
            assert _safe_connection_detail(exc) == operator_facing_detail(exc)

        assert "Verify the role ARN" in operator_facing_detail(curated)
        assert "agent-bom[aws]" in operator_facing_detail(missing_sdk)
        assert operator_facing_detail(unexpected) == "An internal error occurred. Please contact support."

    def test_curated_remediation_is_never_truncated_mid_sentence(self) -> None:
        """Every remediation the broker authors is longer than the 200-char cap
        ``sanitize_error`` applies to arbitrary exception text. Chopping authored
        guidance mid-word ("…configure AWS credentials for the control plane (AWS_")
        is the same defect as dropping it — the operator still cannot act on it.
        """
        import ast
        from pathlib import Path

        from agent_bom.cloud.connection_broker import ConnectionBrokerError, operator_facing_detail

        source = Path(__file__).resolve().parents[1] / "src" / "agent_bom" / "cloud" / "connection_broker.py"
        remediations = [
            keyword.value.value
            for keyword in ast.walk(ast.parse(source.read_text(encoding="utf-8")))
            if isinstance(keyword, ast.keyword)
            and keyword.arg == "remediation"
            and isinstance(keyword.value, ast.Constant)
            and isinstance(keyword.value.value, str)
        ]
        assert len(remediations) >= 3, "expected the broker to curate remediation strings"

        for remediation in remediations:
            assert len(remediation) > 200, "test is only meaningful for remediations past the default cap"
            assert operator_facing_detail(ConnectionBrokerError("free-form", remediation=remediation)) == remediation

    def test_arbitrary_exception_text_stays_capped(self) -> None:
        """Raising the cap for curated text must not uncap arbitrary SDK strings."""
        from agent_bom.security import sanitize_error

        assert len(sanitize_error(RuntimeError("x" * 5000))) == 200


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
            inventory_scope="organization",
            scan_mode="continuous",
            auto_scan_on_create=False,
        )
        assert set(body) <= set(CloudConnectionCreate.model_fields)
        # The body must validate against the API's own request model.
        CloudConnectionCreate(**body)
        assert body["inventory_scope"] == "organization"
        assert body["scan_mode"] == "continuous"
        assert body["auto_scan_on_create"] is False

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
                inventory_scope="organization",
                scan_mode="continuous",
                auto_scan_on_create=False,
            )
        finally:
            client.close()

        assert captured["method"] == "POST"
        assert str(captured["url"]).endswith("/v1/cloud/connections")
        body = captured["json"]
        assert body["external_id"] == SECRET
        assert body["inventory_scope"] == "organization"
        assert body["scan_mode"] == "continuous"
        assert body["auto_scan_on_create"] is False
        CloudConnectionCreate(**body)  # type: ignore[arg-type]
