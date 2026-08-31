"""Bounded cloud capability probes distinguish credentials from usable access."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from agent_bom.cloud.capability_probe import (
    CapabilityProbeError,
    classify_probe_failure,
    probe_read_capability,
)


class _AwsSession:
    def __init__(self, client: object) -> None:
        self._client = client

    def client(self, service: str) -> object:
        assert service == "bedrock-agent"
        return self._client


def test_aws_probe_verifies_bedrock_read_capability() -> None:
    calls: list[dict[str, int]] = []
    client = SimpleNamespace(list_agents=lambda **kwargs: calls.append(kwargs) or {"agentSummaries": []})

    result = probe_read_capability("aws", _AwsSession(client), regions=["us-east-1"], auth_params={})

    assert result.capabilities == ("bedrock:list-agents",)
    assert calls == [{"maxResults": 1}]


def test_gcp_probe_verifies_vertex_read_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[dict[str, object], float]] = []

    class _EndpointClient:
        def __init__(self, *, credentials: object) -> None:
            assert credentials is credential

        def list_endpoints(self, *, request: dict[str, object], timeout: float):
            calls.append((request, timeout))
            return iter(())

    credential = object()
    fake_module = SimpleNamespace(EndpointServiceClient=_EndpointClient)
    monkeypatch.setattr("agent_bom.cloud.capability_probe._load_vertex_module", lambda: fake_module)

    result = probe_read_capability(
        "gcp",
        credential,
        regions=["us-central1"],
        auth_params={"project_id": "project-alpha"},
    )

    assert result.capabilities == ("vertex-ai:list-endpoints",)
    assert calls == [
        (
            {"parent": "projects/project-alpha/locations/us-central1", "page_size": 1},
            10.0,
        )
    ]


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (type("NoCredentialsError", (Exception,), {})("secret.invalid"), "invalid_credentials"),
        (type("AccessDeniedException", (Exception,), {})("arn:aws:iam::123:role/private"), "permission_denied"),
        (TimeoutError("https://private.provider.invalid"), "timeout"),
    ],
)
def test_probe_failure_classification_is_stable_and_secret_free(exc: Exception, expected: str) -> None:
    classified = classify_probe_failure(exc)

    assert classified == expected
    assert "private" not in classified
    assert "secret" not in classified


def test_gcp_probe_requires_non_secret_project_scope() -> None:
    with pytest.raises(CapabilityProbeError) as exc_info:
        probe_read_capability("gcp", object(), regions=["us-central1"], auth_params={})

    assert exc_info.value.code == "invalid_configuration"
    assert "project" not in str(exc_info.value).lower()
