"""Discovery envelope model + AWS provider wiring (#2083 PR A)."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime

import pytest

from agent_bom.discovery_envelope import (
    ENVELOPE_SCHEMA_VERSION,
    DiscoveryEnvelope,
    RedactionStatus,
    ScanMode,
)
from agent_bom.models import Agent, AgentType


def test_envelope_default_shape() -> None:
    envelope = DiscoveryEnvelope()
    payload = envelope.to_dict()
    assert payload["envelope_version"] == ENVELOPE_SCHEMA_VERSION
    assert payload["scan_mode"] == ScanMode.LOCAL_ONLY.value
    assert payload["discovery_scope"] == []
    assert payload["permissions_used"] == []
    assert payload["redaction_status"] == RedactionStatus.NOT_APPLICABLE.value
    # captured_at is an ISO 8601 timestamp.
    parsed = datetime.fromisoformat(payload["captured_at"])
    assert parsed.tzinfo is not None


def test_envelope_round_trip() -> None:
    envelope = DiscoveryEnvelope(
        scan_mode=ScanMode.CLOUD_READ_ONLY,
        discovery_scope=("aws:account/12345", "aws:region/us-east-1"),
        permissions_used=("ec2:DescribeInstances", "iam:ListRoles"),
        redaction_status=RedactionStatus.CENTRAL_SANITIZER_APPLIED,
    )
    payload = envelope.to_dict()
    assert isinstance(payload["discovery_scope"], list)
    assert isinstance(payload["permissions_used"], list)
    rebuilt = DiscoveryEnvelope.from_dict(payload)
    assert rebuilt == envelope


def test_envelope_from_dict_defaults_unknown_enum_values_safely() -> None:
    payload = {
        "envelope_version": ENVELOPE_SCHEMA_VERSION,
        "scan_mode": "future_mode_unknown_to_us",
        "discovery_scope": [],
        "permissions_used": [],
        "redaction_status": "weird_thing",
    }
    rebuilt = DiscoveryEnvelope.from_dict(payload)
    # Forward-compat: unknown enum values fall back to safe defaults.
    assert rebuilt.scan_mode == ScanMode.LOCAL_ONLY
    assert rebuilt.redaction_status == RedactionStatus.NOT_APPLICABLE


def test_envelope_from_dict_rejects_wrong_schema_version() -> None:
    with pytest.raises(ValueError, match="Unsupported envelope_version"):
        DiscoveryEnvelope.from_dict({"envelope_version": 99})


def test_envelope_from_dict_rejects_non_object() -> None:
    with pytest.raises(ValueError, match="must be a JSON object"):
        DiscoveryEnvelope.from_dict([])  # type: ignore[arg-type]


def test_envelope_from_dict_rejects_non_list_scope() -> None:
    with pytest.raises(ValueError, match="discovery_scope"):
        DiscoveryEnvelope.from_dict({"discovery_scope": "not-a-list"})


def test_envelope_from_dict_coerces_scope_and_perms_to_strings() -> None:
    rebuilt = DiscoveryEnvelope.from_dict({"discovery_scope": [1, 2], "permissions_used": [3]})
    assert rebuilt.discovery_scope == ("1", "2")
    assert rebuilt.permissions_used == ("3",)


def test_agent_model_carries_envelope() -> None:
    """Agent dataclass round-trips the envelope dict through asdict()."""
    envelope = DiscoveryEnvelope(scan_mode=ScanMode.RUNTIME_PROBE)
    agent = Agent(
        name="claude-desktop",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/x",
        discovery_envelope=envelope.to_dict(),
    )
    payload = asdict(agent)
    assert payload["discovery_envelope"]["scan_mode"] == "runtime_probe"
    rebuilt = DiscoveryEnvelope.from_dict(payload["discovery_envelope"])
    assert rebuilt.scan_mode == ScanMode.RUNTIME_PROBE


# ─── AWS provider wiring ────────────────────────────────────────────────


def test_aws_permissions_baseline_only() -> None:
    from agent_bom.cloud.aws import _aws_permissions_for_jobs

    perms = _aws_permissions_for_jobs(
        include_ecs=False,
        include_sagemaker=False,
        include_lambda=False,
        include_eks=False,
        include_step_functions=False,
        include_ec2=False,
    )
    # Always-on: STS + Bedrock.
    assert "sts:GetCallerIdentity" in perms
    assert "bedrock-agent:ListAgents" in perms
    # Gated services should not appear when their flag is off.
    assert "ec2:DescribeInstances" not in perms
    assert "lambda:GetFunction" not in perms


def test_aws_permissions_include_optional_services() -> None:
    from agent_bom.cloud.aws import _aws_permissions_for_jobs

    perms = _aws_permissions_for_jobs(
        include_ecs=True,
        include_sagemaker=True,
        include_lambda=True,
        include_eks=True,
        include_step_functions=True,
        include_ec2=True,
    )
    for needle in (
        "ecs:DescribeTasks",
        "sagemaker:DescribeEndpoint",
        "lambda:GetFunction",
        "eks:DescribeCluster",
        "states:DescribeStateMachine",
        "ec2:DescribeInstances",
    ):
        assert needle in perms


def test_aws_permissions_sorted_and_unique() -> None:
    from agent_bom.cloud.aws import _aws_permissions_for_jobs

    perms = _aws_permissions_for_jobs(
        include_ecs=True,
        include_sagemaker=True,
        include_lambda=True,
        include_eks=True,
        include_step_functions=True,
        include_ec2=True,
    )
    assert list(perms) == sorted(perms)
    assert len(perms) == len(set(perms))


def test_aws_envelope_attached_to_discovered_agents(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without boto3 credentials this can't run real discovery, but we can
    verify the wiring by feeding a stub Bedrock job and asserting the
    envelope lands on every returned Agent.
    """
    pytest.importorskip("boto3")

    import agent_bom.cloud.aws as aws_module

    # Feed a single fake Bedrock agent. ECS/SageMaker/etc. are off by default.
    fake_agent = Agent(
        name="bedrock-agent-1",
        agent_type=AgentType.CUSTOM,
        config_path="arn:aws:bedrock:...",
        source="aws-bedrock",
    )

    def _fake_bedrock(*args, **kwargs):
        return [fake_agent], []

    def _fake_account(_session):
        return "111111111111"

    monkeypatch.setattr(aws_module, "_discover_bedrock", _fake_bedrock)
    monkeypatch.setattr(aws_module, "_resolve_account_id", _fake_account)

    class _FakeSession:
        region_name = "us-east-1"

    monkeypatch.setattr(aws_module.boto3 if hasattr(aws_module, "boto3") else __import__("boto3"), "Session", lambda **kw: _FakeSession())

    agents, warnings = aws_module.discover(include_ecs=False)
    assert len(agents) == 1
    envelope = agents[0].discovery_envelope
    assert envelope is not None
    assert envelope["scan_mode"] == ScanMode.CLOUD_READ_ONLY.value
    assert envelope["redaction_status"] == RedactionStatus.CENTRAL_SANITIZER_APPLIED.value
    assert "aws:account/111111111111" in envelope["discovery_scope"]
    assert "aws:region/us-east-1" in envelope["discovery_scope"]
    assert "sts:GetCallerIdentity" in envelope["permissions_used"]
    assert "bedrock-agent:ListAgents" in envelope["permissions_used"]
    assert envelope["envelope_version"] == ENVELOPE_SCHEMA_VERSION
