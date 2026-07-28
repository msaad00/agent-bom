"""Canonical managed-identity to client-profile resolution foundation (#4152)."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime

import pytest

from agent_bom.api.agent_identity_store import AgentIdentity
from agent_bom.api.mcp_config_store import InMemoryMcpConfigStore, McpClientConfigAssignment
from agent_bom.runtime.profile_resolution import ProfileResolutionCode, resolve_runtime_profile


def _identity(**overrides: object) -> AgentIdentity:
    values: dict[str, object] = {
        "identity_id": "identity-a",
        "agent_id": "agent-a",
        "tenant_id": "tenant-a",
        "token_hash": "must-never-leave-the-identity-store",
        "token_prefix": "public",
        "role": "finance-agent",
        "blueprint_id": "finance",
        "status": "active",
        "issued_at": "2026-01-01T00:00:00+00:00",
        "expires_at": "2030-01-01T00:00:00+00:00",
        "allowed_tools": ["read_file", "run_report"],
        "owner": "finance-platform",
    }
    values.update(overrides)
    return AgentIdentity(**values)  # type: ignore[arg-type]


def _assignment(**overrides: object) -> McpClientConfigAssignment:
    values: dict[str, object] = {
        "config_id": "client-profile-finance-prod",
        "tenant_id": "tenant-a",
        "name": "Finance production client",
        "profile_id": "finance",
        "identity_id": "identity-a",
        "connector_ids": ["filesystem", "snowflake"],
        "connection_ids": ["snowflake-prod"],
        "issuer": "agent-bom",
        "environment": "prod",
        "allowed_tools": ["read_file"],
        "required_scopes": ["tools:read"],
        "policy_ids": ["policy-finance"],
        "owner": "finance-security",
        "status": "active",
        "revision": 3,
        "expires_at": "2030-01-01T00:00:00+00:00",
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-07-17T00:00:00+00:00",
    }
    values.update(overrides)
    return McpClientConfigAssignment(**values)  # type: ignore[arg-type]


def _store(assignment: McpClientConfigAssignment | None = None) -> InMemoryMcpConfigStore:
    store = InMemoryMcpConfigStore()
    if assignment is not None:
        store.put(assignment)
    return store


def test_resolves_versioned_secret_free_profile_contract() -> None:
    result = resolve_runtime_profile(
        _store(_assignment()),
        identity=_identity(),
        tenant_id="tenant-a",
        issuer="agent-bom",
        environment="prod",
        granted_scopes={"tools:read", "openid"},
    )

    assert result.code is ProfileResolutionCode.RESOLVED
    assert result.profile is not None
    assert result.profile.schema_version == "runtime.client.profile.v1"
    assert result.profile.client_profile_id == "client-profile-finance-prod"
    assert result.profile.blueprint_id == "finance"
    assert result.profile.revision == 3
    assert result.profile.allowed_upstreams == ("filesystem", "snowflake")
    assert result.profile.allowed_tools == ("read_file",)
    assert result.profile.credential_references == ("connection:snowflake-prod",)
    assert result.profile.owner == "finance-security"
    serialized = repr(result.to_dict())
    assert "must-never-leave-the-identity-store" not in serialized
    assert "token_hash" not in serialized


@pytest.mark.parametrize(
    ("assignment", "code"),
    [
        (_assignment(revoked=True), ProfileResolutionCode.PROFILE_REVOKED),
        (_assignment(status="disabled"), ProfileResolutionCode.PROFILE_DISABLED),
        (_assignment(expires_at="2020-01-01T00:00:00+00:00"), ProfileResolutionCode.PROFILE_EXPIRED),
        (_assignment(profile_id="unknown-role"), ProfileResolutionCode.BLUEPRINT_UNKNOWN),
    ],
)
def test_non_live_or_unknown_profile_fails_closed(
    assignment: McpClientConfigAssignment,
    code: ProfileResolutionCode,
) -> None:
    result = resolve_runtime_profile(
        _store(assignment),
        identity=_identity(blueprint_id=assignment.profile_id),
        tenant_id="tenant-a",
        issuer="agent-bom",
        environment="prod",
        granted_scopes={"tools:read"},
    )
    assert result.code is code
    assert result.profile is None


@pytest.mark.parametrize(
    ("assignment", "kwargs", "code"),
    [
        (_assignment(), {"tenant_id": "tenant-b"}, ProfileResolutionCode.TENANT_MISMATCH),
        (_assignment(), {"issuer": "foreign"}, ProfileResolutionCode.ISSUER_MISMATCH),
        (_assignment(), {"environment": "dev"}, ProfileResolutionCode.ENVIRONMENT_MISMATCH),
        (_assignment(), {"granted_scopes": set()}, ProfileResolutionCode.INSUFFICIENT_SCOPE),
        (_assignment(issuer=""), {}, ProfileResolutionCode.PROFILE_INCOMPLETE),
        (_assignment(environment=""), {}, ProfileResolutionCode.PROFILE_INCOMPLETE),
    ],
)
def test_request_context_cannot_escape_binding(
    assignment: McpClientConfigAssignment,
    kwargs: dict[str, object],
    code: ProfileResolutionCode,
) -> None:
    call: dict[str, object] = {
        "identity": _identity(),
        "tenant_id": "tenant-a",
        "issuer": "agent-bom",
        "environment": "prod",
        "granted_scopes": {"tools:read"},
    }
    call.update(kwargs)
    result = resolve_runtime_profile(_store(assignment), **call)  # type: ignore[arg-type]
    assert result.code is code
    assert result.profile is None


def test_disjoint_identity_and_profile_tool_constraints_deny_all() -> None:
    result = resolve_runtime_profile(
        _store(_assignment(allowed_tools=["write_file"])),
        identity=_identity(allowed_tools=["read_file"]),
        tenant_id="tenant-a",
        issuer="agent-bom",
        environment="prod",
        granted_scopes={"tools:read"},
    )
    assert result.code is ProfileResolutionCode.TOOL_CONSTRAINT_CONFLICT
    assert result.profile is None


def test_missing_binding_and_inactive_identity_fail_closed() -> None:
    missing = resolve_runtime_profile(
        _store(),
        identity=_identity(),
        tenant_id="tenant-a",
        issuer="agent-bom",
        environment="prod",
        granted_scopes={"tools:read"},
    )
    assert missing.code is ProfileResolutionCode.PROFILE_NOT_FOUND

    inactive = resolve_runtime_profile(
        _store(_assignment()),
        identity=replace(_identity(), status="revoked"),
        tenant_id="tenant-a",
        issuer="agent-bom",
        environment="prod",
        granted_scopes={"tools:read"},
    )
    assert inactive.code is ProfileResolutionCode.IDENTITY_INACTIVE


def test_naive_identity_expiry_fails_closed_without_raising() -> None:
    result = resolve_runtime_profile(
        _store(_assignment()),
        identity=_identity(expires_at="2030-01-01T00:00:00"),
        tenant_id="tenant-a",
        issuer="agent-bom",
        environment="prod",
        granted_scopes={"tools:read"},
    )

    assert result.code is ProfileResolutionCode.IDENTITY_INACTIVE
    assert result.profile is None


def test_naive_resolution_clock_fails_closed_without_raising() -> None:
    result = resolve_runtime_profile(
        _store(_assignment()),
        identity=_identity(expires_at=""),
        tenant_id="tenant-a",
        issuer="agent-bom",
        environment="prod",
        granted_scopes={"tools:read"},
        at=datetime(2026, 7, 28),
    )

    assert result.code is ProfileResolutionCode.IDENTITY_INACTIVE
    assert result.profile is None
