"""Canonical, fail-closed managed client-profile resolution.

This joins the existing managed identity, MCP client-config assignment, and
runtime role blueprint. Legacy unbound assignments remain distributable, but
cannot be upgraded into observed runtime authorization.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from agent_bom.api.agent_identity_store import AgentIdentity
from agent_bom.api.mcp_config_store import McpClientConfigAssignment, McpConfigStore
from agent_bom.runtime_blueprints import runtime_role_blueprint

PROFILE_SCHEMA_VERSION = "runtime.client.profile.v1"


class ProfileResolutionCode(str, Enum):
    RESOLVED = "resolved"
    IDENTITY_INACTIVE = "identity_inactive"
    TENANT_MISMATCH = "tenant_mismatch"
    PROFILE_NOT_FOUND = "profile_not_found"
    PROFILE_REVOKED = "profile_revoked"
    PROFILE_DISABLED = "profile_disabled"
    PROFILE_EXPIRED = "profile_expired"
    PROFILE_INCOMPLETE = "profile_incomplete"
    BLUEPRINT_UNKNOWN = "blueprint_unknown"
    BLUEPRINT_MISMATCH = "blueprint_mismatch"
    ISSUER_MISMATCH = "issuer_mismatch"
    ENVIRONMENT_MISMATCH = "environment_mismatch"
    INSUFFICIENT_SCOPE = "insufficient_scope"
    TOOL_CONSTRAINT_CONFLICT = "tool_constraint_conflict"


@dataclass(frozen=True)
class ResolvedRuntimeProfile:
    """Secret-free authorization view for a single managed identity."""

    client_profile_id: str
    tenant_id: str
    revision: int
    blueprint_id: str
    blueprint_revision: int
    identity_id: str
    agent_id: str
    issuer: str
    environment: str
    allowed_upstreams: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    required_scopes: tuple[str, ...]
    policy_ids: tuple[str, ...]
    credential_references: tuple[str, ...]
    owner: str
    status: str
    expires_at: str
    schema_version: str = PROFILE_SCHEMA_VERSION

    def allows_upstream(self, upstream: str) -> bool:
        return "*" in self.allowed_upstreams or upstream in self.allowed_upstreams

    def allows_tool(self, tool: str) -> bool:
        return not self.allowed_tools or "*" in self.allowed_tools or tool in self.allowed_tools

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ProfileResolution:
    code: ProfileResolutionCode
    profile: ResolvedRuntimeProfile | None = None

    @property
    def resolved(self) -> bool:
        return self.code is ProfileResolutionCode.RESOLVED and self.profile is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": PROFILE_SCHEMA_VERSION,
            "code": self.code.value,
            "resolved": self.resolved,
            "profile": self.profile.to_dict() if self.profile is not None else None,
        }


def _normalized(values: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value.strip() for value in values if value.strip()))


def _intersect_constraints(identity_values: list[str], profile_values: list[str]) -> tuple[str, ...] | None:
    identity = _normalized(identity_values)
    profile = _normalized(profile_values)
    if not identity:
        return profile
    if not profile:
        return identity
    if "*" in identity:
        return profile
    if "*" in profile:
        return identity
    intersection = tuple(value for value in identity if value in set(profile))
    # Empty normally means unrestricted in the established identity contract;
    # preserve that meaning by representing disjoint non-empty constraints as
    # an explicit resolution denial instead of an empty allowlist.
    return intersection or None


def _expired(value: str, *, at: datetime) -> bool:
    if not value:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return True
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return True
    return parsed <= at


def _deny(code: ProfileResolutionCode) -> ProfileResolution:
    return ProfileResolution(code=code)


def _inactive_code(rows: list[McpClientConfigAssignment]) -> ProfileResolutionCode:
    if len(rows) == 1:
        if rows[0].revoked or rows[0].status == "revoked":
            return ProfileResolutionCode.PROFILE_REVOKED
        if rows[0].status != "active":
            return ProfileResolutionCode.PROFILE_DISABLED
    return ProfileResolutionCode.PROFILE_NOT_FOUND


def resolve_runtime_profile(
    assignment_store: McpConfigStore,
    *,
    identity: AgentIdentity,
    tenant_id: str,
    issuer: str,
    environment: str,
    granted_scopes: set[str] | frozenset[str],
    at: datetime | None = None,
) -> ProfileResolution:
    """Resolve one managed identity to its unique live, versioned profile."""

    now = at or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        return _deny(ProfileResolutionCode.IDENTITY_INACTIVE)
    if identity.tenant_id != tenant_id:
        return _deny(ProfileResolutionCode.TENANT_MISMATCH)
    try:
        identity_live = identity.is_live(at=now)
    except (TypeError, ValueError):
        # Legacy or externally restored identities can contain malformed or
        # timezone-naive expiry values. Resolution is an authorization seam,
        # so invalid lifecycle evidence is a denial rather than a runtime 500.
        identity_live = False
    if not identity_live:
        return _deny(ProfileResolutionCode.IDENTITY_INACTIVE)

    assignment = assignment_store.get_active_for_identity(tenant_id, identity.identity_id)
    if assignment is None:
        return _deny(_inactive_code(assignment_store.list_for_identity(tenant_id, identity.identity_id, limit=2)))
    if assignment.revoked:
        return _deny(ProfileResolutionCode.PROFILE_REVOKED)
    if assignment.status != "active":
        return _deny(ProfileResolutionCode.PROFILE_DISABLED)
    if _expired(assignment.expires_at, at=now):
        return _deny(ProfileResolutionCode.PROFILE_EXPIRED)
    if not assignment.issuer or not assignment.environment:
        return _deny(ProfileResolutionCode.PROFILE_INCOMPLETE)

    blueprint = runtime_role_blueprint(assignment.profile_id)
    if blueprint is None:
        return _deny(ProfileResolutionCode.BLUEPRINT_UNKNOWN)
    blueprint_id = str(blueprint["blueprint_id"])
    identity_blueprint = identity.blueprint_id.strip().lower().replace("-", "_")
    if identity_blueprint != blueprint_id:
        return _deny(ProfileResolutionCode.BLUEPRINT_MISMATCH)
    if assignment.issuer != issuer:
        return _deny(ProfileResolutionCode.ISSUER_MISMATCH)
    if assignment.environment != environment:
        return _deny(ProfileResolutionCode.ENVIRONMENT_MISMATCH)

    required_scopes = _normalized(assignment.required_scopes)
    if not set(required_scopes).issubset(granted_scopes):
        return _deny(ProfileResolutionCode.INSUFFICIENT_SCOPE)
    allowed_tools = _intersect_constraints(identity.allowed_tools, assignment.allowed_tools)
    if allowed_tools is None:
        return _deny(ProfileResolutionCode.TOOL_CONSTRAINT_CONFLICT)

    raw_blueprint_revision = blueprint.get("revision")
    blueprint_revision = raw_blueprint_revision if isinstance(raw_blueprint_revision, int) else 1
    return ProfileResolution(
        code=ProfileResolutionCode.RESOLVED,
        profile=ResolvedRuntimeProfile(
            client_profile_id=assignment.config_id,
            tenant_id=tenant_id,
            revision=max(1, int(assignment.revision)),
            blueprint_id=blueprint_id,
            blueprint_revision=max(1, blueprint_revision),
            identity_id=identity.identity_id,
            agent_id=identity.agent_id,
            issuer=assignment.issuer,
            environment=assignment.environment,
            allowed_upstreams=_normalized(assignment.connector_ids),
            allowed_tools=allowed_tools,
            required_scopes=required_scopes,
            policy_ids=_normalized(assignment.policy_ids),
            credential_references=tuple(f"connection:{value}" for value in _normalized(assignment.connection_ids)),
            owner=assignment.owner or identity.owner,
            status=assignment.status,
            expires_at=assignment.expires_at,
        ),
    )


__all__ = [
    "PROFILE_SCHEMA_VERSION",
    "ProfileResolution",
    "ProfileResolutionCode",
    "ResolvedRuntimeProfile",
    "resolve_runtime_profile",
]
