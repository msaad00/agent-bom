"""Per-run discovery envelope (#2083 PR A).

The envelope is the **per-run trust contract** for an Agent. It records
*what the scan actually did* on this run: which mode it ran in, what scope
was requested, which IAM/API permissions were exercised, and whether
sensitive values were redacted or never collected at all.

This is distinct from `discovery_provenance` (the sanitized record of
*where the asset came from*) — both can coexist on the same Agent:

- `discovery_provenance`: "This Agent was pulled from AWS account 12345 via
  cloud_pull observed_via=['cloud_pull']."
- `discovery_envelope`:   "This run used cloud_read_only mode, scoped to
  account/12345, region/us-east-1, exercised ec2:DescribeInstances and
  iam:GetRole, redaction_status=central_sanitizer_applied."

Operators running agent-bom locally, on endpoints, or inside cloud / SaaS
infrastructure get a code-backed answer for "what did this scan do" without
having to read the provider source.

Scope (PR A): the canonical model. AWS is wired as the first producer.
Other providers and connectors follow in subsequent PRs (#2083 series).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

ENVELOPE_SCHEMA_VERSION = 1


class ScanMode(str, Enum):
    """Locked enum of how the scan was executed.

    A locked vocabulary keeps the trust contract reliable. New modes get
    added here intentionally; ad hoc strings are not accepted.
    """

    LOCAL_ONLY = "local_only"
    """No network egress, no cloud / SaaS read, no runtime probe."""

    CLOUD_READ_ONLY = "cloud_read_only"
    """Read-only API calls against a cloud provider (AWS, Azure, GCP, …)."""

    SAAS_READ_ONLY = "saas_read_only"
    """Read-only API calls against a SaaS surface (Snowflake, Databricks, …)."""

    RUNTIME_PROBE = "runtime_probe"
    """Live MCP server introspection (tools/list, resources/list, …)."""

    CONTAINER_LOCAL = "container_local"
    """Local container scan — image layers, manifests, no runtime probe."""

    ENDPOINT_PUSH = "endpoint_push"
    """Endpoint-side discovery pushed into the API; pull-only on the server side."""


class RedactionStatus(str, Enum):
    """Redaction posture for sensitive values seen during this run."""

    NEVER_COLLECTED = "never_collected"
    """The provider deliberately never read the sensitive value (e.g. a token)."""

    REDACTED_IN_PLACE = "redacted_in_place"
    """The provider redacted the value before returning it (e.g. last 4 of a key)."""

    CENTRAL_SANITIZER_APPLIED = "central_sanitizer_applied"
    """The shared `agent_bom.security` sanitizer scrubbed the value before storage."""

    NOT_APPLICABLE = "not_applicable"
    """No sensitive values were in scope for this run."""


@dataclass(frozen=True)
class DiscoveryEnvelope:
    """Per-run trust contract attached to a discovered Agent.

    All fields are intentionally simple types so the envelope round-trips
    cleanly through JSON / SARIF / OCSF / SBOM exporters and across the
    `/v1/agents` API surface.
    """

    envelope_version: int = ENVELOPE_SCHEMA_VERSION
    scan_mode: ScanMode = ScanMode.LOCAL_ONLY
    discovery_scope: tuple[str, ...] = ()
    """Strings describing what was explicitly in scope, e.g.
    ``("aws:account/123456789012", "aws:region/us-east-1")``."""

    permissions_used: tuple[str, ...] = ()
    """Actual IAM/API permissions exercised, e.g.
    ``("ec2:DescribeInstances", "iam:ListRoles")``."""

    redaction_status: RedactionStatus = RedactionStatus.NOT_APPLICABLE
    captured_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable payload (canonical shape).

        Tuples are flattened to lists so the wire shape matches `/v1/agents`
        responses without a custom encoder.
        """
        return {
            "envelope_version": self.envelope_version,
            "scan_mode": self.scan_mode.value,
            "discovery_scope": list(self.discovery_scope),
            "permissions_used": list(self.permissions_used),
            "redaction_status": self.redaction_status.value,
            "captured_at": self.captured_at,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> DiscoveryEnvelope:
        """Build an envelope from a JSON-decoded payload.

        Strict on schema version (only `1` accepted today) so an envelope
        emitted by a newer producer can be detected and routed; loose on
        unknown enum values (falls back to LOCAL_ONLY / NOT_APPLICABLE so a
        future producer doesn't crash old consumers).
        """
        if not isinstance(payload, dict):
            raise ValueError("DiscoveryEnvelope payload must be a JSON object")
        version = payload.get("envelope_version", ENVELOPE_SCHEMA_VERSION)
        if version != ENVELOPE_SCHEMA_VERSION:
            raise ValueError(f"Unsupported envelope_version: {version!r} (expected {ENVELOPE_SCHEMA_VERSION})")
        try:
            scan_mode = ScanMode(payload.get("scan_mode", ScanMode.LOCAL_ONLY.value))
        except ValueError:
            scan_mode = ScanMode.LOCAL_ONLY
        try:
            redaction_status = RedactionStatus(payload.get("redaction_status", RedactionStatus.NOT_APPLICABLE.value))
        except ValueError:
            redaction_status = RedactionStatus.NOT_APPLICABLE

        scope = payload.get("discovery_scope") or ()
        if not isinstance(scope, (list, tuple)):
            raise ValueError("discovery_scope must be a list of strings")
        perms = payload.get("permissions_used") or ()
        if not isinstance(perms, (list, tuple)):
            raise ValueError("permissions_used must be a list of strings")
        captured_at = payload.get("captured_at") or datetime.now(timezone.utc).isoformat()
        return cls(
            envelope_version=version,
            scan_mode=scan_mode,
            discovery_scope=tuple(str(s) for s in scope),
            permissions_used=tuple(str(p) for p in perms),
            redaction_status=redaction_status,
            captured_at=str(captured_at),
        )


__all__ = [
    "ENVELOPE_SCHEMA_VERSION",
    "DiscoveryEnvelope",
    "RedactionStatus",
    "ScanMode",
]
