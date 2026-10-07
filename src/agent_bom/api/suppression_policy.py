"""Operator policy bounding suppression requests and approvals.

Every suppression surface (REST exceptions, finding feedback, triage, MCP tools)
shares these rules so a waiver can neither outlive the review window nor be
approved by the principal who requested it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from agent_bom.core.settings import env_flag, env_int
from agent_bom.core.timestamps import parse_identity_timestamp

MAX_EXPIRY_DAYS_ENV = "AGENT_BOM_EXCEPTION_MAX_EXPIRY_DAYS"
ALLOW_SELF_APPROVAL_ENV = "AGENT_BOM_EXCEPTION_ALLOW_SELF_APPROVAL"
DEFAULT_MAX_EXPIRY_DAYS = 365
_MAX_CONFIGURABLE_DAYS = 3650


class SelfApprovalError(ValueError):
    """The approver is the same principal that requested the suppression."""


def max_expiry_days() -> int:
    return env_int(MAX_EXPIRY_DAYS_ENV, DEFAULT_MAX_EXPIRY_DAYS, minimum=1, maximum=_MAX_CONFIGURABLE_DAYS, on_invalid="default")


def self_approval_allowed() -> bool:
    return env_flag(ALLOW_SELF_APPROVAL_ENV)


def expiry_window_error(expires_at: str, *, now: datetime | None = None) -> str | None:
    """Reject an expiry past the configured review window; blank stays pending."""
    expiry = parse_identity_timestamp(expires_at, require_timezone=True)
    if expiry is None:
        return None
    days = max_expiry_days()
    if expiry > (now or datetime.now(timezone.utc)) + timedelta(days=days):
        return f"expires_at must be within {days} days ({MAX_EXPIRY_DAYS_ENV})"
    return None


def require_distinct_approver(requested_by: str, approver: str) -> None:
    requester = requested_by.strip().lower()
    if requester and requester == approver.strip().lower() and not self_approval_allowed():
        raise SelfApprovalError(
            f"Suppression approval requires a different approver than the requester; "
            f"single-operator deployments can set {ALLOW_SELF_APPROVAL_ENV}=1"
        )
