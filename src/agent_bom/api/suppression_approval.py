"""One activation contract for exceptions, feedback and triage suppressions."""

import json
from datetime import datetime, timezone
from typing import Any, Protocol, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from agent_bom.api import audit_log
from agent_bom.api.suppression_policy import SelfApprovalError as SelfApprovalError
from agent_bom.api.suppression_policy import expiry_window_error, require_distinct_approver
from agent_bom.core.timestamps import parse_identity_timestamp


class VulnException(Protocol):
    """Fields of a suppression record the activation contract reads and writes.

    ``exception_store.VulnException`` satisfies it; typing against the shape
    keeps this policy module from importing the store that calls it.
    """

    exception_id: str
    vuln_id: str
    package_name: str
    reason: str
    requested_by: str
    approved_by: str
    status: Any
    expires_at: str
    approved_at: str
    revoked_at: str
    approval_version: int
    decided_by: str

    def to_dict(self) -> dict[str, Any]: ...


_Record = TypeVar("_Record", bound=VulnException)
_Record_contra = TypeVar("_Record_contra", contravariant=True)


class ExceptionStore(Protocol[_Record_contra]):
    def put(self, exc: _Record_contra, *, tenant_id: str) -> None: ...


APPROVAL_VERSION = 1


class SuppressionApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expires_at: str | None = Field(None, max_length=64)


def suppression_requested(exc: "VulnException") -> bool:
    if exc.reason.startswith("[finding_feedback:"):
        state = exc.reason.split("]", 1)[0].removeprefix("[finding_feedback:")
        return state in {"false_positive", "accepted_risk", "not_affected", "not_applicable", "fixed_verified"}
    if exc.reason.startswith("[finding_triage]"):
        try:
            data = json.loads(exc.reason.removeprefix("[finding_triage]").strip())
        except (TypeError, ValueError):
            return False
        return isinstance(data, dict) and data.get("decision") == "not_affected"
    return True


def approval_error(exc: "VulnException", *, now: datetime | None = None) -> str | None:
    if any(not value.strip() or "*" in value for value in (exc.vuln_id, exc.package_name)):
        return "Suppression approval requires an exact finding and package scope"
    expiry = parse_identity_timestamp(exc.expires_at, require_timezone=True)
    if expiry is None or expiry <= (now or datetime.now(timezone.utc)):
        return "Suppression approval requires a valid future timezone-aware expiry"
    if not suppression_requested(exc):
        return "Investigation notes do not require suppression approval"
    return None


def suppression_active(exc: "VulnException") -> bool:
    now = datetime.now(timezone.utc)
    approved = parse_identity_timestamp(exc.approved_at, require_timezone=True)
    return (
        exc.approval_version == APPROVAL_VERSION
        and exc.status.value in {"active", "approved"}
        and bool(exc.approved_by.strip())
        and approved is not None
        and approved <= now
        and not exc.revoked_at
        and approval_error(exc, now=now) is None
    )


def activate_suppression(exc: "VulnException", *, actor: str) -> None:
    """Called only by separate authenticated admin approval surfaces."""
    if not actor.strip():
        raise ValueError("Authenticated approver identity is required")
    error = approval_error(exc) or expiry_window_error(exc.expires_at)
    if error:
        raise ValueError(error)
    require_distinct_approver(exc.requested_by, actor, decided_by=exc.decided_by)
    if exc.status.value not in {"pending", "active", "approved"}:
        raise ValueError("Exception state cannot be approved")
    exc.status = type(exc.status).ACTIVE
    exc.approved_by = actor
    exc.approved_at = datetime.now(timezone.utc).isoformat()
    exc.approval_version = APPROVAL_VERSION


def reset_suppression_request(exc: "VulnException", *, decided_by: str) -> None:
    """Changed assertions require a new explicit approval, never inherited authority.

    The principal asserting the changed decision is recorded separately from the
    original requester so four-eyes approval excludes both.
    """
    if not decided_by.strip():
        raise ValueError("Authenticated decision author identity is required")
    exc.decided_by = decided_by.strip()
    exc.status = type(exc.status).PENDING
    exc.approval_version = 0
    exc.approved_by = ""
    exc.approved_at = ""


class ApprovalPersistenceError(RuntimeError):
    """Approval could not be durably recorded."""


def persist_approval(exc: _Record, store: "ExceptionStore[_Record]", *, actor: str, tenant_id: str) -> None:
    activate_suppression(exc, actor=actor)
    try:
        # The receipt proves authorization to attempt activation, not a committed
        # cross-store transaction. If audit fails, no activation is written.
        audit_log.log_action(
            "exception.approval_authorized",
            actor=actor,
            resource=f"exception/{exc.exception_id}",
            tenant_id=tenant_id,
            expires_at=exc.expires_at,
        )
        store.put(exc, tenant_id=tenant_id)
    except Exception as error:  # broad-except: backend failure must not bypass required approval evidence.
        raise ApprovalPersistenceError("Suppression approval persistence unavailable") from error


def suppression_review_fields(exc: "VulnException") -> dict:
    """Approval state plus the decision author a reviewer must differ from."""
    return {
        "decided_by": exc.decided_by,
        "approval_status": exc.status.value,
        "approval_required": suppression_requested(exc) and not suppression_active(exc),
    }


def exception_response(exc: "VulnException") -> dict:
    """Expose effective approval separately from retained historical status."""
    return {
        **exc.to_dict(),
        "suppression_active": suppression_active(exc),
        "approval_required": suppression_requested(exc) and not suppression_active(exc),
    }
