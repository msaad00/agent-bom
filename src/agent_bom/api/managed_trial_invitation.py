"""Secret-minimal, email-bound invitations for opt-in managed trials."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Protocol

MANAGED_TRIAL_INVITATION_TTL = timedelta(hours=48)
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class ManagedTrialInvitationError(ValueError):
    """Raised when an invitation cannot be safely issued or accepted."""


class ManagedTrialInvitationConfigurationError(ManagedTrialInvitationError):
    """Raised when the opt-in managed-trial authority is unavailable."""


@dataclass(frozen=True)
class ManagedTrialInvitation:
    invitation_id: str
    token_digest: str
    email: str
    tenant_id: str
    state: str
    created_at: datetime
    expires_at: datetime
    accepted_at: datetime | None = None
    verified_subject: str | None = None


@dataclass(frozen=True)
class IssuedManagedTrialInvitation:
    """One-time delivery result. Only this transient value contains the raw token."""

    raw_token: str
    invitation: ManagedTrialInvitation


class ManagedTrialInvitationStore(Protocol):
    def issue(self, invitation: ManagedTrialInvitation, *, team_name: str) -> None: ...

    def get_by_digest(self, token_digest: str, *, now: datetime | None = None) -> ManagedTrialInvitation: ...

    def accept_digest(
        self,
        token_digest: str,
        *,
        verified_email: str,
        verified_subject: str = "managed-trial-subject",
        now: datetime | None = None,
    ) -> ManagedTrialInvitation: ...


def managed_trial_invitations_enabled() -> bool:
    return os.environ.get("AGENT_BOM_MANAGED_TRIAL_INVITATIONS", "").strip().lower() in {"1", "true", "yes", "on"}


def normalize_invitation_email(email: str) -> str:
    normalized = email.strip().casefold()
    if (
        not normalized
        or len(normalized) > 254
        or normalized.count("@") != 1
        or any(char.isspace() or ord(char) < 32 for char in normalized)
    ):
        raise ManagedTrialInvitationError("Invalid invitation email")
    local, domain = normalized.split("@", 1)
    if not local or not domain or domain.startswith(".") or domain.endswith(".") or "." not in domain:
        raise ManagedTrialInvitationError("Invalid invitation email")
    return normalized


def token_digest(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def validate_token_digest(value: str) -> str:
    if not _DIGEST_RE.fullmatch(value):
        raise ManagedTrialInvitationError("Invalid or expired managed-trial invitation")
    return value


def issue_managed_trial_invitation(
    store: ManagedTrialInvitationStore,
    *,
    email: str,
    tenant_id: str,
    team_name: str,
    now: datetime | None = None,
    ttl: timedelta = MANAGED_TRIAL_INVITATION_TTL,
) -> IssuedManagedTrialInvitation:
    issued_at = now or datetime.now(timezone.utc)
    if ttl <= timedelta(0):
        raise ManagedTrialInvitationError("Invitation lifetime must be positive")
    raw_token = f"abti_{secrets.token_urlsafe(32)}"
    invitation = ManagedTrialInvitation(
        invitation_id=f"mti_{secrets.token_hex(16)}",
        token_digest=token_digest(raw_token),
        email=normalize_invitation_email(email),
        tenant_id=tenant_id,
        state="pending",
        created_at=issued_at,
        expires_at=issued_at + ttl,
    )
    store.issue(invitation, team_name=team_name)
    return IssuedManagedTrialInvitation(raw_token=raw_token, invitation=invitation)


class InMemoryManagedTrialInvitationStore:
    """Explicit test backend; managed production trials require PostgreSQL."""

    def __init__(self) -> None:
        self._records: dict[str, ManagedTrialInvitation] = {}

    def issue(self, invitation: ManagedTrialInvitation, *, team_name: str) -> None:
        del team_name
        validate_token_digest(invitation.token_digest)
        if invitation.token_digest in self._records:
            raise ManagedTrialInvitationError("Invitation could not be issued")
        self._records[invitation.token_digest] = invitation

    def get_by_digest(self, token_digest_value: str, *, now: datetime | None = None) -> ManagedTrialInvitation:
        digest = validate_token_digest(token_digest_value)
        current = now or datetime.now(timezone.utc)
        invitation = self._records.get(digest)
        if invitation is None or invitation.state != "pending":
            raise ManagedTrialInvitationError("Invalid or expired managed-trial invitation")
        if invitation.expires_at <= current:
            self._records[digest] = replace(invitation, state="expired")
            raise ManagedTrialInvitationError("Invalid or expired managed-trial invitation")
        return invitation

    def accept_digest(
        self,
        token_digest_value: str,
        *,
        verified_email: str,
        verified_subject: str = "managed-trial-subject",
        now: datetime | None = None,
    ) -> ManagedTrialInvitation:
        current = now or datetime.now(timezone.utc)
        invitation = self.get_by_digest(token_digest_value, now=current)
        try:
            normalized_email = normalize_invitation_email(verified_email)
        except ManagedTrialInvitationError as exc:
            raise ManagedTrialInvitationError("Invalid or expired managed-trial invitation") from exc
        if not hmac.compare_digest(invitation.email, normalized_email):
            raise ManagedTrialInvitationError("Invalid or expired managed-trial invitation")
        normalized_subject = verified_subject.strip()
        if not normalized_subject or len(normalized_subject) > 256:
            raise ManagedTrialInvitationError("Invalid or expired managed-trial invitation")
        accepted = replace(
            invitation,
            state="accepted",
            accepted_at=current,
            verified_subject=normalized_subject,
        )
        self._records[invitation.token_digest] = accepted
        return accepted


_store: ManagedTrialInvitationStore | None = None


def get_managed_trial_invitation_store() -> ManagedTrialInvitationStore:
    """Return the durable managed-trial store, failing closed without Postgres."""
    global _store
    if _store is None:
        from agent_bom.api.storage_schema import postgres_deployment_configured

        if not postgres_deployment_configured():
            raise ManagedTrialInvitationConfigurationError("Managed-trial invitations require PostgreSQL")
        from agent_bom.api.postgres_managed_trial_invitation import PostgresManagedTrialInvitationStore

        _store = PostgresManagedTrialInvitationStore()
    return _store


def set_managed_trial_invitation_store_for_tests(store: ManagedTrialInvitationStore | None) -> None:
    global _store
    _store = store
