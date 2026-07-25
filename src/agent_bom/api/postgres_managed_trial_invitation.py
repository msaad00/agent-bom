"""PostgreSQL authority for managed-trial invitation lifecycle."""

from __future__ import annotations

import hmac
from datetime import datetime, timezone
from typing import Any

from agent_bom.api.managed_trial_invitation import (
    ManagedTrialInvitation,
    ManagedTrialInvitationError,
    normalize_invitation_email,
    validate_token_digest,
)
from agent_bom.api.postgres_common import (
    ConnectionPool,
    _get_pool,
    _tenant_connection,
    bypass_tenant_rls,
    reset_current_tenant,
    set_current_tenant,
)
from agent_bom.api.storage_schema import ensure_postgres_schema_version


class PostgresManagedTrialInvitationStore:
    def __init__(self, pool: ConnectionPool | None = None) -> None:
        self._pool = pool or _get_pool()
        with self._pool.connection() as conn:
            ensure_postgres_schema_version(conn, "managed_trial_invitations")

    @staticmethod
    def _from_row(row: tuple[Any, ...]) -> ManagedTrialInvitation:
        return ManagedTrialInvitation(
            invitation_id=str(row[0]),
            token_digest=str(row[1]),
            email=str(row[2]),
            tenant_id=str(row[3]),
            state=str(row[4]),
            created_at=row[5],
            expires_at=row[6],
            accepted_at=row[7],
        )

    def issue(self, invitation: ManagedTrialInvitation, *, team_name: str) -> None:
        validate_token_digest(invitation.token_digest)
        tenant_token = set_current_tenant(invitation.tenant_id)
        try:
            with _tenant_connection(self._pool) as conn:
                conn.execute(
                    "INSERT INTO teams (team_id, name, slug) VALUES (%s, %s, %s)",
                    (invitation.tenant_id, team_name.strip() or invitation.tenant_id, invitation.tenant_id),
                )
                conn.execute(
                    """INSERT INTO managed_trial_invitations
                       (invitation_id, token_digest, email, tenant_id, state, created_at, expires_at, accepted_at)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, NULL)""",
                    (
                        invitation.invitation_id,
                        invitation.token_digest,
                        invitation.email,
                        invitation.tenant_id,
                        invitation.state,
                        invitation.created_at,
                        invitation.expires_at,
                    ),
                )
                conn.commit()
        finally:
            reset_current_tenant(tenant_token)

    def get_by_digest(self, token_digest_value: str, *, now: datetime | None = None) -> ManagedTrialInvitation:
        digest = validate_token_digest(token_digest_value)
        current = now or datetime.now(timezone.utc)
        with bypass_tenant_rls():
            with _tenant_connection(self._pool) as conn:
                row = conn.execute(
                    """SELECT invitation_id, token_digest, email, tenant_id, state,
                              created_at, expires_at, accepted_at
                       FROM managed_trial_invitations WHERE token_digest = %s""",
                    (digest,),
                ).fetchone()
                if row is None or row[4] != "pending":
                    raise ManagedTrialInvitationError("Invalid or expired managed-trial invitation")
                if row[6] <= current:
                    conn.execute(
                        "UPDATE managed_trial_invitations SET state = 'expired' WHERE token_digest = %s AND state = 'pending'",
                        (digest,),
                    )
                    conn.commit()
                    raise ManagedTrialInvitationError("Invalid or expired managed-trial invitation")
                return self._from_row(row)

    def accept_digest(
        self,
        token_digest_value: str,
        *,
        verified_email: str,
        now: datetime | None = None,
    ) -> ManagedTrialInvitation:
        digest = validate_token_digest(token_digest_value)
        current = now or datetime.now(timezone.utc)
        try:
            normalized_email = normalize_invitation_email(verified_email)
        except ManagedTrialInvitationError as exc:
            raise ManagedTrialInvitationError("Invalid or expired managed-trial invitation") from exc
        with bypass_tenant_rls():
            with _tenant_connection(self._pool) as conn:
                row = conn.execute(
                    """SELECT invitation_id, token_digest, email, tenant_id, state,
                              created_at, expires_at, accepted_at
                       FROM managed_trial_invitations WHERE token_digest = %s FOR UPDATE""",
                    (digest,),
                ).fetchone()
                if row is None or row[4] != "pending":
                    raise ManagedTrialInvitationError("Invalid or expired managed-trial invitation")
                if row[6] <= current:
                    conn.execute(
                        "UPDATE managed_trial_invitations SET state = 'expired' WHERE token_digest = %s AND state = 'pending'",
                        (digest,),
                    )
                    conn.commit()
                    raise ManagedTrialInvitationError("Invalid or expired managed-trial invitation")
                if not hmac.compare_digest(str(row[2]), normalized_email):
                    raise ManagedTrialInvitationError("Invalid or expired managed-trial invitation")
                accepted = conn.execute(
                    """UPDATE managed_trial_invitations
                       SET state = 'accepted', accepted_at = %s
                       WHERE token_digest = %s AND state = 'pending'
                       RETURNING invitation_id, token_digest, email, tenant_id, state,
                                 created_at, expires_at, accepted_at""",
                    (current, digest),
                ).fetchone()
                if accepted is None:
                    raise ManagedTrialInvitationError("Invalid or expired managed-trial invitation")
                conn.commit()
                return self._from_row(accepted)
